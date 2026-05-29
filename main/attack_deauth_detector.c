#include "attack_deauth_detector.h"
#include "frame_analyzer.h"
#include "wifi_controller.h"
#include <string.h>
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_timer.h"

static const char *TAG = "DEAUTH_DETECTOR";

#define ALERT_HOLD_MS 5000

typedef struct {
    uint8_t frame_ctrl[2];
    uint16_t duration;
    uint8_t addr1[6];
    uint8_t addr2[6];
    uint8_t addr3[6];
} __attribute__((packed)) wifi_80211_hdr_t;

static deauth_detector_status_t detector_status = {0};
static bool promiscuous_held = false;

static bool is_zero_mac(const uint8_t *mac) {
    for (int i = 0; i < 6; i++) {
        if (mac[i] != 0x00) {
            return false;
        }
    }
    return true;
}

static deauth_track_entry_t *get_or_create_entry(const uint8_t *bssid) {
    for (int i = 0; i < detector_status.count; i++) {
        if (memcmp(detector_status.entries[i].bssid, bssid, 6) == 0) {
            return &detector_status.entries[i];
        }
    }
    if (detector_status.count >= MAX_TRACKED_BSSIDS) {
        return &detector_status.entries[0];
    }
    deauth_track_entry_t *e = &detector_status.entries[detector_status.count++];
    memset(e, 0, sizeof(*e));
    memcpy(e->bssid, bssid, 6);
    e->window_start_ms = esp_timer_get_time() / 1000;
    return e;
}

static void promiscuous_rx_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT) {
        return;
    }
    
    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    if (pkt == NULL) {
        return;
    }
    
    /* Frame must be at least 24 bytes for management frame header */
    if (pkt->rx_ctrl.sig_len < 24) {
        return;
    }
    
    const uint8_t *payload = pkt->payload;
    
    /* Check frame control to identify deauth/disassoc frames */
    uint8_t frame_ctrl_low = payload[0];
    uint8_t subtype = (frame_ctrl_low >> 4) & 0x0F;
    
    /* Subtype 12 = Deauth (0xC0), Subtype 10 = Disassoc (0xA0) */
    if (subtype != 12 && subtype != 10) {
        return;
    }
    
    const wifi_80211_hdr_t *hdr = (wifi_80211_hdr_t *)payload;
    
    /* Skip zero MAC addresses */
    if (is_zero_mac(hdr->addr3)) {
        return;
    }

    int64_t now_ms = esp_timer_get_time() / 1000;
    deauth_track_entry_t *entry = get_or_create_entry(hdr->addr3);
    
    /* Check if we're in a new time window */
    if ((now_ms - entry->window_start_ms) > DEAUTH_WINDOW_MS) {
        entry->count = 0;
        entry->window_start_ms = now_ms;
    }
    
    entry->count++;
    
    /* Alert if threshold exceeded */
    if (entry->count >= DEAUTH_THRESHOLD && !entry->alerting) {
        entry->alerting = true;
        entry->last_alert_ms = now_ms;
        ESP_LOGW(TAG, "⚠️ DEAUTH ATTACK DETECTED! BSSID: " MACSTR " (%d frames)", 
                 MAC2STR(entry->bssid), entry->count);
    }
}

const deauth_detector_status_t *deauth_detector_get_status(void) {
    int64_t now_ms = esp_timer_get_time() / 1000;
    for (int i = 0; i < detector_status.count; i++) {
        deauth_track_entry_t *e = &detector_status.entries[i];
        if (e->alerting && (now_ms - e->last_alert_ms > ALERT_HOLD_MS)) {
            e->alerting = false;
        }
    }
    return &detector_status;
}

void deauth_detector_start(void) {
    esp_err_t ret;
    
    memset(&detector_status, 0, sizeof(detector_status));
    detector_status.running = true;
    
    /* Acquire promiscuous mode */
    ret = wifi_controller_promiscuous_acquire();
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to acquire promiscuous mode: %s", esp_err_to_name(ret));
        detector_status.running = false;
        return;
    }
    promiscuous_held = true;
    
    /* Enable promiscuous mode */
    ret = esp_wifi_set_promiscuous(true);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to enable promiscuous mode: %s", esp_err_to_name(ret));
        wifi_controller_promiscuous_release();
        promiscuous_held = false;
        detector_status.running = false;
        return;
    }
    
    /* Set promiscuous callback */
    esp_wifi_set_promiscuous_rx_cb(&promiscuous_rx_cb);
    
    /* Filter for management frames only */
    wifi_promiscuous_filter_t filter = {.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT};
    esp_wifi_set_promiscuous_filter(&filter);
    
    ESP_LOGI(TAG, "✅ Deauth detector started");
}

void deauth_detector_stop(void) {
    if (!detector_status.running) {
        return;
    }
    
    /* Disable promiscuous mode */
    esp_wifi_set_promiscuous(false);
    
    /* Clear callback */
    esp_wifi_set_promiscuous_rx_cb(NULL);
    
    /* Release promiscuous mode */
    if (promiscuous_held) {
        wifi_controller_promiscuous_release();
        promiscuous_held = false;
    }
    
    detector_status.running = false;
    ESP_LOGI(TAG, "✅ Deauth detector stopped");
}
