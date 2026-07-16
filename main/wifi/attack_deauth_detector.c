#include "attack_deauth_detector.h"
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "cJSON.h"

static const char *TAG = "deauth_detector";

/* ──────────────────────────────────────────────
 *  802.11 header for parsing
 * ────────────────────────────────────────────── */
typedef struct {
    uint8_t  frame_ctrl[2];
    uint16_t duration;
    uint8_t  addr1[6];   /* destination */
    uint8_t  addr2[6];   /* source      */
    uint8_t  addr3[6];   /* BSSID       */
} __attribute__((packed)) wifi_80211_hdr_t;

/* ──────────────────────────────────────────────
 *  Mutex (lazy-init)
 * ────────────────────────────────────────────── */
static SemaphoreHandle_t deauth_mutex = NULL;

static void deauth_mutex_init(void) {
    if (deauth_mutex == NULL) {
        deauth_mutex = xSemaphoreCreateMutex();
    }
}

/* ──────────────────────────────────────────────
 *  State variables
 * ────────────────────────────────────────────── */
static deauth_detector_status_t detector_status = { 0 };

static bool          is_running    = false;
static bool          was_timeout   = false;
static int64_t       start_time_us = 0;     /* when detector started */
static esp_timer_handle_t timeout_timer = NULL;
static uint32_t      total_deauths = 0;     /* global deauth frame counter */

/* ──────────────────────────────────────────────
 *  Helpers
 * ────────────────────────────────────────────── */
static bool is_zero_mac(const uint8_t *mac) {
    for (int i = 0; i < 6; i++) {
        if (mac[i] != 0x00) return false;
    }
    return true;
}

static void mac_to_str(const uint8_t *mac, char *out, size_t out_len) {
    snprintf(out, out_len, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/* ──────────────────────────────────────────────
 *  Tracking table management
 * ────────────────────────────────────────────── */
static deauth_track_entry_t *get_or_create_entry(const uint8_t *bssid) {
    /* Find existing */
    for (int i = 0; i < detector_status.count; i++) {
        if (memcmp(detector_status.entries[i].bssid, bssid, 6) == 0) {
            return &detector_status.entries[i];
        }
    }

    /* Table full — evict the oldest (lowest total_deauths, non-alerting) */
    if (detector_status.count >= MAX_TRACKED_BSSIDS) {
        int evict = 0;
        uint32_t lowest = UINT32_MAX;
        for (int i = 0; i < detector_status.count; i++) {
            if (!detector_status.entries[i].alerting &&
                detector_status.entries[i].total_deauths < lowest) {
                lowest = detector_status.entries[i].total_deauths;
                evict  = i;
            }
        }
        /* Overwrite the evicted slot */
        memset(&detector_status.entries[evict], 0, sizeof(deauth_track_entry_t));
        memcpy(detector_status.entries[evict].bssid, bssid, 6);
        detector_status.entries[evict].window_start_ms = esp_timer_get_time() / 1000;
        return &detector_status.entries[evict];
    }

    /* Add new */
    deauth_track_entry_t *e = &detector_status.entries[detector_status.count++];
    memset(e, 0, sizeof(*e));
    memcpy(e->bssid, bssid, 6);
    e->window_start_ms = esp_timer_get_time() / 1000;

    return e;
}

/* ──────────────────────────────────────────────
 *  Timeout callback
 * ────────────────────────────────────────────── */
static void deauth_timeout_cb(void *arg) {
    (void)arg;
    deauth_mutex_init();
    if (xSemaphoreTake(deauth_mutex, pdMS_TO_TICKS(1000))) {
        if (is_running) {
            was_timeout = true;
            is_running  = false;

            esp_wifi_set_promiscuous(false);
            esp_wifi_set_promiscuous_rx_cb(NULL);

            ESP_LOGW(TAG, "Deauth detector auto-stopped after %d s timeout.",
                     DEAUTH_DETECT_TIMEOUT_SEC);
        }
        xSemaphoreGive(deauth_mutex);
    }
}

/* ──────────────────────────────────────────────
 *  Promiscuous RX callback
 * ────────────────────────────────────────────── */
static void promiscuous_rx_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (type != WIFI_PKT_MGMT) return;

    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *) buf;
    const wifi_80211_hdr_t       *hdr = (wifi_80211_hdr_t *) pkt->payload;

    if (is_zero_mac(hdr->addr3)) return;

    /* Check: deauth (0xC0) or disassoc (0xA0) management subtype */
    uint8_t frame_type    = hdr->frame_ctrl[0] & 0x0C;
    uint8_t frame_subtype = hdr->frame_ctrl[0] & 0xF0;

    if (frame_type != 0x00) return;
    if (frame_subtype != 0xC0 && frame_subtype != 0xA0) return;

    bool is_disassoc = (frame_subtype == 0xA0);

    int64_t now_ms = esp_timer_get_time() / 1000;

    deauth_track_entry_t *entry = get_or_create_entry(hdr->addr3);

    /* Sliding window: reset if window expired */
    if ((now_ms - entry->window_start_ms) > DEAUTH_WINDOW_MS) {
        entry->count = 0;
        entry->window_start_ms = now_ms;
    }

    entry->count++;
    entry->total_deauths++;
    total_deauths++;

    /* Trigger alert if threshold exceeded */
    if (entry->count >= DEAUTH_THRESHOLD && !entry->alerting) {
        entry->alerting      = true;
        entry->last_alert_ms = now_ms;

        char bssid_str[18];
        mac_to_str(entry->bssid, bssid_str, sizeof(bssid_str));

        ESP_LOGW(TAG,
                 "DEAUTH %s: BSSID %s [%lu frames in window, %lu total]%s",
                 is_disassoc ? "DISASSOC" : "DETECTED",
                 bssid_str,
                 (unsigned long)entry->count,
                 (unsigned long)entry->total_deauths,
                 entry->ssid[0] ? "" : " (unknown SSID)");
    }
}

/* ──────────────────────────────────────────────
 *  Clear alert flags that have expired
 * ────────────────────────────────────────────── */
static void expire_alerts(void) {
    int64_t now_ms = esp_timer_get_time() / 1000;
    for (int i = 0; i < detector_status.count; i++) {
        deauth_track_entry_t *e = &detector_status.entries[i];
        if (e->alerting && (now_ms - e->last_alert_ms > DEAUTH_ALERT_HOLD_MS)) {
            e->alerting = false;
        }
    }
}

/* ──────────────────────────────────────────────
 *  Core API
 * ────────────────────────────────────────────── */

void deauth_detector_start(void) {
    deauth_mutex_init();

    if (xSemaphoreTake(deauth_mutex, pdMS_TO_TICKS(1000)) == pdFALSE) {
        ESP_LOGE(TAG, "Failed to acquire mutex in start");
        return;
    }

    /* Double-start guard */
    if (is_running) {
        ESP_LOGW(TAG, "Deauth detector already running — ignoring start");
        xSemaphoreGive(deauth_mutex);
        return;
    }

    /* Reset all state */
    memset(&detector_status, 0, sizeof(detector_status));
    total_deauths = 0;
    was_timeout   = false;
    start_time_us = esp_timer_get_time();

    /* Start promiscuous mode — management frames only */
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(&promiscuous_rx_cb);
    esp_wifi_set_promiscuous(true);

    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT
    };
    esp_wifi_set_promiscuous_filter(&filter);

    is_running = true;
    detector_status.running = true;

    /* Start / restart timeout timer */
    if (timeout_timer != NULL) {
        esp_timer_stop(timeout_timer);
        esp_timer_delete(timeout_timer);
        timeout_timer = NULL;
    }

    const esp_timer_create_args_t timer_args = {
        .callback = deauth_timeout_cb,
        .name     = "deauth_timeout"
    };
    esp_timer_create(&timer_args, &timeout_timer);
    esp_timer_start_once(timeout_timer, DEAUTH_DETECT_TIMEOUT_US);

    ESP_LOGI(TAG, "Deauth detector started — auto-stop in %d s",
             DEAUTH_DETECT_TIMEOUT_SEC);

    xSemaphoreGive(deauth_mutex);
}

void deauth_detector_stop(void) {
    deauth_mutex_init();

    if (xSemaphoreTake(deauth_mutex, pdMS_TO_TICKS(1000)) == pdFALSE) {
        ESP_LOGE(TAG, "Failed to acquire mutex in stop");
        return;
    }

    if (!is_running) {
        xSemaphoreGive(deauth_mutex);
        return;
    }

    /* Disable promiscuous mode */
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(NULL);

    is_running = false;
    detector_status.running = false;

    /* Stop timeout timer */
    if (timeout_timer != NULL) {
        esp_timer_stop(timeout_timer);
        esp_timer_delete(timeout_timer);
        timeout_timer = NULL;
    }

    ESP_LOGI(TAG, "Deauth detector stopped. Total deauth frames seen: %lu",
             (unsigned long)total_deauths);

    xSemaphoreGive(deauth_mutex);
}

/* ──────────────────────────────────────────────
 *  Webserver / Dashboard Getters  (thread-safe)
 * ────────────────────────────────────────────── */

bool deauth_detector_is_running(void) {
    deauth_mutex_init();
    bool val = false;
    if (xSemaphoreTake(deauth_mutex, pdMS_TO_TICKS(500))) {
        val = is_running;
        xSemaphoreGive(deauth_mutex);
    }
    return val;
}

uint8_t deauth_detector_get_tracked_count(void) {
    deauth_mutex_init();
    uint8_t val = 0;
    if (xSemaphoreTake(deauth_mutex, pdMS_TO_TICKS(500))) {
        val = (uint8_t)detector_status.count;
        xSemaphoreGive(deauth_mutex);
    }
    return val;
}

uint8_t deauth_detector_get_alert_count(void) {
    deauth_mutex_init();
    uint8_t count = 0;
    if (xSemaphoreTake(deauth_mutex, pdMS_TO_TICKS(500))) {
        expire_alerts();
        for (int i = 0; i < detector_status.count; i++) {
            if (detector_status.entries[i].alerting) count++;
        }
        xSemaphoreGive(deauth_mutex);
    }
    return count;
}

uint32_t deauth_detector_get_total_deauths(void) {
    deauth_mutex_init();
    uint32_t val = 0;
    if (xSemaphoreTake(deauth_mutex, pdMS_TO_TICKS(500))) {
        val = total_deauths;
        xSemaphoreGive(deauth_mutex);
    }
    return val;
}

uint32_t deauth_detector_get_peak_count(void) {
    deauth_mutex_init();
    uint32_t peak = 0;
    if (xSemaphoreTake(deauth_mutex, pdMS_TO_TICKS(500))) {
        for (int i = 0; i < detector_status.count; i++) {
            if (detector_status.entries[i].count > peak) {
                peak = detector_status.entries[i].count;
            }
        }
        xSemaphoreGive(deauth_mutex);
    }
    return peak;
}

uint32_t deauth_detector_get_elapsed_sec(void) {
    deauth_mutex_init();
    uint32_t val = 0;
    if (xSemaphoreTake(deauth_mutex, pdMS_TO_TICKS(500))) {
        if (is_running) {
            int64_t elapsed_us = esp_timer_get_time() - start_time_us;
            val = (uint32_t)(elapsed_us / 1000000ULL);
        }
        xSemaphoreGive(deauth_mutex);
    }
    return val;
}

uint32_t deauth_detector_get_remaining_sec(void) {
    deauth_mutex_init();
    uint32_t val = 0;
    if (xSemaphoreTake(deauth_mutex, pdMS_TO_TICKS(500))) {
        if (is_running) {
            int64_t elapsed_us = esp_timer_get_time() - start_time_us;
            int64_t remain_us  = DEAUTH_DETECT_TIMEOUT_US - elapsed_us;
            if (remain_us > 0) {
                val = (uint32_t)(remain_us / 1000000ULL);
            }
        }
        xSemaphoreGive(deauth_mutex);
    }
    return val;
}

bool deauth_detector_was_timeout(void) {
    deauth_mutex_init();
    bool val = false;
    if (xSemaphoreTake(deauth_mutex, pdMS_TO_TICKS(500))) {
        val = was_timeout;
        xSemaphoreGive(deauth_mutex);
    }
    return val;
}

const deauth_detector_status_t *deauth_detector_get_status(void) {
    deauth_mutex_init();
    if (xSemaphoreTake(deauth_mutex, pdMS_TO_TICKS(500))) {
        expire_alerts();
        xSemaphoreGive(deauth_mutex);
    }
    return &detector_status;
}

const char *deauth_detector_get_status_str(void) {
    deauth_mutex_init();
    const char *str = DEAUTH_STATUS_IDLE;
    if (xSemaphoreTake(deauth_mutex, pdMS_TO_TICKS(500))) {
        if (is_running) {
            /* Check if any alerts are active */
            bool any_alert = false;
            expire_alerts();
            for (int i = 0; i < detector_status.count; i++) {
                if (detector_status.entries[i].alerting) {
                    any_alert = true;
                    break;
                }
            }
            str = any_alert ? DEAUTH_STATUS_ALERT : DEAUTH_STATUS_RUNNING;
        } else if (was_timeout) {
            str = DEAUTH_STATUS_TIMEOUT;
        } else if (detector_status.count > 0) {
            /* Was run but stopped manually, and we have data */
            str = DEAUTH_STATUS_STOPPED;
        } else {
            str = DEAUTH_STATUS_IDLE;
        }
        xSemaphoreGive(deauth_mutex);
    }
    return str;
}

cJSON *deauth_detector_get_status_json(void) {
    deauth_mutex_init();
    cJSON *root = cJSON_CreateObject();

    if (xSemaphoreTake(deauth_mutex, pdMS_TO_TICKS(1000))) {
        expire_alerts();

        cJSON_AddBoolToObject(root, "running", is_running);
        cJSON_AddNumberToObject(root, "tracked_count", detector_status.count);

        /* Count active alerts */
        uint8_t alert_count = 0;
        for (int i = 0; i < detector_status.count; i++) {
            if (detector_status.entries[i].alerting) alert_count++;
        }
        cJSON_AddNumberToObject(root, "alert_count", alert_count);
        cJSON_AddNumberToObject(root, "total_deauths", total_deauths);

        /* Peak count across all BSSIDs */
        uint32_t peak = 0;
        for (int i = 0; i < detector_status.count; i++) {
            if (detector_status.entries[i].count > peak) {
                peak = detector_status.entries[i].count;
            }
        }
        cJSON_AddNumberToObject(root, "peak_count", peak);

        /* Time info */
        if (is_running) {
            int64_t elapsed_us = esp_timer_get_time() - start_time_us;
            uint32_t elapsed_s = (uint32_t)(elapsed_us / 1000000ULL);
            int64_t remain_us  = DEAUTH_DETECT_TIMEOUT_US - elapsed_us;
            uint32_t remain_s  = remain_us > 0 ? (uint32_t)(remain_us / 1000000ULL) : 0;

            cJSON_AddNumberToObject(root, "elapsed_sec", elapsed_s);
            cJSON_AddNumberToObject(root, "remaining_sec", remain_s);
        } else {
            cJSON_AddNumberToObject(root, "elapsed_sec", 0);
            cJSON_AddNumberToObject(root, "remaining_sec", 0);
        }

        cJSON_AddBoolToObject(root, "timeout", was_timeout);
        cJSON_AddStringToObject(root, "status", deauth_detector_get_status_str());

        /* Build alerts array — all tracked BSSIDs with details */
        cJSON *alerts = cJSON_CreateArray();
        for (int i = 0; i < detector_status.count; i++) {
            deauth_track_entry_t *e = &detector_status.entries[i];
            cJSON *entry = cJSON_CreateObject();

            char bssid_str[18];
            mac_to_str(e->bssid, bssid_str, sizeof(bssid_str));
            cJSON_AddStringToObject(entry, "bssid", bssid_str);

            cJSON_AddStringToObject(entry, "ssid",
                                    e->ssid[0] ? e->ssid : "(unknown)");
            cJSON_AddNumberToObject(entry, "channel", e->channel);
            cJSON_AddNumberToObject(entry, "window_count", e->count);
            cJSON_AddNumberToObject(entry, "total_deauths", e->total_deauths);
            cJSON_AddBoolToObject(entry, "alerting", e->alerting);

            cJSON_AddItemToArray(alerts, entry);
        }
        cJSON_AddItemToObject(root, "alerts", alerts);

        xSemaphoreGive(deauth_mutex);
    } else {
        /* Mutex timeout — return minimal info */
        cJSON_AddBoolToObject(root, "running", false);
        cJSON_AddStringToObject(root, "status", "error: mutex timeout");
    }

    return root;
}
