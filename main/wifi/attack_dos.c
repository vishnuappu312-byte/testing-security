#include "attack_dos.h"

#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_err.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#include "attack.h"
#include "attack_method.h"
#include "wifi_controller.h"

/* ═══════════════════════════════════════════════
 *  Constants
 * ═══════════════════════════════════════════════ */
static const char *TAG = "main:attack_dos";

static const char *dos_method_strings[] = {
    [ATTACK_DOS_METHOD_NONE]        = "Idle",
    [ATTACK_DOS_METHOD_ROGUE_AP]    = "Rogue AP",
    [ATTACK_DOS_METHOD_BROADCAST]   = "Broadcast Deauth",
    [ATTACK_DOS_METHOD_COMBINE_ALL] = "Combine All",
    [ATTACK_DOS_METHOD_SUPER_CLONE] = "Super Clone",
    [ATTACK_DOS_METHOD_AUTH_FLOOD]  = "Auth Flood",
    [ATTACK_DOS_METHOD_BEACON_FLOOD]= "Beacon Flood",
    [ATTACK_DOS_METHOD_DISASSOC]    = "Disassociation",
};

/* ═══════════════════════════════════════════════
 *  Shared state  (all access MUST go through mutex)
 * ═══════════════════════════════════════════════ */
static SemaphoreHandle_t dos_mutex       = NULL;
static bool              is_running      = false;
static attack_dos_methods_t cur_method   = ATTACK_DOS_METHOD_NONE;
static bool              timeout_occurred= false;
static esp_timer_handle_t timeout_timer  = NULL;

/* Target info for status reporting */
static char    target_ssid[33]     = {0};   /* max 32 chars + null */
static char    target_bssid[18]    = {0};   /* "XX:XX:XX:XX:XX:XX\0" */
static uint8_t target_channel      = 0;

/* Packet counter — incremented by attack methods via helper */
static uint32_t packet_count       = 0;

/* ═══════════════════════════════════════════════
 *  Mutex helpers  (lazy-init, same pattern as PMKID)
 * ═══════════════════════════════════════════════ */
static bool dos_mutex_take(void) {
    if (dos_mutex == NULL) {
        dos_mutex = xSemaphoreCreateMutex();
        if (dos_mutex == NULL) {
            ESP_LOGE(TAG, "Failed to create DoS mutex!");
            return false;
        }
    }
    return xSemaphoreTake(dos_mutex, pdMS_TO_TICKS(5000)) == pdTRUE;
}

static void dos_mutex_give(void) {
    if (dos_mutex != NULL) {
        xSemaphoreGive(dos_mutex);
    }
}

/* ═══════════════════════════════════════════════
 *  Timeout timer callback
 * ═══════════════════════════════════════════════ */
static void dos_timeout_cb(void *arg) {
    ESP_LOGW(TAG, "DoS attack timeout reached (%d s), stopping...", ATTACK_DOS_TIMEOUT_SEC);
    if (dos_mutex_take()) {
        timeout_occurred = true;
        dos_mutex_give();
    }
    attack_dos_stop();
}

static void dos_timeout_start(void) {
    if (timeout_timer != NULL) {
        esp_timer_stop(timeout_timer);
        esp_timer_delete(timeout_timer);
        timeout_timer = NULL;
    }
    const esp_timer_create_args_t args = {
        .callback = dos_timeout_cb,
        .name     = "dos_timeout",
    };
    esp_timer_create(&args, &timeout_timer);
    esp_timer_start_once(timeout_timer, ATTACK_DOS_TIMEOUT_US);
}

static void dos_timeout_stop(void) {
    if (timeout_timer != NULL) {
        esp_timer_stop(timeout_timer);
        esp_timer_delete(timeout_timer);
        timeout_timer = NULL;
    }
}

/* ═══════════════════════════════════════════════
 *  Target-info helpers
 * ═══════════════════════════════════════════════ */
static void save_target_info(const wifi_ap_record_t *ap) {
    if (ap == NULL) return;
    snprintf(target_ssid,  sizeof(target_ssid),  "%s", ap->ssid);
    snprintf(target_bssid, sizeof(target_bssid), "%02X:%02X:%02X:%02X:%02X:%02X",
             ap->bssid[0], ap->bssid[1], ap->bssid[2],
             ap->bssid[3], ap->bssid[4], ap->bssid[5]);
    target_channel = ap->primary;
}

static void clear_target_info(void) {
    target_ssid[0]  = '\0';
    target_bssid[0] = '\0';
    target_channel  = 0;
}

/* ═══════════════════════════════════════════════
 *  BSSID helper for MAC bytes
 * ═══════════════════════════════════════════════ */
static const uint8_t *get_bssid_bytes(const wifi_ap_record_t *ap) {
    return ap->bssid;
}

/* ═══════════════════════════════════════════════
 *  attack_dos_start
 * ═══════════════════════════════════════════════ */
void attack_dos_start(attack_config_t *attack_config) {
    if (attack_config == NULL ||
        attack_config->target_count == 0 ||
        attack_config->ap_records[0] == NULL) {
        ESP_LOGE(TAG, "DoS start failed: missing target AP record");
        return;
    }

    if (!dos_mutex_take()) {
        ESP_LOGE(TAG, "DoS start failed: mutex timeout");
        return;
    }

    /* Already running? reject */
    if (is_running) {
        ESP_LOGW(TAG, "DoS attack already running, ignoring start request");
        dos_mutex_give();
        return;
    }

    /* Reset state for new run */
    timeout_occurred = false;
    packet_count     = 0;
    cur_method       = (attack_dos_methods_t)attack_config->method;
    save_target_info(attack_config->ap_records[0]);
    is_running       = true;

    ESP_LOGI(TAG, "Starting DoS attack on %d target(s), method=%s",
             attack_config->target_count,
             (cur_method < ATTACK_DOS_METHOD_COUNT)
                 ? dos_method_strings[cur_method] : "Unknown");

    /* ── Release mutex BEFORE long-running work ──
     * The attack_method_* calls are blocking / long-running.
     * We keep is_running = true so other threads see the state,
     * but we must NOT hold the mutex during the attack itself
     * or the webserver status API would deadlock.           */
    dos_mutex_give();

    /* Stop management AP for broadcast-based methods */
    switch (cur_method) {
        case ATTACK_DOS_METHOD_BROADCAST:
        case ATTACK_DOS_METHOD_COMBINE_ALL:
        case ATTACK_DOS_METHOD_AUTH_FLOOD:
        case ATTACK_DOS_METHOD_BEACON_FLOOD:
        case ATTACK_DOS_METHOD_DISASSOC:
            wifictl_mgmt_ap_stop();
            break;
        default:
            break;
    }

    /* Start timeout timer */
    dos_timeout_start();

    /* ── Execute attack on each target ── */
    for (int i = 0; i < attack_config->target_count; i++) {
        const wifi_ap_record_t *ap_record = attack_config->ap_records[i];

        switch (cur_method) {
            case ATTACK_DOS_METHOD_ROGUE_AP:
                attack_method_rogueap(ap_record);
                break;

            case ATTACK_DOS_METHOD_BROADCAST:
                attack_method_broadcast(ap_record, 1);
                break;

            case ATTACK_DOS_METHOD_COMBINE_ALL:
                attack_method_rogueap(ap_record);
                attack_method_broadcast(ap_record, 1);
                break;

            case ATTACK_DOS_METHOD_SUPER_CLONE:
                attack_method_rogueap(ap_record);
                attack_method_super_clone(ap_record);
                break;

            case ATTACK_DOS_METHOD_AUTH_FLOOD:
                /* Auth flood: send continuous auth frames */
                attack_method_broadcast(ap_record, 1); /* reuse as auth flood placeholder */
                break;

            case ATTACK_DOS_METHOD_BEACON_FLOOD:
                /* Beacon flood: send fake beacons */
                attack_method_broadcast(ap_record, 1); /* reuse as beacon flood placeholder */
                break;

            case ATTACK_DOS_METHOD_DISASSOC:
                /* Disassociation flood */
                attack_method_broadcast(ap_record, 1); /* reuse as disassoc placeholder */
                break;

            default:
                ESP_LOGE(TAG, "Unknown DoS method: %d", cur_method);
                break;
        }
    }
}

/* ═══════════════════════════════════════════════
 *  attack_dos_stop
 * ═══════════════════════════════════════════════ */
void attack_dos_stop(void) {
    if (!dos_mutex_take()) {
        ESP_LOGE(TAG, "DoS stop failed: mutex timeout");
        return;
    }

    if (!is_running) {
        dos_mutex_give();
        return;
    }

    ESP_LOGI(TAG, "Stopping DoS attack (method=%s)",
             (cur_method < ATTACK_DOS_METHOD_COUNT)
                 ? dos_method_strings[cur_method] : "Unknown");

    /* Snapshot method under mutex so we can release it
     * before calling potentially-blocking stop functions */
    attack_dos_methods_t snap_method = cur_method;

    is_running = false;
    cur_method = ATTACK_DOS_METHOD_NONE;
    dos_mutex_give();

    /* Stop timeout timer */
    dos_timeout_stop();

    /* Restore AP / stop attack methods (outside mutex) */
    switch (snap_method) {
        case ATTACK_DOS_METHOD_ROGUE_AP:
            wifictl_mgmt_ap_start();
            wifictl_restore_ap_mac();
            break;

        case ATTACK_DOS_METHOD_BROADCAST:
            attack_method_broadcast_stop();
            wifictl_mgmt_ap_start();
            break;

        case ATTACK_DOS_METHOD_COMBINE_ALL:
            attack_method_broadcast_stop();
            wifictl_mgmt_ap_start();
            wifictl_restore_ap_mac();
            break;

        case ATTACK_DOS_METHOD_SUPER_CLONE:
            attack_method_super_clone_stop();
            wifictl_mgmt_ap_start();
            wifictl_restore_ap_mac();
            break;

        case ATTACK_DOS_METHOD_AUTH_FLOOD:
        case ATTACK_DOS_METHOD_BEACON_FLOOD:
        case ATTACK_DOS_METHOD_DISASSOC:
            attack_method_broadcast_stop();
            wifictl_mgmt_ap_start();
            break;

        default:
            ESP_LOGE(TAG, "Unknown method during stop! May not be cleaned up properly.");
            break;
    }

    /* Clear target info */
    if (dos_mutex_take()) {
        clear_target_info();
        dos_mutex_give();
    }

    ESP_LOGI(TAG, "DoS attack stopped. Packets sent: %lu", (unsigned long)packet_count);
}

/* ═══════════════════════════════════════════════
 *  Webserver / Dashboard API getters
 *  (all thread-safe via mutex)
 * ═══════════════════════════════════════════════ */

bool attack_dos_is_running(void) {
    bool running = false;
    if (dos_mutex_take()) {
        running = is_running;
        dos_mutex_give();
    }
    return running;
}

attack_dos_methods_t attack_dos_get_method(void) {
    attack_dos_methods_t m = ATTACK_DOS_METHOD_NONE;
    if (dos_mutex_take()) {
        m = cur_method;
        dos_mutex_give();
    }
    return m;
}

const char *attack_dos_get_method_str(void) {
    attack_dos_methods_t m = attack_dos_get_method();
    if (m >= ATTACK_DOS_METHOD_COUNT) m = ATTACK_DOS_METHOD_NONE;
    return dos_method_strings[m];
}

const char *attack_dos_get_ssid(void) {
    static char buf[33];
    if (dos_mutex_take()) {
        snprintf(buf, sizeof(buf), "%s", target_ssid);
        dos_mutex_give();
    }
    return buf;
}

const char *attack_dos_get_bssid_str(void) {
    static char buf[18];
    if (dos_mutex_take()) {
        snprintf(buf, sizeof(buf), "%s", target_bssid);
        dos_mutex_give();
    }
    return buf;
}

uint8_t attack_dos_get_channel(void) {
    uint8_t ch = 0;
    if (dos_mutex_take()) {
        ch = target_channel;
        dos_mutex_give();
    }
    return ch;
}

uint32_t attack_dos_get_packet_count(void) {
    uint32_t cnt = 0;
    if (dos_mutex_take()) {
        cnt = packet_count;
        dos_mutex_give();
    }
    return cnt;
}

bool attack_dos_was_timeout(void) {
    bool t = false;
    if (dos_mutex_take()) {
        t = timeout_occurred;
        dos_mutex_give();
    }
    return t;
}

const char *attack_dos_get_status_str(void) {
    if (!attack_dos_is_running()) {
        if (attack_dos_was_timeout()) {
            return "Timeout";
        }
        return "Idle";
    }
    return "Attacking";
}

/* ═══════════════════════════════════════════════
 *  Full status JSON for dashboard API
 * ═══════════════════════════════════════════════ */
cJSON *attack_dos_get_status_json(void) {
    cJSON *root = cJSON_CreateObject();
    if (root == NULL) return NULL;

    if (dos_mutex_take()) {
        cJSON_AddBoolToObject(root,   "running",       is_running);
        cJSON_AddNumberToObject(root, "method",        (double)cur_method);
        cJSON_AddStringToObject(root, "method_str",
            (cur_method < ATTACK_DOS_METHOD_COUNT)
                ? dos_method_strings[cur_method] : "Unknown");
        cJSON_AddStringToObject(root, "ssid",          target_ssid);
        cJSON_AddStringToObject(root, "bssid",         target_bssid);
        cJSON_AddNumberToObject(root, "channel",       target_channel);
        cJSON_AddNumberToObject(root, "packet_count",  packet_count);
        cJSON_AddBoolToObject(root,   "timeout",       timeout_occurred);
        cJSON_AddStringToObject(root, "status",
            (!is_running)
                ? (timeout_occurred ? "Timeout" : "Idle")
                : "Attacking");
        dos_mutex_give();
    } else {
        /* Fallback if mutex unavailable */
        cJSON_AddBoolToObject(root,   "running",  false);
        cJSON_AddStringToObject(root, "status",   "Unknown");
        cJSON_AddStringToObject(root, "method_str","Unknown");
        cJSON_AddStringToObject(root, "ssid",     "");
        cJSON_AddStringToObject(root, "bssid",    "");
    }

    return root;
}

/* ═══════════════════════════════════════════════
 *  Packet count incrementer  (call from attack
 *  methods to track activity)
 * ═══════════════════════════════════════════════ */
void attack_dos_increment_packet_count(uint32_t count) {
    if (dos_mutex_take()) {
        packet_count += count;
        dos_mutex_give();
    }
}
