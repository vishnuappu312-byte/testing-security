// /* BLE scan module - NimBLE-backed scan implementation */
// #include "ble_scan.h"
// #include <stdio.h>
// #include <string.h>
// #include "esp_log.h"
// #include "freertos/FreeRTOS.h"
// #include "freertos/semphr.h"
// #include "freertos/task.h"

// /* NimBLE headers */
// #include "nimble/nimble_port.h"
// #include "nimble/nimble_port_freertos.h"
// #include "host/ble_hs.h"
// #include "host/ble_gap.h"

// #include "ble_common.h"

// static const char *TAG = "ble_scan";
// static bool initialized = false;

// static cJSON *scan_results = NULL;
// static SemaphoreHandle_t scan_sem = NULL;

// static bool addr_seen(const char *addr) {
//     if (!scan_results) return false;
//     int cnt = cJSON_GetArraySize(scan_results);
//     for (int i = 0; i < cnt; i++) {
//         cJSON *it = cJSON_GetArrayItem(scan_results, i);
//         if (!it) continue;
//         cJSON *a = cJSON_GetObjectItem(it, "addr");
//         if (a && cJSON_IsString(a) && strcmp(a->valuestring, addr) == 0) return true;
//     }
//     return false;
// }

// static void parse_adv_name(const uint8_t *data, int len, char *out, int outlen) {
//     int i = 0;
//     while (i < len) {
//         uint8_t l = data[i++];
//         if (l == 0 || i + l > len) break;
//         uint8_t t = data[i];
//         if (t == 0x09 || t == 0x08) {
//             int n = l - 1;
//             if (n <= 0) break;
//             if (n >= outlen) n = outlen - 1;
//             memcpy(out, &data[i+1], n);
//             out[n] = '\0';
//             return;
//         }
//         i += l;
//     }
//     out[0] = '\0';
// }

// static int scan_cb(struct ble_gap_event *event, void *arg) {
//     if (event->type == BLE_GAP_EVENT_DISC) {
//         struct ble_gap_disc_desc *disc = &event->disc;
//         char addr_str[18];
//         snprintf(addr_str, sizeof(addr_str), "%02X:%02X:%02X:%02X:%02X:%02X",
//                  disc->addr.val[5], disc->addr.val[4], disc->addr.val[3], disc->addr.val[2], disc->addr.val[1], disc->addr.val[0]);
//         if (addr_seen(addr_str)) return 0;
//         char name[64];
//         parse_adv_name(disc->data, disc->length_data, name, sizeof(name));
//         cJSON *obj = cJSON_CreateObject();
//         cJSON_AddStringToObject(obj, "addr", addr_str);
//         cJSON_AddNumberToObject(obj, "rssi", disc->rssi);
//         if (name[0]) cJSON_AddStringToObject(obj, "name", name);
//         cJSON_AddItemToArray(scan_results, obj);
//     } else if (event->type == BLE_GAP_EVENT_DISC_COMPLETE) {
//         if (scan_sem) xSemaphoreGive(scan_sem);
//     }
//     return 0;
// }

// void ble_scan_init(void) {
//     if (initialized) return;
//     initialized = true;
//     if (scan_sem == NULL) scan_sem = xSemaphoreCreateBinary();
//     ESP_LOGI(TAG, "BLE scan module initialized");
// }

// cJSON *ble_scan_perform(int timeout_ms) {
//     ble_scan_init();
//     ESP_LOGI(TAG, "Starting BLE scan for %d ms", timeout_ms);

//     if (scan_results) {
//         cJSON_Delete(scan_results);
//         scan_results = NULL;
//     }
//     scan_results = cJSON_CreateArray();
//     if (!scan_results) return cJSON_CreateArray();

//     struct ble_gap_disc_params params;
//     memset(&params, 0, sizeof(params));
//     params.passive = 1;

//     int rc = ble_gap_disc(ble_common_own_addr_type(), timeout_ms, &params, scan_cb, NULL);
//     if (rc != 0) {
//         ESP_LOGE(TAG, "ble_gap_disc failed: %d", rc);
//         cJSON *ret = scan_results;
//         scan_results = NULL;
//         return ret;
//     }

//     /* Wait for completion (timeout_ms + margin) */
//     if (scan_sem) xSemaphoreTake(scan_sem, pdMS_TO_TICKS(timeout_ms + 200));

//     cJSON *ret = scan_results;
//     scan_results = NULL;
//     return ret;
// }

/* BLE scan module - NimBLE-backed scan implementation */
#include "ble_scan.h"
#include <stdio.h>
#include <string.h>
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

/* NimBLE headers */
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "host/ble_hs.h"
#include "host/ble_gap.h"

#include "ble_common.h"

static const char *TAG = "ble_scan";
static bool initialized = false;

static cJSON *scan_results = NULL;
static SemaphoreHandle_t scan_sem = NULL;
static SemaphoreHandle_t scan_mutex = NULL;  /* FIX: Protect scan_results */

static bool addr_seen(const char *addr) {
    if (!scan_results) return false;
    int cnt = cJSON_GetArraySize(scan_results);
    for (int i = 0; i < cnt; i++) {
        cJSON *it = cJSON_GetArrayItem(scan_results, i);
        if (!it) continue;
        cJSON *a = cJSON_GetObjectItem(it, "addr");
        if (a && cJSON_IsString(a) && strcmp(a->valuestring, addr) == 0) return true;
    }
    return false;
}

static void parse_adv_name(const uint8_t *data, int len, char *out, int outlen) {
    int i = 0;
    while (i < len) {
        uint8_t l = data[i++];
        if (l == 0 || i + l > len) break;
        uint8_t t = data[i];
        if (t == 0x09 || t == 0x08) {
            int n = l - 1;
            if (n <= 0) break;
            if (n >= outlen) n = outlen - 1;
            memcpy(out, &data[i+1], n);
            out[n] = '\0';
            return;
        }
        i += l;
    }
    out[0] = '\0';
}

static int scan_cb(struct ble_gap_event *event, void *arg) {
    if (event->type == BLE_GAP_EVENT_DISC) {
        struct ble_gap_disc_desc *disc = &event->disc;

        char addr_str[18];
        snprintf(addr_str, sizeof(addr_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                 disc->addr.val[5], disc->addr.val[4], disc->addr.val[3],
                 disc->addr.val[2], disc->addr.val[1], disc->addr.val[0]);

        /* FIX: Protect scan_results with mutex since callback runs in
         * NimBLE host task context, not the caller's task. */
        if (scan_mutex) xSemaphoreTake(scan_mutex, portMAX_DELAY);

        if (addr_seen(addr_str)) {
            /* Update RSSI for existing entry with stronger signal */
            int cnt = cJSON_GetArraySize(scan_results);
            for (int i = 0; i < cnt; i++) {
                cJSON *it = cJSON_GetArrayItem(scan_results, i);
                if (!it) continue;
                cJSON *a = cJSON_GetObjectItem(it, "addr");
                if (a && cJSON_IsString(a) && strcmp(a->valuestring, addr_str) == 0) {
                    cJSON *r = cJSON_GetObjectItem(it, "rssi");
                    if (r && cJSON_IsNumber(r) && disc->rssi > r->valueint) {
                        r->valueint = disc->rssi;
                    }
                    break;
                }
            }
            if (scan_mutex) xSemaphoreGive(scan_mutex);
            return 0;
        }

        char name[64];
        parse_adv_name(disc->data, disc->length_data, name, sizeof(name));

        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "addr", addr_str);
        cJSON_AddNumberToObject(obj, "rssi", disc->rssi);
        if (name[0]) cJSON_AddStringToObject(obj, "name", name);
        cJSON_AddItemToArray(scan_results, obj);

        if (scan_mutex) xSemaphoreGive(scan_mutex);

    } else if (event->type == BLE_GAP_EVENT_DISC_COMPLETE) {
        ESP_LOGI(TAG, "Scan complete");
        if (scan_sem) xSemaphoreGive(scan_sem);
    }
    return 0;
}

void ble_scan_init(void) {
    if (initialized) return;

    /* FIX: Ensure NimBLE is initialized */
    ble_common_init();

    if (scan_sem == NULL) scan_sem = xSemaphoreCreateBinary();
    if (scan_mutex == NULL) scan_mutex = xSemaphoreCreateMutex();

    initialized = true;
    ESP_LOGI(TAG, "BLE scan module initialized");
}

cJSON *ble_scan_perform(int timeout_ms) {
    ble_scan_init();
    ESP_LOGI(TAG, "Starting BLE scan for %d ms", timeout_ms);

    /* FIX: Clear any stale semaphore signal from a previous scan */
    if (scan_sem) xSemaphoreTake(scan_sem, 0);

    /* FIX: Stop advertising if active — can't scan and advertise simultaneously */
    if (ble_gap_adv_active()) {
        ble_gap_adv_stop();
        vTaskDelay(pdMS_TO_TICKS(50));
    }

    /* Clean up previous results */
    if (scan_mutex) xSemaphoreTake(scan_mutex, portMAX_DELAY);
    if (scan_results) {
        cJSON_Delete(scan_results);
        scan_results = NULL;
    }
    scan_results = cJSON_CreateArray();
    if (scan_mutex) xSemaphoreGive(scan_mutex);

    if (!scan_results) return cJSON_CreateArray();

    /* FIX: Active scan instead of passive */
    struct ble_gap_disc_params params;
    memset(&params, 0, sizeof(params));
    params.passive = 0;             /* Active scan — sends SCAN_REQ */
    params.itvl = 0x0010;           /* 10ms interval */
    params.window = 0x0010;         /* 10ms window (100% duty cycle) */
    params.filter_duplicates = 0;   /* Don't filter — see all advertisements */

    int rc = ble_gap_disc(ble_common_own_addr_type(), timeout_ms, &params, scan_cb, NULL);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_gap_disc failed: %d", rc);
        if (scan_mutex) xSemaphoreTake(scan_mutex, portMAX_DELAY);
        cJSON *ret = scan_results;
        scan_results = NULL;
        if (scan_mutex) xSemaphoreGive(scan_mutex);
        return ret;
    }

    /* Wait for completion (timeout_ms + margin) */
    if (scan_sem) {
        xSemaphoreTake(scan_sem, pdMS_TO_TICKS(timeout_ms + 1000));
    }

    if (scan_mutex) xSemaphoreTake(scan_mutex, portMAX_DELAY);
    cJSON *ret = scan_results;
    scan_results = NULL;
    if (scan_mutex) xSemaphoreGive(scan_mutex);

    ESP_LOGI(TAG, "Scan returning %d devices", cJSON_GetArraySize(ret));
    return ret;
}