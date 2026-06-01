// /* BLE GATT probe - stub that would perform service discovery */
// #include "ble_gatt_probe.h"
// #include "esp_log.h"
// #include "freertos/FreeRTOS.h"
// #include "freertos/task.h"
// #include <string.h>

// /* NimBLE headers */
// #include "nimble/nimble_port.h"
// #include "host/ble_hs.h"
// #include "host/ble_gap.h"

// #include "ble_common.h"

// static const char *TAG = "ble_gatt_probe";
// static bool running = false;
// static TaskHandle_t task_handle = NULL;
// static char target[32] = {0};

// static int gap_event_cb(struct ble_gap_event *event, void *arg) {
//     (void)arg;

//     switch (event->type) {
//         case BLE_GAP_EVENT_DISC_COMPLETE:
//             if (task_handle != NULL) {
//                 xTaskNotifyGive(task_handle);
//             }
//             return 0;
//         default:
//             return 0;
//     }
// }

// static void probe_task(void *arg) {
//     while (running) {
//         ESP_LOGI(TAG, "GATT probe: scanning for %s (passive adv-based)", target[0]?target:"(none)");

//         /* Start a short NimBLE discovery (events delivered via callback). */
//         struct ble_gap_disc_params params;
//         memset(&params, 0, sizeof(params));
//         params.passive = 1;

//         int rc = ble_gap_disc(ble_common_own_addr_type(), 3000, &params, gap_event_cb, NULL);
//         if (rc != 0) {
//             ESP_LOGE(TAG, "ble_gap_disc failed: %d", rc);
//         } else {
//             (void)ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(3500));
//             ESP_LOGI(TAG, "GATT probe scan completed (passive)");
//         }

//         vTaskDelay(pdMS_TO_TICKS(1000));
//     }
//     task_handle = NULL;
//     vTaskDelete(NULL);
// }

// void ble_gatt_probe_init(void) { ESP_LOGI(TAG, "gatt probe init"); }

// void ble_gatt_probe_start(const char *target_addr) {
//     if (running) return;
//     strncpy(target, target_addr?target_addr:"", sizeof(target)-1);
//     running = true;
//     xTaskCreate(probe_task, "ble_gatt_probe", 3072, NULL, 5, &task_handle);
// }

// void ble_gatt_probe_stop(void) { if (!running) return; running = false; vTaskDelay(pdMS_TO_TICKS(200)); }
// bool ble_gatt_probe_is_running(void) { return running; }
/* BLE GATT probe - performs service discovery and target detection */
#include "ble_gatt_probe.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <string.h>

/* NimBLE headers */
#include "nimble/nimble_port.h"
#include "host/ble_hs.h"
#include "host/ble_gap.h"

#include "ble_common.h"

static const char *TAG = "ble_gatt_probe";
static bool running = false;
static TaskHandle_t task_handle = NULL;
static char target[32] = {0};
static bool target_found = false;

static int gap_event_cb(struct ble_gap_event *event, void *arg) {
    (void)arg;

    switch (event->type) {
        case BLE_GAP_EVENT_DISC: {
            struct ble_gap_disc_desc *desc = &event->disc;

            /* Format the discovered address as a string for comparison */
            char addr_str[18];
            snprintf(addr_str, sizeof(addr_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                     desc->addr.val[5], desc->addr.val[4], desc->addr.val[3],
                     desc->addr.val[2], desc->addr.val[1], desc->addr.val[0]);

            if (target[0] != '\0' && strcasecmp(addr_str, target) == 0) {
                /* FIX: Only log and notify ONCE per scan cycle, not every packet */
                if (!target_found) {
                    ESP_LOGI(TAG, "TARGET FOUND: %s (addr_type=%d, rssi=%d)",
                             addr_str, desc->addr.type, desc->rssi);
                    target_found = true;

                    /* Notify the task that we found the target */
                    if (task_handle != NULL) {
                        xTaskNotifyGive(task_handle);
                    }
                }
            }
            return 0;
        }

        case BLE_GAP_EVENT_DISC_COMPLETE:
            ESP_LOGI(TAG, "GATT probe scan completed");
            if (task_handle != NULL) {
                xTaskNotifyGive(task_handle);
            }
            return 0;

        default:
            return 0;
    }
}

static void probe_task(void *arg) {
    while (running) {
        target_found = false;

        /* Wait if another GAP procedure is active */
        if (ble_gap_adv_active() || ble_gap_conn_active()) {
            vTaskDelay(pdMS_TO_TICKS(200));
            continue;
        }

        /* FIX: Clear any stale notifications from previous scan cycles
         * so ulTaskNotifyTake doesn't return immediately */
        ulTaskNotifyTake(pdTRUE, 0);

        ESP_LOGI(TAG, "GATT probe: scanning for %s (ACTIVE scan)", target[0] ? target : "(none)");

        /* Start an ACTIVE NimBLE discovery */
        struct ble_gap_disc_params params;
        memset(&params, 0, sizeof(params));
        params.passive = 0;            /* Active scan */
        params.itvl = 0x0010;          /* 10ms scan interval */
        params.window = 0x0010;        /* 10ms scan window (100% duty) */
        params.filter_duplicates = 0;   /* Don't filter duplicates */

        int rc = ble_gap_disc(ble_common_own_addr_type(), 5000, &params, gap_event_cb, NULL);

        if (rc == BLE_HS_EALREADY) {
            /* FIX: Scan already running — just wait for it to complete */
            ESP_LOGD(TAG, "Scan already in progress, waiting...");
            (void)ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(6000));
        } else if (rc != 0) {
            ESP_LOGE(TAG, "ble_gap_disc failed: %d", rc);
        } else {
            /* Wait for either TARGET FOUND or DISC_COMPLETE notification */
            (void)ulTaskNotifyTake(pdTRUE, pdMS_TO_TICKS(6000));

            if (target_found) {
                ESP_LOGI(TAG, "GATT probe: target %s is ADVERTISING and reachable", target);
            } else {
                ESP_LOGW(TAG, "GATT probe: target %s was NOT seen in this scan cycle", target);
            }
        }

        /* FIX: If scan is still running (we exited early due to target found),
         * stop it before starting a new one */
        if (ble_gap_disc_active()) {
            ble_gap_disc_cancel();
            vTaskDelay(pdMS_TO_TICKS(100));
        }

        vTaskDelay(pdMS_TO_TICKS(2000));
    }
    task_handle = NULL;
    vTaskDelete(NULL);
}

void ble_gatt_probe_init(void) {
    ble_common_init();
    ESP_LOGI(TAG, "gatt probe init");
}

void ble_gatt_probe_start(const char *target_addr) {
    if (running) return;
    strncpy(target, target_addr ? target_addr : "", sizeof(target) - 1);
    target[sizeof(target) - 1] = '\0';
    running = true;
    xTaskCreate(probe_task, "ble_gatt_probe", 4096, NULL, 5, &task_handle);
}

void ble_gatt_probe_stop(void) {
    if (!running) return;
    running = false;
    vTaskDelay(pdMS_TO_TICKS(200));
}

bool ble_gatt_probe_is_running(void) {
    return running;
}

bool ble_gatt_probe_target_found(void) {
    return target_found;
}