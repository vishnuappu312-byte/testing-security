// /* BLE name/advert spoof module */
// #include "ble_spoof.h"
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

// static const char *TAG = "ble_spoof";
// static bool running = false;
// static TaskHandle_t task_handle = NULL;
// static char current_name[128] = {0};
// static SemaphoreHandle_t mutex = NULL;

// static void build_adv_payload(const char *name, uint8_t *out, size_t *out_len) {
//     size_t n = name ? strlen(name) : 0;
//     if (n > 29) n = 29; // keep total adv <= 31
//     size_t idx = 0;
//     // Flags
//     out[idx++] = 2; // length
//     out[idx++] = 0x01; // Flags
//     out[idx++] = 0x06; // LE General Discoverable + BR/EDR not supported
//     if (n > 0) {
//         out[idx++] = (uint8_t)(n + 1);
//         out[idx++] = 0x09; // Complete Local Name
//         memcpy(&out[idx], name, n);
//         idx += n;
//     }
//     *out_len = idx;
// }

// static void spoof_task(void *arg) {
//     char names[5][64];
//     int name_count = 0;
//     int cur = 0;

//     xSemaphoreTake(mutex, portMAX_DELAY);
//     strncpy(names[0], current_name, sizeof(names[0])-1);
//     // parse comma-separated names up to 5
//     char *p = strchr(names[0], ',');
//     while (p && name_count < 4) {
//         // split
//         *p = '\0';
//         name_count++;
//         strncpy(names[name_count], p+1, sizeof(names[0])-1);
//         p = strchr(names[name_count], ',');
//     }
//     name_count++; // at least one
//     xSemaphoreGive(mutex);

//     ESP_LOGI(TAG, "Starting BLE spoof task with %d names", name_count);

//     while (running) {
//         xSemaphoreTake(mutex, portMAX_DELAY);
//         char sel[64] = {0};
//         strncpy(sel, names[cur % name_count], sizeof(sel)-1);
//         xSemaphoreGive(mutex);

//         uint8_t adv[31]; size_t adv_len = 0;
//         build_adv_payload(sel, adv, &adv_len);

//         int rc = ble_gap_adv_set_data(adv, adv_len);
//         if (rc) ESP_LOGE(TAG, "ble_gap_adv_set_data failed: %d", rc);

//         struct ble_gap_adv_params adv_params;
//         memset(&adv_params, 0, sizeof(adv_params));
//         adv_params.conn_mode = BLE_GAP_CONN_MODE_NON;
//         adv_params.disc_mode = BLE_GAP_DISC_MODE_GEN;
//         adv_params.itvl_min = 0x20; adv_params.itvl_max = 0x28;

//         if (ble_gap_adv_active()) {
//             ble_gap_adv_stop();
//         }
//         uint8_t own_addr_type = ble_common_own_addr_type();
//         rc = ble_gap_adv_start(own_addr_type, NULL, 100, &adv_params, NULL, NULL);
//         if (rc) {
//             ESP_LOGE(TAG, "ble_gap_adv_start failed: %d", rc);
//         } else {
//             vTaskDelay(pdMS_TO_TICKS(200));
//             if (ble_gap_adv_active()) ble_gap_adv_stop();
//         }

//         cur++;
//         vTaskDelay(pdMS_TO_TICKS(500));
//     }

//     if (ble_gap_adv_active()) ble_gap_adv_stop();
//     task_handle = NULL;
//     vTaskDelete(NULL);
// }

// void ble_spoof_init(void) {
//     if (mutex == NULL) mutex = xSemaphoreCreateMutex();
//     ESP_LOGI(TAG, "ble_spoof initialized");
// }

// void ble_spoof_start(const char *name) {
//     if (running) return;
//     if (mutex == NULL) mutex = xSemaphoreCreateMutex();
//     xSemaphoreTake(mutex, portMAX_DELAY);
//     strncpy(current_name, name ? name : "", sizeof(current_name)-1);
//     xSemaphoreGive(mutex);
//     running = true;
//     xTaskCreate(spoof_task, "ble_spoof", 4096, NULL, 5, &task_handle);
// }

// void ble_spoof_stop(void) {
//     if (!running) return;
//     running = false;
//     vTaskDelay(pdMS_TO_TICKS(300));
// }

// bool ble_spoof_is_running(void) { return running; }
/* BLE name/advert spoof module */
#include "ble_spoof.h"
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

static const char *TAG = "ble_spoof";
static bool running = false;
static TaskHandle_t task_handle = NULL;
static char current_name[128] = {0};
static SemaphoreHandle_t mutex = NULL;
static SemaphoreHandle_t task_exit_sem = NULL;

static void build_adv_payload(const char *name, uint8_t *out, size_t *out_len) {
    size_t n = name ? strlen(name) : 0;
    if (n > 29) n = 29; /* keep total adv <= 31 */
    size_t idx = 0;
    /* Flags */
    out[idx++] = 2;    /* length */
    out[idx++] = 0x01; /* Flags */
    out[idx++] = 0x06; /* LE General Discoverable + BR/EDR not supported */
    if (n > 0) {
        out[idx++] = (uint8_t)(n + 1);
        out[idx++] = 0x09; /* Complete Local Name */
        memcpy(&out[idx], name, n);
        idx += n;
    }
    *out_len = idx;
}

/* FIX: Rotate random MAC each cycle so target can't filter us */
static void set_random_mac(void) {
    uint8_t mac[6];
    esp_fill_random(mac, 6);
    mac[5] |= 0xC0;  /* Random static address */
    int rc = ble_hs_id_set_rnd(mac);
    if (rc != 0) {
        ESP_LOGW(TAG, "set_random_mac failed: %d", rc);
    }
}

/* FIX: Proper advertising event callback */
static int adv_event_cb(struct ble_gap_event *event, void *arg) {
    (void)arg;
    switch (event->type) {
        case BLE_GAP_EVENT_ADV_COMPLETE:
            ESP_LOGD(TAG, "Advertising duration completed");
            break;
        default:
            break;
    }
    return 0;
}

static void spoof_task(void *arg) {
    char names[5][64];
    int name_count = 0;
    int cur = 0;

    xSemaphoreTake(mutex, portMAX_DELAY);
    strncpy(names[0], current_name, sizeof(names[0]) - 1);
    names[0][sizeof(names[0]) - 1] = '\0';

    /* Parse comma-separated names up to 5 */
    char *p = strchr(names[0], ',');
    while (p && name_count < 4) {
        *p = '\0';
        name_count++;
        strncpy(names[name_count], p + 1, sizeof(names[0]) - 1);
        names[name_count][sizeof(names[0]) - 1] = '\0';  /* FIX: null terminate */
        p = strchr(names[name_count], ',');
    }
    name_count++; /* at least one */
    xSemaphoreGive(mutex);

    ESP_LOGI(TAG, "Starting BLE spoof task with %d names", name_count);

    while (running) {
        /* FIX: Yield to other BLE operations (scanning/connecting).
         * NimBLE controller can only run ONE GAP procedure at a time. */
        if (ble_gap_conn_active() || ble_gap_disc_active()) {
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }

        if (ble_gap_adv_active()) {
            ble_gap_adv_stop();
            vTaskDelay(pdMS_TO_TICKS(20));
        }

        /* FIX: Rotate MAC address each cycle */
        set_random_mac();
        vTaskDelay(pdMS_TO_TICKS(10));

        xSemaphoreTake(mutex, portMAX_DELAY);
        char sel[64] = {0};
        strncpy(sel, names[cur % name_count], sizeof(sel) - 1);
        sel[sizeof(sel) - 1] = '\0';
        xSemaphoreGive(mutex);

        uint8_t adv[31];
        size_t adv_len = 0;
        build_adv_payload(sel, adv, &adv_len);

        int rc = ble_gap_adv_set_data(adv, adv_len);
        if (rc) {
            ESP_LOGE(TAG, "ble_gap_adv_set_data failed: %d", rc);
            vTaskDelay(pdMS_TO_TICKS(50));
            continue;
        }

        struct ble_gap_adv_params adv_params;
        memset(&adv_params, 0, sizeof(adv_params));
        adv_params.conn_mode = BLE_GAP_CONN_MODE_NON;
        adv_params.disc_mode = BLE_GAP_DISC_MODE_GEN;
        adv_params.itvl_min = 0x20;
        adv_params.itvl_max = 0x28;

        /* FIX: Use random address + advertising callback */
        rc = ble_gap_adv_start(BLE_OWN_ADDR_RANDOM, NULL, 200,
                               &adv_params, adv_event_cb, NULL);
        if (rc) {
            ESP_LOGE(TAG, "ble_gap_adv_start failed: %d", rc);
        } else {
            vTaskDelay(pdMS_TO_TICKS(200));
            if (ble_gap_adv_active()) ble_gap_adv_stop();
        }

        cur++;
        vTaskDelay(pdMS_TO_TICKS(500));
    }

    if (ble_gap_adv_active()) ble_gap_adv_stop();

    ESP_LOGI(TAG, "BLE spoof task exiting");
    task_handle = NULL;
    if (task_exit_sem) xSemaphoreGive(task_exit_sem);
    vTaskDelete(NULL);
}

void ble_spoof_init(void) {
    if (mutex == NULL) mutex = xSemaphoreCreateMutex();
    if (task_exit_sem == NULL) task_exit_sem = xSemaphoreCreateBinary();

    /* FIX: Ensure NimBLE is initialized */
    ble_common_init();

    ESP_LOGI(TAG, "ble_spoof initialized");
}

void ble_spoof_start(const char *name) {
    if (running) return;
    if (mutex == NULL) mutex = xSemaphoreCreateMutex();

    xSemaphoreTake(mutex, portMAX_DELAY);
    strncpy(current_name, name ? name : "", sizeof(current_name) - 1);
    current_name[sizeof(current_name) - 1] = '\0';
    xSemaphoreGive(mutex);

    running = true;

    if (task_exit_sem != NULL) {
        xSemaphoreTake(task_exit_sem, 0);  /* Clear any previous signal */
    }

    BaseType_t ret = xTaskCreate(spoof_task, "ble_spoof", 4096, NULL, 5, &task_handle);
    if (ret != pdPASS) {
        ESP_LOGE(TAG, "Failed to create spoof task");
        running = false;
    }
}

void ble_spoof_stop(void) {
    if (!running) return;
    running = false;

    /* FIX: Wait for the task to actually exit */
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

    ESP_LOGI(TAG, "BLE spoof stopped");
}

bool ble_spoof_is_running(void) {
    return running;
}