// // /* BLE name/advert spoof module */
// // #include "ble_spoof.h"
// // #include "esp_log.h"
// // #include "freertos/FreeRTOS.h"
// // #include "freertos/task.h"
// // #include "freertos/semphr.h"
// // #include <string.h>

// // /* NimBLE headers */
// // #include "nimble/nimble_port.h"
// // #include "host/ble_hs.h"
// // #include "host/ble_gap.h"

// // #include "ble_common.h"

// // static const char *TAG = "ble_spoof";
// // static bool running = false;
// // static TaskHandle_t task_handle = NULL;
// // static char current_name[128] = {0};
// // static SemaphoreHandle_t mutex = NULL;

// // static void build_adv_payload(const char *name, uint8_t *out, size_t *out_len) {
// //     size_t n = name ? strlen(name) : 0;
// //     if (n > 29) n = 29; // keep total adv <= 31
// //     size_t idx = 0;
// //     // Flags
// //     out[idx++] = 2; // length
// //     out[idx++] = 0x01; // Flags
// //     out[idx++] = 0x06; // LE General Discoverable + BR/EDR not supported
// //     if (n > 0) {
// //         out[idx++] = (uint8_t)(n + 1);
// //         out[idx++] = 0x09; // Complete Local Name
// //         memcpy(&out[idx], name, n);
// //         idx += n;
// //     }
// //     *out_len = idx;
// // }

// // static void spoof_task(void *arg) {
// //     char names[5][64];
// //     int name_count = 0;
// //     int cur = 0;

// //     xSemaphoreTake(mutex, portMAX_DELAY);
// //     strncpy(names[0], current_name, sizeof(names[0])-1);
// //     // parse comma-separated names up to 5
// //     char *p = strchr(names[0], ',');
// //     while (p && name_count < 4) {
// //         // split
// //         *p = '\0';
// //         name_count++;
// //         strncpy(names[name_count], p+1, sizeof(names[0])-1);
// //         p = strchr(names[name_count], ',');
// //     }
// //     name_count++; // at least one
// //     xSemaphoreGive(mutex);

// //     ESP_LOGI(TAG, "Starting BLE spoof task with %d names", name_count);

// //     while (running) {
// //         xSemaphoreTake(mutex, portMAX_DELAY);
// //         char sel[64] = {0};
// //         strncpy(sel, names[cur % name_count], sizeof(sel)-1);
// //         xSemaphoreGive(mutex);

// //         uint8_t adv[31]; size_t adv_len = 0;
// //         build_adv_payload(sel, adv, &adv_len);

// //         int rc = ble_gap_adv_set_data(adv, adv_len);
// //         if (rc) ESP_LOGE(TAG, "ble_gap_adv_set_data failed: %d", rc);

// //         struct ble_gap_adv_params adv_params;
// //         memset(&adv_params, 0, sizeof(adv_params));
// //         adv_params.conn_mode = BLE_GAP_CONN_MODE_NON;
// //         adv_params.disc_mode = BLE_GAP_DISC_MODE_GEN;
// //         adv_params.itvl_min = 0x20; adv_params.itvl_max = 0x28;

// //         if (ble_gap_adv_active()) {
// //             ble_gap_adv_stop();
// //         }
// //         uint8_t own_addr_type = ble_common_own_addr_type();
// //         rc = ble_gap_adv_start(own_addr_type, NULL, 100, &adv_params, NULL, NULL);
// //         if (rc) {
// //             ESP_LOGE(TAG, "ble_gap_adv_start failed: %d", rc);
// //         } else {
// //             vTaskDelay(pdMS_TO_TICKS(200));
// //             if (ble_gap_adv_active()) ble_gap_adv_stop();
// //         }

// //         cur++;
// //         vTaskDelay(pdMS_TO_TICKS(500));
// //     }

// //     if (ble_gap_adv_active()) ble_gap_adv_stop();
// //     task_handle = NULL;
// //     vTaskDelete(NULL);
// // }

// // void ble_spoof_init(void) {
// //     if (mutex == NULL) mutex = xSemaphoreCreateMutex();
// //     ESP_LOGI(TAG, "ble_spoof initialized");
// // }

// // void ble_spoof_start(const char *name) {
// //     if (running) return;
// //     if (mutex == NULL) mutex = xSemaphoreCreateMutex();
// //     xSemaphoreTake(mutex, portMAX_DELAY);
// //     strncpy(current_name, name ? name : "", sizeof(current_name)-1);
// //     xSemaphoreGive(mutex);
// //     running = true;
// //     xTaskCreate(spoof_task, "ble_spoof", 4096, NULL, 5, &task_handle);
// // }

// // void ble_spoof_stop(void) {
// //     if (!running) return;
// //     running = false;
// //     vTaskDelay(pdMS_TO_TICKS(300));
// // }

// // bool ble_spoof_is_running(void) { return running; }
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
// static SemaphoreHandle_t task_exit_sem = NULL;

// static void build_adv_payload(const char *name, uint8_t *out, size_t *out_len) {
//     size_t n = name ? strlen(name) : 0;
//     if (n > 29) n = 29; /* keep total adv <= 31 */
//     size_t idx = 0;
//     /* Flags */
//     out[idx++] = 2;    /* length */
//     out[idx++] = 0x01; /* Flags */
//     out[idx++] = 0x06; /* LE General Discoverable + BR/EDR not supported */
//     if (n > 0) {
//         out[idx++] = (uint8_t)(n + 1);
//         out[idx++] = 0x09; /* Complete Local Name */
//         memcpy(&out[idx], name, n);
//         idx += n;
//     }
//     *out_len = idx;
// }

// /* FIX: Rotate random MAC each cycle so target can't filter us */
// static void set_random_mac(void) {
//     uint8_t mac[6];
//     esp_fill_random(mac, 6);
//     mac[5] |= 0xC0;  /* Random static address */
//     int rc = ble_hs_id_set_rnd(mac);
//     if (rc != 0) {
//         ESP_LOGW(TAG, "set_random_mac failed: %d", rc);
//     }
// }

// /* FIX: Proper advertising event callback */
// static int adv_event_cb(struct ble_gap_event *event, void *arg) {
//     (void)arg;
//     switch (event->type) {
//         case BLE_GAP_EVENT_ADV_COMPLETE:
//             ESP_LOGD(TAG, "Advertising duration completed");
//             break;
//         default:
//             break;
//     }
//     return 0;
// }

// static void spoof_task(void *arg) {
//     char names[5][64];
//     int name_count = 0;
//     int cur = 0;

//     xSemaphoreTake(mutex, portMAX_DELAY);
//     strncpy(names[0], current_name, sizeof(names[0]) - 1);
//     names[0][sizeof(names[0]) - 1] = '\0';

//     /* Parse comma-separated names up to 5 */
//     char *p = strchr(names[0], ',');
//     while (p && name_count < 4) {
//         *p = '\0';
//         name_count++;
//         strncpy(names[name_count], p + 1, sizeof(names[0]) - 1);
//         names[name_count][sizeof(names[0]) - 1] = '\0';  /* FIX: null terminate */
//         p = strchr(names[name_count], ',');
//     }
//     name_count++; /* at least one */
//     xSemaphoreGive(mutex);

//     ESP_LOGI(TAG, "Starting BLE spoof task with %d names", name_count);

//     while (running) {
//         /* FIX: Yield to other BLE operations (scanning/connecting).
//          * NimBLE controller can only run ONE GAP procedure at a time. */
//         if (ble_gap_conn_active() || ble_gap_disc_active()) {
//             vTaskDelay(pdMS_TO_TICKS(100));
//             continue;
//         }

//         if (ble_gap_adv_active()) {
//             ble_gap_adv_stop();
//             vTaskDelay(pdMS_TO_TICKS(20));
//         }

//         /* FIX: Rotate MAC address each cycle */
//         set_random_mac();
//         vTaskDelay(pdMS_TO_TICKS(10));

//         xSemaphoreTake(mutex, portMAX_DELAY);
//         char sel[64] = {0};
//         strncpy(sel, names[cur % name_count], sizeof(sel) - 1);
//         sel[sizeof(sel) - 1] = '\0';
//         xSemaphoreGive(mutex);

//         uint8_t adv[31];
//         size_t adv_len = 0;
//         build_adv_payload(sel, adv, &adv_len);

//         int rc = ble_gap_adv_set_data(adv, adv_len);
//         if (rc) {
//             ESP_LOGE(TAG, "ble_gap_adv_set_data failed: %d", rc);
//             vTaskDelay(pdMS_TO_TICKS(50));
//             continue;
//         }

//         struct ble_gap_adv_params adv_params;
//         memset(&adv_params, 0, sizeof(adv_params));
//         adv_params.conn_mode = BLE_GAP_CONN_MODE_NON;
//         adv_params.disc_mode = BLE_GAP_DISC_MODE_GEN;
//         adv_params.itvl_min = 0x20;
//         adv_params.itvl_max = 0x28;

//         /* FIX: Use random address + advertising callback */
//         rc = ble_gap_adv_start(BLE_OWN_ADDR_RANDOM, NULL, 200,
//                                &adv_params, adv_event_cb, NULL);
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

//     ESP_LOGI(TAG, "BLE spoof task exiting");
//     task_handle = NULL;
//     if (task_exit_sem) xSemaphoreGive(task_exit_sem);
//     vTaskDelete(NULL);
// }

// void ble_spoof_init(void) {
//     if (mutex == NULL) mutex = xSemaphoreCreateMutex();
//     if (task_exit_sem == NULL) task_exit_sem = xSemaphoreCreateBinary();

//     /* FIX: Ensure NimBLE is initialized */
//     ble_common_init();

//     ESP_LOGI(TAG, "ble_spoof initialized");
// }

// void ble_spoof_start(const char *name) {
//     if (running) return;
//     if (mutex == NULL) mutex = xSemaphoreCreateMutex();

//     xSemaphoreTake(mutex, portMAX_DELAY);
//     strncpy(current_name, name ? name : "", sizeof(current_name) - 1);
//     current_name[sizeof(current_name) - 1] = '\0';
//     xSemaphoreGive(mutex);

//     running = true;

//     if (task_exit_sem != NULL) {
//         xSemaphoreTake(task_exit_sem, 0);  /* Clear any previous signal */
//     }

//     BaseType_t ret = xTaskCreate(spoof_task, "ble_spoof", 4096, NULL, 5, &task_handle);
//     if (ret != pdPASS) {
//         ESP_LOGE(TAG, "Failed to create spoof task");
//         running = false;
//     }
// }

// void ble_spoof_stop(void) {
//     if (!running) return;
//     running = false;

//     /* FIX: Wait for the task to actually exit */
//     if (task_exit_sem != NULL) {
//         if (xSemaphoreTake(task_exit_sem, pdMS_TO_TICKS(5000)) != pdTRUE) {
//             ESP_LOGW(TAG, "Task exit timeout, forcing delete");
//             if (task_handle != NULL) {
//                 vTaskDelete(task_handle);
//                 task_handle = NULL;
//             }
//         }
//     } else {
//         vTaskDelay(pdMS_TO_TICKS(1000));
//         if (task_handle != NULL) {
//             vTaskDelete(task_handle);
//             task_handle = NULL;
//         }
//     }

//     ESP_LOGI(TAG, "BLE spoof stopped");
// }

// bool ble_spoof_is_running(void) {
//     return running;
// }

/*
 * ble_spoof.c - BLE Name Spoof & Device Clone Implementation
 *
 * Two operational modes:
 *
 *   NAME-SPOOF  (legacy) – Rotate through comma-separated BLE device names.
 *   Each cycle changes the advertised name and random MAC so that nearby
 *   scanners see a sequence of different devices.
 *
 *   CLONE       (new)    – Clone a scanned device's full advertising payload
 *   including services, appearance, TX power, manufacturer-specific data,
 *   and flags.  The ESP32 re-broadcasts this payload with a rotating random
 *   MAC, effectively impersonating the target device at the link-layer level.
 *   This is far more convincing than name-only spoofing because phones and
 *   laptops match on service UUIDs, appearance icons, and manufacturer data
 *   when deciding whether to auto-connect.
 *
 * Concurrency:
 *   The NimBLE controller supports only ONE GAP procedure at a time.  The
 *   task therefore yields whenever another procedure (scan / connect) is
 *   active, preventing BLE_GAP_ERR_*_COMMAND_DISALLOWED errors.
 *
 * Dependencies:
 *   - ble_common.h  (nimble_port_init + own_addr_type helper)
 *   - NimBLE stack  (host + controller)
 *   - FreeRTOS
 */

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

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

static const char *TAG = "ble_spoof";

#define MAX_NAMES          5       /* comma-separated names to rotate  */
#define MAX_NAME_LEN       63      /* per-name buffer (before trim)    */
#define ADV_MAX_LEN        31      /* BLE adv payload max              */
#define TASK_STACK_SIZE    4096
#define TASK_PRIORITY      5
#define ADV_INTERVAL_MIN   0x0020  /* 20 ms */
#define ADV_INTERVAL_MAX   0x0028  /* 25 ms */
#define ADV_DURATION_MS    200     /* per-cycle broadcast window       */
#define CYCLE_DELAY_MS     500     /* pause between cycles             */
#define YIELD_DELAY_MS     100     /* yield when controller is busy    */
#define STOP_TIMEOUT_MS    5000    /* max wait for task to exit        */

/* ------------------------------------------------------------------ */
/*  Module state                                                       */
/* ------------------------------------------------------------------ */

static bool               running       = false;
static ble_spoof_mode_t   active_mode   = BLE_SPOOF_MODE_NAME;
static TaskHandle_t       task_handle   = NULL;
static SemaphoreHandle_t  mutex         = NULL;
static SemaphoreHandle_t  task_exit_sem = NULL;
static int                last_error    = 0;

/* Name-spoof state */
static char  current_name[128] = {0};

/* Clone state (deep copy of profile) */
static ble_spoof_clone_profile_t clone_profile = {0};

/* ------------------------------------------------------------------ */
/*  Forward declarations                                               */
/* ------------------------------------------------------------------ */

static void spoof_task(void *arg);
static void set_random_mac(void);
static int  adv_event_cb(struct ble_gap_event *event, void *arg);
static void build_name_adv_payload(const char *name, uint8_t *out, size_t *out_len);
static void build_clone_adv_payload(const ble_spoof_clone_profile_t *prof,
                                     uint8_t *out, size_t *out_len);

/* ------------------------------------------------------------------ */
/*  Random MAC rotation                                                */
/* ------------------------------------------------------------------ */

static void set_random_mac(void) {
    uint8_t mac[6];
    esp_fill_random(mac, 6);
    /* Top two bits must be 1 for random static address (BT spec 4.2 Vol 6 Part B 1.3.2.1) */
    mac[5] |= 0xC0;
    int rc = ble_hs_id_set_rnd(mac);
    if (rc != 0) {
        ESP_LOGW(TAG, "set_random_mac failed: %d", rc);
        last_error = rc;
    }
}

/* ------------------------------------------------------------------ */
/*  GAP event callback                                                 */
/* ------------------------------------------------------------------ */

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

/* ------------------------------------------------------------------ */
/*  Build advertising payloads                                         */
/* ------------------------------------------------------------------ */

/**
 * Build a minimal adv payload for name-spoof mode.
 * [Flags] [Complete Local Name]
 */
static void build_name_adv_payload(const char *name, uint8_t *out, size_t *out_len) {
    size_t n = name ? strlen(name) : 0;
    if (n > 29) n = 29;  /* 31 - 2 (flags field) */
    size_t idx = 0;

    /* Flags: LE General Discoverable + BR/EDR Not Supported */
    out[idx++] = 2;       /* length */
    out[idx++] = 0x01;    /* AD type: Flags */
    out[idx++] = 0x06;

    if (n > 0) {
        out[idx++] = (uint8_t)(n + 1);  /* length of this field */
        out[idx++] = 0x09;              /* AD type: Complete Local Name */
        memcpy(&out[idx], name, n);
        idx += n;
    }

    *out_len = idx;
}

/**
 * Build a full adv payload for clone mode.
 * Tries to fit: [Flags] [16-bit UUIDs] [128-bit UUID] [Appearance]
 *               [TX Power] [Manufacturer Data] [Complete/Shortened Name]
 *
 * We add fields in order of priority; if the 31-byte limit is reached,
 * less important fields are silently dropped.  The name is added last
 * so that service UUIDs (which phones use for auto-connect matching)
 * take priority.
 */
static void build_clone_adv_payload(const ble_spoof_clone_profile_t *prof,
                                     uint8_t *out, size_t *out_len) {
    size_t idx = 0;

    /* If we have a raw payload from the scan, just use it directly */
    if (prof->raw_adv_len > 0 && prof->raw_adv_len <= ADV_MAX_LEN) {
        memcpy(out, prof->raw_adv, prof->raw_adv_len);
        *out_len = prof->raw_adv_len;
        return;
    }

    /* --- Flags (3 bytes) --- */
    if (idx + 3 <= ADV_MAX_LEN) {
        out[idx++] = 2;
        out[idx++] = 0x01;
        out[idx++] = prof->flags;
    }

    /* --- 16-bit Service UUID list --- */
    if (prof->svc_uuids_16_count > 0) {
        size_t field_len = 1 + (prof->svc_uuids_16_count * 2);
        if (idx + 1 + field_len <= ADV_MAX_LEN) {
            out[idx++] = (uint8_t)field_len;
            out[idx++] = (prof->svc_uuids_16_count > 1) ? 0x03 : 0x02;
            /* Complete vs Incomplete 16-bit UUID list */
            if (prof->svc_uuids_16_count > 1)
                out[idx - 1] = 0x03;  /* Complete List of 16-bit UUIDs */
            else
                out[idx - 1] = 0x02;  /* Incomplete List of 16-bit UUIDs */
            for (int i = 0; i < prof->svc_uuids_16_count; i++) {
                out[idx++] = prof->svc_uuids_16[i][0];
                out[idx++] = prof->svc_uuids_16[i][1];
            }
        }
    }

    /* --- 128-bit Service UUID (only first, it's huge) --- */
    if (prof->svc_uuids_128_count > 0 && idx + 17 <= ADV_MAX_LEN) {
        out[idx++] = 16 + 1;
        out[idx++] = 0x06;  /* Incomplete List of 128-bit UUIDs */
        memcpy(&out[idx], prof->svc_uuids_128[0], 16);
        idx += 16;
    }

    /* --- Appearance --- */
    if (prof->has_appearance && idx + 4 <= ADV_MAX_LEN) {
        out[idx++] = 3;
        out[idx++] = 0x19;  /* Appearance */
        out[idx++] = (uint8_t)(prof->appearance & 0xFF);
        out[idx++] = (uint8_t)((prof->appearance >> 8) & 0xFF);
    }

    /* --- TX Power Level --- */
    if (prof->has_tx_power && idx + 3 <= ADV_MAX_LEN) {
        out[idx++] = 2;
        out[idx++] = 0x0A;  /* TX Power Level */
        out[idx++] = (uint8_t)prof->tx_power;
    }

    /* --- Manufacturer Specific Data --- */
    if (prof->has_mfr_data && prof->mfr_data_len > 0) {
        size_t field_len = 1 + 2 + prof->mfr_data_len;  /* type + company_id + data */
        if (idx + 1 + field_len <= ADV_MAX_LEN) {
            out[idx++] = (uint8_t)field_len;
            out[idx++] = 0xFF;  /* Manufacturer Specific Data */
            out[idx++] = (uint8_t)(prof->mfr_company_id & 0xFF);
            out[idx++] = (uint8_t)((prof->mfr_company_id >> 8) & 0xFF);
            memcpy(&out[idx], prof->mfr_data, prof->mfr_data_len);
            idx += prof->mfr_data_len;
        }
    }

    /* --- Local Name (lowest priority, added last) --- */
    size_t name_len = strlen(prof->name);
    if (name_len > 0) {
        size_t remaining = ADV_MAX_LEN - idx;
        if (remaining >= 3) {  /* need at least: len(1) + type(1) + 1 char */
            size_t max_name = remaining - 2;  /* minus len+type bytes */
            if (name_len > max_name) {
                /* Use Shortened Local Name if it doesn't fit */
                out[idx++] = (uint8_t)(max_name + 1);
                out[idx++] = 0x08;  /* Shortened Local Name */
                memcpy(&out[idx], prof->name, max_name);
                idx += max_name;
            } else {
                out[idx++] = (uint8_t)(name_len + 1);
                out[idx++] = 0x09;  /* Complete Local Name */
                memcpy(&out[idx], prof->name, name_len);
                idx += name_len;
            }
        }
    }

    *out_len = idx;
}

/* ------------------------------------------------------------------ */
/*  Main spoof/clone task                                              */
/* ------------------------------------------------------------------ */

static void spoof_task(void *arg) {
    (void)arg;

    /* ---- NAME-SPOOF MODE ---- */
    if (active_mode == BLE_SPOOF_MODE_NAME) {
        char names[MAX_NAMES][MAX_NAME_LEN + 1];
        int  name_count = 0;
        int  cur = 0;

        xSemaphoreTake(mutex, portMAX_DELAY);
        strncpy(names[0], current_name, MAX_NAME_LEN);
        names[0][MAX_NAME_LEN] = '\0';

        /* Parse comma-separated names */
        char *p = strchr(names[0], ',');
        while (p && name_count < MAX_NAMES - 1) {
            *p = '\0';
            name_count++;
            strncpy(names[name_count], p + 1, MAX_NAME_LEN);
            names[name_count][MAX_NAME_LEN] = '\0';
            p = strchr(names[name_count], ',');
        }
        name_count++;  /* at least one */
        xSemaphoreGive(mutex);

        ESP_LOGI(TAG, "NAME-SPOOF mode: %d name(s) loaded", name_count);

        while (running) {
            /* Yield to other BLE operations */
            if (ble_gap_conn_active() || ble_gap_disc_active()) {
                vTaskDelay(pdMS_TO_TICKS(YIELD_DELAY_MS));
                continue;
            }
            if (ble_gap_adv_active()) {
                ble_gap_adv_stop();
                vTaskDelay(pdMS_TO_TICKS(20));
            }

            set_random_mac();
            vTaskDelay(pdMS_TO_TICKS(10));

            xSemaphoreTake(mutex, portMAX_DELAY);
            char sel[MAX_NAME_LEN + 1] = {0};
            strncpy(sel, names[cur % name_count], MAX_NAME_LEN);
            xSemaphoreGive(mutex);

            uint8_t adv[ADV_MAX_LEN];
            size_t  adv_len = 0;
            build_name_adv_payload(sel, adv, &adv_len);

            int rc = ble_gap_adv_set_data(adv, (int)adv_len);
            if (rc) {
                ESP_LOGE(TAG, "adv_set_data failed: %d", rc);
                last_error = rc;
                vTaskDelay(pdMS_TO_TICKS(50));
                cur++;
                continue;
            }

            struct ble_gap_adv_params adv_params = {0};
            adv_params.conn_mode = BLE_GAP_CONN_MODE_NON;
            adv_params.disc_mode = BLE_GAP_DISC_MODE_GEN;
            adv_params.itvl_min = ADV_INTERVAL_MIN;
            adv_params.itvl_max = ADV_INTERVAL_MAX;

            rc = ble_gap_adv_start(BLE_OWN_ADDR_RANDOM, NULL, ADV_DURATION_MS,
                                   &adv_params, adv_event_cb, NULL);
            if (rc) {
                ESP_LOGE(TAG, "adv_start failed: %d", rc);
                last_error = rc;
            } else {
                vTaskDelay(pdMS_TO_TICKS(ADV_DURATION_MS));
                if (ble_gap_adv_active()) ble_gap_adv_stop();
            }

            cur++;
            vTaskDelay(pdMS_TO_TICKS(CYCLE_DELAY_MS));
        }

    /* ---- CLONE MODE ---- */
    } else if (active_mode == BLE_SPOOF_MODE_CLONE) {
        ESP_LOGI(TAG, "CLONE mode: cloning device '%s'", clone_profile.name);

        while (running) {
            /* Yield to other BLE operations */
            if (ble_gap_conn_active() || ble_gap_disc_active()) {
                vTaskDelay(pdMS_TO_TICKS(YIELD_DELAY_MS));
                continue;
            }
            if (ble_gap_adv_active()) {
                ble_gap_adv_stop();
                vTaskDelay(pdMS_TO_TICKS(20));
            }

            /* Rotate MAC each cycle */
            set_random_mac();
            vTaskDelay(pdMS_TO_TICKS(10));

            uint8_t adv[ADV_MAX_LEN];
            size_t  adv_len = 0;
            build_clone_adv_payload(&clone_profile, adv, &adv_len);

            int rc = ble_gap_adv_set_data(adv, (int)adv_len);
            if (rc) {
                ESP_LOGE(TAG, "clone adv_set_data failed: %d", rc);
                last_error = rc;
                vTaskDelay(pdMS_TO_TICKS(50));
                continue;
            }

            struct ble_gap_adv_params adv_params = {0};
            adv_params.conn_mode = BLE_GAP_CONN_MODE_NON;
            adv_params.disc_mode = BLE_GAP_DISC_MODE_GEN;
            adv_params.itvl_min = ADV_INTERVAL_MIN;
            adv_params.itvl_max = ADV_INTERVAL_MAX;

            rc = ble_gap_adv_start(BLE_OWN_ADDR_RANDOM, NULL, ADV_DURATION_MS,
                                   &adv_params, adv_event_cb, NULL);
            if (rc) {
                ESP_LOGE(TAG, "clone adv_start failed: %d", rc);
                last_error = rc;
            } else {
                vTaskDelay(pdMS_TO_TICKS(ADV_DURATION_MS));
                if (ble_gap_adv_active()) ble_gap_adv_stop();
            }

            vTaskDelay(pdMS_TO_TICKS(CYCLE_DELAY_MS));
        }
    }

    /* ---- Cleanup ---- */
    if (ble_gap_adv_active()) {
        ble_gap_adv_stop();
    }

    ESP_LOGI(TAG, "BLE spoof/clone task exiting");
    task_handle = NULL;
    if (task_exit_sem) {
        xSemaphoreGive(task_exit_sem);
    }
    vTaskDelete(NULL);
}

/* ------------------------------------------------------------------ */
/*  Public API – init                                                  */
/* ------------------------------------------------------------------ */

void ble_spoof_init(void) {
    if (mutex == NULL) {
        mutex = xSemaphoreCreateMutex();
    }
    if (task_exit_sem == NULL) {
        task_exit_sem = xSemaphoreCreateBinary();
    }

    /* Ensure NimBLE is initialized */
    ble_common_init();

    ESP_LOGI(TAG, "ble_spoof initialized (name-spoof + clone)");
}

/* ------------------------------------------------------------------ */
/*  Public API – name spoof                                            */
/* ------------------------------------------------------------------ */

void ble_spoof_start(const char *name) {
    if (running) {
        ESP_LOGW(TAG, "Already running, stop first");
        return;
    }
    if (mutex == NULL) mutex = xSemaphoreCreateMutex();

    xSemaphoreTake(mutex, portMAX_DELAY);
    strncpy(current_name, name ? name : "", sizeof(current_name) - 1);
    current_name[sizeof(current_name) - 1] = '\0';
    xSemaphoreGive(mutex);

    active_mode = BLE_SPOOF_MODE_NAME;
    running = true;
    last_error = 0;

    if (task_exit_sem != NULL) {
        xSemaphoreTake(task_exit_sem, 0);  /* clear previous signal */
    }

    BaseType_t ret = xTaskCreate(spoof_task, "ble_spoof", TASK_STACK_SIZE,
                                  NULL, TASK_PRIORITY, &task_handle);
    if (ret != pdPASS) {
        ESP_LOGE(TAG, "Failed to create spoof task");
        running = false;
    } else {
        ESP_LOGI(TAG, "Name-spoof started: '%s'", name ? name : "(empty)");
    }
}

/* ------------------------------------------------------------------ */
/*  Public API – clone from profile                                    */
/* ------------------------------------------------------------------ */

void ble_spoof_clone_start(const ble_spoof_clone_profile_t *profile) {
    if (running) {
        ESP_LOGW(TAG, "Already running, stop first");
        return;
    }
    if (profile == NULL) {
        ESP_LOGE(TAG, "clone_start: NULL profile");
        return;
    }
    if (mutex == NULL) mutex = xSemaphoreCreateMutex();

    xSemaphoreTake(mutex, portMAX_DELAY);
    memcpy(&clone_profile, profile, sizeof(clone_profile));
    xSemaphoreGive(mutex);

    active_mode = BLE_SPOOF_MODE_CLONE;
    running = true;
    last_error = 0;

    if (task_exit_sem != NULL) {
        xSemaphoreTake(task_exit_sem, 0);
    }

    BaseType_t ret = xTaskCreate(spoof_task, "ble_clone", TASK_STACK_SIZE,
                                  NULL, TASK_PRIORITY, &task_handle);
    if (ret != pdPASS) {
        ESP_LOGE(TAG, "Failed to create clone task");
        running = false;
    } else {
        ESP_LOGI(TAG, "Clone mode started: '%s'", profile->name);
    }
}

/* ------------------------------------------------------------------ */
/*  Public API – clone from raw adv data                               */
/* ------------------------------------------------------------------ */

void ble_spoof_clone_start_raw(const uint8_t *raw_adv, uint8_t raw_len) {
    if (raw_adv == NULL || raw_len == 0 || raw_len > ADV_MAX_LEN) {
        ESP_LOGE(TAG, "clone_start_raw: invalid args (len=%d)", raw_len);
        return;
    }

    ble_spoof_clone_profile_t profile = {0};
    if (ble_spoof_parse_adv(raw_adv, raw_len, &profile) != ESP_OK) {
        ESP_LOGE(TAG, "clone_start_raw: failed to parse adv data");
        return;
    }

    /* Also store the raw data as fallback */
    memcpy(profile.raw_adv, raw_adv, raw_len);
    profile.raw_adv_len = raw_len;

    ble_spoof_clone_start(&profile);
}

/* ------------------------------------------------------------------ */
/*  Public API – stop                                                  */
/* ------------------------------------------------------------------ */

void ble_spoof_stop(void) {
    if (!running) return;
    running = false;

    /* Wait for the task to actually exit */
    if (task_exit_sem != NULL) {
        if (xSemaphoreTake(task_exit_sem, pdMS_TO_TICKS(STOP_TIMEOUT_MS)) != pdTRUE) {
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

    ESP_LOGI(TAG, "BLE spoof/clone stopped");
}

/* ------------------------------------------------------------------ */
/*  Public API – status                                                */
/* ------------------------------------------------------------------ */

bool ble_spoof_is_running(void) {
    return running;
}

ble_spoof_mode_t ble_spoof_get_mode(void) {
    return active_mode;
}

int ble_spoof_last_error(void) {
    return last_error;
}

/* ================================================================== */
/*  ADV PARSER – extract fields from raw BLE advertising data          */
/* ================================================================== */

esp_err_t ble_spoof_parse_adv(const uint8_t *raw_adv, uint8_t raw_len,
                               ble_spoof_clone_profile_t *out) {
    if (raw_adv == NULL || out == NULL) {
        return ESP_FAIL;
    }

    memset(out, 0, sizeof(*out));
    out->flags = 0x06;  /* default: LE General Discoverable + BR/EDR not supported */

    size_t pos = 0;
    while (pos + 1 < raw_len) {
        uint8_t field_len = raw_adv[pos];
        if (field_len == 0 || pos + 1 + field_len > raw_len) {
            break;  /* malformed or end */
        }
        uint8_t field_type = raw_adv[pos + 1];
        const uint8_t *data = &raw_adv[pos + 2];
        uint8_t data_len = field_len - 1;

        switch (field_type) {
            /* ---- Flags ---- */
            case 0x01:
                if (data_len >= 1) {
                    out->flags = data[0];
                }
                break;

            /* ---- Incomplete List of 16-bit UUIDs ---- */
            case 0x02:
                /* fall-through */
            /* ---- Complete List of 16-bit UUIDs ---- */
            case 0x03: {
                int count = data_len / 2;
                if (count > BLE_SPOOF_MAX_SVC_UUIDS) count = BLE_SPOOF_MAX_SVC_UUIDS;
                for (int i = 0; i < count; i++) {
                    out->svc_uuids_16[out->svc_uuids_16_count][0] = data[i * 2];
                    out->svc_uuids_16[out->svc_uuids_16_count][1] = data[i * 2 + 1];
                    out->svc_uuids_16_count++;
                }
                break;
            }

            /* ---- Incomplete List of 128-bit UUIDs ---- */
            case 0x06:
                /* fall-through */
            /* ---- Complete List of 128-bit UUIDs ---- */
            case 0x07: {
                if (data_len >= 16 && out->svc_uuids_128_count < BLE_SPOOF_MAX_SVC_UUIDS) {
                    memcpy(out->svc_uuids_128[out->svc_uuids_128_count], data, 16);
                    out->svc_uuids_128_count++;
                }
                break;
            }

            /* ---- Shortened Local Name ---- */
            case 0x08:
                /* fall-through */
            /* ---- Complete Local Name ---- */
            case 0x09: {
                size_t copy_len = data_len;
                if (copy_len > BLE_SPOOF_MAX_NAME_LEN) copy_len = BLE_SPOOF_MAX_NAME_LEN;
                memcpy(out->name, data, copy_len);
                out->name[copy_len] = '\0';
                break;
            }

            /* ---- Appearance ---- */
            case 0x19:
                if (data_len >= 2) {
                    out->appearance = data[0] | ((uint16_t)data[1] << 8);
                    out->has_appearance = true;
                }
                break;

            /* ---- TX Power Level ---- */
            case 0x0A:
                if (data_len >= 1) {
                    out->tx_power = (int8_t)data[0];
                    out->has_tx_power = true;
                }
                break;

            /* ---- Manufacturer Specific Data ---- */
            case 0xFF:
                if (data_len >= 2) {
                    out->mfr_company_id = data[0] | ((uint16_t)data[1] << 8);
                    int mfr_len = data_len - 2;
                    if (mfr_len > BLE_SPOOF_MAX_MFR_DATA_LEN) {
                        mfr_len = BLE_SPOOF_MAX_MFR_DATA_LEN;
                    }
                    memcpy(out->mfr_data, &data[2], mfr_len);
                    out->mfr_data_len = mfr_len;
                    out->has_mfr_data = true;
                }
                break;

            default:
                /* Unknown AD type – skip */
                break;
        }

        pos += 1 + field_len;
    }

    return ESP_OK;
}

/* ================================================================== */
/*  ADV BUILDER – reconstruct payload from clone profile               */
/* ================================================================== */

esp_err_t ble_spoof_build_adv(const ble_spoof_clone_profile_t *profile,
                               uint8_t *out, size_t *out_len) {
    if (profile == NULL || out == NULL || out_len == NULL) {
        return ESP_FAIL;
    }
    build_clone_adv_payload(profile, out, out_len);
    return ESP_OK;
}
