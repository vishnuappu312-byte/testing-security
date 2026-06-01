// #include "ble_common.h"

// #include "esp_log.h"

// #include "host/ble_hs.h"
// #include "host/ble_hs_id.h"

// static const char *TAG = "ble_common";

// uint8_t ble_common_own_addr_type(void) {
//     uint8_t addr_type = BLE_ADDR_PUBLIC;
//     int rc = ble_hs_id_infer_auto(0, &addr_type);
//     if (rc != 0) {
//         ESP_LOGW(TAG, "ble_hs_id_infer_auto failed: %d (using public)", rc);
//         addr_type = BLE_ADDR_PUBLIC;
//     }
//     return addr_type;
// }

// void ble_common_ensure_rnd_addr(void) {
//     ble_addr_t addr;
//     int rc = ble_hs_id_gen_rnd(0, &addr);
//     if (rc != 0) {
//         ESP_LOGW(TAG, "ble_hs_id_gen_rnd failed: %d", rc);
//         return;
//     }

//     rc = ble_hs_id_set_rnd(addr.val);
//     if (rc != 0) {
//         ESP_LOGW(TAG, "ble_hs_id_set_rnd failed: %d", rc);
//         return;
//     }
// }

#include "ble_common.h"

#include "esp_log.h"

#include "host/ble_hs.h"
#include "host/ble_hs_id.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "esp_nimble_hci.h"
#include "services/gap/ble_svc_gap.h"
#include "host/ble_store.h"

extern void ble_store_config_init(void);

static const char *TAG = "ble_common";

static bool nimble_initialized = false;
static SemaphoreHandle_t sync_sem = NULL;

/* ---- Shared sync callback ---- */

static void ble_common_on_sync(void) {
    ESP_LOGI(TAG, "NimBLE host synced");
    ble_common_ensure_rnd_addr();
    if (sync_sem != NULL) {
        xSemaphoreGive(sync_sem);
    }
}

static void ble_common_on_reset(int reason) {
    ESP_LOGE(TAG, "NimBLE host reset, reason=%d", reason);
}

static void nimble_host_task(void *param) {
    nimble_port_run();
    nimble_port_freertos_deinit();
    vTaskDelete(NULL);
}

/* ---- One-time NimBLE init (safe to call from any component) ---- */

bool ble_common_init(void) {
    if (nimble_initialized) {
        ESP_LOGI(TAG, "NimBLE already initialized");
        /* Try to take sync sem (may already be given from earlier init) */
        if (sync_sem != NULL) {
            xSemaphoreTake(sync_sem, pdMS_TO_TICKS(500));
        }
        return true;
    }

    if (sync_sem == NULL) {
        sync_sem = xSemaphoreCreateBinary();
    }

    /* Set callbacks BEFORE init */
    ble_hs_cfg.sync_cb  = ble_common_on_sync;
    ble_hs_cfg.reset_cb = ble_common_on_reset;
    ble_hs_cfg.store_status_cb = ble_store_util_status_rr;

    ESP_ERROR_CHECK(esp_nimble_hci_and_controller_init());
    nimble_port_init();

    /* Security defaults */
    ble_hs_cfg.sm_io_cap = BLE_HS_IO_NO_INPUT_OUTPUT;
    ble_hs_cfg.sm_bonding = 0;
    ble_hs_cfg.sm_mitm = 0;
    ble_hs_cfg.sm_sc = 0;
    ble_hs_cfg.sm_our_key_dist = BLE_SM_PAIR_KEY_DIST_ENC;
    ble_hs_cfg.sm_their_key_dist = BLE_SM_PAIR_KEY_DIST_ENC;

    ble_svc_gap_device_name_set("nimble-device");
    ble_store_config_init();

    nimble_port_freertos_init(nimble_host_task);
    nimble_initialized = true;

    /* Wait for sync */
    vTaskDelay(pdMS_TO_TICKS(200));
    if (xSemaphoreTake(sync_sem, pdMS_TO_TICKS(5000)) != pdTRUE) {
        ESP_LOGE(TAG, "NimBLE sync timeout!");
        return false;
    }

    ESP_LOGI(TAG, "NimBLE initialized and synced");
    return true;
}

bool ble_common_is_initialized(void) {
    return nimble_initialized;
}

/* ---- Existing helpers (unchanged) ---- */

uint8_t ble_common_own_addr_type(void) {
    uint8_t addr_type = BLE_ADDR_PUBLIC;
    int rc = ble_hs_id_infer_auto(0, &addr_type);
    if (rc != 0) {
        ESP_LOGW(TAG, "ble_hs_id_infer_auto failed: %d (using public)", rc);
        addr_type = BLE_ADDR_PUBLIC;
    }
    return addr_type;
}

void ble_common_ensure_rnd_addr(void) {
    ble_addr_t addr;
    int rc = ble_hs_id_gen_rnd(0, &addr);
    if (rc != 0) {
        ESP_LOGW(TAG, "ble_hs_id_gen_rnd failed: %d", rc);
        return;
    }

    rc = ble_hs_id_set_rnd(addr.val);
    if (rc != 0) {
        ESP_LOGW(TAG, "ble_hs_id_set_rnd failed: %d", rc);
        return;
    }
}