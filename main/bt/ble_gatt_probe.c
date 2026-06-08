/*
 * ble_gatt_probe.c - BLE GATT Probe Attack Implementation
 *
 * Connects to a target BLE device, performs full GATT service and
 * characteristic enumeration, then optionally reads, writes, and
 * subscribes to every discovered characteristic.  The cycle repeats
 * until the timeout expires or the attack is stopped.
 *
 * Thread safety:
 *   - `running` is volatile bool: set from stop()/timer, read in task
 *   - Counters are volatile uint32_t: atomic on 32-bit Xtensa
 *   - `cfg` is protected by mutex
 *   - `timeout_fired` is volatile for cross-task visibility
 *
 * Async flow:
 *   The GAP/GATT event callbacks NEVER call vTaskDelay (which would
 *   block the entire NimBLE host task).  Instead they update state
 *   and give `probe_sem` to wake the probe task, which then applies
 *   the appropriate delay before the next operation.
 *
 * GATT discovery:
 *   After connecting, the probe task issues:
 *     - ble_gattc_disc_all_svcs()    → enumerate all primary services
 *     - ble_gattc_disc_all_chrs()    → enumerate chars per service
 *     - ble_gattc_read()             → read each readable char
 *     - ble_gattc_write_no_rsp()     → write to each writable char
 *     - ble_gattc_notify()           → subscribe to notifiable chars
 *   All results are collected via the GATT discovery callback.
 *
 * Dependencies:
 *   - ble_common.h  (nimble_port_init + own_addr_type helper)
 *   - NimBLE stack  (host + controller)
 *   - FreeRTOS
 *   - cJSON
 *   - esp_timer
 */

#include "ble_gatt_probe.h"
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

static const char *TAG = "ble_gatt_probe";

#define DEFAULT_TIMEOUT_SEC          300
#define DEFAULT_CONNECT_TIMEOUT_MS   5000
#define DEFAULT_PROBE_READ           true
#define DEFAULT_PROBE_WRITE          false
#define DEFAULT_PROBE_SUBSCRIBE      true
#define DEFAULT_PROBE_INTERVAL_MS    50
#define DEFAULT_POST_DISCONNECT_MS   500
#define DEFAULT_FAIL_BACKOFF_MS      2000
#define DEFAULT_ADDR_TYPE            BLE_GATT_PROBE_ADDR_AUTO
#define DEFAULT_ROTATE_OWN_MAC       true
#define STOP_SEM_TIMEOUT_MS          5000
#define PROBE_SEM_TIMEOUT_MS         10000
#define TASK_STACK_SIZE              6144
#define TASK_PRIORITY                5

/* Maximum tracked services / characteristics per probe cycle */
#define MAX_SERVICES_PER_CYCLE       32
#define MAX_CHARS_PER_CYCLE          64

/* ================================================================== */
/*  Discovered GATT item                                               */
/* ================================================================== */

typedef struct {
    uint16_t start_handle;
    uint16_t end_handle;
    ble_uuid_any_t uuid;
} discovered_svc_t;

typedef struct {
    uint16_t val_handle;
    uint16_t decl_handle;
    uint8_t  properties;          /* BLE_GATT_CHR_F_READ, _WRITE, etc. */
    ble_uuid_any_t uuid;
} discovered_chr_t;

/* ================================================================== */
/*  Module state                                                       */
/* ================================================================== */

/* Control */
static volatile bool running           = false;
static SemaphoreHandle_t mutex         = NULL;
static SemaphoreHandle_t task_exit_sem = NULL;
static SemaphoreHandle_t probe_sem     = NULL;
static TaskHandle_t task_handle        = NULL;

/* Timeout timer */
static esp_timer_handle_t timeout_timer = NULL;
static volatile bool timeout_fired      = false;

/* Timing */
static volatile int64_t start_time_ms  = 0;

/* Counters (atomic on 32-bit Xtensa) */
static volatile uint32_t probe_count      = 0;   /* full probe cycles      */
static volatile uint32_t services_found   = 0;
static volatile uint32_t chars_found      = 0;
static volatile uint32_t read_count       = 0;
static volatile uint32_t write_count      = 0;
static volatile uint32_t subscribe_count  = 0;
static volatile uint32_t fail_count       = 0;

/* Connection state (written by callback, read by task) */
static volatile bool last_connect_ok    = false;
static volatile int  last_conn_handle   = -1;
static volatile uint8_t active_addr_type = BLE_ADDR_PUBLIC;

/* Discovered items during the current connection */
static discovered_svc_t disc_svcs[MAX_SERVICES_PER_CYCLE];
static volatile uint16_t disc_svc_count = 0;
static discovered_chr_t disc_chrs[MAX_CHARS_PER_CYCLE];
static volatile uint16_t disc_chr_count = 0;

/* Current discovery tracking (which service we are enumerating chars for) */
static volatile uint16_t disc_svc_idx   = 0;

/* Configuration */
static gatt_probe_config_t cfg = {
    .target_addr        = "",
    .timeout_sec        = DEFAULT_TIMEOUT_SEC,
    .connect_timeout_ms = DEFAULT_CONNECT_TIMEOUT_MS,
    .probe_read         = DEFAULT_PROBE_READ,
    .probe_write        = DEFAULT_PROBE_WRITE,
    .probe_subscribe    = DEFAULT_PROBE_SUBSCRIBE,
    .probe_interval_ms  = DEFAULT_PROBE_INTERVAL_MS,
    .post_disconnect_ms = DEFAULT_POST_DISCONNECT_MS,
    .fail_backoff_ms    = DEFAULT_FAIL_BACKOFF_MS,
    .addr_type          = DEFAULT_ADDR_TYPE,
    .rotate_own_mac     = DEFAULT_ROTATE_OWN_MAC,
};

/* ================================================================== */
/*  Forward declarations                                               */
/* ================================================================== */

static void probe_task(void *arg);
static void timeout_cb(void *arg);
static int gap_event_cb(struct ble_gap_event *event, void *arg);
static int gatt_disc_svc_cb(uint16_t conn_handle,
                            const struct ble_gatt_error *error,
                            const struct ble_gatt_svc *svc, void *arg);
static int gatt_disc_chr_cb(uint16_t conn_handle,
                            const struct ble_gatt_error *error,
                            const struct ble_gatt_chr *chr, void *arg);

/* ================================================================== */
/*  Helpers                                                            */
/* ================================================================== */

static int64_t now_ms(void)
{
    return (int64_t)esp_timer_get_time() / 1000;
}

static void set_random_mac(void)
{
    uint8_t rnd_addr[6];
    esp_fill_random(rnd_addr, sizeof(rnd_addr));
    /* Set two LSBs of first byte for random static address (11) */
    rnd_addr[0] |= 0xC0;
    int rc = ble_hs_id_set_rnd(rnd_addr);
    if (rc != 0) {
        ESP_LOGD(TAG, "ble_hs_id_set_rnd failed: %d", rc);
    }
}

static const char *addr_type_str(gatt_probe_addr_type_t t)
{
    switch (t) {
        case BLE_GATT_PROBE_ADDR_PUBLIC: return "PUBLIC";
        case BLE_GATT_PROBE_ADDR_RANDOM: return "RANDOM";
        case BLE_GATT_PROBE_ADDR_AUTO:   return "AUTO";
        default:                          return "UNKNOWN";
    }
}

/* ================================================================== */
/*  Timeout timer                                                      */
/* ================================================================== */

static void timeout_cb(void *arg)
{
    (void)arg;
    timeout_fired = true;
    running       = false;
    ESP_LOGW(TAG, "Timeout expired — stopping GATT probe");
}

/* ================================================================== */
/*  GAP event callback                                                 */
/* ================================================================== */

static int gap_event_cb(struct ble_gap_event *event, void *arg)
{
    (void)arg;

    switch (event->type) {

    case BLE_GAP_EVENT_CONNECT: {
        if (event->connect.status == 0) {
            last_connect_ok  = true;
            last_conn_handle = event->connect.conn_handle;
            ESP_LOGI(TAG, "Connected to target (handle=%d)",
                     event->connect.conn_handle);
        } else {
            last_connect_ok  = false;
            last_conn_handle = -1;
            fail_count++;

            int reason = event->connect.status;
            ESP_LOGW(TAG, "Connect failed: status=%d", reason);

            /* AUTO mode: switch to RANDOM on status 13 (wrong addr type) */
            if (reason == 13 && cfg.addr_type == BLE_GATT_PROBE_ADDR_AUTO) {
                active_addr_type = BLE_ADDR_RANDOM;
                ESP_LOGI(TAG, "AUTO → switching to RANDOM address type");
            }
        }
        /* Wake the probe task */
        if (probe_sem) {
            xSemaphoreGive(probe_sem);
        }
        return 0;
    }

    case BLE_GAP_EVENT_DISCONNECT: {
        ESP_LOGI(TAG, "Disconnected (reason=%d)",
                 event->disconnect.reason);
        last_conn_handle = -1;
        return 0;
    }

    case BLE_GAP_EVENT_CONN_UPDATE:
    case BLE_GAP_EVENT_MTU:
        /* Informational — nothing to do */
        return 0;

    default:
        return 0;
    }
}

/* ================================================================== */
/*  GATT service discovery callback                                    */
/* ================================================================== */

static int gatt_disc_svc_cb(uint16_t conn_handle,
                            const struct ble_gatt_error *error,
                            const struct ble_gatt_svc *svc,
                            void *arg)
{
    (void)conn_handle;
    (void)arg;

    if (error->status == 0 && svc != NULL) {
        uint16_t idx = disc_svc_count;
        if (idx < MAX_SERVICES_PER_CYCLE) {
            disc_svcs[idx].start_handle = svc->start_handle;
            disc_svcs[idx].end_handle   = svc->end_handle;
            memcpy(&disc_svcs[idx].uuid, &svc->uuid, sizeof(ble_uuid_any_t));
            disc_svc_count = idx + 1;
            services_found++;
        }
    } else if (error->status == BLE_HS_EDONE) {
        /* Discovery complete — wake the probe task */
        if (probe_sem) {
            xSemaphoreGive(probe_sem);
        }
    } else {
        ESP_LOGD(TAG, "SVC discovery error: %d", error->status);
        if (probe_sem) {
            xSemaphoreGive(probe_sem);
        }
    }
    return 0;
}

/* ================================================================== */
/*  GATT characteristic discovery callback                             */
/* ================================================================== */

static int gatt_disc_chr_cb(uint16_t conn_handle,
                            const struct ble_gatt_error *error,
                            const struct ble_gatt_chr *chr,
                            void *arg)
{
    (void)conn_handle;
    (void)arg;

    if (error->status == 0 && chr != NULL) {
        uint16_t idx = disc_chr_count;
        if (idx < MAX_CHARS_PER_CYCLE) {
            disc_chrs[idx].val_handle  = chr->val_handle;
            disc_chrs[idx].decl_handle = chr->def_handle;
            disc_chrs[idx].properties  = chr->properties;
            memcpy(&disc_chrs[idx].uuid, &chr->uuid, sizeof(ble_uuid_any_t));
            disc_chr_count = idx + 1;
            chars_found++;
        }
    } else if (error->status == BLE_HS_EDONE) {
        /* Characteristic discovery complete for this service */
        if (probe_sem) {
            xSemaphoreGive(probe_sem);
        }
    } else {
        ESP_LOGD(TAG, "CHR discovery error: %d", error->status);
        if (probe_sem) {
            xSemaphoreGive(probe_sem);
        }
    }
    return 0;
}

/* ================================================================== */
/*  GATT read callback                                                 */
/* ================================================================== */

static int gatt_read_cb(uint16_t conn_handle,
                        const struct ble_gatt_error *error,
                        struct ble_gatt_attr *attr,
                        void *arg)
{
    (void)conn_handle;
    (void)attr;
    (void)arg;

    if (error->status == 0) {
        read_count++;
    } else {
        ESP_LOGD(TAG, "Read failed: %d", error->status);
    }
    /* Wake task after each read completes */
    if (probe_sem) {
        xSemaphoreGive(probe_sem);
    }
    return 0;
}

/* ================================================================== */
/*  GATT write callback                                                */
/* ================================================================== */

static int gatt_write_cb(uint16_t conn_handle,
                         const struct ble_gatt_error *error,
                         struct ble_gatt_attr *attr,
                         void *arg)
{
    (void)conn_handle;
    (void)attr;
    (void)arg;

    if (error->status == 0) {
        write_count++;
    } else {
        ESP_LOGD(TAG, "Write failed: %d", error->status);
    }
    if (probe_sem) {
        xSemaphoreGive(probe_sem);
    }
    return 0;
}

/* ================================================================== */
/*  GATT subscribe callback                                            */
/* ================================================================== */

static int gatt_subscribe_cb(uint16_t conn_handle,
                             const struct ble_gatt_error *error,
                             struct ble_gatt_attr *attr,
                             void *arg)
{
    (void)conn_handle;
    (void)attr;
    (void)arg;

    if (error->status == 0) {
        subscribe_count++;
    } else {
        ESP_LOGD(TAG, "Subscribe failed: %d", error->status);
    }
    if (probe_sem) {
        xSemaphoreGive(probe_sem);
    }
    return 0;
}

/* ================================================================== */
/*  Probe a single connection                                          */
/* ================================================================== */

/**
 * After a successful GAP connection, this function:
 *   1. Discovers all primary services
 *   2. For each service, discovers all characteristics
 *   3. Reads / writes / subscribes based on config
 *
 * Returns true if the probe cycle completed, false on error.
 */
static bool probe_connection(uint16_t conn_handle)
{
    int rc;

    /* ---- Step 1: Discover all primary services ---- */
    disc_svc_count = 0;
    memset((void *)disc_svcs, 0, sizeof(disc_svcs));

    rc = ble_gattc_disc_all_svcs(conn_handle, gatt_disc_svc_cb, NULL);
    if (rc != 0) {
        ESP_LOGE(TAG, "ble_gattc_disc_all_svcs failed: %d", rc);
        return false;
    }

    /* Wait for service discovery to complete */
    if (xSemaphoreTake(probe_sem, pdMS_TO_TICKS(PROBE_SEM_TIMEOUT_MS)) != pdTRUE) {
        ESP_LOGW(TAG, "Service discovery timed out");
        return false;
    }

    if (!running) return false;

    ESP_LOGI(TAG, "Discovered %u services", (unsigned)disc_svc_count);

    if (disc_svc_count == 0) {
        ESP_LOGW(TAG, "No services found — target may not be GATT server");
        return true;  /* Not an error, just empty GATT server */
    }

    /* ---- Step 2: For each service, discover characteristics ---- */
    disc_chr_count = 0;
    memset((void *)disc_chrs, 0, sizeof(disc_chrs));

    for (uint16_t s = 0; s < disc_svc_count && running; s++) {
        disc_svc_idx = s;

        rc = ble_gattc_disc_all_chrs(conn_handle,
                                     disc_svcs[s].start_handle,
                                     disc_svcs[s].end_handle,
                                     gatt_disc_chr_cb, NULL);
        if (rc != 0) {
            ESP_LOGD(TAG, "ble_gattc_disc_all_chrs failed for svc[%u]: %d",
                     (unsigned)s, rc);
            continue;
        }

        /* Wait for characteristic discovery for this service */
        if (xSemaphoreTake(probe_sem, pdMS_TO_TICKS(PROBE_SEM_TIMEOUT_MS)) != pdTRUE) {
            ESP_LOGW(TAG, "Char discovery timed out for svc[%u]", (unsigned)s);
            continue;
        }

        if (cfg.probe_interval_ms > 0) {
            vTaskDelay(pdMS_TO_TICKS(cfg.probe_interval_ms));
        }
    }

    ESP_LOGI(TAG, "Discovered %u characteristics total", (unsigned)disc_chr_count);

    if (!running) return false;

    /* ---- Step 3: Read / Write / Subscribe each characteristic ---- */
    for (uint16_t c = 0; c < disc_chr_count && running; c++) {
        uint8_t props = disc_chrs[c].properties;

        /* READ */
        if (cfg.probe_read && (props & BLE_GATT_CHR_F_READ)) {
            rc = ble_gattc_read(conn_handle, disc_chrs[c].val_handle,
                                gatt_read_cb, NULL);
            if (rc != 0) {
                ESP_LOGD(TAG, "ble_gattc_read failed (handle=%d): %d",
                         disc_chrs[c].val_handle, rc);
            } else {
                /* Wait for read callback */
                xSemaphoreTake(probe_sem, pdMS_TO_TICKS(3000));
            }
        }

        if (!running) break;

        /* WRITE — write a single zero byte as probe data */
        if (cfg.probe_write && (props & (BLE_GATT_CHR_F_WRITE |
                                          BLE_GATT_CHR_F_WRITE_NO_RSP))) {
            uint8_t probe_byte = 0x00;
            struct os_mbuf *om = ble_hs_mbuf_from_flat(&probe_byte, 1);
            if (om != NULL) {
                if (props & BLE_GATT_CHR_F_WRITE_NO_RSP) {
                    rc = ble_gattc_write_no_rsp(conn_handle,
                                                disc_chrs[c].val_handle,
                                                om);
                    if (rc == 0) {
                        write_count++;
                    } else {
                        ESP_LOGD(TAG, "write_no_rsp failed: %d", rc);
                    }
                    /* No callback for no-rsp write — no sem wait */
                } else {
                    rc = ble_gattc_write(conn_handle,
                                         disc_chrs[c].val_handle,
                                         om, gatt_write_cb, NULL);
                    if (rc != 0) {
                        ESP_LOGD(TAG, "ble_gattc_write failed: %d", rc);
                    } else {
                        xSemaphoreTake(probe_sem, pdMS_TO_TICKS(3000));
                    }
                }
            }
        }

        if (!running) break;

        /* SUBSCRIBE / NOTIFY — write to CCCD to enable notifications.
         * NimBLE v4.4.7 doesn't have a subscribe API, so we write
         * 0x0001 (notifications) directly to the CCCD handle. */
        if (cfg.probe_subscribe && (props & (BLE_GATT_CHR_F_NOTIFY |
                                              BLE_GATT_CHR_F_INDICATE))) {
            /* CCCD is typically at val_handle + 1 */
            uint16_t cccd_handle = disc_chrs[c].val_handle + 1;
            if (cccd_handle < disc_chrs[c].val_handle) {
                cccd_handle = 0;   /* Overflow guard */
            }

            if (cccd_handle != 0) {
                uint16_t cccd_val = 0x0001;  /* Enable notifications */
                struct os_mbuf *om = ble_hs_mbuf_from_flat(&cccd_val, 2);
                if (om != NULL) {
                    rc = ble_gattc_write(conn_handle, cccd_handle,
                                         om, gatt_subscribe_cb, NULL);
                    if (rc != 0) {
                        ESP_LOGD(TAG, "CCCD write failed (handle=%d): %d",
                                 cccd_handle, rc);
                    } else {
                        xSemaphoreTake(probe_sem, pdMS_TO_TICKS(3000));
                    }
                }
            }
        }

        /* Delay between characteristic probes */
        if (cfg.probe_interval_ms > 0) {
            vTaskDelay(pdMS_TO_TICKS(cfg.probe_interval_ms));
        }
    }

    probe_count++;
    return true;
}

/* ================================================================== */
/*  Probe task                                                         */
/* ================================================================== */

static void probe_task(void *arg)
{
    (void)arg;

    ESP_LOGI(TAG, "Probe task started (target=%s, timeout=%us, read=%d, write=%d, subscribe=%d)",
             cfg.target_addr, (unsigned)cfg.timeout_sec,
             cfg.probe_read, cfg.probe_write, cfg.probe_subscribe);

    start_time_ms = now_ms();

    while (running) {

        /* Rotate own MAC if configured */
        if (cfg.rotate_own_mac) {
            set_random_mac();
        }

        /* Determine address type to use */
        uint8_t use_addr_type = BLE_ADDR_PUBLIC;
        if (cfg.addr_type == BLE_GATT_PROBE_ADDR_RANDOM) {
            use_addr_type = BLE_ADDR_RANDOM;
        } else if (cfg.addr_type == BLE_GATT_PROBE_ADDR_AUTO) {
            use_addr_type = active_addr_type;
        }

        /* Parse target address */
        ble_addr_t target_ble_addr;
        target_ble_addr.type = use_addr_type;
        int parsed = sscanf(cfg.target_addr,
                            "%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx",
                            &target_ble_addr.val[5], &target_ble_addr.val[4],
                            &target_ble_addr.val[3], &target_ble_addr.val[2],
                            &target_ble_addr.val[1], &target_ble_addr.val[0]);
        if (parsed != 6) {
            ESP_LOGE(TAG, "Invalid target address: %s", cfg.target_addr);
            break;
        }

        /* Connect to target */
        ESP_LOGI(TAG, "Connecting to %s (addr_type=%s)...",
                 cfg.target_addr,
                 use_addr_type == BLE_ADDR_RANDOM ? "RANDOM" : "PUBLIC");

        last_connect_ok  = false;
        last_conn_handle = -1;

        int rc = ble_gap_connect(use_addr_type, &target_ble_addr,
                                 cfg.connect_timeout_ms,
                                 NULL, gap_event_cb, NULL);
        if (rc != 0) {
            ESP_LOGE(TAG, "ble_gap_connect failed: %d", rc);
            fail_count++;
            vTaskDelay(pdMS_TO_TICKS(cfg.fail_backoff_ms));
            continue;
        }

        /* Wait for GAP connect callback */
        if (xSemaphoreTake(probe_sem,
                           pdMS_TO_TICKS(cfg.connect_timeout_ms + 2000)) != pdTRUE) {
            ESP_LOGW(TAG, "Connect timed out (no callback)");
            fail_count++;
            continue;
        }

        if (!running) break;

        if (!last_connect_ok) {
            ESP_LOGW(TAG, "Connect failed — backoff %ums",
                     (unsigned)cfg.fail_backoff_ms);
            vTaskDelay(pdMS_TO_TICKS(cfg.fail_backoff_ms));
            continue;
        }

        /* ---- Connected — run GATT probe ---- */
        ESP_LOGI(TAG, "Starting GATT probe on handle=%d", last_conn_handle);
        bool probe_ok = probe_connection((uint16_t)last_conn_handle);

        if (!running) break;

        /* ---- Disconnect ---- */
        if (last_conn_handle >= 0) {
            rc = ble_gap_terminate((uint16_t)last_conn_handle,
                                   BLE_ERR_REM_USER_CONN_TERM);
            if (rc != 0) {
                ESP_LOGD(TAG, "ble_gap_terminate failed: %d (already gone?)", rc);
            }
        }

        /* Wait for disconnect to settle */
        vTaskDelay(pdMS_TO_TICKS(cfg.post_disconnect_ms));

        if (probe_ok) {
            ESP_LOGI(TAG, "Probe cycle #%u complete", (unsigned)probe_count);
        }

        if (!running) break;
    }

    /* Cleanup */
    if (last_conn_handle >= 0) {
        ble_gap_terminate((uint16_t)last_conn_handle,
                          BLE_ERR_REM_USER_CONN_TERM);
        last_conn_handle = -1;
    }

    if (timeout_timer) {
        esp_timer_stop(timeout_timer);
    }

    running = false;
    ESP_LOGI(TAG, "Probe task exiting");

    if (task_exit_sem) {
        xSemaphoreGive(task_exit_sem);
    }

    task_handle = NULL;
    vTaskDelete(NULL);
}

/* ================================================================== */
/*  Public API — Lifecycle                                             */
/* ================================================================== */

void ble_gatt_probe_init(void)
{
    ble_common_init();

    mutex = xSemaphoreCreateMutex();
    probe_sem     = xSemaphoreCreateBinary();
    task_exit_sem = xSemaphoreCreateBinary();

    /* Create one-shot timeout timer */
    esp_timer_create_args_t timer_args = {
        .callback = timeout_cb,
        .name     = "gatt_probe_timeout",
    };
    esp_timer_create(&timer_args, &timeout_timer);

    ESP_LOGI(TAG, "ble_gatt_probe initialized");
}

void ble_gatt_probe_start(const char *target_addr)
{
    gatt_probe_config_t default_cfg = {
        .target_addr        = "",
        .timeout_sec        = DEFAULT_TIMEOUT_SEC,
        .connect_timeout_ms = DEFAULT_CONNECT_TIMEOUT_MS,
        .probe_read         = DEFAULT_PROBE_READ,
        .probe_write        = DEFAULT_PROBE_WRITE,
        .probe_subscribe    = DEFAULT_PROBE_SUBSCRIBE,
        .probe_interval_ms  = DEFAULT_PROBE_INTERVAL_MS,
        .post_disconnect_ms = DEFAULT_POST_DISCONNECT_MS,
        .fail_backoff_ms    = DEFAULT_FAIL_BACKOFF_MS,
        .addr_type          = DEFAULT_ADDR_TYPE,
        .rotate_own_mac     = DEFAULT_ROTATE_OWN_MAC,
    };
    if (target_addr) {
        strncpy(default_cfg.target_addr, target_addr,
                sizeof(default_cfg.target_addr) - 1);
    }
    ble_gatt_probe_start_config(&default_cfg);
}

void ble_gatt_probe_start_config(const gatt_probe_config_t *new_cfg)
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

    /* Reset counters */
    probe_count     = 0;
    services_found  = 0;
    chars_found     = 0;
    read_count      = 0;
    write_count     = 0;
    subscribe_count = 0;
    fail_count      = 0;
    timeout_fired   = false;
    active_addr_type = BLE_ADDR_PUBLIC;

    /* Reset semaphore */
    xSemaphoreTake(probe_sem, 0);

    /* Start timeout timer */
    if (timeout_timer) {
        esp_timer_start_once(timeout_timer,
                             (uint64_t)cfg.timeout_sec * 1000000);
    }

    running = true;

    BaseType_t created = xTaskCreate(probe_task, "ble_gatt_probe",
                                     TASK_STACK_SIZE, NULL,
                                     TASK_PRIORITY, &task_handle);
    if (created != pdPASS) {
        ESP_LOGE(TAG, "Failed to create probe task");
        running = false;
        if (timeout_timer) {
            esp_timer_stop(timeout_timer);
        }
    }
}

void ble_gatt_probe_stop(void)
{
    if (!running) return;

    ESP_LOGI(TAG, "Stopping GATT probe...");
    running = false;

    /* Wake task if it's blocked on the semaphore */
    if (probe_sem) {
        xSemaphoreGive(probe_sem);
    }

    /* Wait for task to exit */
    if (task_exit_sem) {
        xSemaphoreTake(task_exit_sem, pdMS_TO_TICKS(STOP_SEM_TIMEOUT_MS));
    }

    if (timeout_timer) {
        esp_timer_stop(timeout_timer);
    }

    task_handle = NULL;
    ESP_LOGI(TAG, "GATT probe stopped");
}

/* ================================================================== */
/*  Public API — Status getters                                        */
/* ================================================================== */

bool ble_gatt_probe_is_running(void)
{
    return running;
}

uint32_t ble_gatt_probe_get_probe_count(void)
{
    return probe_count;
}

uint32_t ble_gatt_probe_get_services_found(void)
{
    return services_found;
}

uint32_t ble_gatt_probe_get_chars_found(void)
{
    return chars_found;
}

uint32_t ble_gatt_probe_get_read_count(void)
{
    return read_count;
}

uint32_t ble_gatt_probe_get_write_count(void)
{
    return write_count;
}

uint32_t ble_gatt_probe_get_subscribe_count(void)
{
    return subscribe_count;
}

uint32_t ble_gatt_probe_get_fail_count(void)
{
    return fail_count;
}

int32_t ble_gatt_probe_get_elapsed_sec(void)
{
    if (!running && start_time_ms == 0) return 0;
    int64_t elapsed = now_ms() - start_time_ms;
    return (int32_t)(elapsed / 1000);
}

int32_t ble_gatt_probe_get_remaining_sec(void)
{
    if (!running) return 0;
    int32_t elapsed = ble_gatt_probe_get_elapsed_sec();
    int32_t remaining = (int32_t)cfg.timeout_sec - elapsed;
    return remaining > 0 ? remaining : 0;
}

bool ble_gatt_probe_was_timeout(void)
{
    return timeout_fired;
}

cJSON *ble_gatt_probe_get_status_json(void)
{
    cJSON *root = cJSON_CreateObject();
    if (!root) return NULL;

    cJSON_AddBoolToObject(root, "running", running);
    cJSON_AddStringToObject(root, "target",
                            cfg.target_addr[0] ? cfg.target_addr : "");
    cJSON_AddNumberToObject(root, "timeout_sec", cfg.timeout_sec);
    cJSON_AddNumberToObject(root, "probe_count",    probe_count);
    cJSON_AddNumberToObject(root, "services_found",  services_found);
    cJSON_AddNumberToObject(root, "chars_found",     chars_found);
    cJSON_AddNumberToObject(root, "read_count",      read_count);
    cJSON_AddNumberToObject(root, "write_count",     write_count);
    cJSON_AddNumberToObject(root, "subscribe_count", subscribe_count);
    cJSON_AddNumberToObject(root, "fail_count",      fail_count);
    cJSON_AddNumberToObject(root, "elapsed_sec",
                            ble_gatt_probe_get_elapsed_sec());
    cJSON_AddNumberToObject(root, "remaining_sec",
                            ble_gatt_probe_get_remaining_sec());
    cJSON_AddBoolToObject(root, "timeout", timeout_fired);
    cJSON_AddStringToObject(root, "addr_type", addr_type_str(cfg.addr_type));
    cJSON_AddBoolToObject(root, "probe_read",      cfg.probe_read);
    cJSON_AddBoolToObject(root, "probe_write",     cfg.probe_write);
    cJSON_AddBoolToObject(root, "probe_subscribe", cfg.probe_subscribe);
    cJSON_AddBoolToObject(root, "rotate_mac",      cfg.rotate_own_mac);

    return root;
}
