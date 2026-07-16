/*
 * ble_spoof.c - BLE Name Spoof & Device Clone Implementation
 *
 * Two operational modes:
 *
 *   NAME-SPOOF  (legacy) - Rotate through comma-separated BLE device names.
 *   Each cycle changes the advertised name and random MAC so that nearby
 *   scanners see a sequence of different devices.
 *
 *   CLONE       (new)    - Clone a scanned device's full advertising payload
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
 * Thread safety:
 *   - `running` is volatile bool: set from stop()/timer, read in task loop
 *   - `packet_count` is volatile uint32_t: incremented in task, read from
 *     webserver context (atomic on 32-bit Xtensa)
 *   - `current_names` and `clone_profile` protected by mutex
 *   - `timeout_fired`, `last_error` are volatile for cross-task visibility
 *
 * Dependencies:
 *   - ble_common.h  (nimble_port_init + own_addr_type helper)
 *   - NimBLE stack  (host + controller)
 *   - FreeRTOS
 *   - cJSON
 *   - esp_timer
 */

#include "ble_spoof.h"
#include "esp_log.h"
#include "esp_timer.h"
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

static const char *TAG = "ble_spoof";

#define MAX_NAMES          5       /* comma-separated names to rotate  */
#define MAX_NAME_LEN       63      /* per-name buffer (before trim)    */
#define ADV_MAX_LEN        31      /* BLE adv payload max              */
#define TASK_STACK_SIZE    4096
#define TASK_PRIORITY      5
#define ADV_DURATION_MS    200     /* per-cycle broadcast window       */
#define DEFAULT_ADV_INT_MS 100
#define DEFAULT_CYCLE_MS   500
#define DEFAULT_TIMEOUT_S  300
#define YIELD_DELAY_MS     100     /* yield when controller is busy    */
#define STOP_TIMEOUT_MS    5000    /* max wait for task to exit        */

/* ================================================================== */
/*  Module state                                                       */
/* ================================================================== */

static volatile bool          running          = false;
static ble_spoof_mode_t       active_mode      = BLE_SPOOF_MODE_NAME;
static TaskHandle_t           task_handle      = NULL;
static SemaphoreHandle_t      mutex            = NULL;
static SemaphoreHandle_t      task_exit_sem    = NULL;
static esp_timer_handle_t     timeout_timer    = NULL;

/* Name-spoof state (protected by mutex) */
static char  current_names[128] = {0};

/* Clone state (protected by mutex) */
static ble_spoof_clone_profile_t clone_profile = {0};

/* Timing & counters */
static volatile uint32_t    packet_count       = 0;
static int64_t              start_time_us      = 0;
static int64_t              stop_time_us       = 0;
static int                  config_timeout_sec = 0;
static int                  config_adv_int_ms  = 0;
static int                  config_cycle_ms    = 0;
static volatile bool        timeout_fired      = false;
static volatile int         last_error         = 0;

/* ================================================================== */
/*  Forward declarations                                               */
/* ================================================================== */

static void timeout_timer_cb(void *arg);
static void spoof_task(void *arg);
static void set_random_mac(void);
static int  adv_event_cb(struct ble_gap_event *event, void *arg);
static void build_name_adv_payload(const char *name, uint8_t *out, size_t *out_len);
static void build_clone_adv_payload(const ble_spoof_clone_profile_t *prof,
                                     uint8_t *out, size_t *out_len);
static int  count_names_in_str(const char *s);

/* ================================================================== */
/*  Timeout timer                                                      */
/* ================================================================== */

static void timeout_timer_cb(void *arg) {
    (void)arg;
    timeout_fired = true;
    running       = false;
    ESP_LOGW(TAG, "Auto-stop timeout reached (%d sec)", config_timeout_sec);
}

/**
 * Create and start a one-shot timeout timer.
 * Pass timeout_sec <= 0 to skip (no timer created).
 * If a previous timer exists, it is stopped and deleted first.
 */
static void start_timeout_timer(int timeout_sec) {
    /* Clean up any previous timer */
    if (timeout_timer != NULL) {
        esp_timer_stop(timeout_timer);
        esp_timer_delete(timeout_timer);
        timeout_timer = NULL;
    }
    if (timeout_sec > 0) {
        const esp_timer_create_args_t args = {
            .callback = timeout_timer_cb,
            .name     = "ble_spoof_timeout",
        };
        esp_timer_create(&args, &timeout_timer);
        esp_timer_start_once(timeout_timer, (int64_t)timeout_sec * 1000000LL);
    }
}

/** Stop and delete the timeout timer if it exists. */
static void stop_timeout_timer(void) {
    if (timeout_timer != NULL) {
        esp_timer_stop(timeout_timer);
        esp_timer_delete(timeout_timer);
        timeout_timer = NULL;
    }
}

/* ================================================================== */
/*  Utility                                                            */
/* ================================================================== */

/** Count comma-separated names in a string (max MAX_NAMES). */
static int count_names_in_str(const char *s) {
    if (s == NULL || s[0] == '\0') return 0;
    int count = 1;
    for (const char *p = s; *p; p++) {
        if (*p == ',') count++;
    }
    return (count > MAX_NAMES) ? MAX_NAMES : count;
}

/* ================================================================== */
/*  Random MAC rotation                                                */
/* ================================================================== */

static void set_random_mac(void) {
    uint8_t mac[6];
    esp_fill_random(mac, 6);
    /* Top two bits must be 1 for random static address
     * (BT spec 4.2 Vol 6 Part B 1.3.2.1) */
    mac[5] |= 0xC0;
    int rc = ble_hs_id_set_rnd(mac);
    if (rc != 0) {
        ESP_LOGW(TAG, "set_random_mac failed: %d", rc);
        last_error = rc;
    }
}

/* ================================================================== */
/*  GAP event callback                                                 */
/* ================================================================== */

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

/* ================================================================== */
/*  Build advertising payloads                                         */
/* ================================================================== */

/**
 * Build a minimal adv payload for name-spoof mode.
 * [Flags] [Complete Local Name]
 *
 * Total must not exceed 31 bytes.
 */
static void build_name_adv_payload(const char *name, uint8_t *out, size_t *out_len) {
    size_t n = name ? strlen(name) : 0;
    /* Flags(3) + name len+type(2) = 5 overhead → max name = 26 */
    if (n > 26) n = 26;
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
 * Fields are added in priority order.  If the 31-byte limit is reached,
 * less important fields (name is last) are silently dropped.  Service
 * UUIDs take priority because phones use them for auto-connect matching.
 *
 * If the profile has raw_adv data, it is used directly (highest fidelity).
 */
static void build_clone_adv_payload(const ble_spoof_clone_profile_t *prof,
                                     uint8_t *out, size_t *out_len) {
    size_t idx = 0;

    /* ---- Use raw payload directly if available ---- */
    if (prof->raw_adv_len > 0 && prof->raw_adv_len <= ADV_MAX_LEN) {
        memcpy(out, prof->raw_adv, prof->raw_adv_len);
        *out_len = prof->raw_adv_len;
        return;
    }

    /* ---- Reconstruct from parsed fields ---- */

    /* Flags (3 bytes) */
    if (idx + 3 <= ADV_MAX_LEN) {
        out[idx++] = 2;
        out[idx++] = 0x01;
        out[idx++] = prof->flags;
    }

    /* 16-bit Service UUID list */
    if (prof->svc_uuids_16_count > 0) {
        size_t field_len = 1 + (prof->svc_uuids_16_count * 2);
        if (idx + 1 + field_len <= ADV_MAX_LEN) {
            out[idx++] = (uint8_t)field_len;
            /* 0x02 = Incomplete, 0x03 = Complete 16-bit UUID list */
            out[idx++] = (prof->svc_uuids_16_count > 1) ? 0x03 : 0x02;
            for (int i = 0; i < prof->svc_uuids_16_count; i++) {
                out[idx++] = prof->svc_uuids_16[i][0];
                out[idx++] = prof->svc_uuids_16[i][1];
            }
        }
    }

    /* 128-bit Service UUID (only first - it takes 17 bytes) */
    if (prof->svc_uuids_128_count > 0 && idx + 17 <= ADV_MAX_LEN) {
        out[idx++] = 16 + 1;
        out[idx++] = 0x06;  /* Incomplete List of 128-bit UUIDs */
        memcpy(&out[idx], prof->svc_uuids_128[0], 16);
        idx += 16;
    }

    /* Appearance (4 bytes) */
    if (prof->has_appearance && idx + 4 <= ADV_MAX_LEN) {
        out[idx++] = 3;
        out[idx++] = 0x19;  /* Appearance */
        out[idx++] = (uint8_t)(prof->appearance & 0xFF);
        out[idx++] = (uint8_t)((prof->appearance >> 8) & 0xFF);
    }

    /* TX Power Level (3 bytes) */
    if (prof->has_tx_power && idx + 3 <= ADV_MAX_LEN) {
        out[idx++] = 2;
        out[idx++] = 0x0A;  /* TX Power Level */
        out[idx++] = (uint8_t)prof->tx_power;
    }

    /* Manufacturer Specific Data */
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

    /* Local Name (lowest priority, added last) */
    size_t name_len = strlen(prof->name);
    if (name_len > 0) {
        size_t remaining = ADV_MAX_LEN - idx;
        if (remaining >= 3) {  /* need at least: len(1) + type(1) + 1 char */
            size_t max_name = remaining - 2;
            if (name_len > max_name) {
                /* Use Shortened Local Name if full name doesn't fit */
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

/* ================================================================== */
/*  Main spoof/clone task                                              */
/* ================================================================== */

static void spoof_task(void *arg) {
    (void)arg;

    /* ---- Compute NimBLE advertising interval from config ---- */
    int adv_int_ms = (config_adv_int_ms > 0) ? config_adv_int_ms : DEFAULT_ADV_INT_MS;
    int cycle_ms   = (config_cycle_ms > 0)   ? config_cycle_ms   : DEFAULT_CYCLE_MS;

    /* NimBLE interval units: 1 unit = 0.625 ms */
    uint16_t itvl_min = (uint16_t)(adv_int_ms * 8 / 5);   /* ms * 1000/625 */
    uint16_t itvl_max = itvl_min + 8;                       /* small randomization */
    if (itvl_min < 0x0020) itvl_min = 0x0020;              /* BLE spec minimum */
    if (itvl_max > 0x4000) itvl_max = 0x4000;              /* BLE spec maximum */

    /* ================================================================ */
    /*  NAME-SPOOF MODE                                                 */
    /* ================================================================ */
    if (active_mode == BLE_SPOOF_MODE_NAME) {
        char names[MAX_NAMES][MAX_NAME_LEN + 1];
        int  name_count = 0;
        int  cur = 0;

        /* Parse comma-separated names under mutex */
        xSemaphoreTake(mutex, portMAX_DELAY);
        strncpy(names[0], current_names, MAX_NAME_LEN);
        names[0][MAX_NAME_LEN] = '\0';

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

        if (name_count <= 0 || names[0][0] == '\0') {
            ESP_LOGW(TAG, "No valid names provided, advertising flags only");
            name_count = 1;
        }

        ESP_LOGI(TAG, "NAME-SPOOF mode: %d name(s), interval=%dms, cycle=%dms, timeout=%ds",
                 name_count, adv_int_ms, cycle_ms,
                 config_timeout_sec > 0 ? config_timeout_sec : -1);

        while (running) {
            /* Yield to other BLE operations (scan / connect) */
            if (ble_gap_conn_active() || ble_gap_disc_active()) {
                vTaskDelay(pdMS_TO_TICKS(YIELD_DELAY_MS));
                continue;
            }
            if (ble_gap_adv_active()) {
                ble_gap_adv_stop();
                vTaskDelay(pdMS_TO_TICKS(20));
            }

            /* Rotate MAC each cycle for stealth */
            set_random_mac();
            vTaskDelay(pdMS_TO_TICKS(10));

            /* Pick next name */
            xSemaphoreTake(mutex, portMAX_DELAY);
            char sel[MAX_NAME_LEN + 1] = {0};
            strncpy(sel, names[cur % name_count], MAX_NAME_LEN);
            xSemaphoreGive(mutex);

            /* Build and set advertising data */
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

            /* Start advertising */
            struct ble_gap_adv_params adv_params = {0};
            adv_params.conn_mode = BLE_GAP_CONN_MODE_NON;
            adv_params.disc_mode = BLE_GAP_DISC_MODE_GEN;
            adv_params.itvl_min  = itvl_min;
            adv_params.itvl_max  = itvl_max;

            rc = ble_gap_adv_start(BLE_OWN_ADDR_RANDOM, NULL, ADV_DURATION_MS,
                                   &adv_params, adv_event_cb, NULL);
            if (rc) {
                ESP_LOGE(TAG, "adv_start failed: %d", rc);
                last_error = rc;
            } else {
                packet_count++;
                vTaskDelay(pdMS_TO_TICKS(ADV_DURATION_MS));
                if (ble_gap_adv_active()) ble_gap_adv_stop();
            }

            cur++;
            vTaskDelay(pdMS_TO_TICKS(cycle_ms));
        }

    /* ================================================================ */
    /*  CLONE MODE                                                      */
    /* ================================================================ */
    } else if (active_mode == BLE_SPOOF_MODE_CLONE) {
        ESP_LOGI(TAG, "CLONE mode: cloning '%s', interval=%dms, cycle=%dms, timeout=%ds",
                 clone_profile.name, adv_int_ms, cycle_ms,
                 config_timeout_sec > 0 ? config_timeout_sec : -1);

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

            /* Build clone payload */
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

            /* Start advertising */
            struct ble_gap_adv_params adv_params = {0};
            adv_params.conn_mode = BLE_GAP_CONN_MODE_NON;
            adv_params.disc_mode = BLE_GAP_DISC_MODE_GEN;
            adv_params.itvl_min  = itvl_min;
            adv_params.itvl_max  = itvl_max;

            rc = ble_gap_adv_start(BLE_OWN_ADDR_RANDOM, NULL, ADV_DURATION_MS,
                                   &adv_params, adv_event_cb, NULL);
            if (rc) {
                ESP_LOGE(TAG, "clone adv_start failed: %d", rc);
                last_error = rc;
            } else {
                packet_count++;
                vTaskDelay(pdMS_TO_TICKS(ADV_DURATION_MS));
                if (ble_gap_adv_active()) ble_gap_adv_stop();
            }

            vTaskDelay(pdMS_TO_TICKS(cycle_ms));
        }
    }

    /* ---- Task cleanup ---- */
    if (ble_gap_adv_active()) {
        ble_gap_adv_stop();
    }

    ESP_LOGI(TAG, "BLE spoof/clone task exiting (packets=%u)", packet_count);
    task_handle = NULL;
    if (task_exit_sem) {
        xSemaphoreGive(task_exit_sem);
    }
    vTaskDelete(NULL);
}

/* ================================================================== */
/*  Public API - init                                                  */
/* ================================================================== */

void ble_spoof_init(void) {
    if (mutex == NULL) {
        mutex = xSemaphoreCreateMutex();
    }
    if (task_exit_sem == NULL) {
        task_exit_sem = xSemaphoreCreateBinary();
    }

    /* Ensure NimBLE is initialized (idempotent) */
    ble_common_init();

    ESP_LOGI(TAG, "ble_spoof initialized (name-spoof + clone)");
}

/* ================================================================== */
/*  Public API - start with config                                     */
/* ================================================================== */

void ble_spoof_start_config(const ble_spoof_config_t *cfg) {
    if (running) {
        ESP_LOGW(TAG, "Already running, stop first");
        return;
    }
    if (cfg == NULL) {
        ESP_LOGE(TAG, "start_config: NULL config");
        return;
    }
    if (mutex == NULL) mutex = xSemaphoreCreateMutex();

    /* Clean up any previous timeout timer */
    stop_timeout_timer();

    /* Reset counters and state */
    packet_count       = 0;
    timeout_fired      = false;
    last_error         = 0;
    start_time_us      = esp_timer_get_time();
    stop_time_us       = 0;

    /* Store config (treat 0 as "use default") */
    active_mode        = cfg->mode;
    config_adv_int_ms  = (cfg->adv_interval_ms > 0) ? cfg->adv_interval_ms : DEFAULT_ADV_INT_MS;
    config_cycle_ms    = (cfg->cycle_delay_ms > 0)   ? cfg->cycle_delay_ms  : DEFAULT_CYCLE_MS;

    /* timeout: 0 = use default, -1 = no timeout, >0 = custom */
    if (cfg->timeout_sec == 0) {
        config_timeout_sec = DEFAULT_TIMEOUT_S;
    } else {
        config_timeout_sec = cfg->timeout_sec;
    }

    /* Mode-specific config */
    if (cfg->mode == BLE_SPOOF_MODE_NAME) {
        xSemaphoreTake(mutex, portMAX_DELAY);
        strncpy(current_names, cfg->names, sizeof(current_names) - 1);
        current_names[sizeof(current_names) - 1] = '\0';
        xSemaphoreGive(mutex);
    } else if (cfg->mode == BLE_SPOOF_MODE_CLONE) {
        xSemaphoreTake(mutex, portMAX_DELAY);
        memcpy(&clone_profile, &cfg->clone_profile, sizeof(clone_profile));
        xSemaphoreGive(mutex);
    }

    running = true;

    /* Clear any stale exit semaphore */
    if (task_exit_sem != NULL) {
        xSemaphoreTake(task_exit_sem, 0);
    }

    /* Start auto-stop timeout timer */
    start_timeout_timer(config_timeout_sec);

    /* Create the spoof/clone task */
    BaseType_t ret = xTaskCreate(spoof_task, "ble_spoof", TASK_STACK_SIZE,
                                  NULL, TASK_PRIORITY, &task_handle);
    if (ret != pdPASS) {
        ESP_LOGE(TAG, "Failed to create spoof task");
        running = false;
        stop_timeout_timer();
    } else {
        ESP_LOGI(TAG, "Started %s mode (timeout=%ds)",
                 cfg->mode == BLE_SPOOF_MODE_NAME ? "NAME-SPOOF" : "CLONE",
                 config_timeout_sec > 0 ? config_timeout_sec : -1);
    }
}

/* ================================================================== */
/*  Public API - backward-compat name spoof                            */
/* ================================================================== */

void ble_spoof_start(const char *name) {
    ble_spoof_config_t cfg = {0};
    cfg.mode = BLE_SPOOF_MODE_NAME;
    if (name) {
        strncpy(cfg.names, name, sizeof(cfg.names) - 1);
    }
    /* Uses default timeout, interval, and cycle delay */
    ble_spoof_start_config(&cfg);
}

/* ================================================================== */
/*  Public API - clone from profile                                    */
/* ================================================================== */

void ble_spoof_clone_start(const ble_spoof_clone_profile_t *profile) {
    if (profile == NULL) {
        ESP_LOGE(TAG, "clone_start: NULL profile");
        return;
    }
    ble_spoof_config_t cfg = {0};
    cfg.mode = BLE_SPOOF_MODE_CLONE;
    memcpy(&cfg.clone_profile, profile, sizeof(cfg.clone_profile));
    /* Uses default timeout, interval, and cycle delay */
    ble_spoof_start_config(&cfg);
}

/* ================================================================== */
/*  Public API - clone from raw adv data                               */
/* ================================================================== */

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

    /* Also store the raw data as highest-fidelity fallback */
    memcpy(profile.raw_adv, raw_adv, raw_len);
    profile.raw_adv_len = raw_len;

    ble_spoof_clone_start(&profile);
}

/* ================================================================== */
/*  Public API - stop                                                  */
/* ================================================================== */

void ble_spoof_stop(void) {
    bool was_running = running;
    running = false;

    /* Record stop time for elapsed calculation */
    if (stop_time_us == 0) {
        stop_time_us = esp_timer_get_time();
    }

    /* Stop and delete the timeout timer */
    stop_timeout_timer();

    /* Wait for the task to actually exit */
    if (was_running) {
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
        ESP_LOGI(TAG, "BLE spoof/clone stopped (packets=%u, elapsed=%ds)",
                 packet_count, ble_spoof_get_elapsed_sec());
    }
}

/* ================================================================== */
/*  Public API - status getters                                        */
/* ================================================================== */

bool ble_spoof_is_running(void) {
    return running;
}

ble_spoof_mode_t ble_spoof_get_mode(void) {
    return active_mode;
}

const char* ble_spoof_get_mode_name(void) {
    return (active_mode == BLE_SPOOF_MODE_CLONE) ? "clone" : "name";
}

uint32_t ble_spoof_get_packet_count(void) {
    return packet_count;
}

int ble_spoof_get_elapsed_sec(void) {
    if (start_time_us == 0) return 0;

    int64_t end;
    if (running) {
        end = esp_timer_get_time();
    } else if (stop_time_us > start_time_us) {
        end = stop_time_us;
    } else {
        end = esp_timer_get_time();
    }

    int sec = (int)((end - start_time_us) / 1000000);
    return (sec < 0) ? 0 : sec;
}

int ble_spoof_get_remaining_sec(void) {
    if (config_timeout_sec <= 0) return -1;  /* no timeout configured */
    int elapsed = ble_spoof_get_elapsed_sec();
    int rem = config_timeout_sec - elapsed;
    return (rem < 0) ? 0 : rem;
}

bool ble_spoof_was_timeout(void) {
    return timeout_fired;
}

int ble_spoof_last_error(void) {
    return last_error;
}

cJSON* ble_spoof_get_status_json(void) {
    cJSON *root = cJSON_CreateObject();
    if (root == NULL) return NULL;

    cJSON_AddBoolToObject(root,   "running",          running);
    cJSON_AddStringToObject(root, "mode",             ble_spoof_get_mode_name());
    cJSON_AddNumberToObject(root, "packets",          packet_count);
    cJSON_AddNumberToObject(root, "elapsed",          ble_spoof_get_elapsed_sec());
    cJSON_AddNumberToObject(root, "remaining",        ble_spoof_get_remaining_sec());
    cJSON_AddBoolToObject(root,   "timeout",          timeout_fired);
    cJSON_AddNumberToObject(root, "last_error",       last_error);
    cJSON_AddNumberToObject(root, "adv_interval_ms",  config_adv_int_ms);
    cJSON_AddNumberToObject(root, "cycle_delay_ms",   config_cycle_ms);

    if (active_mode == BLE_SPOOF_MODE_NAME) {
        xSemaphoreTake(mutex, portMAX_DELAY);
        cJSON_AddStringToObject(root, "device_name", current_names);
        cJSON_AddNumberToObject(root, "name_count",  count_names_in_str(current_names));
        xSemaphoreGive(mutex);
    } else {
        xSemaphoreTake(mutex, portMAX_DELAY);
        cJSON_AddStringToObject(root, "device_name", clone_profile.name);
        cJSON_AddNumberToObject(root, "name_count",  1);
        xSemaphoreGive(mutex);
    }

    return root;
}

/* ================================================================== */
/*  ADV PARSER - extract fields from raw BLE advertising data          */
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
            /* ---- Complete List of 16-bit UUIDs ---- */
            case 0x03: {
                int count = data_len / 2;
                if (count > BLE_SPOOF_MAX_SVC_UUIDS) count = BLE_SPOOF_MAX_SVC_UUIDS;
                for (int i = 0; i < count && out->svc_uuids_16_count < BLE_SPOOF_MAX_SVC_UUIDS; i++) {
                    out->svc_uuids_16[out->svc_uuids_16_count][0] = data[i * 2];
                    out->svc_uuids_16[out->svc_uuids_16_count][1] = data[i * 2 + 1];
                    out->svc_uuids_16_count++;
                }
                break;
            }

            /* ---- Incomplete List of 128-bit UUIDs ---- */
            case 0x06:
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
                /* Unknown AD type - skip */
                break;
        }

        pos += 1 + field_len;
    }

    return ESP_OK;
}

/* ================================================================== */
/*  ADV BUILDER - reconstruct payload from clone profile               */
/* ================================================================== */

esp_err_t ble_spoof_build_adv(const ble_spoof_clone_profile_t *profile,
                               uint8_t *out, size_t *out_len) {
    if (profile == NULL || out == NULL || out_len == NULL) {
        return ESP_FAIL;
    }
    build_clone_adv_payload(profile, out, out_len);
    return ESP_OK;
}
