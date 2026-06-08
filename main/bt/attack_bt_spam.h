/**
 * @file attack_bt_spam.h
 * @brief BLE Spam Attack — header
 *
 * Floods nearby BLE scanners with fake advertising packets.
 * Supports Apple Audio/Setup, Samsung Buds, Google Fast Pair,
 * and a Random Mix mode that cycles through all families.
 *
 * Thread safety:  mutex-protected config/stats, volatile running flag,
 * optional auto-stop timeout via esp_timer.
 */

#ifndef ATTACK_BT_SPAM_H
#define ATTACK_BT_SPAM_H

#include <stdint.h>
#include <stdbool.h>
#include "esp_err.h"
#include "cJSON.h"
#ifdef __cplusplus
extern "C" {
#endif

/* ================================================================== */
/*  Configuration                                                      */
/* ================================================================== */

/**
 * BLE spam configuration — passed to attack_bt_spam_start().
 *
 * device_type:   Selects the advertising profile family.
 *                1-8   = Apple Audio (AirPods / AirTag popups)
 *                9-13  = Apple Setup (pairing screen popups)
 *                14-19 = Samsung Buds (Galaxy Buds Fast Pair)
 *                20-24 = Google Fast Pair (Android notifications)
 *                25    = Random Mix (cycles through all)
 *
 * delay_ms:      Extra idle time between advertising bursts (0-2000 ms).
 *                Increase to reduce packet rate / device load.
 *
 * timeout_sec:   Auto-stop timeout in seconds.
 *                0 = use default (300s / 5 minutes).
 *                -1 = no timeout (run until explicitly stopped).
 */
typedef struct {
    int device_type;
    int delay_ms;
    int timeout_sec;
} bt_spam_config_t;

/* ================================================================== */
/*  Lifecycle                                                          */
/* ================================================================== */

/**
 * One-time initialisation — creates mutex, timer, ensures NimBLE is up.
 * Call once from app_main() before any start/stop calls.
 * Idempotent — safe to call multiple times.
 */
void attack_bt_spam_init(void);

/**
 * Start BLE spam advertising with the given configuration.
 * Spawns a FreeRTOS task that runs until stopped or timed out.
 *
 * @param c  Pointer to configuration.  Contents are copied internally;
 *           caller may free/reuse the struct after this returns.
 */
void attack_bt_spam_start(bt_spam_config_t *c);

/**
 * Stop any running BLE spam operation.
 * Blocks until the task has exited (up to 3 s timeout), then
 * forces deletion if it hasn't.
 */
void attack_bt_spam_stop(void);

/* ================================================================== */
/*  Status                                                             */
/* ================================================================== */

/** Returns true if a spam task is currently running. */
bool attack_bt_spam_is_running(void);

/** Total advertising packets sent since the last start. */
uint32_t attack_bt_spam_get_packet_count(void);

/** Seconds elapsed since the current run started.  0 if not running. */
int attack_bt_spam_get_elapsed_sec(void);

/** Seconds remaining until auto-stop timeout.  0 if not running or no timeout. */
int attack_bt_spam_get_remaining_sec(void);

/** Returns true if the last stop was caused by the auto-stop timeout. */
bool attack_bt_spam_was_timeout(void);

/** Human-readable name of the active device type profile. */
const char *attack_bt_spam_get_device_type_name(void);

/**
 * Build a JSON object with the full current status.
 * Keys: running, packet_count, device_type, device_type_name,
 *       delay_ms, timeout_sec, was_timeout,
 *       elapsed_sec (if running), remaining_sec (if running).
 *
 * Caller must delete the returned cJSON object with cJSON_Delete().
 */
cJSON *attack_bt_spam_get_status_json(void);

/* ================================================================== */
/*  BLE Scan                                                           */
/* ================================================================== */

/**
 * Perform a BLE active scan for the given duration.
 * Returns a cJSON array of objects, each with:
 *   "addr"     — MAC address string "xx:xx:xx:xx:xx:xx"
 *   "rssi"     — Signal strength (int)
 *   "name"     — Device name (may be empty)
 *   "adv_data" — Raw advertising data as hex string (for clone feature)
 *
 * Caller must delete the returned cJSON object with cJSON_Delete().
 */
cJSON *attack_bt_scan(int timeout_ms);

#ifdef __cplusplus
}
#endif

#endif /* ATTACK_BT_SPAM_H */