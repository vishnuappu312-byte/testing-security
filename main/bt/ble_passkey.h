/*
 * ble_passkey.h - BLE Passkey Capture Module
 *
 * Captures the BLE pairing passkey when a phone reconnects to a
 * spoofed device after the original connection was broken by BLE Deauth.
 *
 * Attack flow:
 *   1. BLE Deauth breaks phone ↔ device connection
 *   2. This module advertises as the target device
 *   3. Phone auto-reconnects to our ESP32-S3
 *   4. During SMP pairing, the passkey is captured
 *   5. After capture, disconnect and restore original SM config
 *
 * Supported pairing methods:
 *   - Numeric Comparison: 6-digit number shown on both devices
 *   - Passkey Display:    We display a random 6-digit passkey
 *   - Passkey Input:      We submit 000000 as the passkey
 *   - Just Works:         No passkey (auto-accept)
 *
 * Features:
 *   - Configurable target address, timeout, device name
 *   - SMP config save/restore (doesn't affect other modules)
 *   - esp_timer one-shot timeout (default 60s)
 *   - Mutex + volatile + consistent module pattern
 *   - Full status getter set for web dashboard integration
 */

#ifndef BLE_PASSKEY_H
#define BLE_PASSKEY_H

#include <stdbool.h>
#include <stdint.h>
#include "cJSON.h"

/* ------------------------------------------------------------------ */
/*  Configuration (passed to ble_passkey_start_config)                 */
/* ------------------------------------------------------------------ */

typedef struct {
    char target_addr[32];           /* "AA:BB:CC:DD:EE:FF"             */
    uint32_t timeout_sec;           /* auto-stop (default 60)          */
    uint32_t adv_duration_sec;      /* how long to spoof-advertise     */
                                    /* (default 60)                    */
    bool auto_disconnect;           /* disconnect after capture         */
                                    /* (default true)                   */
} ble_passkey_config_t;

/* ------------------------------------------------------------------ */
/*  Lifecycle                                                          */
/* ------------------------------------------------------------------ */

/** One-time init — call from app_main or module setup. */
void ble_passkey_init(void);

/** Start with defaults (backward compatible). */
void ble_passkey_start(const char *target_addr);

/** Start with full config. */
void ble_passkey_start_config(const ble_passkey_config_t *cfg);

/** Stop the capture and clean up. */
void ble_passkey_stop(void);

/* ------------------------------------------------------------------ */
/*  Status getters  (safe to call from any task / HTTP handler)        */
/* ------------------------------------------------------------------ */

bool     ble_passkey_is_running(void);
int32_t  ble_passkey_get_elapsed_sec(void);
int32_t  ble_passkey_get_remaining_sec(void);
bool     ble_passkey_was_timeout(void);
bool     ble_passkey_is_pairing_complete(void);

/** Get the captured pairing method string.
 *  Returns: "none", "numeric_comparison", "passkey_display",
 *           "passkey_input", "just_works", "oob", "failed", "timeout"
 */
const char *ble_passkey_get_method(void);

/** Get the captured passkey string (e.g. "000482").
 *  Empty string if not yet captured.
 */
const char *ble_passkey_get_passkey(void);

/** Returns a new cJSON object — caller must delete. */
cJSON   *ble_passkey_get_status_json(void);

#endif /* BLE_PASSKEY_H */
