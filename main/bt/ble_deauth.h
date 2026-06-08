/*
 * ble_deauth.h - BLE Deauth Attack Module
 *
 * Force-disconnects target's active BLE connections using a
 * three-phase attack strategy:
 *
 * Phase 1 (Direct Connect):
 *   Target is advertising → connect (kicks off phone), send hostile
 *   connection parameter updates, terminate with varied error codes.
 *
 * Phase 2 (WiFi RF Jam):
 *   Target is NOT advertising (already connected to phone) → use
 *   WiFi 802.11 raw transmission on channels 1/6/11 to create RF
 *   interference that overlaps BLE data channels.  This corrupts
 *   BLE packets between phone and target → supervision timeout →
 *   connection drops.  Then Phase 1 takes over.
 *
 * Phase 3 (Address Spoof):
 *   After jamming, advertise as the target device to capture the
 *   phone's reconnection attempt, then deauth again.
 *
 * Features:
 *   - Configurable target address, timeout, phase thresholds
 *   - Auto-switching address type on status 13 errors
 *   - Optional own-MAC rotation per attempt
 *   - Mutex + volatile + esp_timer timeout (consistent module pattern)
 *   - Full status getter set for web dashboard integration
 */

#ifndef BLE_DEAUTH_H
#define BLE_DEAUTH_H

#include <stdbool.h>
#include <stdint.h>
#include "cJSON.h"

/* ------------------------------------------------------------------ */
/*  Address type preference                                            */
/* ------------------------------------------------------------------ */

typedef enum {
    BLE_DEAUTH_ADDR_PUBLIC = 0,  /* Use public address only             */
    BLE_DEAUTH_ADDR_RANDOM = 1,  /* Use random static address only      */
    BLE_DEAUTH_ADDR_AUTO   = 2,  /* Start PUBLIC, flip to RANDOM on     */
                                   /* status 13 (wrong addr type)         */
} ble_deauth_addr_type_t;

/* ------------------------------------------------------------------ */
/*  Configuration (passed to ble_deauth_start_config)                  */
/* ------------------------------------------------------------------ */

typedef struct {
    char target_addr[32];                  /* "AA:BB:CC:DD:EE:FF"        */
    uint32_t timeout_sec;                  /* auto-stop (default 300)     */
    uint32_t connect_timeout_ms;           /* GAP connect timeout (3000)  */
    uint32_t jam_threshold;                /* status-13 before Phase 2    */
                                           /* (default 3)                 */
    uint32_t wifi_jam_rounds;              /* WiFi jam sweep rounds       */
                                           /* (default 3)                 */
    uint32_t spoof_duration_sec;           /* Phase 3 spoof time (5s)     */
    uint32_t post_disconnect_ms;           /* Delay after deauth (200)    */
    uint32_t fail_backoff_ms;              /* Max backoff on fail (2000)  */
    ble_deauth_addr_type_t addr_type;      /* Address type strategy       */
    bool rotate_own_mac;                   /* New random MAC per attempt  */
                                           /* (default true)              */
} ble_deauth_config_t;

/* ------------------------------------------------------------------ */
/*  Lifecycle                                                          */
/* ------------------------------------------------------------------ */

/** One-time init — call from app_main or module setup. */
void ble_deauth_init(void);

/** Start with defaults (backward compatible). */
void ble_deauth_start(const char *target_addr);

/** Start with full config. */
void ble_deauth_start_config(const ble_deauth_config_t *cfg);

/** Stop the attack and clean up. */
void ble_deauth_stop(void);

/* ------------------------------------------------------------------ */
/*  Status getters  (safe to call from any task / HTTP handler)        */
/* ------------------------------------------------------------------ */

bool     ble_deauth_is_running(void);
uint32_t ble_deauth_get_connect_count(void);
uint32_t ble_deauth_get_deauth_count(void);
uint32_t ble_deauth_get_jam_count(void);
uint32_t ble_deauth_get_spoof_count(void);
uint32_t ble_deauth_get_fail_count(void);
int32_t  ble_deauth_get_current_phase(void);
int32_t  ble_deauth_get_elapsed_sec(void);
int32_t  ble_deauth_get_remaining_sec(void);
bool     ble_deauth_was_timeout(void);

/** Returns a new cJSON object — caller must delete. */
cJSON   *ble_deauth_get_status_json(void);

#endif /* BLE_DEAUTH_H */
