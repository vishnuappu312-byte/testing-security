/*
 * ble_l2cap_flood.h - BLE L2CAP Flood Attack Module
 *
 * Connects to a target BLE device and rapidly sends L2CAP signaling
 * commands (MTU exchange requests, connection parameter updates) to
 * overwhelm the target's L2CAP processing queue.  After the signaling
 * burst, the connection is terminated and the cycle repeats.
 *
 * Attack flow per cycle:
 *   1. GAP connect to target
 *   2. Burst of L2CAP signaling:
 *      - ble_att_mtu_exchange()  (MTU negotiation request)
 *      - ble_gap_conn_param_update() with varying params
 *   3. GAP terminate
 *   4. Repeat
 *
 * Features:
 *   - Configurable target address, timeout, burst count, intervals
 *   - Auto-switching address type on status 13 errors
 *   - Optional own-MAC rotation per attempt
 *   - Async flow: no vTaskDelay in GAP callback
 *   - Mutex + volatile + esp_timer timeout (consistent module pattern)
 *   - Full status getter set for web dashboard integration
 */

#ifndef BLE_L2CAP_FLOOD_H
#define BLE_L2CAP_FLOOD_H

#include <stdbool.h>
#include <stdint.h>
#include "cJSON.h"

/* ------------------------------------------------------------------ */
/*  Address type preference                                            */
/* ------------------------------------------------------------------ */

typedef enum {
    BLE_L2CAP_ADDR_PUBLIC = 0,  /* Use public address only             */
    BLE_L2CAP_ADDR_RANDOM = 1,  /* Use random static address only      */
    BLE_L2CAP_ADDR_AUTO   = 2,  /* Start PUBLIC, flip to RANDOM on     */
                                  /* status 13 (wrong addr type)         */
} ble_l2cap_flood_addr_type_t;

/* ------------------------------------------------------------------ */
/*  Configuration (passed to ble_l2cap_flood_start_config)             */
/* ------------------------------------------------------------------ */

typedef struct {
    char target_addr[32];                  /* "AA:BB:CC:DD:EE:FF"        */
    uint32_t timeout_sec;                  /* auto-stop (default 300)     */
    uint32_t connect_timeout_ms;           /* GAP connect timeout (5000)  */
    uint32_t signal_burst_count;           /* L2CAP signals per connect   */
                                           /* (default 50)                */
    uint32_t signal_interval_ms;           /* delay between signals       */
                                           /* (default 10)                */
    uint32_t post_disconnect_ms;           /* delay after disconnect      */
                                           /* (default 500)               */
    uint32_t fail_backoff_ms;              /* backoff after failed        */
                                           /* connect (default 2000)      */
    ble_l2cap_flood_addr_type_t addr_type; /* addr type strategy          */
    bool rotate_own_mac;                   /* new random MAC per attempt  */
                                           /* (default true)              */
} ble_l2cap_flood_config_t;

/* ------------------------------------------------------------------ */
/*  Lifecycle                                                          */
/* ------------------------------------------------------------------ */

/** One-time init — call from app_main or module setup. */
void ble_l2cap_flood_init(void);

/** Start with defaults (backward compatible). */
void ble_l2cap_flood_start(const char *target_addr);

/** Start with full config. */
void ble_l2cap_flood_start_config(const ble_l2cap_flood_config_t *cfg);

/** Stop the flood and clean up. */
void ble_l2cap_flood_stop(void);

/* ------------------------------------------------------------------ */
/*  Status getters  (safe to call from any task / HTTP handler)        */
/* ------------------------------------------------------------------ */

bool     ble_l2cap_flood_is_running(void);
uint32_t ble_l2cap_flood_get_attempt_count(void);
uint32_t ble_l2cap_flood_get_success_count(void);
uint32_t ble_l2cap_flood_get_fail_count(void);
uint32_t ble_l2cap_flood_get_signal_count(void);
int32_t  ble_l2cap_flood_get_elapsed_sec(void);
int32_t  ble_l2cap_flood_get_remaining_sec(void);
bool     ble_l2cap_flood_was_timeout(void);

/** Returns a new cJSON object — caller must delete. */
cJSON   *ble_l2cap_flood_get_status_json(void);

#endif /* BLE_L2CAP_FLOOD_H */
