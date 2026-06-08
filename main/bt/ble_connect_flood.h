/*
 * ble_connect_flood.h - BLE Connect Flood Attack Module
 *
 * Rapidly creates and drops BLE connections to a target device,
 * exhausting its limited connection slots so that no legitimate
 * device can connect (denial of service).
 *
 * Features:
 *   - Configurable target address, timeout, intervals
 *   - Auto-switching address type on status 13 errors
 *   - Optional own-MAC rotation per attempt
 *   - Async flow: no vTaskDelay in GAP callback
 *   - Mutex + volatile + esp_timer timeout (consistent module pattern)
 *   - Full status getter set for web dashboard integration
 */

#ifndef BLE_CONNECT_FLOOD_H
#define BLE_CONNECT_FLOOD_H

#include <stdbool.h>
#include <stdint.h>
#include "cJSON.h"

/* ------------------------------------------------------------------ */
/*  Address type preference                                            */
/* ------------------------------------------------------------------ */

typedef enum {
    BLE_CF_ADDR_PUBLIC = 0,   /* Use public address only             */
    BLE_CF_ADDR_RANDOM = 1,   /* Use random static address only      */
    BLE_CF_ADDR_AUTO   = 2,   /* Start PUBLIC, flip to RANDOM on     */
                               /* status 13 (wrong addr type)         */
} ble_connect_flood_addr_type_t;

/* ------------------------------------------------------------------ */
/*  Configuration (passed to ble_connect_flood_start_config)           */
/* ------------------------------------------------------------------ */

typedef struct {
    char target_addr[32];                  /* "AA:BB:CC:DD:EE:FF"        */
    uint32_t timeout_sec;                  /* auto-stop (default 300)     */
    uint32_t connect_interval_ms;          /* base delay between attempts */
                                           /* (default 1500)              */
    uint32_t success_cooldown_ms;          /* cooldown after successful   */
                                           /* connect+disconnect (5000)   */
    uint32_t fail_backoff_ms;              /* backoff after failed        */
                                           /* connect (default 2000)      */
    ble_connect_flood_addr_type_t addr_type;  /* addr type strategy       */
    bool rotate_own_mac;                   /* new random MAC per attempt  */
                                           /* (default true)              */
} ble_connect_flood_config_t;

/* ------------------------------------------------------------------ */
/*  Lifecycle                                                          */
/* ------------------------------------------------------------------ */

/** One-time init — call from app_main or module setup. */
void ble_connect_flood_init(void);

/** Start with defaults (backward compatible). */
void ble_connect_flood_start(const char *target_addr);

/** Start with full config. */
void ble_connect_flood_start_config(const ble_connect_flood_config_t *cfg);

/** Stop the flood and clean up. */
void ble_connect_flood_stop(void);

/* ------------------------------------------------------------------ */
/*  Status getters  (safe to call from any task / HTTP handler)        */
/* ------------------------------------------------------------------ */

bool     ble_connect_flood_is_running(void);
uint32_t ble_connect_flood_get_attempt_count(void);
uint32_t ble_connect_flood_get_success_count(void);
uint32_t ble_connect_flood_get_fail_count(void);
int32_t  ble_connect_flood_get_elapsed_sec(void);
int32_t  ble_connect_flood_get_remaining_sec(void);
bool     ble_connect_flood_was_timeout(void);

/** Returns a new cJSON object — caller must delete. */
cJSON   *ble_connect_flood_get_status_json(void);

#endif /* BLE_CONNECT_FLOOD_H */
