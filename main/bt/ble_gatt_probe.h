/*
 * ble_gatt_probe.h - BLE GATT Probe Attack Module
 *
 * Connects to a target BLE device, performs full GATT service and
 * characteristic enumeration, then optionally reads, writes, and
 * subscribes to every discovered characteristic.  The cycle repeats
 * until the timeout expires or the attack is stopped.
 *
 * Attack flow per cycle:
 *   1. GAP connect to target
 *   2. Discover all primary services   (ble_gattc_disc_all_svcs)
 *   3. For each service, discover all characteristics (ble_gattc_disc_all_chrs)
 *   4. Read all readable characteristics        (ble_gattc_read)
 *   5. Write to all writable characteristics    (ble_gattc_write_no_rsp)
 *   6. Subscribe to all notifiable chars        (ble_gattc_notify)
 *   7. GAP terminate
 *   8. Repeat
 *
 * Features:
 *   - Configurable target address, timeout, probe options
 *   - Auto-switching address type on status 13 errors
 *   - Optional own-MAC rotation per connection
 *   - Async flow: no vTaskDelay in GAP/GATT callbacks
 *   - Mutex + volatile + esp_timer timeout (consistent module pattern)
 *   - Full status getter set for web dashboard integration
 */

#ifndef BLE_GATT_PROBE_H
#define BLE_GATT_PROBE_H

#include <stdbool.h>
#include <stdint.h>
#include "cJSON.h"

/* ------------------------------------------------------------------ */
/*  Address type preference                                            */
/* ------------------------------------------------------------------ */

typedef enum {
    BLE_GATT_PROBE_ADDR_PUBLIC = 0,  /* Use public address only             */
    BLE_GATT_PROBE_ADDR_RANDOM = 1,  /* Use random static address only      */
    BLE_GATT_PROBE_ADDR_AUTO   = 2,  /* Start PUBLIC, flip to RANDOM on     */
                                       /* status 13 (wrong addr type)         */
} gatt_probe_addr_type_t;

/* ------------------------------------------------------------------ */
/*  Configuration (passed to ble_gatt_probe_start_config)              */
/* ------------------------------------------------------------------ */

typedef struct {
    char target_addr[32];                  /* "AA:BB:CC:DD:EE:FF"        */
    uint32_t timeout_sec;                  /* auto-stop (default 300)     */
    uint32_t connect_timeout_ms;           /* GAP connect timeout (5000)  */
    bool probe_read;                       /* Read discovered chars       */
                                           /* (default true)              */
    bool probe_write;                      /* Write to writable chars     */
                                           /* (default false)             */
    bool probe_subscribe;                  /* Subscribe to notify chars   */
                                           /* (default true)              */
    uint32_t probe_interval_ms;            /* Delay between char probes   */
                                           /* (default 50)                */
    uint32_t post_disconnect_ms;           /* Delay after disconnect      */
                                           /* (default 500)               */
    uint32_t fail_backoff_ms;              /* Backoff after failed        */
                                           /* connect (default 2000)      */
    gatt_probe_addr_type_t addr_type;      /* Address type strategy       */
    bool rotate_own_mac;                   /* New random MAC per attempt  */
                                           /* (default true)              */
} gatt_probe_config_t;

/* ------------------------------------------------------------------ */
/*  Lifecycle                                                          */
/* ------------------------------------------------------------------ */

/** One-time init — call from app_main or module setup. */
void ble_gatt_probe_init(void);

/** Start with defaults (backward compatible). */
void ble_gatt_probe_start(const char *target_addr);

/** Start with full config. */
void ble_gatt_probe_start_config(const gatt_probe_config_t *cfg);

/** Stop the probe and clean up. */
void ble_gatt_probe_stop(void);

/* ------------------------------------------------------------------ */
/*  Status getters  (safe to call from any task / HTTP handler)        */
/* ------------------------------------------------------------------ */

bool     ble_gatt_probe_is_running(void);
uint32_t ble_gatt_probe_get_probe_count(void);
uint32_t ble_gatt_probe_get_services_found(void);
uint32_t ble_gatt_probe_get_chars_found(void);
uint32_t ble_gatt_probe_get_read_count(void);
uint32_t ble_gatt_probe_get_write_count(void);
uint32_t ble_gatt_probe_get_subscribe_count(void);
uint32_t ble_gatt_probe_get_fail_count(void);
int32_t  ble_gatt_probe_get_elapsed_sec(void);
int32_t  ble_gatt_probe_get_remaining_sec(void);
bool     ble_gatt_probe_was_timeout(void);

/** Returns a new cJSON object — caller must delete. */
cJSON   *ble_gatt_probe_get_status_json(void);

#endif /* BLE_GATT_PROBE_H */
