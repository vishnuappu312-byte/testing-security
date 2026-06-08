/*
 * ble_takeover.h - BLE Device Takeover Module
 *
 * After BLE Deauth + Passkey Capture, this module connects to the
 * REAL target device, enumerates all GATT services/characteristics,
 * enables notifications, and allows reading/writing values.
 *
 * Attack flow:
 *   1. Connect to target device (replaces the phone's connection)
 *   2. Discover all primary services and characteristics
 *   3. Auto-enable notifications on all N/I characteristics
 *   4. Maintain connection — receive notifications, read/write values
 *   5. Optionally trigger re-pairing for passkey capture
 *
 * Notification flow:
 *   Phone App --WRITE-->  Device (control commands)
 *   Phone App <--NOTIFY-- Device (automatic status updates)
 *
 * This module replaces the phone:
 *   ESP32   --WRITE-->  Device (send control commands)
 *   ESP32   <--NOTIFY-- Device (receive automatic updates)
 *
 * Features:
 *   - Configurable target address, timeout, connection params
 *   - Auto-switching address type on status 13 errors
 *   - Optional own-MAC rotation
 *   - Full GATT enumeration (services + characteristics)
 *   - Auto-enable notifications/indications
 *   - Interactive read/write operations while connected
 *   - Notification ring buffer with timestamp
 *   - SMP config save/restore (doesn't affect other modules)
 *   - esp_timer one-shot timeout (default 300s)
 *   - Mutex + volatile + consistent module pattern
 *   - Full status getter set for web dashboard integration
 */

#ifndef BLE_TAKEOVER_H
#define BLE_TAKEOVER_H

#include <stdbool.h>
#include <stdint.h>
#include "cJSON.h"

/* ------------------------------------------------------------------ */
/*  Address type preference                                            */
/* ------------------------------------------------------------------ */

typedef enum {
    BLE_TAKEOVER_ADDR_PUBLIC = 0,  /* Use public address only             */
    BLE_TAKEOVER_ADDR_RANDOM = 1,  /* Use random static address only      */
    BLE_TAKEOVER_ADDR_AUTO   = 2,  /* Start PUBLIC, flip to RANDOM on     */
                                    /* status 13 (wrong addr type)         */
} takeover_addr_type_t;

/* ------------------------------------------------------------------ */
/*  Configuration (passed to ble_takeover_start_config)                 */
/* ------------------------------------------------------------------ */

typedef struct {
    char target_addr[32];              /* "AA:BB:CC:DD:EE:FF"             */
    uint32_t timeout_sec;              /* auto-stop (default 300)          */
    uint32_t connect_timeout_ms;       /* GAP connect timeout (15000)      */
    bool auto_enable_notifies;         /* auto-enable N/I chars            */
                                       /* (default true)                    */
    bool rotate_own_mac;               /* new random MAC per connect       */
                                       /* (default true)                    */
    takeover_addr_type_t addr_type;    /* address type strategy             */
    uint32_t scan_itvl;                /* scan interval (default 0x0010)   */
    uint32_t scan_window;              /* scan window (default 0x0010)     */
    uint32_t conn_itvl_min;            /* conn interval min (default 6)    */
    uint32_t conn_itvl_max;            /* conn interval max (default 12)   */
    uint32_t conn_latency;             /* slave latency (default 0)        */
    uint32_t conn_supervision_timeout; /* supervision timeout (default 100)*/
} ble_takeover_config_t;

/* ------------------------------------------------------------------ */
/*  Takeover state                                                     */
/* ------------------------------------------------------------------ */

typedef enum {
    BLE_TAKEOVER_IDLE = 0,
    BLE_TAKEOVER_CONNECTING,
    BLE_TAKEOVER_DISCOVERING,
    BLE_TAKEOVER_CONNECTED,
    BLE_TAKEOVER_DISCONNECTED,
} takeover_state_t;

/* ------------------------------------------------------------------ */
/*  Lifecycle                                                          */
/* ------------------------------------------------------------------ */

/** One-time init -- call from app_main or module setup. */
void ble_takeover_init(void);

/** Start with defaults (backward compatible). */
void ble_takeover_start(const char *target_addr);

/** Start with full config. */
void ble_takeover_start_config(const ble_takeover_config_t *cfg);

/** Stop the takeover and clean up. */
void ble_takeover_stop(void);

/* ------------------------------------------------------------------ */
/*  Status getters  (safe to call from any task / HTTP handler)         */
/* ------------------------------------------------------------------ */

bool           ble_takeover_is_running(void);
takeover_state_t ble_takeover_get_state(void);
const char    *ble_takeover_get_state_str(void);
uint32_t       ble_takeover_get_connect_count(void);
uint32_t       ble_takeover_get_svc_count(void);
uint32_t       ble_takeover_get_chr_count(void);
uint32_t       ble_takeover_get_read_count(void);
uint32_t       ble_takeover_get_write_count(void);
uint32_t       ble_takeover_get_notify_rx_count(void);
uint32_t       ble_takeover_get_notify_enabled_count(void);
uint32_t       ble_takeover_get_enc_change_count(void);
uint32_t       ble_takeover_get_fail_count(void);
int32_t        ble_takeover_get_elapsed_sec(void);
int32_t        ble_takeover_get_remaining_sec(void);
bool           ble_takeover_was_timeout(void);

/** Returns a new cJSON object -- caller must delete. */
cJSON         *ble_takeover_get_status_json(void);

/* ------------------------------------------------------------------ */
/*  Interactive operations (only while CONNECTED)                       */
/* ------------------------------------------------------------------ */

/** Read a characteristic by value handle. Returns true on success. */
bool ble_takeover_read_chr(uint16_t handle);

/** Get the last read result as JSON string.
 *  {"success":bool,"handle":N,"value":"hex"}
 */
const char *ble_takeover_get_read_result(void);

/** Write hex value to a characteristic handle. Returns true on success. */
bool ble_takeover_write_chr(uint16_t handle, const char *hex_value);

/** Enable/disable notifications on a characteristic.
 *  val_handle = the characteristic's value handle.
 */
bool ble_takeover_enable_notify(uint16_t val_handle, bool enable);

/** Get discovered services/characteristics as JSON string. */
const char *ble_takeover_get_services_json(void);

/** Get notification log (ring buffer) as JSON string. */
const char *ble_takeover_get_notifications_json(void);

#endif /* BLE_TAKEOVER_H */
