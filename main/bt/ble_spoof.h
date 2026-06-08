/*
 * ble_spoof.h - BLE Name Spoof & Device Clone
 *
 * Two operational modes:
 *
 *   NAME-SPOOF  - Rotate through comma-separated BLE device names.
 *                 Each cycle changes the advertised name and random MAC
 *                 so nearby scanners see a sequence of different devices.
 *
 *   CLONE       - Clone a scanned device's full advertising payload
 *                 including services, appearance, TX power, manufacturer-
 *                 specific data, and flags.  The ESP32 re-broadcasts
 *                 this payload with a rotating random MAC, effectively
 *                 impersonating the target device at the link-layer level.
 *
 * Usage pattern (consistent with other Omega modules):
 *   1. ble_spoof_init()           - once at startup
 *   2. ble_spoof_start_config()   - start with full config
 *      OR ble_spoof_start()       - backward-compat name-only start
 *      OR ble_spoof_clone_start() - clone from parsed profile
 *      OR ble_spoof_clone_start_raw() - clone from raw adv bytes
 *   3. ble_spoof_get_status_json()- poll from webserver
 *   4. ble_spoof_stop()           - stop attack
 */

#ifndef BLE_SPOOF_H
#define BLE_SPOOF_H

#include "esp_err.h"
#include "cJSON.h"
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

/** Maximum number of 16-bit or 128-bit service UUIDs stored in profile */
#define BLE_SPOOF_MAX_SVC_UUIDS       8

/** Maximum device name length (bytes, excluding null terminator) */
#define BLE_SPOOF_MAX_NAME_LEN        63

/** Maximum manufacturer-specific data length (bytes) */
#define BLE_SPOOF_MAX_MFR_DATA_LEN    24

/** Maximum BLE advertising payload length */
#define BLE_SPOOF_ADV_MAX_LEN         31

/** Default auto-stop timeout in seconds */
#define BLE_SPOOF_DEFAULT_TIMEOUT_SEC 300

/** Default advertising interval in milliseconds */
#define BLE_SPOOF_DEFAULT_ADV_INT_MS  100

/** Default cycle delay in milliseconds (between name rotations) */
#define BLE_SPOOF_DEFAULT_CYCLE_MS    500

/* ------------------------------------------------------------------ */
/*  Types                                                              */
/* ------------------------------------------------------------------ */

/** Operational mode */
typedef enum {
    BLE_SPOOF_MODE_NAME  = 0,   /**< Rotate through comma-separated names */
    BLE_SPOOF_MODE_CLONE = 1,   /**< Clone a scanned device's full payload */
} ble_spoof_mode_t;

/**
 * Parsed advertising profile for clone mode.
 *
 * Populated by ble_spoof_parse_adv() or manually by the caller.
 * The raw_adv / raw_adv_len fields, when set, are used as-is by the
 * clone broadcaster (highest fidelity).  When raw_adv_len == 0, the
 * individual fields are reconstructed into a new payload.
 */
typedef struct {
    char     name[BLE_SPOOF_MAX_NAME_LEN + 1];  /**< Device name         */
    uint8_t  flags;                               /**< AD flags byte       */

    /* 16-bit service UUIDs */
    uint8_t  svc_uuids_16[BLE_SPOOF_MAX_SVC_UUIDS][2];
    int      svc_uuids_16_count;

    /* 128-bit service UUIDs */
    uint8_t  svc_uuids_128[BLE_SPOOF_MAX_SVC_UUIDS][16];
    int      svc_uuids_128_count;

    /* Appearance */
    uint16_t appearance;
    bool     has_appearance;

    /* TX Power Level */
    int8_t   tx_power;
    bool     has_tx_power;

    /* Manufacturer Specific Data */
    uint16_t mfr_company_id;
    uint8_t  mfr_data[BLE_SPOOF_MAX_MFR_DATA_LEN];
    int      mfr_data_len;
    bool     has_mfr_data;

    /* Raw advertising data (highest-fidelity clone) */
    uint8_t  raw_adv[BLE_SPOOF_ADV_MAX_LEN];
    uint8_t  raw_adv_len;
} ble_spoof_clone_profile_t;

/**
 * Configuration for starting a BLE spoof/clone attack.
 *
 * Pass to ble_spoof_start_config().  Fields set to 0 use defaults.
 * Set timeout_sec to -1 to disable auto-stop.
 */
typedef struct {
    ble_spoof_mode_t mode;                          /**< NAME or CLONE             */
    char             names[128];                    /**< Comma-separated names
                                                         (NAME mode only)          */
    int              adv_interval_ms;               /**< 0 = default (100 ms)      */
    int              cycle_delay_ms;                /**< 0 = default (500 ms)      */
    int              timeout_sec;                   /**< 0 = default (300 s),
                                                         -1 = no timeout           */
    ble_spoof_clone_profile_t clone_profile;        /**< Profile (CLONE mode only) */
} ble_spoof_config_t;

/* ------------------------------------------------------------------ */
/*  Lifecycle                                                          */
/* ------------------------------------------------------------------ */

/** Initialize module (create mutex, ensure NimBLE is ready). Call once. */
void ble_spoof_init(void);

/**
 * Start attack with full configuration.
 * Replaces ble_spoof_start / ble_spoof_clone_start for new code.
 */
void ble_spoof_start_config(const ble_spoof_config_t *cfg);

/** Backward-compatible NAME-mode start. Uses default timeout/interval. */
void ble_spoof_start(const char *name);

/** Start CLONE mode from a parsed profile. Uses default timeout/interval. */
void ble_spoof_clone_start(const ble_spoof_clone_profile_t *profile);

/** Start CLONE mode from raw advertising bytes. Parses + stores raw. */
void ble_spoof_clone_start_raw(const uint8_t *raw_adv, uint8_t raw_len);

/** Stop attack. Safe to call multiple times. Cleans up timer + task. */
void ble_spoof_stop(void);

/* ------------------------------------------------------------------ */
/*  Status getters (for web dashboard polling)                         */
/* ------------------------------------------------------------------ */

/** Is the attack currently running? */
bool ble_spoof_is_running(void);

/** Active operational mode. */
ble_spoof_mode_t ble_spoof_get_mode(void);

/** Human-readable mode name: "name" or "clone". */
const char* ble_spoof_get_mode_name(void);

/** Total advertising packets sent since start. */
uint32_t ble_spoof_get_packet_count(void);

/** Seconds elapsed since attack started. */
int ble_spoof_get_elapsed_sec(void);

/**
 * Seconds remaining until auto-stop.
 * Returns -1 if no timeout configured.
 * Returns  0 if already expired.
 */
int ble_spoof_get_remaining_sec(void);

/** Did the attack auto-stop because the timeout expired? */
bool ble_spoof_was_timeout(void);

/** Last NimBLE error code (0 = no error). */
int ble_spoof_last_error(void);

/**
 * Complete status as a cJSON object.
 * Caller MUST call cJSON_Delete() on the returned pointer.
 *
 * JSON fields:
 *   running          bool
 *   mode             string  ("name" | "clone")
 *   packets          number
 *   elapsed          number  (seconds)
 *   remaining        number  (seconds, -1 = no timeout)
 *   timeout          bool
 *   device_name      string  (comma-separated names or clone name)
 *   name_count       number
 *   adv_interval_ms  number
 *   cycle_delay_ms   number
 *   last_error       number
 */
cJSON* ble_spoof_get_status_json(void);

/* ------------------------------------------------------------------ */
/*  ADV parser / builder utilities                                     */
/* ------------------------------------------------------------------ */

/**
 * Parse raw BLE advertising data into a structured profile.
 * Used by ble_spoof_clone_start_raw() internally, but also available
 * for the BLE scanner to preview what a clone would look like.
 */
esp_err_t ble_spoof_parse_adv(const uint8_t *raw_adv, uint8_t raw_len,
                               ble_spoof_clone_profile_t *out);

/**
 * Build a BLE advertising payload from a clone profile.
 * Useful for testing or for the web UI to preview the payload.
 */
esp_err_t ble_spoof_build_adv(const ble_spoof_clone_profile_t *profile,
                               uint8_t *out, size_t *out_len);

#ifdef __cplusplus
}
#endif

#endif /* BLE_SPOOF_H */
