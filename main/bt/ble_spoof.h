// #ifndef BLE_SPOOF_H
// #define BLE_SPOOF_H

// #ifdef __cplusplus
// extern "C" {
// #endif

// #include <stdbool.h>

// void ble_spoof_init(void);
// void ble_spoof_start(const char *name);
// void ble_spoof_stop(void);
// bool ble_spoof_is_running(void);

// #ifdef __cplusplus
// }
// #endif

// #endif // BLE_SPOOF_H
/*
 * ble_spoof.h - BLE Name Spoof & Device Clone Module
 *
 * Provides two modes:
 *   1) NAME SPOOF  - Rotate through comma-separated BLE advertising names
 *   2) DEVICE CLONE - Clone a scanned device's full advertising payload
 *                     (name + services + appearance + TX power + manufacturer data)
 *                     and re-broadcast it with a random MAC, effectively
 *                     impersonating the target device.
 *
 * Depends on:  ble_common.h  (nimble init + own_addr_type helper)
 *              ble_scan.h    (optional, for scan-then-clone flow)
 *
 * Usage from webserver:
 *   ble_spoof_init();
 *   ble_spoof_start("MyDevice");                // name-spoof mode
 *   ble_spoof_clone_start(adv_data, adv_len);   // clone mode
 *   ble_spoof_stop();
 */
/*
 * ble_spoof.h - BLE Name Spoof & Device Clone Module
 *
 * Provides two modes:
 *   1) NAME SPOOF  - Rotate through comma-separated BLE advertising names
 *   2) DEVICE CLONE - Clone a scanned device's full advertising payload
 *                     (name + services + appearance + TX power + manufacturer data)
 *                     and re-broadcast it with a random MAC, effectively
 *                     impersonating the target device.
 *
 * Depends on:  ble_common.h  (nimble init + own_addr_type helper)
 *              ble_scan.h    (optional, for scan-then-clone flow)
 *
 * Usage from webserver:
 *   ble_spoof_init();
 *   ble_spoof_start("MyDevice");                // name-spoof mode
 *   ble_spoof_clone_start(adv_data, adv_len);   // clone mode
 *   ble_spoof_stop();
 */

#ifndef BLE_SPOOF_H
#define BLE_SPOOF_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/*  Mode constants                                                     */
/* ------------------------------------------------------------------ */

typedef enum {
    BLE_SPOOF_MODE_NAME   = 0,   /* Rotate advertised names            */
    BLE_SPOOF_MODE_CLONE  = 1,   /* Re-broadcast cloned adv payload    */
} ble_spoof_mode_t;

/* ------------------------------------------------------------------ */
/*  Clone profile – everything we copy from a scanned device           */
/* ------------------------------------------------------------------ */

#define BLE_SPOOF_MAX_SVC_UUIDS      8
#define BLE_SPOOF_MAX_MFR_DATA_LEN   28
#define BLE_SPOOF_MAX_NAME_LEN       28   /* fits inside 31-byte adv  */

typedef struct {
    /* Device identity */
    char     name[BLE_SPOOF_MAX_NAME_LEN + 1];
    uint8_t  addr[6];                        /* original BD_ADDR         */

    /* Advertising data fields */
    uint8_t  svc_uuids_16[BLE_SPOOF_MAX_SVC_UUIDS][2];  /* 16-bit UUIDs */
    int      svc_uuids_16_count;
    uint8_t  svc_uuids_128[BLE_SPOOF_MAX_SVC_UUIDS][16]; /* 128-bit     */
    int      svc_uuids_128_count;

    uint16_t appearance;                     /* GAP appearance value     */
    bool     has_appearance;

    int8_t   tx_power;                       /* dBm                      */
    bool     has_tx_power;

    uint8_t  mfr_data[BLE_SPOOF_MAX_MFR_DATA_LEN];
    uint16_t mfr_company_id;
    int      mfr_data_len;
    bool     has_mfr_data;

    /* Flags */
    uint8_t  flags;                          /* usually 0x06             */

    /* Raw advertising data fallback */
    uint8_t  raw_adv[31];                    /* complete raw adv payload */
    uint8_t  raw_adv_len;                    /* 0 = not set              */
} ble_spoof_clone_profile_t;

/* ------------------------------------------------------------------ */
/*  Init / lifecycle                                                   */
/* ------------------------------------------------------------------ */

/**
 * One-time init – creates mutexes, ensures NimBLE is up.
 * Call once from app_main() before any start/stop calls.
 */
void ble_spoof_init(void);

/**
 * Start NAME-SPOOF mode.
 * @param name  Comma-separated list of names to rotate through
 *              (up to 5 names).  e.g. "AirPods,Galaxy Buds,JBL Flip"
 *              If NULL or empty, defaults to "NimBLE-Device".
 */
void ble_spoof_start(const char *name);

/**
 * Start CLONE mode.
 * Copies the profile and begins advertising the cloned payload
 * with rotating random MAC addresses.
 *
 * @param profile  Populated clone profile (contents are copied internally).
 */
void ble_spoof_clone_start(const ble_spoof_clone_profile_t *profile);

/**
 * Start CLONE mode from raw advertising data.
 * Parses the raw advertisement and fills a clone profile, then
 * begins broadcasting.  Useful when you already have the raw adv
 * bytes from a BLE scan result.
 *
 * @param raw_adv  Pointer to raw advertising data bytes.
 * @param raw_len  Length of raw advertising data (max 31).
 */
void ble_spoof_clone_start_raw(const uint8_t *raw_adv, uint8_t raw_len);

/**
 * Stop any running spoof/clone operation.
 * Blocks until the task has exited (up to 5 s timeout).
 */
void ble_spoof_stop(void);

/**
 * Returns true if a spoof/clone task is currently running.
 */
bool ble_spoof_is_running(void);

/* ------------------------------------------------------------------ */
/*  Profile helpers – parse raw adv data into a clone profile          */
/* ------------------------------------------------------------------ */

/**
 * Parse a raw BLE advertising payload into a clone profile.
 * Extracts: Complete/Shortened Local Name, 16-bit & 128-bit UUIDs,
 *           Appearance, TX Power Level, Manufacturer Data, Flags.
 *
 * @param raw_adv  Raw advertising bytes.
 * @param raw_len  Length (typically 0..31).
 * @param out      Output profile (zeroed by this function).
 * @return ESP_OK on success, ESP_FAIL on invalid args.
 */
esp_err_t ble_spoof_parse_adv(const uint8_t *raw_adv, uint8_t raw_len,
                               ble_spoof_clone_profile_t *out);

/**
 * Build a raw advertising payload from a clone profile.
 * Reconstructs the advertising data in proper BLE AD structure format,
 * suitable for ble_gap_adv_set_data().
 *
 * @param profile  Source profile.
 * @param out      Output buffer (must be >= 31 bytes).
 * @param out_len  Set to the actual payload length.
 * @return ESP_OK on success.
 */
esp_err_t ble_spoof_build_adv(const ble_spoof_clone_profile_t *profile,
                               uint8_t *out, size_t *out_len);

/**
 * Quick utility: get the currently-active mode.
 */
ble_spoof_mode_t ble_spoof_get_mode(void);

/**
 * Get the last error code from the advertising subsystem.
 * Returns 0 if no error.
 */
int ble_spoof_last_error(void);

#ifdef __cplusplus
}
#endif

#endif /* BLE_SPOOF_H */
