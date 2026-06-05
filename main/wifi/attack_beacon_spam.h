#ifndef ATTACK_BEACON_SPAM_H
#define ATTACK_BEACON_SPAM_H

#include <stdbool.h>
#include <stdint.h>
#include "cJSON.h"

/* ──────────────────────────────────────────────
 *  Beacon Spam Modes
 * ────────────────────────────────────────────── */
typedef enum {
    BEACON_MODE_COMMON   = 0,   /* Realistic SSID names (TP-Link, Netgear, etc.) */
    BEACON_MODE_GARBAGE  = 1,   /* Random garbage characters */
    BEACON_MODE_RICK_ROLL = 2,  /* Rick Astley lyrics across SSIDs */
    BEACON_MODE_SECURITY = 3,   /* Troll / security-themed names */
    BEACON_MODE_COUNT           /* sentinel – must be last */
} beacon_spam_mode_t;

/* ──────────────────────────────────────────────
 *  Timeout configuration
 * ────────────────────────────────────────────── */
#define BEACON_SPAM_TIMEOUT_SEC        300   /* 5 min default */
#define BEACON_SPAM_TIMEOUT_US         (BEACON_SPAM_TIMEOUT_SEC * 1000000ULL)

#define BEACON_SPAM_MAX_APS            100
#define BEACON_SPAM_TIMER_INTERVAL_US  100000  /* 100ms = 10 beacons/sec per AP */

/* ──────────────────────────────────────────────
 *  Core API
 * ────────────────────────────────────────────── */

/**
 * Start beacon spam with the given count and mode.
 * Thread-safe: acquires internal mutex.
 * @param count  Number of fake APs to generate (1–100, default 20)
 * @param mode   Spam mode (common, garbage, rick roll, security)
 */
void attack_beacon_spam_start(uint8_t count, beacon_spam_mode_t mode);

/**
 * Stop the running beacon spam attack.
 * Thread-safe: acquires internal mutex.
 */
void attack_beacon_spam_stop(void);

/* ──────────────────────────────────────────────
 *  Webserver / Dashboard API  (all thread-safe)
 * ────────────────────────────────────────────── */

/** Is beacon spam currently running? */
bool attack_beacon_spam_is_running(void);

/** Get current mode enum (BEACON_MODE_COMMON if idle) */
beacon_spam_mode_t attack_beacon_spam_get_mode(void);

/** Get human-readable mode string */
const char *attack_beacon_spam_get_mode_str(void);

/** Get the number of active fake APs */
uint16_t attack_beacon_spam_get_ap_count(void);

/** Get total number of beacon frames transmitted */
uint32_t attack_beacon_spam_get_packet_count(void);

/** Get elapsed time in seconds since attack started */
uint32_t attack_beacon_spam_get_elapsed_sec(void);

/** Did the attack end because of timeout? */
bool attack_beacon_spam_was_timeout(void);

/** Get human-readable status string */
const char *attack_beacon_spam_get_status_str(void);

/**
 * Build a JSON object with full beacon spam status:
 *   { running, mode, mode_str, ap_count, packet_count,
 *     elapsed_sec, timeout, status }
 * Caller must delete the returned cJSON object.
 */
cJSON *attack_beacon_spam_get_status_json(void);

#endif /* ATTACK_BEACON_SPAM_H */
