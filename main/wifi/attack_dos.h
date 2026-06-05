#ifndef ATTACK_DOS_H
#define ATTACK_DOS_H

#include <stdbool.h>
#include <stdint.h>
#include "cJSON.h"
#include "attack.h"

/* ──────────────────────────────────────────────
 *  DoS Attack Methods
 * ────────────────────────────────────────────── */
typedef enum {
    ATTACK_DOS_METHOD_NONE = 0,
    ATTACK_DOS_METHOD_ROGUE_AP,
    ATTACK_DOS_METHOD_BROADCAST,
    ATTACK_DOS_METHOD_COMBINE_ALL,
    ATTACK_DOS_METHOD_SUPER_CLONE,
    ATTACK_DOS_METHOD_AUTH_FLOOD,
    ATTACK_DOS_METHOD_BEACON_FLOOD,
    ATTACK_DOS_METHOD_DISASSOC,
    ATTACK_DOS_METHOD_COUNT          /* sentinel – must be last */
} attack_dos_methods_t;

/* ──────────────────────────────────────────────
 *  Timeout configuration
 * ────────────────────────────────────────────── */
#define ATTACK_DOS_TIMEOUT_SEC        120   /* 2 min default */
#define ATTACK_DOS_TIMEOUT_US         (ATTACK_DOS_TIMEOUT_SEC * 1000000ULL)

/* ──────────────────────────────────────────────
 *  Core API
 * ────────────────────────────────────────────── */

/**
 * Start a DoS attack with the given configuration.
 * Thread-safe: acquires internal mutex.
 */
void attack_dos_start(attack_config_t *attack_config);

/**
 * Stop the running DoS attack.
 * Thread-safe: acquires internal mutex.
 */
void attack_dos_stop(void);

/* ──────────────────────────────────────────────
 *  Webserver / Dashboard API  (all thread-safe)
 * ────────────────────────────────────────────── */

/** Is a DoS attack currently running? */
bool attack_dos_is_running(void);

/** Get current method enum (ATTACK_DOS_METHOD_NONE if idle) */
attack_dos_methods_t attack_dos_get_method(void);

/** Get human-readable method string (e.g. "Rogue AP", "Broadcast Deauth") */
const char *attack_dos_get_method_str(void);

/** Get target SSID (empty string if idle) */
const char *attack_dos_get_ssid(void);

/** Get target BSSID string "XX:XX:XX:XX:XX:XX" (empty if idle) */
const char *attack_dos_get_bssid_str(void);

/** Get target channel (0 if idle) */
uint8_t attack_dos_get_channel(void);

/** Get number of packets transmitted so far */
uint32_t attack_dos_get_packet_count(void);

/** Did the last attack end because of timeout? */
bool attack_dos_was_timeout(void);

/** Get human-readable status string */
const char *attack_dos_get_status_str(void);

/**
 * Build a JSON object with full DoS status:
 *   { running, method, method_str, ssid, bssid, channel,
 *     packet_count, timeout, status }
 * Caller must delete the returned cJSON object.
 */
cJSON *attack_dos_get_status_json(void);

#endif /* ATTACK_DOS_H */