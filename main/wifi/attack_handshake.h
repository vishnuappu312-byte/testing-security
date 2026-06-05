/**
 * @file attack_handshake.h
 * @date 2026
 * @brief Handshake capture attack — header with webserver API.
 *
 * Omega Solutions — ESP32-S3 Wireless Security Testing Tool
 */

#ifndef ATTACK_HANDSHAKE_H
#define ATTACK_HANDSHAKE_H

#include "attack.h"
#include <stdbool.h>
#include <stdint.h>
#include "cJSON.h"
#ifdef __cplusplus
extern "C" {
#endif

/* ── Attack Methods ─────────────────────────────────────────── */

typedef enum {
    ATTACK_HANDSHAKE_METHOD_BROADCAST = 0,
    ATTACK_HANDSHAKE_METHOD_ROGUE_AP  = 1,
    ATTACK_HANDSHAKE_METHOD_PASSIVE   = 2,
} attack_handshake_methods_t;

/* ── Core Attack API ────────────────────────────────────────── */

/**
 * @brief Start a handshake capture attack.
 * @param attack_config  Target AP info + chosen method.
 */
void attack_handshake_start(attack_config_t *attack_config);

/**
 * @brief Stop the running handshake attack and clean up.
 */
void attack_handshake_stop(void);

/* ── Webserver / Dashboard API ──────────────────────────────── */

/**
 * @brief Check if the handshake attack is currently running.
 * @return true if running, false otherwise.
 */
bool attack_handshake_is_running(void);

/**
 * @brief Check if a full handshake has been captured.
 *        (4 EAPOL frames captured = complete handshake)
 * @return true if capture is complete.
 */
bool attack_handshake_has_capture(void);

/**
 * @brief Get the number of EAPOL frames captured so far.
 * @return Frame count (0–4+).
 */
uint8_t attack_handshake_get_eapol_count(void);

/**
 * @brief Get a human-readable status string for the dashboard.
 * @return One of: "idle", "running", "partial", "captured", "timeout"
 */
const char *attack_handshake_get_status_str(void);

/**
 * @brief Check if the attack timed out without capturing a full handshake.
 * @return true if timeout occurred.
 */
bool attack_handshake_was_timeout(void);

/**
 * @brief Get the target AP SSID (if attack was started).
 * @return SSID string or "—" if no target.
 */
const char *attack_handshake_get_ssid(void);

/**
 * @brief Get the target AP BSSID as a formatted string.
 * @param buf  Output buffer (min 18 bytes).
 */
void attack_handshake_get_bssid(char *buf, size_t buf_len);

/**
 * @brief Get the target AP channel.
 * @return Channel number, or 0 if no target.
 */
uint8_t attack_handshake_get_channel(void);

/**
 * @brief Build a JSON status object for the web API.
 *        Caller must free with cJSON_Delete().
 * @return cJSON object with: running, eapol_count, eapol_required,
 *         status, timeout, ssid, bssid, channel.
 */
cJSON *attack_handshake_get_status_json(void);

/**
 * @brief Get the PCAP file size (for web download).
 * @return Size in bytes, or 0 if no capture.
 */
size_t attack_handshake_get_pcap_size(void);

/**
 * @brief Get the PCAP buffer pointer (for web download).
 * @return Pointer to PCAP data, or NULL.
 */
const uint8_t *attack_handshake_get_pcap_data(void);

#ifdef __cplusplus
}
#endif

#endif /* ATTACK_HANDSHAKE_H */