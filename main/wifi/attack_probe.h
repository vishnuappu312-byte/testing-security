/**
 * @file attack_probe.h
 * @brief Probe Request Sniffer / Ghost AP creator
 *
 * Sniffs WiFi Probe Requests from nearby devices and creates
 * "ghost" beacon frames for each discovered SSID.
 */

#ifndef ATTACK_PROBE_H
#define ATTACK_PROBE_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include "esp_err.h"
#include "attack.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/*  Ghost AP entry (public)                                            */
/* ------------------------------------------------------------------ */

#define PROBE_MAX_SSID_LEN  33
#define PROBE_MAX_GHOSTS    20

typedef struct {
    char    ssid[PROBE_MAX_SSID_LEN];   /* null-terminated SSID */
    uint8_t len;                         /* SSID length (not counting null) */
    uint8_t bssid[6];                    /* generated BSSID for ghost beacon */
    int8_t  rssi;                        /* best signal strength seen */
    int     probe_count;                 /* how many probes for this SSID */
    uint8_t channel;                     /* channel where first seen */
} probe_ghost_entry_t;

/* ------------------------------------------------------------------ */
/*  Init / lifecycle                                                   */
/* ------------------------------------------------------------------ */

/**
 * One-time init. Call from app_main() before start/stop.
 */
void attack_probe_init(void);

/**
 * Start probe sniffing.
 * @param attack_config  Attack configuration (from webserver).
 */
void attack_probe_start(attack_config_t *attack_config);

/**
 * Stop probe sniffing and ghost beacons.
 */
void attack_probe_stop(void);

/**
 * Returns true if probe sniffer is active.
 */
bool attack_probe_is_running(void);

/* ------------------------------------------------------------------ */
/*  Results access                                                     */
/* ------------------------------------------------------------------ */

/**
 * Get number of discovered ghost APs.
 */
int attack_probe_get_ghost_count(void);

/**
 * Get the list of discovered ghost APs.
 *
 * @param out_entries  Caller-allocated array to fill.
 * @param max_entries  Size of the array.
 * @param out_count    Set to actual number of entries written.
 */
void attack_probe_get_ghosts(probe_ghost_entry_t *out_entries,
                              int max_entries, int *out_count);

/**
 * Clear all discovered ghosts.
 */
void attack_probe_clear_ghosts(void);

/**
 * Get current status as JSON string.
 * Returns: {"running":bool,"ghost_count":N,"total_probes":N}
 * Caller must NOT free the returned pointer (static buffer).
 */
const char *attack_probe_get_status_json(void);

/* ------------------------------------------------------------------ */
/*  Legacy API compatibility                                           */
/* ------------------------------------------------------------------ */

void attack_method_probe(attack_config_t *config);

#ifdef __cplusplus
}
#endif

#endif /* ATTACK_PROBE_H */