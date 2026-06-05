#ifndef ATTACK_DEAUTH_DETECTOR_H
#define ATTACK_DEAUTH_DETECTOR_H

#include <stdbool.h>
#include <stdint.h>
#include "cJSON.h"

/* ──────────────────────────────────────────────
 *  Configuration
 * ────────────────────────────────────────────── */
#define MAX_TRACKED_BSSIDS        16
#define DEAUTH_WINDOW_MS          10000   /* 10-second sliding window */
#define DEAUTH_THRESHOLD          5       /* frames within window to trigger alert */
#define DEAUTH_ALERT_HOLD_MS      5000    /* alert stays active this long */

/* ──────────────────────────────────────────────
 *  Timeout configuration
 * ────────────────────────────────────────────── */
#define DEAUTH_DETECT_TIMEOUT_SEC   300   /* 5 min default auto-stop */
#define DEAUTH_DETECT_TIMEOUT_US    (DEAUTH_DETECT_TIMEOUT_SEC * 1000000ULL)

/* ──────────────────────────────────────────────
 *  Detector Status Strings
 * ────────────────────────────────────────────── */
#define DEAUTH_STATUS_IDLE        "Idle"
#define DEAUTH_STATUS_RUNNING     "Monitoring"
#define DEAUTH_STATUS_ALERT       "ALERT: Deauth Detected!"
#define DEAUTH_STATUS_TIMEOUT     "Stopped (Timeout)"
#define DEAUTH_STATUS_STOPPED     "Stopped"

/* ──────────────────────────────────────────────
 *  Per-BSSID tracking entry
 * ────────────────────────────────────────────── */
typedef struct {
    uint8_t  bssid[6];           /* BSSID of the affected AP           */
    int64_t  window_start_ms;    /* start of current counting window   */
    uint32_t count;              /* deauth frames in this window       */
    bool     alerting;           /* currently in alert state           */
    int64_t  last_alert_ms;      /* timestamp of last alert trigger    */
    char     ssid[33];           /* SSID if known (optional, \0=unkn)  */
    uint8_t  channel;            /* channel if known (0 = unknown)     */
    uint32_t total_deauths;      /* total deauth frames for this BSSID */
} deauth_track_entry_t;

/* ──────────────────────────────────────────────
 *  Detector status structure
 * ────────────────────────────────────────────── */
typedef struct {
    bool     running;                          /* detector active             */
    int      count;                            /* number of tracked BSSIDs    */
    deauth_track_entry_t entries[MAX_TRACKED_BSSIDS];
} deauth_detector_status_t;

/* ──────────────────────────────────────────────
 *  Core API
 * ────────────────────────────────────────────── */

/**
 * Start the deauth detector in promiscuous mode.
 * Thread-safe: acquires internal mutex.
 * Double-start guard: no-op if already running.
 * Auto-stops after DEAUTH_DETECT_TIMEOUT_SEC (300s).
 */
void deauth_detector_start(void);

/**
 * Stop the deauth detector and disable promiscuous mode.
 * Thread-safe: acquires internal mutex.
 */
void deauth_detector_stop(void);

/* ──────────────────────────────────────────────
 *  Webserver / Dashboard API  (all thread-safe)
 * ────────────────────────────────────────────── */

/** Is the detector currently running? */
bool deauth_detector_is_running(void);

/** Get number of tracked BSSIDs */
uint8_t deauth_detector_get_tracked_count(void);

/** Get number of BSSIDs currently in alert state */
uint8_t deauth_detector_get_alert_count(void);

/** Get total deauth frames seen across all BSSIDs */
uint32_t deauth_detector_get_total_deauths(void);

/** Get the highest deauth count on any single BSSID (current window) */
uint32_t deauth_detector_get_peak_count(void);

/** Get elapsed time in seconds since detector started */
uint32_t deauth_detector_get_elapsed_sec(void);

/** Get remaining time in seconds before auto-stop timeout */
uint32_t deauth_detector_get_remaining_sec(void);

/** Did the detector stop because of timeout? */
bool deauth_detector_was_timeout(void);

/** Get the raw status struct pointer (snapshot — caller should not hold) */
const deauth_detector_status_t *deauth_detector_get_status(void);

/** Get human-readable status string */
const char *deauth_detector_get_status_str(void);

/**
 * Build a JSON object with full detector status:
 *   { running, tracked_count, alert_count, total_deauths,
 *     peak_count, elapsed_sec, remaining_sec, timeout, status,
 *     alerts: [ { bssid, ssid, channel, window_count, total_deauths } ] }
 *
 * Caller must delete the returned cJSON object.
 */
cJSON *deauth_detector_get_status_json(void);

#endif /* ATTACK_DEAUTH_DETECTOR_H */