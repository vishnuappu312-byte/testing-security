#ifndef ATTACK_DEAUTH_DETECTOR_H
#define ATTACK_DEAUTH_DETECTOR_H

#include <stdint.h>
#include <stdbool.h>

#define DEAUTH_WINDOW_MS 1000
#define DEAUTH_THRESHOLD 10
#define MAX_TRACKED_BSSIDS 10

typedef struct {
    uint8_t bssid[6];
    uint32_t count;
    int64_t window_start_ms;
    bool alerting;
    int64_t last_alert_ms;
} deauth_track_entry_t;

typedef struct {
    deauth_track_entry_t entries[MAX_TRACKED_BSSIDS];
    int count;
    bool running;
} deauth_detector_status_t;

void deauth_detector_start(void);
void deauth_detector_stop(void);
const deauth_detector_status_t *deauth_detector_get_status(void);

#endif
