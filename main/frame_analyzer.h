#ifndef FRAME_ANALYZER_H
#define FRAME_ANALYZER_H

#include "esp_event.h"

ESP_EVENT_DECLARE_BASE(FRAME_ANALYZER_EVENTS);

typedef enum {
    DATA_FRAME_EVENT_EAPOLKEY_FRAME,
    DATA_FRAME_EVENT_PMKID
} data_frame_event_t;

typedef enum {
    SEARCH_HANDSHAKE,
    SEARCH_PMKID
} search_type_t;

void frame_analyzer_capture_start(search_type_t type, const uint8_t *bssid);
void frame_analyzer_capture_stop(void);

#endif