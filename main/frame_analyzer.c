#include "frame_analyzer.h"
#include "esp_log.h"

static const char *TAG = "frame_analyzer";

ESP_EVENT_DEFINE_BASE(FRAME_ANALYZER_EVENTS);

void frame_analyzer_capture_start(search_type_t type, const uint8_t *bssid) {
    ESP_LOGI(TAG, "Frame analyzer started, type: %d, BSSID: " MACSTR, type, MAC2STR(bssid));
    // Stub - would analyze frames for handshake/PMKID
}

void frame_analyzer_capture_stop(void) {
    ESP_LOGI(TAG, "Frame analyzer stopped");
}