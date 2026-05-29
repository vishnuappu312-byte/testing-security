#include "hccapx_serializer.h"
#include "esp_log.h"

static const char *TAG = "hccapx_serializer";

void hccapx_serializer_init(const uint8_t *ssid, uint8_t ssid_len) {
    ESP_LOGI(TAG, "HCCAPX serializer initialized for SSID: %.*s", ssid_len, ssid);
}

void hccapx_serializer_add_frame(data_frame_t *frame) {
    ESP_LOGD(TAG, "Adding frame to HCCAPX");
    // Stub - would process EAPOL frames
}