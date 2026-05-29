#include "pcap_serializer.h"
#include "esp_log.h"

static const char *TAG = "pcap_serializer";

void pcap_serializer_init(void) {
    ESP_LOGI(TAG, "PCAP serializer initialized");
}

void pcap_serializer_append_frame(const uint8_t *frame, size_t len, uint32_t timestamp) {
    ESP_LOGD(TAG, "Appending frame to PCAP: %d bytes at %u", len, timestamp);
    // Stub - would write to SD/SPIFFS
}