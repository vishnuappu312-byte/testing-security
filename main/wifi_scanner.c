#include "wifi_scanner.h"
#include "esp_log.h"

static const char *TAG = "wifi_scanner";

void scanner_init(void) {
    ESP_LOGI(TAG, "WiFi scanner initialized");
}

void scanner_scan(void) {
    wifictl_scan_nearby_aps();
}

const wifictl_ap_records_t *scanner_get_records(void) {
    return wifictl_get_ap_records();
}

const wifi_ap_record_t *scanner_get_record(uint16_t index) {
    return wifictl_get_ap_record(index);
}
