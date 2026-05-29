#include <string.h>
#include <stdlib.h>
#include "esp_log.h"
#include "esp_wifi.h"
#include "wifi_scanner.h"

static const char *TAG = "SCANNER";

void scanner_init(void) {
    ESP_LOGI(TAG, "Scanner initialized");
}

wifi_ap_record_t *scan_networks(int *out_count) {
    if (out_count) {
        *out_count = 0;
    }

    wifi_scan_config_t scan_config = {
        .ssid = NULL,
        .bssid = NULL,
        .channel = 0,
        .show_hidden = true,
        .scan_type = WIFI_SCAN_TYPE_ACTIVE,
        .scan_time = { .active = { .min = 100, .max = 300 } }
    };

    esp_err_t err = esp_wifi_scan_start(&scan_config, true);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "scan_start failed: %s", esp_err_to_name(err));
        return NULL;
    }

    uint16_t ap_count = 0;
    err = esp_wifi_scan_get_ap_num(&ap_count);
    if (err != ESP_OK || ap_count == 0) {
        ESP_LOGW(TAG, "No networks found");
        return NULL;
    }

    if (ap_count > MAX_AP_SCAN) {
        ap_count = MAX_AP_SCAN;
    }

    wifi_ap_record_t *ap_records = calloc(ap_count, sizeof(wifi_ap_record_t));
    if (!ap_records) {
        ESP_LOGE(TAG, "Out of memory");
        return NULL;
    }

    err = esp_wifi_scan_get_ap_records(&ap_count, ap_records);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "get_ap_records failed: %s", esp_err_to_name(err));
        free(ap_records);
        return NULL;
    }

    if (out_count) {
        *out_count = (int)ap_count;
    }
    ESP_LOGI(TAG, "Found %d networks", ap_count);
    return ap_records;
}
