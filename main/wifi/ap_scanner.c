
#include "ap_scanner.h"
#include "heap_psram.h"

#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_err.h"
#include "esp_wifi.h"

#include "wifi_controller.h"

#include <string.h>


static const char* TAG = "wifi_controller/ap_scanner";
/**
 * @brief Stores last scanned AP records (allocated in PSRAM when available).
 */
static wifictl_ap_records_t *ap_records = NULL;

static bool ensure_ap_records(void)
{
    if (ap_records != NULL) {
        return true;
    }
    ap_records = heap_psram_calloc(1, sizeof(wifictl_ap_records_t));
    if (ap_records == NULL) {
        ESP_LOGE(TAG, "Failed to allocate AP records buffer");
        return false;
    }
    return true;
}

void wifictl_scan_nearby_aps(){
    ESP_LOGI(TAG, "Scanning nearby APs...");

    if (!ensure_ap_records()) {
        return;
    }

    wifictl_prepare_for_scan();

    /* Keep previous results if this pass fails so the web UI can still show data. */
    uint16_t previous_count = ap_records->count;
    ap_records->count = CONFIG_SCAN_MAX_AP;

    wifi_scan_config_t scan_config = {
        .ssid = NULL,
        .bssid = NULL,
        .channel = 0,
        .show_hidden = true,
        .scan_type = WIFI_SCAN_TYPE_ACTIVE,
        .scan_time = {
            .active = { .min = 100, .max = 300 },
        },
    };

    esp_err_t err = esp_wifi_scan_start(&scan_config, true);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Scan start failed: %s", esp_err_to_name(err));
        ap_records->count = previous_count;
        return;
    }

    err = esp_wifi_scan_get_ap_records(&ap_records->count, ap_records->records);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Scan result read failed: %s", esp_err_to_name(err));
        ap_records->count = previous_count;
        return;
    }
    ESP_LOGI(TAG, "Found %u APs.", ap_records->count);
}

const wifictl_ap_records_t *wifictl_get_ap_records() {
    if (!ensure_ap_records()) {
        return NULL;
    }
    return ap_records;
}

const wifi_ap_record_t *wifictl_get_ap_record(unsigned index) {
    if (!ensure_ap_records()) {
        return NULL;
    }
    if(index >= ap_records->count){
        ESP_LOGE(TAG, "Index out of bounds! %u records available, but %u requested", ap_records->count, index);
        return NULL;
    }
    return &ap_records->records[index];
}
