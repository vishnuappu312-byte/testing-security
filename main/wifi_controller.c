#include "wifi_controller.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include <string.h>
#include "esp_err.h"
static const char *TAG = "wifi_controller";
static uint8_t original_ap_mac[6];
static bool ap_mac_saved = false;

void wifictl_mgmt_ap_start(void) {
    ESP_LOGI(TAG, "Management AP starting");
    // Stub - would restart management AP
}

void wifictl_mgmt_ap_stop(void) {
    ESP_LOGI(TAG, "Management AP stopping");
    // Stub - would stop management AP
}

void wifictl_restore_ap_mac(void) {
    if (ap_mac_saved) {
        esp_wifi_set_mac(WIFI_IF_AP, original_ap_mac);
        ESP_LOGI(TAG, "AP MAC restored");
    }
}

void wifictl_set_ap_mac(const uint8_t *mac) {
    if (!ap_mac_saved) {
        esp_wifi_get_mac(WIFI_IF_AP, original_ap_mac);
        ap_mac_saved = true;
    }
    esp_wifi_set_mac(WIFI_IF_AP, mac);
    ESP_LOGI(TAG, "AP MAC set to " MACSTR, MAC2STR(mac));
}

void wifictl_get_ap_mac(uint8_t *mac) {
    esp_wifi_get_mac(WIFI_IF_AP, mac);
}

void wifictl_get_sta_mac(uint8_t *mac) {
    esp_wifi_get_mac(WIFI_IF_STA, mac);
}

void wifictl_ap_start(wifi_config_t *config) {
    esp_wifi_set_config(WIFI_IF_AP, config);
    ESP_LOGI(TAG, "AP started with SSID: %s", config->ap.ssid);
}

void wifictl_sniffer_start(uint8_t channel) {
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    esp_wifi_set_promiscuous(true);
    ESP_LOGI(TAG, "Sniffer started on channel %d", channel);
}

void wifictl_sniffer_stop(void) {
    esp_wifi_set_promiscuous(false);
    ESP_LOGI(TAG, "Sniffer stopped");
}

void wifictl_sniffer_filter_frame_types(bool data, bool mgmt, bool ctrl) {
    wifi_promiscuous_filter_t filter = { .filter_mask = 0 };
    if (mgmt) filter.filter_mask |= WIFI_PROMIS_FILTER_MASK_MGMT;
    if (data) filter.filter_mask |= WIFI_PROMIS_FILTER_MASK_DATA;
    if (ctrl) filter.filter_mask |= WIFI_PROMIS_FILTER_MASK_CTRL;
    esp_wifi_set_promiscuous_filter(&filter);
    ESP_LOGI(TAG, "Sniffer filter set: data=%d, mgmt=%d, ctrl=%d", data, mgmt, ctrl);
}

void wifictl_sta_connect_to_ap(const wifi_ap_record_t *ap, const char *password) {
    wifi_config_t sta_config = {
        .sta = {
            .channel = ap->primary,
            .scan_method = WIFI_FAST_SCAN
        },
    };
    memcpy(sta_config.sta.ssid, ap->ssid, 32);
    if (password) {
        memcpy(sta_config.sta.password, password, strlen(password));
    }
    esp_wifi_set_config(WIFI_IF_STA, &sta_config);
    esp_wifi_connect();
    ESP_LOGI(TAG, "Connecting to AP: %s", ap->ssid);
}

void wifictl_sta_disconnect(void) {
    esp_wifi_disconnect();
    ESP_LOGI(TAG, "STA disconnected");
}


esp_err_t wifi_controller_promiscuous_acquire(void)

{

    return ESP_OK;

}

esp_err_t wifi_controller_promiscuous_release(void)

{

    return ESP_OK;

}