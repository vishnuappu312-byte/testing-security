#ifndef WSL_BYPASSER_H
#define WSL_BYPASSER_H

#include <stdint.h>
#include "esp_wifi_types.h"

void wsl_bypasser_send_raw_frame(const uint8_t *frame_buffer, int size);
void wsl_bypasser_send_deauth_frame(const wifi_ap_record_t *ap_record);
void wsl_bypasser_send_deauth_targeted(const uint8_t *ap_bssid, const uint8_t *client_mac);
void wsl_bypasser_send_beacon_frame(uint8_t *bssid, uint8_t *ssid, uint8_t ssid_length, uint8_t channel);
void wsl_bypasser_send_disassociation_frame(const uint8_t *ap_bssid, const uint8_t *client_mac);

#endif