#ifndef WIFI_CONTROLLER_H
#define WIFI_CONTROLLER_H

#include "esp_wifi_types.h"
#include "esp_err.h"

esp_err_t wifi_controller_promiscuous_acquire(void);
esp_err_t wifi_controller_promiscuous_release(void);
void wifictl_mgmt_ap_start(void);
void wifictl_mgmt_ap_stop(void);
void wifictl_restore_ap_mac(void);
void wifictl_set_ap_mac(const uint8_t *mac);
void wifictl_get_ap_mac(uint8_t *mac);
void wifictl_get_sta_mac(uint8_t *mac);
void wifictl_ap_start(wifi_config_t *config);
void wifictl_sniffer_start(uint8_t channel);
void wifictl_sniffer_stop(void);
void wifictl_sniffer_filter_frame_types(bool data, bool mgmt, bool ctrl);
void wifictl_sta_connect_to_ap(const wifi_ap_record_t *ap, const char *password);
void wifictl_sta_disconnect(void);

#endif