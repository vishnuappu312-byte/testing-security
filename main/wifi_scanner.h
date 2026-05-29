#ifndef WIFI_SCANNER_H
#define WIFI_SCANNER_H

#include "esp_wifi_types.h"
#include "esp_err.h"
#define MAX_AP_SCAN 30

void scanner_init(void);
wifi_ap_record_t *scan_networks(int *out_count);


esp_err_t wifi_controller_promiscuous_acquire(void);
esp_err_t wifi_controller_promiscuous_release(void);
#endif
