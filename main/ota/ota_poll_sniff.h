/**
 * ota_poll_sniff.h - Promiscuous DNS/HTTP OTA poll sniff
 */

#ifndef OTA_POLL_SNIFF_H
#define OTA_POLL_SNIFF_H

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"
#include "cJSON.h"

typedef struct {
    char wifi_ssid[33];
    char wifi_password[64];
    uint8_t target_device_ip[4];
    bool capture_dns;
    bool capture_http;
    uint32_t timeout_sec;
} ota_poll_sniff_config_t;

typedef struct {
    bool active;
    bool timeout;
    uint32_t dns_count;
    uint32_t http_count;
    uint32_t ota_dns_count;
    uint32_t ota_http_count;
    uint32_t urls;
    uint32_t elapsed_sec;
    uint32_t remaining_sec;
    char state[32];
    char error[64];
} ota_poll_sniff_state_t;

void ota_poll_sniff_init(void);
esp_err_t ota_poll_sniff_start(const ota_poll_sniff_config_t *cfg);
esp_err_t ota_poll_sniff_stop(void);
bool ota_poll_sniff_is_active(void);
const ota_poll_sniff_state_t *ota_poll_sniff_get_state(void);
cJSON *ota_poll_sniff_get_status_json(void);
const char *ota_poll_sniff_get_dns_json(void);
const char *ota_poll_sniff_get_http_json(void);
const char *ota_poll_sniff_get_urls_json(void);

#endif /* OTA_POLL_SNIFF_H */
