/**
 * ota_provision.h - HTTP provision credential sniffer
 */

#ifndef OTA_PROVISION_H
#define OTA_PROVISION_H

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"
#include "cJSON.h"
#include "ota_common.h"

typedef struct {
    char wifi_ssid[33];
    char wifi_password[64];
    uint16_t sniff_port;
    bool capture_post_only;
    bool auto_parse_json;
    uint32_t timeout_sec;
} ota_provision_config_t;

typedef struct {
    bool active;
    bool timeout;
    uint32_t cred_count;
    uint32_t sensitive_count;
    uint32_t elapsed_sec;
    uint32_t remaining_sec;
    char state[32];
    char error[64];
} ota_provision_state_t;

void ota_provision_init(void);
esp_err_t ota_provision_start(const ota_provision_config_t *cfg);
esp_err_t ota_provision_stop(void);
bool ota_provision_is_active(void);
const ota_provision_state_t *ota_provision_get_state(void);
cJSON *ota_provision_get_status_json(void);
const char *ota_provision_get_creds_json(void);
const char *ota_provision_get_summary_json(void);
void ota_provision_get_summary(ota_prov_summary_t *out);
uint32_t ota_provision_get_cred_count(void);
uint32_t ota_provision_get_sensitive_count(void);
void ota_provision_clear_creds(void);

#endif /* OTA_PROVISION_H */
