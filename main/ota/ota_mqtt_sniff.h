/**
 * ota_mqtt_sniff.h - MQTT OTA sniff / client (subscribe + capture)
 */

#ifndef OTA_MQTT_SNIFF_H
#define OTA_MQTT_SNIFF_H

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"
#include "cJSON.h"

typedef struct {
    char wifi_ssid[33];
    char wifi_password[64];
    char mqtt_broker[96];
    uint16_t mqtt_port;
    char mqtt_username[48];
    char mqtt_password[48];
    char mqtt_client_id[24];
    char subscribe_topic[64];
    bool enable_promiscuous; /* also sniff DNS/HTTP while listening */
    bool capture_dns;
    bool capture_http;
    uint32_t timeout_sec;
} ota_mqtt_sniff_config_t;

typedef struct {
    bool active;
    bool timeout;
    bool mqtt_connected;
    uint32_t mqtt_msgs;
    uint32_t urls;
    uint32_t github_urls;
    uint32_t elapsed_sec;
    uint32_t remaining_sec;
    char state[32];
    char error[64];
} ota_mqtt_sniff_state_t;

void ota_mqtt_sniff_init(void);
esp_err_t ota_mqtt_sniff_start(const ota_mqtt_sniff_config_t *cfg);
esp_err_t ota_mqtt_sniff_stop(void);
bool ota_mqtt_sniff_is_active(void);
const ota_mqtt_sniff_state_t *ota_mqtt_sniff_get_state(void);
cJSON *ota_mqtt_sniff_get_status_json(void);
const char *ota_mqtt_sniff_get_messages_json(void);
const char *ota_mqtt_sniff_get_urls_json(void);
const char *ota_mqtt_sniff_get_github_urls_json(void);

#endif /* OTA_MQTT_SNIFF_H */
