/**
 * ota_inject.h - MQTT OTA message injection
 */

#ifndef OTA_INJECT_H
#define OTA_INJECT_H

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
    char inject_topic[64];
    char inject_payload[256];
    uint32_t inject_count;
    uint32_t inject_interval_ms;
    uint32_t timeout_sec;
} ota_inject_config_t;

typedef struct {
    bool active;
    bool timeout;
    uint32_t injected;
    uint32_t failed;
    uint32_t elapsed_sec;
    char state[32];
    char error[64];
} ota_inject_state_t;

void ota_inject_init(void);
esp_err_t ota_inject_start(const ota_inject_config_t *cfg);
esp_err_t ota_inject_stop(void);
bool ota_inject_is_active(void);
const ota_inject_state_t *ota_inject_get_state(void);
cJSON *ota_inject_get_status_json(void);
bool ota_inject_message(const char *topic, const char *payload);

#endif /* OTA_INJECT_H */
