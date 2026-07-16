/**
 * ota_rogue_broker.h - MQTT MITM / rogue broker
 */

#ifndef OTA_ROGUE_BROKER_H
#define OTA_ROGUE_BROKER_H

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"
#include "cJSON.h"
#include "ota_common.h"

typedef struct {
    char wifi_ssid[33];
    char wifi_password[64];
    char mqtt_broker[96];
    uint16_t mqtt_port;
    char mqtt_username[48];
    char mqtt_password[48];
    char mqtt_client_id[24];
    uint16_t rogue_port;
    char real_broker_ip[96];
    uint16_t real_broker_port;
    bool modify_payloads;
    char modify_topic[64];
    char modify_payload[256];
    bool arp_spoof;
    uint32_t timeout_sec;
} ota_rogue_broker_config_t;

typedef struct {
    bool active;
    bool timeout;
    uint32_t mitm_count;
    uint32_t modified_count;
    uint32_t elapsed_sec;
    char state[32];
    char error[64];
} ota_rogue_broker_state_t;

void ota_rogue_broker_init(void);
esp_err_t ota_rogue_broker_start(const ota_rogue_broker_config_t *cfg);
esp_err_t ota_rogue_broker_stop(void);
bool ota_rogue_broker_is_active(void);
const ota_rogue_broker_state_t *ota_rogue_broker_get_state(void);
cJSON *ota_rogue_broker_get_status_json(void);
const char *ota_rogue_broker_get_mitm_json(void);
const char *ota_rogue_broker_get_summary_json(void);
void ota_rogue_broker_get_summary(ota_rogue_broker_summary_t *out);
bool ota_rogue_broker_set_modify_rule(const char *topic, const char *new_payload);
uint32_t ota_rogue_broker_get_mitm_count(void);
uint32_t ota_rogue_broker_get_modified_count(void);
void ota_rogue_broker_clear_mitm(void);

#endif /* OTA_ROGUE_BROKER_H */
