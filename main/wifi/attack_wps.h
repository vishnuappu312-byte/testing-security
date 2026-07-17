/**
 * @file attack_wps.h
 * @brief Passiveive WPS IE discovery / audit (no PIN/Pixie offline cracking).
 */
#ifndef ATTACK_WPS_H
#define ATTACK_WPS_H

#include <stdbool.h>
#include <stdint.h>
#include "cJSON.h"
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define WPS_MAX_ENTRIES   40
#define WPS_TIMEOUT_SEC   90

typedef struct {
    char     ssid[33];
    uint8_t  bssid[6];
    uint8_t  channel;
    int8_t   rssi;
    uint8_t  version;
    bool     configured;
    bool     locked;
    uint16_t config_methods;
    char     manufacturer[32];
    char     model[32];
    char     device_name[32];
    char     uuid[37];
    uint32_t frames_seen;
} wps_entry_t;

void attack_wps_init(void);
esp_err_t attack_wps_start(uint8_t channel /* 0 = hop */, uint16_t timeout_sec);
void attack_wps_stop(void);
bool attack_wps_is_running(void);
void attack_wps_clear(void);
cJSON *attack_wps_get_status_json(void);
cJSON *attack_wps_get_results_json(void);

#ifdef __cplusplus
}
#endif

#endif /* ATTACK_WPS_H */
