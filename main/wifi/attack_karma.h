/**
 * @file attack_karma.h
 * @brief Karma/MANA-style probe responder for ESP32 lab use.
 */
#ifndef ATTACK_KARMA_H
#define ATTACK_KARMA_H

#include <stdbool.h>
#include <stdint.h>
#include "cJSON.h"
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define KARMA_MAX_ENTRIES   40
#define KARMA_SSID_MAX      33
#define KARMA_TIMEOUT_SEC   180

typedef struct {
    char     ssid[KARMA_SSID_MAX];
    uint8_t  ssid_len;
    uint8_t  client_mac[6];
    uint8_t  bssid[6];
    uint8_t  channel;
    int8_t   rssi;
    uint32_t probe_count;
    uint32_t response_count;
} karma_entry_t;

void attack_karma_init(void);
esp_err_t attack_karma_start(bool respond_broadcast, bool send_beacons, uint16_t timeout_sec);
void attack_karma_stop(void);
bool attack_karma_is_running(void);
void attack_karma_clear(void);
cJSON *attack_karma_get_status_json(void);
cJSON *attack_karma_get_results_json(void);

#ifdef __cplusplus
}
#endif

#endif /* ATTACK_KARMA_H */
