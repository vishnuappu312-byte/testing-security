/**
 * @file attack_pmf.h
 * @brief Passiveive PMF / 802.11w capability detection from beacons.
 */
#ifndef ATTACK_PMF_H
#define ATTACK_PMF_H

#include <stdbool.h>
#include <stdint.h>
#include "cJSON.h"
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

#define PMF_MAX_ENTRIES   48
#define PMF_TIMEOUT_SEC   90

typedef struct {
    char     ssid[33];
    uint8_t  bssid[6];
    uint8_t  channel;
    int8_t   rssi;
    uint8_t  pmf_state;   /* wifi_pmf_state_t */
    bool     mfpc;
    bool     mfpr;
    bool     rsn_present;
    uint32_t frames_seen;
} pmf_entry_t;

void attack_pmf_init(void);
esp_err_t attack_pmf_start(uint8_t channel /* 0 = hop */, uint16_t timeout_sec);
void attack_pmf_stop(void);
bool attack_pmf_is_running(void);
void attack_pmf_clear(void);
cJSON *attack_pmf_get_status_json(void);
cJSON *attack_pmf_get_results_json(void);

#ifdef __cplusplus
}
#endif

#endif /* ATTACK_PMF_H */
