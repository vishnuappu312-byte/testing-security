/**
 * @file attack_csa.h
 * @brief Channel Switch Announcement injection module.
 */
#ifndef ATTACK_CSA_H
#define ATTACK_CSA_H

#include <stdbool.h>
#include <stdint.h>
#include "cJSON.h"
#include "esp_err.h"
#include "esp_wifi_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define CSA_TIMEOUT_SEC  60

typedef struct {
    wifi_ap_record_t target;
    uint8_t dest_mac[6];       /* broadcast if all 0xFF */
    uint8_t new_channel;
    uint8_t count;
    uint8_t mode;
    bool    use_action;
    bool    use_beacon;
    uint16_t interval_ms;
    uint16_t timeout_sec;
} attack_csa_config_t;

void attack_csa_init(void);
esp_err_t attack_csa_start(const attack_csa_config_t *cfg);
void attack_csa_stop(void);
bool attack_csa_is_running(void);
cJSON *attack_csa_get_status_json(void);

#ifdef __cplusplus
}
#endif

#endif /* ATTACK_CSA_H */
