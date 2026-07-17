/**
 * @file wifi_radio_claim.h
 * @brief Mutual exclusion for Wi-Fi promiscuous / channel-owning modules.
 */
#ifndef WIFI_RADIO_CLAIM_H
#define WIFI_RADIO_CLAIM_H

#include <stdbool.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    WIFI_RADIO_OWNER_NONE = 0,
    WIFI_RADIO_OWNER_PROBE,
    WIFI_RADIO_OWNER_DETECTOR,
    WIFI_RADIO_OWNER_KARMA,
    WIFI_RADIO_OWNER_CSA,
    WIFI_RADIO_OWNER_PMF,
    WIFI_RADIO_OWNER_WPS,
    WIFI_RADIO_OWNER_EAP_AUDIT,
    WIFI_RADIO_OWNER_OTHER
} wifi_radio_owner_t;

void wifi_radio_claim_init(void);

/**
 * Claim exclusive radio ownership.
 * Stops the deauth detector if it was holding the promiscuous callback.
 * @return ESP_OK on success, ESP_ERR_INVALID_STATE if another owner holds it.
 */
esp_err_t wifi_radio_claim(wifi_radio_owner_t owner);

/** Release ownership. Restarts deauth detector if it was paused by claim. */
void wifi_radio_release(wifi_radio_owner_t owner);

wifi_radio_owner_t wifi_radio_owner(void);
bool wifi_radio_is_free(void);
const char *wifi_radio_owner_str(wifi_radio_owner_t owner);

#ifdef __cplusplus
}
#endif

#endif /* WIFI_RADIO_CLAIM_H */
