/**
 * ota_fetch.h - Direct firmware download
 */

#ifndef OTA_FETCH_H
#define OTA_FETCH_H

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"
#include "cJSON.h"

typedef struct {
    char wifi_ssid[33];
    char wifi_password[64];
    char firmware_url[128];
    bool verify_ssl;
    int url_index; /* -1 = use firmware_url; else captured URL index */
    uint32_t timeout_sec;
} ota_fetch_config_t;

typedef struct {
    bool active;
    bool timeout;
    bool success;
    uint32_t size;
    uint32_t download_count;
    char state[32];
    char error[64];
} ota_fetch_state_t;

void ota_fetch_init(void);
esp_err_t ota_fetch_start(const ota_fetch_config_t *cfg);
esp_err_t ota_fetch_stop(void);
bool ota_fetch_is_active(void);
const ota_fetch_state_t *ota_fetch_get_state(void);
cJSON *ota_fetch_get_status_json(void);
bool ota_fetch_download_by_index(int url_index);
bool ota_fetch_download_by_index_ex(int url_index, const char *wifi_ssid,
                                    const char *wifi_password, bool verify_ssl);
const char *ota_fetch_get_download_result_json(void);

#endif /* OTA_FETCH_H */
