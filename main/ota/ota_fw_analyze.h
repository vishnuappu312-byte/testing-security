/**
 * ota_fw_analyze.h - Firmware binary secret extraction
 */

#ifndef OTA_FW_ANALYZE_H
#define OTA_FW_ANALYZE_H

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"
#include "cJSON.h"
#include "ota_common.h"

typedef struct {
    char wifi_ssid[33];
    char wifi_password[64];
    char firmware_url[128];
    int url_index; /* -1 unused */
    bool deep_scan;
    bool extract_strings;
    bool verify_ssl;
    uint32_t timeout_sec;
} ota_fw_analyze_config_t;

typedef struct {
    bool active;
    bool timeout;
    uint32_t secrets;
    uint32_t high_confidence;
    uint32_t firmware_size;
    char state[32];
    char error[64];
} ota_fw_analyze_state_t;

void ota_fw_analyze_init(void);
esp_err_t ota_fw_analyze_start(const ota_fw_analyze_config_t *cfg);
esp_err_t ota_fw_analyze_stop(void);
bool ota_fw_analyze_is_active(void);
const ota_fw_analyze_state_t *ota_fw_analyze_get_state(void);
cJSON *ota_fw_analyze_get_status_json(void);
int ota_fw_analyze_run(void);
const char *ota_fw_analyze_get_secrets_json(void);
const char *ota_fw_analyze_get_summary_json(void);
void ota_fw_analyze_get_summary(ota_fw_analysis_summary_t *out);
uint32_t ota_fw_analyze_get_secret_count(void);
uint32_t ota_fw_analyze_get_high_confidence_count(void);
void ota_fw_analyze_clear_secrets(void);

#endif /* OTA_FW_ANALYZE_H */
