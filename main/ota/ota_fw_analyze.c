/**
 * ota_fw_analyze.c - Firmware binary secret extraction
 */

#include "ota_fw_analyze.h"
#include "ota_common.h"

#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static const char *TAG = "ota_fw_analyze";

static ota_fw_analyze_config_t s_cfg;
static ota_fw_analyze_state_t s_state;
static volatile bool s_running = false;
static TaskHandle_t s_task = NULL;
static SemaphoreHandle_t s_exit_sem = NULL;
static esp_timer_handle_t s_timeout = NULL;

static ota_fw_secret_t fw_secrets[OTA_MAX_FW_SECRETS];
static int fw_secret_count = 0;
static volatile uint32_t fw_high_confidence_count = 0;
static ota_fw_analysis_summary_t fw_analysis_summary;

static void timeout_cb(void *arg)
{
    (void)arg;
    s_state.timeout = true;
    s_running = false;
}

/* Internal helper: scan a binary buffer for known secret patterns */
static void scan_for_pattern(const uint8_t *data, uint32_t data_len,
                             const char *prefix, const char *type, int confidence,
                             bool is_sensitive)
{
    if (!data || data_len == 0) return;
    int prefix_len = (int)strlen(prefix);

    for (uint32_t i = 0; i < data_len - (uint32_t)prefix_len && fw_secret_count < OTA_MAX_FW_SECRETS; i++) {
        if (memcmp(data + i, prefix, prefix_len) == 0) {
            uint32_t val_start = i + prefix_len;

            while (val_start < data_len && (data[val_start] == ' ' ||
                   data[val_start] == '=' || data[val_start] == ':' ||
                   data[val_start] == '"' || data[val_start] == '\'')) {
                val_start++;
            }

            char value[OTA_MAX_SECRET_VALUE_LEN] = "";
            int vi = 0;
            uint32_t j = val_start;
            while (j < data_len && vi < OTA_MAX_SECRET_VALUE_LEN - 1) {
                if (data[j] >= 0x20 && data[j] < 0x7F) {
                    value[vi++] = (char)data[j++];
                } else {
                    break;
                }
            }
            value[vi] = '\0';

            if (vi >= 4 && is_sensitive) {
                ota_fw_secret_t *secret = &fw_secrets[fw_secret_count];
                strncpy(secret->type, type, OTA_MAX_SECRET_TYPE_LEN - 1);
                strncpy(secret->value, value, OTA_MAX_SECRET_VALUE_LEN - 1);
                snprintf(secret->context, OTA_MAX_SECRET_CONTEXT_LEN, "%s%.*s",
                         prefix, vi > 30 ? 30 : vi, value);
                secret->offset = i;
                secret->confidence = confidence;

                fw_secret_count++;
                if (confidence >= 80) fw_high_confidence_count++;
                ESP_LOGI(TAG, "FW_SECRET: [%s] at offset %u (confidence=%d)",
                         type, (unsigned)i, confidence);
            }
        }
    }
}

int ota_fw_analyze_run(void)
{
    uint32_t firmware_size = 0;
    uint8_t *firmware_buffer = ota_common_get_firmware_buffer(&firmware_size);
    if (!firmware_buffer || firmware_size == 0) {
        ESP_LOGW(TAG, "No firmware data to analyze");
        return 0;
    }

    strncpy(s_state.state, "fw_scanning", sizeof(s_state.state) - 1);
    fw_secret_count = 0;
    fw_high_confidence_count = 0;
    memset(fw_secrets, 0, sizeof(fw_secrets));
    memset(&fw_analysis_summary, 0, sizeof(fw_analysis_summary));
    fw_analysis_summary.firmware_size = firmware_size;
    s_state.firmware_size = firmware_size;

    ESP_LOGI(TAG, "Scanning %u bytes for secrets", (unsigned)firmware_size);

    const char *wifi_patterns[] = {
        "wifi_ssid", "ssid=", "WIFI_SSID", "WIFI_PASS",
        "wifi_password", "wifi_pass", "ap_password", "ap_pass",
        "WIFI_PASSWORD", "AP_PASSWORD", NULL
    };
    for (int i = 0; wifi_patterns[i] && fw_secret_count < OTA_MAX_FW_SECRETS; i++) {
        bool sensitive = (strstr(wifi_patterns[i], "pass") != NULL ||
                          strstr(wifi_patterns[i], "PASS") != NULL);
        scan_for_pattern(firmware_buffer, firmware_size,
                         wifi_patterns[i], "wifi_cred",
                         sensitive ? 90 : 70, true);
    }

    const char *mqtt_patterns[] = {
        "mqtt_broker", "mqtt_password", "mqtt_username", "mqtt_user",
        "MQTT_BROKER", "MQTT_PASSWORD", "MQTT_USERNAME", "MQTT_PASS",
        "mqtt://", "MQTT_URL", NULL
    };
    for (int i = 0; mqtt_patterns[i] && fw_secret_count < OTA_MAX_FW_SECRETS; i++) {
        bool sensitive = (strstr(mqtt_patterns[i], "pass") != NULL ||
                          strstr(mqtt_patterns[i], "PASS") != NULL);
        scan_for_pattern(firmware_buffer, firmware_size,
                         mqtt_patterns[i], "mqtt_cred",
                         sensitive ? 95 : 75, true);
    }

    const char *api_patterns[] = {
        "api_key", "API_KEY", "apikey", "ApiKey",
        "access_token", "ACCESS_TOKEN", "auth_token", "AUTH_TOKEN",
        "Bearer ", "Authorization:", "token=", "TOKEN=",
        "private_token", "PRIVATE_TOKEN", "ghp_", "gho_",
        "sk_live", "sk_test", "pk_live", "pk_test", NULL
    };
    for (int i = 0; api_patterns[i] && fw_secret_count < OTA_MAX_FW_SECRETS; i++) {
        scan_for_pattern(firmware_buffer, firmware_size,
                         api_patterns[i], "api_key", 95, true);
    }

    const char *cert_patterns[] = {
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN CERTIFICATE-----",
        "-----BEGIN PUBLIC KEY-----",
        "MIIBIjANBgkq",
        NULL
    };
    for (int i = 0; cert_patterns[i] && fw_secret_count < OTA_MAX_FW_SECRETS; i++) {
        scan_for_pattern(firmware_buffer, firmware_size,
                         cert_patterns[i], "certificate", 98, true);
    }

    const char *url_patterns[] = {
        "https://", "http://", "mqtt://", "mqtts://",
        "wss://", "ws://", "ftp://",
        NULL
    };
    for (int i = 0; url_patterns[i] && fw_secret_count < OTA_MAX_FW_SECRETS; i++) {
        const char *proto = url_patterns[i];
        int proto_len = (int)strlen(proto);
        for (uint32_t j = 0; j < firmware_size - 10 && fw_secret_count < OTA_MAX_FW_SECRETS; j++) {
            if (memcmp(firmware_buffer + j, proto, proto_len) == 0) {
                char url[256] = "";
                int ui = 0;
                uint32_t k = j;
                while (k < firmware_size && ui < 255 &&
                       firmware_buffer[k] >= 0x20 && firmware_buffer[k] < 0x7F &&
                       firmware_buffer[k] != '"' && firmware_buffer[k] != '\'' &&
                       firmware_buffer[k] != ' ' && firmware_buffer[k] != '}') {
                    url[ui++] = (char)firmware_buffer[k++];
                }
                url[ui] = '\0';
                if (ui >= 12) {
                    ota_fw_secret_t *secret = &fw_secrets[fw_secret_count];
                    strncpy(secret->type, "url", OTA_MAX_SECRET_TYPE_LEN - 1);
                    strncpy(secret->value, url, OTA_MAX_SECRET_VALUE_LEN - 1);
                    strncpy(secret->context, url, OTA_MAX_SECRET_CONTEXT_LEN - 1);
                    secret->context[OTA_MAX_SECRET_CONTEXT_LEN - 1] = '\0';
                    secret->offset = j;
                    secret->confidence = 60;
                    fw_secret_count++;
                }
                j = k;
            }
        }
    }

    const char *modbus_patterns[] = {
        "modbus", "MODBUS", "modbus_driver", "ModbusDriver",
        "modbus_url", "MODBUS_URL", "driver_url", "DRIVER_URL",
        NULL
    };
    for (int i = 0; modbus_patterns[i] && fw_secret_count < OTA_MAX_FW_SECRETS; i++) {
        scan_for_pattern(firmware_buffer, firmware_size,
                         modbus_patterns[i], "modbus_config", 70, true);
    }

    fw_analysis_summary.secrets_found = (uint32_t)fw_secret_count;
    fw_analysis_summary.high_confidence_count = fw_high_confidence_count;

    for (int i = 0; i < fw_secret_count; i++) {
        if (strcmp(fw_secrets[i].type, "wifi_cred") == 0) fw_analysis_summary.has_wifi_creds = true;
        if (strcmp(fw_secrets[i].type, "mqtt_cred") == 0) fw_analysis_summary.has_mqtt_creds = true;
        if (strcmp(fw_secrets[i].type, "api_key") == 0) fw_analysis_summary.has_api_keys = true;
        if (strcmp(fw_secrets[i].type, "certificate") == 0) {
            if (strstr(fw_secrets[i].context, "PRIVATE KEY")) fw_analysis_summary.has_private_keys = true;
            else fw_analysis_summary.has_certificates = true;
        }
        if (strcmp(fw_secrets[i].type, "url") == 0) fw_analysis_summary.has_hardcoded_urls = true;
        if (strcmp(fw_secrets[i].type, "modbus_config") == 0) fw_analysis_summary.has_modbus_config = true;
    }

    s_state.secrets = (uint32_t)fw_secret_count;
    s_state.high_confidence = fw_high_confidence_count;
    strncpy(s_state.state, "fw_complete", sizeof(s_state.state) - 1);

    ESP_LOGI(TAG, "Complete - %d secrets, %u high confidence",
             fw_secret_count, (unsigned)fw_high_confidence_count);
    return fw_secret_count;
}

static void task_fn(void *arg)
{
    (void)arg;
    ota_conn_params_t conn = {0};
    strncpy(conn.wifi_ssid, s_cfg.wifi_ssid, sizeof(conn.wifi_ssid) - 1);
    strncpy(conn.wifi_password, s_cfg.wifi_password, sizeof(conn.wifi_password) - 1);

    uint32_t existing_size = 0;
    ota_common_get_firmware_buffer(&existing_size);
    bool need_download = (existing_size == 0);

    const char *url = NULL;
    if (s_cfg.firmware_url[0]) {
        url = s_cfg.firmware_url;
        need_download = true;
    } else if (s_cfg.url_index >= 0 && s_cfg.url_index < ota_common_get_url_entries()) {
        ota_url_entry_t *entries = ota_common_get_urls();
        url = entries[s_cfg.url_index].url;
        if (!entries[s_cfg.url_index].downloaded) need_download = true;
        else need_download = (existing_size == 0);
    }

    if (need_download && url) {
        if (s_cfg.wifi_ssid[0]) {
            strncpy(s_state.state, "wifi_connecting", sizeof(s_state.state) - 1);
            if (ota_common_wifi_connect(&conn) != ESP_OK) {
                strncpy(s_state.error, "wifi_failed", sizeof(s_state.error) - 1);
                strncpy(s_state.state, "error", sizeof(s_state.state) - 1);
                goto done;
            }
        }
        strncpy(s_state.state, "downloading", sizeof(s_state.state) - 1);
        if (ota_common_download_firmware(url, s_cfg.verify_ssl) != ESP_OK) {
            strncpy(s_state.error, "download_failed", sizeof(s_state.error) - 1);
            strncpy(s_state.state, "error", sizeof(s_state.state) - 1);
            goto done;
        }
    }

    strncpy(s_state.state, "fw_analyzing", sizeof(s_state.state) - 1);
    int found = ota_fw_analyze_run();
    if (found == 0 && s_state.firmware_size == 0) {
        strncpy(s_state.error, "no_firmware", sizeof(s_state.error) - 1);
        strncpy(s_state.state, "error", sizeof(s_state.state) - 1);
    } else {
        ESP_LOGI(TAG, "Found %d secrets (%u high confidence)",
                 found, (unsigned)fw_high_confidence_count);
    }

done:
    ota_common_wifi_restore_ap();
    if (s_timeout) esp_timer_stop(s_timeout);
    s_state.active = false;
    s_state.secrets = (uint32_t)fw_secret_count;
    s_state.high_confidence = fw_high_confidence_count;
    if (strcmp(s_state.state, "error") != 0 && strcmp(s_state.state, "fw_complete") != 0)
        strncpy(s_state.state, "idle", sizeof(s_state.state) - 1);
    s_running = false;
    ota_common_release();
    if (s_exit_sem) xSemaphoreGive(s_exit_sem);
    s_task = NULL;
    vTaskDelete(NULL);
}

void ota_fw_analyze_init(void)
{
    if (!s_exit_sem) s_exit_sem = xSemaphoreCreateBinary();
    if (!s_timeout) {
        esp_timer_create_args_t a = { .callback = timeout_cb, .name = "ota_fw_to" };
        esp_timer_create(&a, &s_timeout);
    }
    memset(&s_state, 0, sizeof(s_state));
    memset(&fw_analysis_summary, 0, sizeof(fw_analysis_summary));
    strncpy(s_state.state, "idle", sizeof(s_state.state) - 1);
}

esp_err_t ota_fw_analyze_start(const ota_fw_analyze_config_t *cfg)
{
    if (!cfg) return ESP_ERR_INVALID_ARG;
    if (s_running) return ESP_ERR_INVALID_STATE;
    esp_err_t claim = ota_common_try_claim("fw_analyze");
    if (claim != ESP_OK) return claim;

    s_cfg = *cfg;
    if (!s_cfg.timeout_sec) s_cfg.timeout_sec = OTA_DEFAULT_TIMEOUT_SEC;
    memset(&s_state, 0, sizeof(s_state));
    strncpy(s_state.state, "starting", sizeof(s_state.state) - 1);
    s_state.active = true;
    s_running = true;

    if (s_timeout) {
        esp_timer_stop(s_timeout);
        esp_timer_start_once(s_timeout, (uint64_t)s_cfg.timeout_sec * 1000000ULL);
    }
    if (xTaskCreate(task_fn, "ota_fw", OTA_TASK_STACK_SIZE, NULL,
                    OTA_TASK_PRIORITY, &s_task) != pdPASS) {
        s_running = false;
        s_state.active = false;
        ota_common_release();
        return ESP_ERR_NO_MEM;
    }
    ESP_LOGI(TAG, "Firmware analyze started");
    return ESP_OK;
}

esp_err_t ota_fw_analyze_stop(void)
{
    if (!s_running) return ESP_OK;
    s_running = false;
    if (s_exit_sem &&
        xSemaphoreTake(s_exit_sem, pdMS_TO_TICKS(OTA_STOP_SEM_TIMEOUT_MS)) != pdTRUE) {
        if (s_task) { vTaskDelete(s_task); s_task = NULL; }
        ota_common_wifi_restore_ap();
        ota_common_release();
        s_state.active = false;
    }
    if (s_timeout) esp_timer_stop(s_timeout);
    return ESP_OK;
}

bool ota_fw_analyze_is_active(void) { return s_state.active; }
const ota_fw_analyze_state_t *ota_fw_analyze_get_state(void) { return &s_state; }

cJSON *ota_fw_analyze_get_status_json(void)
{
    cJSON *o = cJSON_CreateObject();
    if (!o) return NULL;
    cJSON_AddBoolToObject(o, "active", s_state.active);
    cJSON_AddBoolToObject(o, "timeout", s_state.timeout);
    cJSON_AddNumberToObject(o, "secrets", s_state.secrets);
    cJSON_AddNumberToObject(o, "high_confidence", s_state.high_confidence);
    cJSON_AddNumberToObject(o, "firmware_size", s_state.firmware_size);
    cJSON_AddStringToObject(o, "state", s_state.state);
    if (s_state.error[0]) cJSON_AddStringToObject(o, "error", s_state.error);
    return o;
}

const char *ota_fw_analyze_get_secrets_json(void)
{
    char *json_buf = ota_common_json_large_b();
    if (!json_buf) return "[]";

    cJSON *root = cJSON_CreateArray();
    for (int i = 0; i < fw_secret_count; i++) {
        cJSON *item = cJSON_CreateObject();
        cJSON_AddStringToObject(item, "type", fw_secrets[i].type);
        cJSON_AddStringToObject(item, "value", fw_secrets[i].value);
        cJSON_AddStringToObject(item, "context", fw_secrets[i].context);
        cJSON_AddNumberToObject(item, "offset", fw_secrets[i].offset);
        cJSON_AddNumberToObject(item, "confidence", fw_secrets[i].confidence);
        cJSON_AddItemToArray(root, item);
    }

    char *printed = cJSON_PrintUnformatted(root);
    snprintf(json_buf, OTA_JSON_LARGE_SZ, "%s", printed ? printed : "[]");
    cJSON_Delete(root);
    free(printed);
    return json_buf;
}

const char *ota_fw_analyze_get_summary_json(void)
{
    char *json_buf = ota_common_json_2k();
    if (!json_buf) return "{}";

    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "firmware_size", fw_analysis_summary.firmware_size);
    cJSON_AddNumberToObject(root, "secrets_found", fw_analysis_summary.secrets_found);
    cJSON_AddNumberToObject(root, "high_confidence_count", fw_analysis_summary.high_confidence_count);
    cJSON_AddBoolToObject(root, "has_wifi_creds", fw_analysis_summary.has_wifi_creds);
    cJSON_AddBoolToObject(root, "has_mqtt_creds", fw_analysis_summary.has_mqtt_creds);
    cJSON_AddBoolToObject(root, "has_api_keys", fw_analysis_summary.has_api_keys);
    cJSON_AddBoolToObject(root, "has_certificates", fw_analysis_summary.has_certificates);
    cJSON_AddBoolToObject(root, "has_private_keys", fw_analysis_summary.has_private_keys);
    cJSON_AddBoolToObject(root, "has_hardcoded_urls", fw_analysis_summary.has_hardcoded_urls);
    cJSON_AddBoolToObject(root, "has_modbus_config", fw_analysis_summary.has_modbus_config);

    char *printed = cJSON_PrintUnformatted(root);
    snprintf(json_buf, OTA_JSON_2K_SZ, "%s", printed ? printed : "{}");
    cJSON_Delete(root);
    free(printed);
    return json_buf;
}

void ota_fw_analyze_get_summary(ota_fw_analysis_summary_t *out)
{
    if (out) *out = fw_analysis_summary;
}

uint32_t ota_fw_analyze_get_secret_count(void)
{
    return (uint32_t)fw_secret_count;
}

uint32_t ota_fw_analyze_get_high_confidence_count(void)
{
    return fw_high_confidence_count;
}

void ota_fw_analyze_clear_secrets(void)
{
    fw_secret_count = 0;
    fw_high_confidence_count = 0;
    memset(fw_secrets, 0, sizeof(fw_secrets));
    memset(&fw_analysis_summary, 0, sizeof(fw_analysis_summary));
    s_state.secrets = 0;
    s_state.high_confidence = 0;
}
