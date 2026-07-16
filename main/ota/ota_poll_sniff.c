/**
 * ota_poll_sniff.c - DNS/HTTP poll sniff
 */

#include "ota_poll_sniff.h"
#include "ota_common.h"

#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include <string.h>
#include <stdio.h>

static const char *TAG = "ota_poll_sniff";

static ota_poll_sniff_config_t s_cfg;
static ota_poll_sniff_state_t s_state;
static volatile bool s_running = false;
static TaskHandle_t s_task = NULL;
static SemaphoreHandle_t s_exit_sem = NULL;
static esp_timer_handle_t s_timeout = NULL;
static int64_t s_start_ms = 0;

static void timeout_cb(void *arg)
{
    (void)arg;
    s_state.timeout = true;
    s_running = false;
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

    ota_common_dns_http_reset();
    ota_sniffer_opts_t opts = {
        .capture_dns = s_cfg.capture_dns,
        .capture_http = s_cfg.capture_http,
        .provision_mode = false,
    };
    memcpy(opts.target_device_ip, s_cfg.target_device_ip, 4);
    ota_common_sniffer_set_opts(&opts);
    ota_common_sniffer_enable(true);
    strncpy(s_state.state, "poll_sniffing", sizeof(s_state.state) - 1);

    while (s_running) {
        s_state.dns_count = ota_common_get_dns_count();
        s_state.http_count = ota_common_get_http_count();
        s_state.ota_dns_count = ota_common_get_ota_dns_count();
        s_state.ota_http_count = ota_common_get_ota_http_count();
        s_state.urls = ota_common_get_url_count();
        s_state.elapsed_sec = (uint32_t)((ota_common_now_ms() - s_start_ms) / 1000);
        if (s_cfg.timeout_sec > s_state.elapsed_sec)
            s_state.remaining_sec = s_cfg.timeout_sec - s_state.elapsed_sec;
        else
            s_state.remaining_sec = 0;
        if (s_state.ota_dns_count)
            strncpy(s_state.state, "dns_found", sizeof(s_state.state) - 1);
        if (s_state.ota_http_count)
            strncpy(s_state.state, "http_found", sizeof(s_state.state) - 1);
        vTaskDelay(pdMS_TO_TICKS(1000));
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

void ota_poll_sniff_init(void)
{
    if (!s_exit_sem) s_exit_sem = xSemaphoreCreateBinary();
    if (!s_timeout) {
        esp_timer_create_args_t a = { .callback = timeout_cb, .name = "ota_poll_to" };
        esp_timer_create(&a, &s_timeout);
    }
    memset(&s_state, 0, sizeof(s_state));
    strncpy(s_state.state, "idle", sizeof(s_state.state) - 1);
}

esp_err_t ota_poll_sniff_start(const ota_poll_sniff_config_t *cfg)
{
    if (!cfg) return ESP_ERR_INVALID_ARG;
    if (s_running) return ESP_ERR_INVALID_STATE;
    esp_err_t claim = ota_common_try_claim("poll_sniff");
    if (claim != ESP_OK) return claim;

    s_cfg = *cfg;
    if (!s_cfg.timeout_sec) s_cfg.timeout_sec = OTA_DEFAULT_TIMEOUT_SEC;
    memset(&s_state, 0, sizeof(s_state));
    strncpy(s_state.state, "starting", sizeof(s_state.state) - 1);
    s_start_ms = ota_common_now_ms();
    s_state.active = true;
    s_running = true;
    if (s_timeout) {
        esp_timer_stop(s_timeout);
        esp_timer_start_once(s_timeout, (uint64_t)s_cfg.timeout_sec * 1000000ULL);
    }
    if (xTaskCreate(task_fn, "ota_poll", OTA_TASK_STACK_SIZE, NULL,
                    OTA_TASK_PRIORITY, &s_task) != pdPASS) {
        s_running = false;
        s_state.active = false;
        ota_common_release();
        return ESP_ERR_NO_MEM;
    }
    ESP_LOGI(TAG, "Poll sniff started");
    return ESP_OK;
}

esp_err_t ota_poll_sniff_stop(void)
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

bool ota_poll_sniff_is_active(void) { return s_state.active; }
const ota_poll_sniff_state_t *ota_poll_sniff_get_state(void) { return &s_state; }

cJSON *ota_poll_sniff_get_status_json(void)
{
    cJSON *o = cJSON_CreateObject();
    if (!o) return NULL;
    cJSON_AddBoolToObject(o, "active", s_state.active);
    cJSON_AddBoolToObject(o, "timeout", s_state.timeout);
    cJSON_AddNumberToObject(o, "dns_count", s_state.dns_count);
    cJSON_AddNumberToObject(o, "http_count", s_state.http_count);
    cJSON_AddNumberToObject(o, "ota_dns_count", s_state.ota_dns_count);
    cJSON_AddNumberToObject(o, "ota_http_count", s_state.ota_http_count);
    cJSON_AddNumberToObject(o, "urls", s_state.urls);
    cJSON_AddNumberToObject(o, "elapsed_sec", s_state.elapsed_sec);
    cJSON_AddNumberToObject(o, "remaining_sec", s_state.remaining_sec);
    cJSON_AddStringToObject(o, "state", s_state.state);
    return o;
}

const char *ota_poll_sniff_get_dns_json(void) { return ota_common_get_dns_entries_json(); }
const char *ota_poll_sniff_get_http_json(void) { return ota_common_get_http_entries_json(); }
const char *ota_poll_sniff_get_urls_json(void) { return ota_common_get_urls_json(); }
