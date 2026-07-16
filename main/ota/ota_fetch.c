/**
 * ota_fetch.c - Firmware download
 */

#include "ota_fetch.h"
#include "ota_common.h"

#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include <string.h>
#include <stdio.h>

static const char *TAG = "ota_fetch";

static ota_fetch_config_t s_cfg;
static ota_fetch_state_t s_state;
static volatile bool s_running = false;
static TaskHandle_t s_task = NULL;
static SemaphoreHandle_t s_exit_sem = NULL;
static esp_timer_handle_t s_timeout = NULL;

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

    strncpy(s_state.state, "wifi_connecting", sizeof(s_state.state) - 1);
    if (s_cfg.wifi_ssid[0] && ota_common_wifi_connect(&conn) != ESP_OK) {
        strncpy(s_state.error, "wifi_failed", sizeof(s_state.error) - 1);
        strncpy(s_state.state, "error", sizeof(s_state.state) - 1);
        goto done;
    }

    const char *url = NULL;
    if (s_cfg.url_index >= 0 && s_cfg.url_index < ota_common_get_url_entries()) {
        url = ota_common_get_urls()[s_cfg.url_index].url;
    } else if (s_cfg.firmware_url[0]) {
        url = s_cfg.firmware_url;
    } else if (ota_common_get_url_entries() > 0) {
        url = ota_common_get_urls()[0].url;
    }

    if (!url) {
        strncpy(s_state.error, "no_url", sizeof(s_state.error) - 1);
        strncpy(s_state.state, "error", sizeof(s_state.state) - 1);
        goto done;
    }

    strncpy(s_state.state, "downloading", sizeof(s_state.state) - 1);
    if (ota_common_download_firmware(url, s_cfg.verify_ssl) == ESP_OK) {
        uint32_t sz = 0;
        ota_common_get_firmware_buffer(&sz);
        s_state.success = true;
        s_state.size = sz;
        s_state.download_count = ota_common_get_download_count();
        strncpy(s_state.state, "downloaded", sizeof(s_state.state) - 1);
    } else {
        strncpy(s_state.error, "download_failed", sizeof(s_state.error) - 1);
        strncpy(s_state.state, "error", sizeof(s_state.state) - 1);
    }

done:
    ota_common_wifi_restore_ap();
    if (s_timeout) esp_timer_stop(s_timeout);
    s_state.active = false;
    s_running = false;
    ota_common_release();
    if (s_exit_sem) xSemaphoreGive(s_exit_sem);
    s_task = NULL;
    vTaskDelete(NULL);
}

void ota_fetch_init(void)
{
    if (!s_exit_sem) s_exit_sem = xSemaphoreCreateBinary();
    if (!s_timeout) {
        esp_timer_create_args_t a = { .callback = timeout_cb, .name = "ota_fetch_to" };
        esp_timer_create(&a, &s_timeout);
    }
    memset(&s_state, 0, sizeof(s_state));
    strncpy(s_state.state, "idle", sizeof(s_state.state) - 1);
}

esp_err_t ota_fetch_start(const ota_fetch_config_t *cfg)
{
    if (!cfg) return ESP_ERR_INVALID_ARG;
    if (s_running) return ESP_ERR_INVALID_STATE;
    esp_err_t claim = ota_common_try_claim("fetch");
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
    if (xTaskCreate(task_fn, "ota_fetch", OTA_TASK_STACK_SIZE, NULL,
                    OTA_TASK_PRIORITY, &s_task) != pdPASS) {
        s_running = false;
        s_state.active = false;
        ota_common_release();
        return ESP_ERR_NO_MEM;
    }
    ESP_LOGI(TAG, "Fetch started");
    return ESP_OK;
}

esp_err_t ota_fetch_stop(void)
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

bool ota_fetch_is_active(void) { return s_state.active; }
const ota_fetch_state_t *ota_fetch_get_state(void) { return &s_state; }

cJSON *ota_fetch_get_status_json(void)
{
    cJSON *o = cJSON_CreateObject();
    if (!o) return NULL;
    cJSON_AddBoolToObject(o, "active", s_state.active);
    cJSON_AddBoolToObject(o, "success", s_state.success);
    cJSON_AddNumberToObject(o, "size", s_state.size);
    cJSON_AddStringToObject(o, "state", s_state.state);
    return o;
}

bool ota_fetch_download_by_index(int url_index)
{
    return ota_fetch_download_by_index_ex(url_index, NULL, NULL, false);
}

bool ota_fetch_download_by_index_ex(int url_index, const char *wifi_ssid,
                                    const char *wifi_password, bool verify_ssl)
{
    if (url_index < 0 || url_index >= ota_common_get_url_entries()) return false;

    /* Prefer async fetch task when WiFi credentials are supplied so STA can join. */
    if (wifi_ssid && wifi_ssid[0]) {
        ota_fetch_config_t cfg = {0};
        strncpy(cfg.wifi_ssid, wifi_ssid, sizeof(cfg.wifi_ssid) - 1);
        if (wifi_password)
            strncpy(cfg.wifi_password, wifi_password, sizeof(cfg.wifi_password) - 1);
        cfg.url_index = url_index;
        cfg.verify_ssl = verify_ssl;
        cfg.timeout_sec = OTA_DEFAULT_TIMEOUT_SEC;
        return ota_fetch_start(&cfg) == ESP_OK;
    }

    /* Sync path: only works if already associated with a network that can reach the URL. */
    return ota_common_download_firmware(ota_common_get_urls()[url_index].url, verify_ssl) == ESP_OK;
}

const char *ota_fetch_get_download_result_json(void)
{
    return ota_common_get_download_result_json();
}
