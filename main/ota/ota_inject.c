/**
 * ota_inject.c - MQTT OTA inject
 */

#include "ota_inject.h"
#include "ota_common.h"

#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include <string.h>
#include <stdio.h>

static const char *TAG = "ota_inject";

static ota_inject_config_t s_cfg;
static ota_inject_state_t s_state;
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
    strncpy(conn.mqtt_broker, s_cfg.mqtt_broker, sizeof(conn.mqtt_broker) - 1);
    conn.mqtt_port = s_cfg.mqtt_port ? s_cfg.mqtt_port : OTA_DEFAULT_MQTT_PORT;
    strncpy(conn.mqtt_username, s_cfg.mqtt_username, sizeof(conn.mqtt_username) - 1);
    strncpy(conn.mqtt_password, s_cfg.mqtt_password, sizeof(conn.mqtt_password) - 1);
    strncpy(conn.mqtt_client_id,
            s_cfg.mqtt_client_id[0] ? s_cfg.mqtt_client_id : "omega_ota",
            sizeof(conn.mqtt_client_id) - 1);
    conn.auto_subscribe = false;

    strncpy(s_state.state, "wifi_connecting", sizeof(s_state.state) - 1);
    if (s_cfg.wifi_ssid[0] && ota_common_wifi_connect(&conn) != ESP_OK) {
        strncpy(s_state.error, "wifi_failed", sizeof(s_state.error) - 1);
        strncpy(s_state.state, "error", sizeof(s_state.state) - 1);
        goto done;
    }

    strncpy(s_state.state, "mqtt_connecting", sizeof(s_state.state) - 1);
    if (ota_common_mqtt_connect(&conn, NULL) != ESP_OK) {
        strncpy(s_state.error, "mqtt_failed", sizeof(s_state.error) - 1);
        strncpy(s_state.state, "error", sizeof(s_state.state) - 1);
        goto done;
    }

    strncpy(s_state.state, "injecting", sizeof(s_state.state) - 1);
    uint32_t count = s_cfg.inject_count ? s_cfg.inject_count : 1;
    for (uint32_t i = 0; i < count && s_running; i++) {
        if (ota_common_mqtt_publish(s_cfg.inject_topic, s_cfg.inject_payload, 1) == ESP_OK) {
            s_state.injected++;
            ota_common_store_message(s_cfg.inject_topic, strlen(s_cfg.inject_topic),
                                     s_cfg.inject_payload, strlen(s_cfg.inject_payload));
            ota_common_scan_payload_for_urls(s_cfg.inject_topic, s_cfg.inject_payload,
                                             strlen(s_cfg.inject_payload));
        } else {
            s_state.failed++;
        }
        if (i + 1 < count && s_cfg.inject_interval_ms)
            vTaskDelay(pdMS_TO_TICKS(s_cfg.inject_interval_ms));
    }

    strncpy(s_state.state, "injected", sizeof(s_state.state) - 1);
    while (s_running && ota_common_mqtt_is_connected()) {
        s_state.elapsed_sec = (uint32_t)((ota_common_now_ms() - s_start_ms) / 1000);
        vTaskDelay(pdMS_TO_TICKS(1000));
    }

done:
    ota_common_mqtt_disconnect();
    ota_common_wifi_restore_ap();
    if (s_timeout) esp_timer_stop(s_timeout);
    s_state.active = false;
    if (strcmp(s_state.state, "error") != 0)
        strncpy(s_state.state, "idle", sizeof(s_state.state) - 1);
    s_running = false;
    ota_common_release();
    if (s_exit_sem) xSemaphoreGive(s_exit_sem);
    s_task = NULL;
    vTaskDelete(NULL);
}

void ota_inject_init(void)
{
    if (!s_exit_sem) s_exit_sem = xSemaphoreCreateBinary();
    if (!s_timeout) {
        esp_timer_create_args_t a = { .callback = timeout_cb, .name = "ota_inj_to" };
        esp_timer_create(&a, &s_timeout);
    }
    memset(&s_state, 0, sizeof(s_state));
    strncpy(s_state.state, "idle", sizeof(s_state.state) - 1);
}

esp_err_t ota_inject_start(const ota_inject_config_t *cfg)
{
    if (!cfg) return ESP_ERR_INVALID_ARG;
    if (s_running) return ESP_ERR_INVALID_STATE;
    esp_err_t claim = ota_common_try_claim("inject");
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
    if (xTaskCreate(task_fn, "ota_inject", OTA_TASK_STACK_SIZE, NULL,
                    OTA_TASK_PRIORITY, &s_task) != pdPASS) {
        s_running = false;
        s_state.active = false;
        ota_common_release();
        return ESP_ERR_NO_MEM;
    }
    ESP_LOGI(TAG, "Inject started");
    return ESP_OK;
}

esp_err_t ota_inject_stop(void)
{
    if (!s_running) return ESP_OK;
    s_running = false;
    if (s_exit_sem &&
        xSemaphoreTake(s_exit_sem, pdMS_TO_TICKS(OTA_STOP_SEM_TIMEOUT_MS)) != pdTRUE) {
        if (s_task) { vTaskDelete(s_task); s_task = NULL; }
        ota_common_mqtt_disconnect();
        ota_common_wifi_restore_ap();
        ota_common_release();
        s_state.active = false;
    }
    if (s_timeout) esp_timer_stop(s_timeout);
    return ESP_OK;
}

bool ota_inject_is_active(void) { return s_state.active; }
const ota_inject_state_t *ota_inject_get_state(void) { return &s_state; }

cJSON *ota_inject_get_status_json(void)
{
    cJSON *o = cJSON_CreateObject();
    if (!o) return NULL;
    cJSON_AddBoolToObject(o, "active", s_state.active);
    cJSON_AddNumberToObject(o, "injected", s_state.injected);
    cJSON_AddNumberToObject(o, "failed", s_state.failed);
    cJSON_AddStringToObject(o, "state", s_state.state);
    return o;
}

bool ota_inject_message(const char *topic, const char *payload)
{
    if (!topic) return false;
    if (ota_common_mqtt_publish(topic, payload, 1) != ESP_OK) return false;
    ota_common_store_message(topic, strlen(topic), payload ? payload : "",
                             payload ? strlen(payload) : 0);
    return true;
}
