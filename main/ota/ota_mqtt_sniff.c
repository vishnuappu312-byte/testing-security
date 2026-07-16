/**
 * ota_mqtt_sniff.c - MQTT subscribe + capture
 */

#include "ota_mqtt_sniff.h"
#include "ota_common.h"

#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include <string.h>
#include <stdio.h>

static const char *TAG = "ota_mqtt_sniff";

static ota_mqtt_sniff_config_t s_cfg;
static ota_mqtt_sniff_state_t s_state;
static volatile bool s_running = false;
static TaskHandle_t s_task = NULL;
static SemaphoreHandle_t s_exit_sem = NULL;
static esp_timer_handle_t s_timeout = NULL;
static volatile bool s_timeout_fired = false;
static int64_t s_start_ms = 0;

static void timeout_cb(void *arg)
{
    (void)arg;
    s_timeout_fired = true;
    s_running = false;
}

static void fill_conn(ota_conn_params_t *p)
{
    memset(p, 0, sizeof(*p));
    strncpy(p->wifi_ssid, s_cfg.wifi_ssid, sizeof(p->wifi_ssid) - 1);
    strncpy(p->wifi_password, s_cfg.wifi_password, sizeof(p->wifi_password) - 1);
    strncpy(p->mqtt_broker, s_cfg.mqtt_broker, sizeof(p->mqtt_broker) - 1);
    p->mqtt_port = s_cfg.mqtt_port ? s_cfg.mqtt_port : OTA_DEFAULT_MQTT_PORT;
    strncpy(p->mqtt_username, s_cfg.mqtt_username, sizeof(p->mqtt_username) - 1);
    strncpy(p->mqtt_password, s_cfg.mqtt_password, sizeof(p->mqtt_password) - 1);
    strncpy(p->mqtt_client_id,
            s_cfg.mqtt_client_id[0] ? s_cfg.mqtt_client_id : "omega_ota",
            sizeof(p->mqtt_client_id) - 1);
    strncpy(p->subscribe_topic,
            s_cfg.subscribe_topic[0] ? s_cfg.subscribe_topic : "#",
            sizeof(p->subscribe_topic) - 1);
    p->auto_subscribe = true;
}

static void task_fn(void *arg)
{
    (void)arg;
    strncpy(s_state.state, "wifi_connecting", sizeof(s_state.state) - 1);
    ota_conn_params_t conn;
    fill_conn(&conn);

    if (s_cfg.wifi_ssid[0]) {
        if (ota_common_wifi_connect(&conn) != ESP_OK) {
            strncpy(s_state.error, "wifi_failed", sizeof(s_state.error) - 1);
            strncpy(s_state.state, "error", sizeof(s_state.state) - 1);
            goto done;
        }
    }

    strncpy(s_state.state, "mqtt_connecting", sizeof(s_state.state) - 1);
    if (ota_common_mqtt_connect(&conn, NULL) != ESP_OK) {
        strncpy(s_state.error, "mqtt_failed", sizeof(s_state.error) - 1);
        strncpy(s_state.state, "error", sizeof(s_state.state) - 1);
        goto done;
    }

    s_state.mqtt_connected = true;
    strncpy(s_state.state, "waiting_ota", sizeof(s_state.state) - 1);

    if (s_cfg.enable_promiscuous && ota_common_wifi_has_ip()) {
        ota_sniffer_opts_t opts = {
            .capture_dns = s_cfg.capture_dns,
            .capture_http = s_cfg.capture_http,
            .provision_mode = false,
        };
        ota_common_sniffer_set_opts(&opts);
        ota_common_sniffer_enable(true);
    }

    while (s_running && ota_common_mqtt_is_connected()) {
        s_state.mqtt_msgs = ota_common_get_mqtt_msg_count();
        s_state.urls = ota_common_get_url_count();
        s_state.github_urls = ota_common_get_github_url_count();
        s_state.elapsed_sec = (uint32_t)((ota_common_now_ms() - s_start_ms) / 1000);
        if (s_cfg.timeout_sec > s_state.elapsed_sec)
            s_state.remaining_sec = s_cfg.timeout_sec - s_state.elapsed_sec;
        else
            s_state.remaining_sec = 0;
        vTaskDelay(pdMS_TO_TICKS(1000));
    }

done:
    ota_common_sniffer_enable(false);
    ota_common_mqtt_disconnect();
    ota_common_wifi_restore_ap();
    if (s_timeout) esp_timer_stop(s_timeout);
    s_state.active = false;
    s_state.timeout = s_timeout_fired;
    s_state.mqtt_connected = false;
    if (strcmp(s_state.state, "error") != 0)
        strncpy(s_state.state, "idle", sizeof(s_state.state) - 1);
    s_running = false;
    ota_common_release();
    if (s_exit_sem) xSemaphoreGive(s_exit_sem);
    s_task = NULL;
    vTaskDelete(NULL);
}

void ota_mqtt_sniff_init(void)
{
    if (!s_exit_sem) s_exit_sem = xSemaphoreCreateBinary();
    if (!s_timeout) {
        esp_timer_create_args_t a = { .callback = timeout_cb, .name = "ota_sniff_to" };
        esp_timer_create(&a, &s_timeout);
    }
    memset(&s_state, 0, sizeof(s_state));
    strncpy(s_state.state, "idle", sizeof(s_state.state) - 1);
}

esp_err_t ota_mqtt_sniff_start(const ota_mqtt_sniff_config_t *cfg)
{
    if (!cfg) return ESP_ERR_INVALID_ARG;
    if (s_running) return ESP_ERR_INVALID_STATE;
    esp_err_t claim = ota_common_try_claim("mqtt_sniff");
    if (claim != ESP_OK) return claim;

    s_cfg = *cfg;
    if (!s_cfg.timeout_sec) s_cfg.timeout_sec = OTA_DEFAULT_TIMEOUT_SEC;
    memset(&s_state, 0, sizeof(s_state));
    strncpy(s_state.state, "starting", sizeof(s_state.state) - 1);
    ota_common_capture_reset();
    s_timeout_fired = false;
    s_start_ms = ota_common_now_ms();
    s_state.active = true;
    s_running = true;

    if (s_timeout) {
        esp_timer_stop(s_timeout);
        esp_timer_start_once(s_timeout, (uint64_t)s_cfg.timeout_sec * 1000000ULL);
    }
    if (xTaskCreate(task_fn, "ota_sniff", OTA_TASK_STACK_SIZE, NULL,
                    OTA_TASK_PRIORITY, &s_task) != pdPASS) {
        s_running = false;
        s_state.active = false;
        ota_common_release();
        return ESP_ERR_NO_MEM;
    }
    ESP_LOGI(TAG, "MQTT sniff started");
    return ESP_OK;
}

esp_err_t ota_mqtt_sniff_stop(void)
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

bool ota_mqtt_sniff_is_active(void) { return s_state.active; }
const ota_mqtt_sniff_state_t *ota_mqtt_sniff_get_state(void) { return &s_state; }

cJSON *ota_mqtt_sniff_get_status_json(void)
{
    cJSON *o = cJSON_CreateObject();
    if (!o) return NULL;
    cJSON_AddBoolToObject(o, "active", s_state.active);
    cJSON_AddBoolToObject(o, "timeout", s_state.timeout);
    cJSON_AddBoolToObject(o, "mqtt_connected", s_state.mqtt_connected);
    cJSON_AddNumberToObject(o, "mqtt_msgs", s_state.mqtt_msgs);
    cJSON_AddNumberToObject(o, "urls", s_state.urls);
    cJSON_AddNumberToObject(o, "github_urls", s_state.github_urls);
    cJSON_AddNumberToObject(o, "elapsed_sec", s_state.elapsed_sec);
    cJSON_AddNumberToObject(o, "remaining_sec", s_state.remaining_sec);
    cJSON_AddStringToObject(o, "state", s_state.state);
    return o;
}

const char *ota_mqtt_sniff_get_messages_json(void)
{
    return ota_common_get_messages_json();
}
const char *ota_mqtt_sniff_get_urls_json(void)
{
    return ota_common_get_urls_json();
}
const char *ota_mqtt_sniff_get_github_urls_json(void)
{
    return ota_common_get_github_urls_json();
}
