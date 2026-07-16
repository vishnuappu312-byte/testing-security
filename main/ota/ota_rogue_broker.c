/**
 * ota_rogue_broker.c - MQTT "MITM" via client subscribe + optional republish
 *
 * NOTE: This module connects as a normal MQTT client to the real broker.
 * It does not start a listening broker on rogue_port. True device MITM would
 * require hosting MQTT on rogue_port and redirecting the target to it.
 */

#include "ota_rogue_broker.h"
#include "ota_common.h"

#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static const char *TAG = "ota_rogue_broker";

static ota_rogue_broker_config_t s_cfg;
static ota_rogue_broker_state_t s_state;
static volatile bool s_running = false;
static TaskHandle_t s_task = NULL;
static SemaphoreHandle_t s_exit_sem = NULL;
static esp_timer_handle_t s_timeout = NULL;
static volatile bool s_timeout_fired = false;
static int64_t s_start_ms = 0;

static ota_mitm_entry_t mitm_entries[OTA_MAX_MITM_MSGS];
static int mitm_entry_count = 0;
static volatile uint32_t mitm_count = 0;
static volatile uint32_t mitm_modified_count = 0;
static volatile uint32_t mitm_forwarded_count = 0;

static ota_rogue_broker_summary_t rb_summary;
static char rb_active_modify_topic[128] = "";
static char rb_active_modify_payload[512] = "";
static bool rb_modify_payloads = false;

static void timeout_cb(void *arg)
{
    (void)arg;
    s_timeout_fired = true;
    s_running = false;
}

static void mqtt_mitm_hook(const char *topic, const char *data, int data_len)
{
    if (!topic || !data || mitm_entry_count >= OTA_MAX_MITM_MSGS) return;

    ota_mitm_entry_t *mitm = &mitm_entries[mitm_entry_count];
    memset(mitm, 0, sizeof(*mitm));
    strncpy(mitm->original_topic, topic, OTA_MAX_MITM_TOPIC_LEN - 1);
    int mplen = data_len < OTA_MAX_MITM_PAYLOAD_LEN - 1 ? data_len : OTA_MAX_MITM_PAYLOAD_LEN - 1;
    if (mplen > 0) memcpy(mitm->original_payload, data, mplen);
    mitm->original_payload[mplen] = '\0';
    mitm->timestamp_ms = ota_common_now_ms();
    mitm->was_modified = false;
    mitm->direction_upload = true;

    if (rb_modify_payloads && rb_active_modify_topic[0] != '\0') {
        bool topic_match = (strcmp(topic, rb_active_modify_topic) == 0 ||
                            strstr(topic, rb_active_modify_topic) != NULL ||
                            strcmp(rb_active_modify_topic, "#") == 0);
        if (topic_match) {
            strncpy(mitm->modified_topic, topic, OTA_MAX_MITM_TOPIC_LEN - 1);
            strncpy(mitm->modified_payload, rb_active_modify_payload,
                    OTA_MAX_MITM_PAYLOAD_LEN - 1);
            mitm->was_modified = true;
            mitm_modified_count++;

            if (ota_common_mqtt_is_connected()) {
                if (ota_common_mqtt_publish(topic, rb_active_modify_payload, 1) == ESP_OK) {
                    mitm_forwarded_count++;
                    strncpy(s_state.state, "rb_modifying", sizeof(s_state.state) - 1);
                    ESP_LOGI(TAG, "Modified message on topic: %s", topic);
                }
            }
        } else {
            mitm_forwarded_count++;
            strncpy(s_state.state, "rb_forwarding", sizeof(s_state.state) - 1);
        }
    }

    mitm_entry_count++;
    mitm_count++;
    rb_summary.messages_intercepted = (int)mitm_count;
    rb_summary.messages_modified = (int)mitm_modified_count;
    rb_summary.messages_forwarded = (int)mitm_forwarded_count;
    s_state.mitm_count = mitm_count;
    s_state.modified_count = mitm_modified_count;
}

static void task_fn(void *arg)
{
    (void)arg;
    ota_conn_params_t conn = {0};

    strncpy(s_state.state, "rb_starting", sizeof(s_state.state) - 1);

    if (s_cfg.wifi_ssid[0]) {
        strncpy(conn.wifi_ssid, s_cfg.wifi_ssid, sizeof(conn.wifi_ssid) - 1);
        strncpy(conn.wifi_password, s_cfg.wifi_password, sizeof(conn.wifi_password) - 1);
        strncpy(s_state.state, "wifi_connecting", sizeof(s_state.state) - 1);
        if (ota_common_wifi_connect(&conn) != ESP_OK) {
            strncpy(s_state.error, "wifi_failed", sizeof(s_state.error) - 1);
            strncpy(s_state.state, "error", sizeof(s_state.state) - 1);
            goto done;
        }
    }

    const char *broker = s_cfg.real_broker_ip[0] ? s_cfg.real_broker_ip : s_cfg.mqtt_broker;
    if (!broker[0]) {
        strncpy(s_state.error, "no_broker", sizeof(s_state.error) - 1);
        strncpy(s_state.state, "error", sizeof(s_state.state) - 1);
        goto done;
    }

    strncpy(conn.mqtt_broker, broker, sizeof(conn.mqtt_broker) - 1);
    conn.mqtt_port = s_cfg.real_broker_port ? s_cfg.real_broker_port :
                     (s_cfg.mqtt_port ? s_cfg.mqtt_port : OTA_DEFAULT_MQTT_PORT);
    strncpy(conn.mqtt_username, s_cfg.mqtt_username, sizeof(conn.mqtt_username) - 1);
    strncpy(conn.mqtt_password, s_cfg.mqtt_password, sizeof(conn.mqtt_password) - 1);
    strncpy(conn.mqtt_client_id,
            s_cfg.mqtt_client_id[0] ? s_cfg.mqtt_client_id : "omega_ota_rb",
            sizeof(conn.mqtt_client_id) - 1);
    strncpy(conn.subscribe_topic, "#", sizeof(conn.subscribe_topic) - 1);
    conn.auto_subscribe = true;

    rb_summary.rogue_port = s_cfg.rogue_port ? s_cfg.rogue_port : OTA_DEFAULT_MQTT_PORT;
    strncpy(rb_summary.real_broker_ip, broker, sizeof(rb_summary.real_broker_ip) - 1);
    rb_summary.real_broker_port = conn.mqtt_port;

    ESP_LOGI(TAG, "Starting MQTT MITM: real broker %s:%u rogue_port=%u",
             broker, (unsigned)conn.mqtt_port, (unsigned)rb_summary.rogue_port);

    strncpy(s_state.state, "mqtt_connecting", sizeof(s_state.state) - 1);
    if (ota_common_mqtt_connect(&conn, mqtt_mitm_hook) != ESP_OK) {
        strncpy(s_state.error, "mqtt_failed", sizeof(s_state.error) - 1);
        strncpy(s_state.state, "error", sizeof(s_state.state) - 1);
        goto done;
    }

    strncpy(s_state.state, "rb_listening", sizeof(s_state.state) - 1);
    ESP_LOGI(TAG, "Connected to real broker, intercepting messages");

    if (s_cfg.arp_spoof && ota_common_wifi_has_ip()) {
        ota_sniffer_opts_t opts = {
            .capture_dns = true,
            .capture_http = true,
            .provision_mode = false,
        };
        ota_common_sniffer_set_opts(&opts);
        ota_common_sniffer_enable(true);
        rb_summary.arp_spoof_active = true;
        ESP_LOGI(TAG, "ARP spoof / sniffer enabled");
    }

    while (s_running && ota_common_mqtt_is_connected()) {
        strncpy(s_state.state, "rb_intercepting", sizeof(s_state.state) - 1);
        s_state.mitm_count = mitm_count;
        s_state.modified_count = mitm_modified_count;
        s_state.elapsed_sec = (uint32_t)((ota_common_now_ms() - s_start_ms) / 1000);
        vTaskDelay(pdMS_TO_TICKS(1000));
    }

done:
    ota_common_sniffer_enable(false);
    rb_summary.arp_spoof_active = false;
    ota_common_mqtt_disconnect();
    ota_common_wifi_restore_ap();
    if (s_timeout) esp_timer_stop(s_timeout);
    s_state.active = false;
    s_state.timeout = s_timeout_fired;
    s_state.mitm_count = mitm_count;
    s_state.modified_count = mitm_modified_count;
    if (strcmp(s_state.state, "error") != 0)
        strncpy(s_state.state, "idle", sizeof(s_state.state) - 1);
    s_running = false;
    ota_common_release();
    if (s_exit_sem) xSemaphoreGive(s_exit_sem);
    s_task = NULL;
    vTaskDelete(NULL);
}

void ota_rogue_broker_init(void)
{
    if (!s_exit_sem) s_exit_sem = xSemaphoreCreateBinary();
    if (!s_timeout) {
        esp_timer_create_args_t a = { .callback = timeout_cb, .name = "ota_rb_to" };
        esp_timer_create(&a, &s_timeout);
    }
    memset(&s_state, 0, sizeof(s_state));
    memset(&rb_summary, 0, sizeof(rb_summary));
    strncpy(s_state.state, "idle", sizeof(s_state.state) - 1);
}

esp_err_t ota_rogue_broker_start(const ota_rogue_broker_config_t *cfg)
{
    if (!cfg) return ESP_ERR_INVALID_ARG;
    if (s_running) return ESP_ERR_INVALID_STATE;
    esp_err_t claim = ota_common_try_claim("rogue_broker");
    if (claim != ESP_OK) return claim;

    s_cfg = *cfg;
    if (!s_cfg.timeout_sec) s_cfg.timeout_sec = OTA_DEFAULT_TIMEOUT_SEC;

    mitm_entry_count = 0;
    mitm_count = 0;
    mitm_modified_count = 0;
    mitm_forwarded_count = 0;
    memset(mitm_entries, 0, sizeof(mitm_entries));
    memset(&rb_summary, 0, sizeof(rb_summary));

    rb_modify_payloads = s_cfg.modify_payloads;
    rb_active_modify_topic[0] = '\0';
    rb_active_modify_payload[0] = '\0';
    if (s_cfg.modify_topic[0]) {
        strncpy(rb_active_modify_topic, s_cfg.modify_topic, sizeof(rb_active_modify_topic) - 1);
        strncpy(rb_active_modify_payload, s_cfg.modify_payload, sizeof(rb_active_modify_payload) - 1);
        rb_modify_payloads = true;
    }

    memset(&s_state, 0, sizeof(s_state));
    strncpy(s_state.state, "starting", sizeof(s_state.state) - 1);
    s_timeout_fired = false;
    s_start_ms = ota_common_now_ms();
    s_state.active = true;
    s_running = true;

    if (s_timeout) {
        esp_timer_stop(s_timeout);
        esp_timer_start_once(s_timeout, (uint64_t)s_cfg.timeout_sec * 1000000ULL);
    }
    if (xTaskCreate(task_fn, "ota_rb", OTA_TASK_STACK_SIZE, NULL,
                    OTA_TASK_PRIORITY, &s_task) != pdPASS) {
        s_running = false;
        s_state.active = false;
        ota_common_release();
        return ESP_ERR_NO_MEM;
    }
    ESP_LOGI(TAG, "Rogue broker started");
    return ESP_OK;
}

esp_err_t ota_rogue_broker_stop(void)
{
    if (!s_running) return ESP_OK;
    s_running = false;
    if (s_exit_sem &&
        xSemaphoreTake(s_exit_sem, pdMS_TO_TICKS(OTA_STOP_SEM_TIMEOUT_MS)) != pdTRUE) {
        if (s_task) { vTaskDelete(s_task); s_task = NULL; }
        ota_common_sniffer_enable(false);
        ota_common_mqtt_disconnect();
        ota_common_wifi_restore_ap();
        ota_common_release();
        s_state.active = false;
    }
    if (s_timeout) esp_timer_stop(s_timeout);
    return ESP_OK;
}

bool ota_rogue_broker_is_active(void) { return s_state.active; }
const ota_rogue_broker_state_t *ota_rogue_broker_get_state(void) { return &s_state; }

cJSON *ota_rogue_broker_get_status_json(void)
{
    cJSON *o = cJSON_CreateObject();
    if (!o) return NULL;
    cJSON_AddBoolToObject(o, "active", s_state.active);
    cJSON_AddBoolToObject(o, "timeout", s_state.timeout);
    cJSON_AddNumberToObject(o, "mitm_count", s_state.mitm_count);
    cJSON_AddNumberToObject(o, "modified_count", s_state.modified_count);
    cJSON_AddNumberToObject(o, "elapsed_sec", s_state.elapsed_sec);
    cJSON_AddStringToObject(o, "state", s_state.state);
    if (s_state.error[0]) cJSON_AddStringToObject(o, "error", s_state.error);
    return o;
}

const char *ota_rogue_broker_get_mitm_json(void)
{
    char *json_buf = ota_common_json_large_a();
    if (!json_buf) return "[]";

    cJSON *root = cJSON_CreateArray();
    for (int i = 0; i < mitm_entry_count; i++) {
        cJSON *item = cJSON_CreateObject();
        cJSON_AddStringToObject(item, "original_topic", mitm_entries[i].original_topic);
        cJSON_AddStringToObject(item, "original_payload", mitm_entries[i].original_payload);
        if (mitm_entries[i].was_modified) {
            cJSON_AddStringToObject(item, "modified_topic", mitm_entries[i].modified_topic);
            cJSON_AddStringToObject(item, "modified_payload", mitm_entries[i].modified_payload);
        }
        cJSON_AddBoolToObject(item, "was_modified", mitm_entries[i].was_modified);
        cJSON_AddBoolToObject(item, "direction_upload", mitm_entries[i].direction_upload);
        cJSON_AddNumberToObject(item, "timestamp_ms", (double)mitm_entries[i].timestamp_ms);
        cJSON_AddItemToArray(root, item);
    }

    char *printed = cJSON_PrintUnformatted(root);
    snprintf(json_buf, OTA_JSON_LARGE_SZ, "%s", printed ? printed : "[]");
    cJSON_Delete(root);
    free(printed);
    return json_buf;
}

const char *ota_rogue_broker_get_summary_json(void)
{
    char *json_buf = ota_common_json_result();
    if (!json_buf) return "{}";

    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "rogue_port", rb_summary.rogue_port);
    if (rb_summary.real_broker_ip[0])
        cJSON_AddStringToObject(root, "real_broker_ip", rb_summary.real_broker_ip);
    cJSON_AddNumberToObject(root, "real_broker_port", rb_summary.real_broker_port);
    cJSON_AddNumberToObject(root, "devices_connected", rb_summary.devices_connected);
    cJSON_AddNumberToObject(root, "messages_intercepted", rb_summary.messages_intercepted);
    cJSON_AddNumberToObject(root, "messages_modified", rb_summary.messages_modified);
    cJSON_AddNumberToObject(root, "messages_forwarded", rb_summary.messages_forwarded);
    cJSON_AddBoolToObject(root, "arp_spoof_active", rb_summary.arp_spoof_active);

    char *printed = cJSON_PrintUnformatted(root);
    snprintf(json_buf, OTA_JSON_2K_SZ, "%s", printed ? printed : "{}");
    cJSON_Delete(root);
    free(printed);
    return json_buf;
}

void ota_rogue_broker_get_summary(ota_rogue_broker_summary_t *out)
{
    if (out) *out = rb_summary;
}

bool ota_rogue_broker_set_modify_rule(const char *topic, const char *new_payload)
{
    if (!topic || !new_payload) return false;
    if (!s_running) {
        ESP_LOGW(TAG, "MITM modify rule: not running");
        return false;
    }
    strncpy(rb_active_modify_topic, topic, sizeof(rb_active_modify_topic) - 1);
    rb_active_modify_topic[sizeof(rb_active_modify_topic) - 1] = '\0';
    strncpy(rb_active_modify_payload, new_payload, sizeof(rb_active_modify_payload) - 1);
    rb_active_modify_payload[sizeof(rb_active_modify_payload) - 1] = '\0';
    rb_modify_payloads = true;
    ESP_LOGI(TAG, "Set modify rule topic='%s'", rb_active_modify_topic);
    return true;
}

uint32_t ota_rogue_broker_get_mitm_count(void)
{
    return mitm_count;
}

uint32_t ota_rogue_broker_get_modified_count(void)
{
    return mitm_modified_count;
}

void ota_rogue_broker_clear_mitm(void)
{
    mitm_entry_count = 0;
    mitm_count = 0;
    mitm_modified_count = 0;
    mitm_forwarded_count = 0;
    memset(mitm_entries, 0, sizeof(mitm_entries));
    rb_active_modify_topic[0] = '\0';
    rb_active_modify_payload[0] = '\0';
    rb_modify_payloads = false;
    rb_summary.messages_intercepted = 0;
    rb_summary.messages_modified = 0;
    rb_summary.messages_forwarded = 0;
    s_state.mitm_count = 0;
    s_state.modified_count = 0;
}
