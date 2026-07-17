#include "attack_wps.h"

#include <string.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

#include "heap_psram.h"
#include "wifi_ie_parser.h"
#include "wifi_radio_claim.h"
#include "wifi_controller.h"

static const char *TAG = "wps_audit";

static SemaphoreHandle_t s_mutex;
static bool s_running;
static wps_entry_t *s_entries;
static int s_count;
static uint32_t s_frames;
static uint8_t s_fixed_channel;
static uint16_t s_timeout_sec;
static TaskHandle_t s_hop_task;
static esp_timer_handle_t s_timeout_timer;

static void ensure_mutex(void)
{
    if (s_mutex == NULL) {
        s_mutex = xSemaphoreCreateMutex();
    }
}

static int find_bssid(const uint8_t bssid[6])
{
    for (int i = 0; i < s_count; i++) {
        if (memcmp(s_entries[i].bssid, bssid, 6) == 0) {
            return i;
        }
    }
    return -1;
}

static void timeout_cb(void *arg)
{
    (void)arg;
    attack_wps_stop();
}

static void hop_task(void *arg)
{
    (void)arg;
    uint8_t channels[] = {1, 6, 11, 2, 7, 12, 3, 8, 13, 4, 9, 5, 10};
    int idx = 0;
    while (s_running) {
        if (s_fixed_channel == 0) {
            esp_wifi_set_channel(channels[idx], WIFI_SECOND_CHAN_NONE);
            idx = (idx + 1) % (int)sizeof(channels);
        }
        vTaskDelay(pdMS_TO_TICKS(200));
    }
    s_hop_task = NULL;
    vTaskDelete(NULL);
}

static void handle_mgmt(wifi_promiscuous_pkt_t *pkt)
{
    const uint8_t *frame = pkt->payload;
    size_t len = pkt->rx_ctrl.sig_len;
    if (!wifi_mgmt_is_beacon(frame, len) && !wifi_mgmt_is_probe_resp(frame, len)) {
        return;
    }

    const uint8_t *ies = NULL;
    size_t ies_len = 0;
    if (!wifi_mgmt_get_ies(frame, len, &ies, &ies_len)) {
        return;
    }

    wifi_wps_info_t wps;
    if (!wifi_ie_parse_wps(ies, ies_len, &wps) || !wps.present) {
        return;
    }

    char ssid[33] = {0};
    wifi_ie_extract_ssid(ies, ies_len, ssid, sizeof(ssid), NULL);
    const uint8_t *bssid = frame + 16;

    if (xSemaphoreTake(s_mutex, pdMS_TO_TICKS(5)) != pdTRUE) {
        return;
    }
    s_frames++;
    int idx = find_bssid(bssid);
    if (idx < 0) {
        if (s_count >= WPS_MAX_ENTRIES) {
            xSemaphoreGive(s_mutex);
            return;
        }
        idx = s_count++;
        memset(&s_entries[idx], 0, sizeof(s_entries[idx]));
        memcpy(s_entries[idx].bssid, bssid, 6);
        strncpy(s_entries[idx].ssid, ssid, sizeof(s_entries[idx].ssid) - 1);
        s_entries[idx].channel = pkt->rx_ctrl.channel;
        s_entries[idx].rssi = pkt->rx_ctrl.rssi;
        ESP_LOGI(TAG, "WPS AP \"%s\" configured=%d locked=%d",
                 ssid, wps.configured, wps.locked);
    } else if (pkt->rx_ctrl.rssi > s_entries[idx].rssi) {
        s_entries[idx].rssi = pkt->rx_ctrl.rssi;
    }

    s_entries[idx].frames_seen++;
    s_entries[idx].version = wps.version;
    s_entries[idx].configured = wps.configured;
    s_entries[idx].locked = wps.locked;
    s_entries[idx].config_methods = wps.config_methods;
    if (wps.manufacturer[0]) {
        strncpy(s_entries[idx].manufacturer, wps.manufacturer, sizeof(s_entries[idx].manufacturer) - 1);
    }
    if (wps.model[0]) {
        strncpy(s_entries[idx].model, wps.model, sizeof(s_entries[idx].model) - 1);
    }
    if (wps.device_name[0]) {
        strncpy(s_entries[idx].device_name, wps.device_name, sizeof(s_entries[idx].device_name) - 1);
    }
    if (wps.uuid[0]) {
        strncpy(s_entries[idx].uuid, wps.uuid, sizeof(s_entries[idx].uuid) - 1);
    }
    xSemaphoreGive(s_mutex);
}

static void sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (!s_running || type != WIFI_PKT_MGMT) {
        return;
    }
    handle_mgmt((wifi_promiscuous_pkt_t *)buf);
}

void attack_wps_init(void)
{
    ensure_mutex();
    if (s_entries == NULL) {
        s_entries = heap_psram_calloc(WPS_MAX_ENTRIES, sizeof(wps_entry_t));
    }
    ESP_LOGI(TAG, "WPS audit initialized");
}

esp_err_t attack_wps_start(uint8_t channel, uint16_t timeout_sec)
{
    ensure_mutex();
    if (s_running) {
        return ESP_ERR_INVALID_STATE;
    }
    if (s_entries == NULL) {
        attack_wps_init();
        if (s_entries == NULL) {
            return ESP_ERR_NO_MEM;
        }
    }

    esp_err_t err = wifi_radio_claim(WIFI_RADIO_OWNER_WPS);
    if (err != ESP_OK) {
        return err;
    }

    s_fixed_channel = channel;
    s_timeout_sec = timeout_sec ? timeout_sec : WPS_TIMEOUT_SEC;
    if (s_timeout_sec > 300) {
        s_timeout_sec = 300;
    }
    s_count = 0;
    s_frames = 0;
    memset(s_entries, 0, sizeof(wps_entry_t) * WPS_MAX_ENTRIES);

    if (s_fixed_channel) {
        wifictl_set_channel(s_fixed_channel);
    }

    esp_wifi_set_promiscuous_rx_cb(&sniffer_cb);
    wifi_promiscuous_filter_t filter = { .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT };
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous(true);

    s_running = true;
    if (s_hop_task == NULL) {
        xTaskCreatePinnedToCore(hop_task, "wps_hop", 3072, NULL, 3, &s_hop_task, 1);
    }

    const esp_timer_create_args_t targs = { .callback = &timeout_cb, .name = "wps_timeout" };
    if (s_timeout_timer == NULL) {
        esp_timer_create(&targs, &s_timeout_timer);
    }
    esp_timer_start_once(s_timeout_timer, (uint64_t)s_timeout_sec * 1000000ULL);
    ESP_LOGI(TAG, "WPS audit started");
    return ESP_OK;
}

void attack_wps_stop(void)
{
    if (!s_running) {
        return;
    }
    s_running = false;
    if (s_timeout_timer) {
        if (esp_timer_is_active(s_timeout_timer)) {
            esp_timer_stop(s_timeout_timer);
        }
        esp_timer_delete(s_timeout_timer);
        s_timeout_timer = NULL;
    }
    esp_wifi_set_promiscuous_rx_cb(NULL);
    esp_wifi_set_promiscuous(false);
    vTaskDelay(pdMS_TO_TICKS(250));
    if (s_hop_task) {
        vTaskDelete(s_hop_task);
        s_hop_task = NULL;
    }
    wifi_radio_release(WIFI_RADIO_OWNER_WPS);
    ESP_LOGI(TAG, "WPS audit stopped (%d APs)", s_count);
}

bool attack_wps_is_running(void)
{
    return s_running;
}

void attack_wps_clear(void)
{
    ensure_mutex();
    if (xSemaphoreTake(s_mutex, portMAX_DELAY) == pdTRUE) {
        s_count = 0;
        s_frames = 0;
        if (s_entries) {
            memset(s_entries, 0, sizeof(wps_entry_t) * WPS_MAX_ENTRIES);
        }
        xSemaphoreGive(s_mutex);
    }
}

cJSON *attack_wps_get_status_json(void)
{
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        return NULL;
    }
    ensure_mutex();
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    cJSON_AddBoolToObject(root, "running", s_running);
    cJSON_AddNumberToObject(root, "entry_count", s_count);
    cJSON_AddNumberToObject(root, "frames", s_frames);
    cJSON_AddNumberToObject(root, "channel", s_fixed_channel);
    cJSON_AddNumberToObject(root, "timeout_sec", s_timeout_sec);
    cJSON_AddStringToObject(root, "status", s_running ? "Running" : "Stopped");
    xSemaphoreGive(s_mutex);
    return root;
}

cJSON *attack_wps_get_results_json(void)
{
    cJSON *root = cJSON_CreateObject();
    cJSON *arr = cJSON_CreateArray();
    if (!root || !arr) {
        cJSON_Delete(root);
        cJSON_Delete(arr);
        return NULL;
    }
    ensure_mutex();
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    for (int i = 0; i < s_count; i++) {
        cJSON *item = cJSON_CreateObject();
        char bssid[18];
        wifi_mac_to_str(s_entries[i].bssid, bssid);
        cJSON_AddStringToObject(item, "ssid", s_entries[i].ssid);
        cJSON_AddStringToObject(item, "bssid", bssid);
        cJSON_AddNumberToObject(item, "channel", s_entries[i].channel);
        cJSON_AddNumberToObject(item, "rssi", s_entries[i].rssi);
        cJSON_AddNumberToObject(item, "version", s_entries[i].version);
        cJSON_AddBoolToObject(item, "configured", s_entries[i].configured);
        cJSON_AddBoolToObject(item, "locked", s_entries[i].locked);
        cJSON_AddNumberToObject(item, "config_methods", s_entries[i].config_methods);
        cJSON_AddStringToObject(item, "manufacturer", s_entries[i].manufacturer);
        cJSON_AddStringToObject(item, "model", s_entries[i].model);
        cJSON_AddStringToObject(item, "device_name", s_entries[i].device_name);
        cJSON_AddStringToObject(item, "uuid", s_entries[i].uuid);
        cJSON_AddNumberToObject(item, "frames", s_entries[i].frames_seen);
        /* Risk hint for dashboard */
        const char *risk = "info";
        if (!s_entries[i].locked && s_entries[i].configured) {
            risk = "elevated";
        }
        if (s_entries[i].locked) {
            risk = "locked";
        }
        cJSON_AddStringToObject(item, "risk", risk);
        cJSON_AddItemToArray(arr, item);
    }
    cJSON_AddItemToObject(root, "entries", arr);
    cJSON_AddNumberToObject(root, "count", s_count);
    xSemaphoreGive(s_mutex);
    return root;
}
