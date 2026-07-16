#include "wifi_controller.h"

#include <stdio.h>
#include <string.h>
#include <stdbool.h>

#ifndef CONFIG_MGMT_AP_SSID
#define CONFIG_MGMT_AP_SSID "OmegaSolutions"
#endif

#ifndef CONFIG_MGMT_AP_PASSWORD
#define CONFIG_MGMT_AP_PASSWORD "solutions123"
#endif

#ifndef CONFIG_MGMT_AP_CHANNEL
#define CONFIG_MGMT_AP_CHANNEL 6
#endif

#ifndef CONFIG_MGMT_AP_MAX_CONNECTIONS
#define CONFIG_MGMT_AP_MAX_CONNECTIONS 4
#endif

#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_err.h"
#include "esp_wifi.h"
#include "esp_wifi_types.h"
#include "esp_netif.h"
#include "esp_event.h"

#include "nvs_flash.h"
#include "nvs.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

static const char* TAG = "wifi_controller";
/**
 * @brief Stores current state of Wi-Fi interface
 */
static bool wifi_init = false;
static uint8_t original_mac_ap[6];

static void wifi_event_handler(void *event_handler_arg, esp_event_base_t event_base, int32_t event_id, void *event_data){

}

/**
 * @brief Initializes Wi-Fi interface into APSTA mode and starts it.
 *
 * @attention This function should be called only once.
 */
static void wifi_init_apsta(){
    ESP_ERROR_CHECK(esp_netif_init());

    esp_netif_create_default_wifi_ap();
    esp_netif_create_default_wifi_sta();

    wifi_init_config_t wifi_init_config = WIFI_INIT_CONFIG_DEFAULT();

    ESP_ERROR_CHECK(esp_wifi_init(&wifi_init_config));
    ESP_ERROR_CHECK(esp_wifi_set_storage(WIFI_STORAGE_RAM));
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));

    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL));

    ESP_ERROR_CHECK(esp_wifi_get_mac(WIFI_IF_AP, original_mac_ap));

    ESP_ERROR_CHECK(esp_wifi_start());
    wifi_init = true;
}

void wifictl_ap_start(wifi_config_t *wifi_config) {
    ESP_LOGD(TAG, "Starting AP...");
    if(!wifi_init){
        wifi_init_apsta();
    }

    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, wifi_config));
    ESP_LOGI(TAG, "AP started with SSID=%s", wifi_config->ap.ssid);
}

void wifictl_ap_stop(){
    ESP_LOGD(TAG, "Stopping AP...");
    wifi_config_t wifi_config = {
        .ap = {
            .max_connection = 0
        },
    };
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &wifi_config));
    ESP_LOGD(TAG, "AP stopped");
}


void wifictl_sta_connect_to_ap(const wifi_ap_record_t *ap_record, const char password[]){
    ESP_LOGD(TAG, "Connecting STA to AP...");
    if(!wifi_init){
        wifi_init_apsta();
    }

    wifi_config_t sta_wifi_config = {
        .sta = {
            .channel = ap_record->primary,
            .scan_method = WIFI_FAST_SCAN,
            .pmf_cfg.capable = false,
            .pmf_cfg.required = false
        },
    };
    memcpy(sta_wifi_config.sta.ssid, ap_record->ssid, sizeof(sta_wifi_config.sta.ssid));

    if(password != NULL){
        if(strlen(password) >= 64) {
            ESP_LOGE(TAG, "Password is too long. Max supported length is 64");
            return;
        }
        memcpy(sta_wifi_config.sta.password, password, strlen(password) + 1);
    }

    ESP_LOGD(TAG, ".ssid=%s", sta_wifi_config.sta.ssid);

    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_STA, &sta_wifi_config));
    ESP_ERROR_CHECK(esp_wifi_connect());

}

void wifictl_sta_disconnect(){
    ESP_ERROR_CHECK(esp_wifi_disconnect());
}

void wifictl_set_ap_mac(const uint8_t *mac_ap){
    ESP_LOGD(TAG, "Changing AP MAC address...");
    ESP_ERROR_CHECK(esp_wifi_set_mac(WIFI_IF_AP, mac_ap));
}

void wifictl_get_ap_mac(uint8_t *mac_ap){
    esp_wifi_get_mac(WIFI_IF_AP, mac_ap);
}

void wifictl_restore_ap_mac(){
    ESP_LOGD(TAG, "Restoring original AP MAC address...");
    ESP_ERROR_CHECK(esp_wifi_set_mac(WIFI_IF_AP, original_mac_ap));
}

void wifictl_get_sta_mac(uint8_t *mac_sta){
    esp_wifi_get_mac(WIFI_IF_STA, mac_sta);
}

void wifictl_set_channel(uint8_t channel){
    if((channel == 0) || (channel >  13)){
        ESP_LOGE(TAG,"Channel out of range. Expected value from <1,13> but got %u", channel);
        return;
    }
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
}

static void wifictl_get_mgmt_creds_unsafe(char* ssid, char* pass) {
    nvs_handle_t nvs_h;
    esp_err_t err = nvs_open("storage", NVS_READONLY, &nvs_h);
    if (err == ESP_OK) {
        size_t s_len = 32, p_len = 64;
        if (nvs_get_str(nvs_h, "ap_ssid", ssid, &s_len) != ESP_OK) {
            strcpy(ssid, CONFIG_MGMT_AP_SSID);
        }
        if (nvs_get_str(nvs_h, "ap_pass", pass, &p_len) != ESP_OK) {
            strcpy(pass, CONFIG_MGMT_AP_PASSWORD);
        }
        nvs_close(nvs_h);
    } else {
        strcpy(ssid, CONFIG_MGMT_AP_SSID);
        strcpy(pass, CONFIG_MGMT_AP_PASSWORD);
    }
}

esp_err_t wifictl_mgmt_ap_get_creds(char *ssid, size_t ssid_size, char *pass, size_t pass_size) {
    if (ssid == NULL || pass == NULL || ssid_size == 0 || pass_size == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    char tmp_ssid[32] = {0};
    char tmp_pass[64] = {0};
    wifictl_get_mgmt_creds_unsafe(tmp_ssid, tmp_pass);

    snprintf(ssid, ssid_size, "%s", tmp_ssid);
    snprintf(pass, pass_size, "%s", tmp_pass);
    return ESP_OK;
}

static bool mgmt_ap_creds_valid(const char *ssid, const char *pass) {
    if (ssid == NULL || pass == NULL) {
        return false;
    }
    size_t ssid_len = strlen(ssid);
    size_t pass_len = strlen(pass);

    if (ssid_len == 0 || ssid_len > 32) {
        return false;
    }

    if (pass_len == 0) {
        return true; // open auth
    }
    return (pass_len >= 8 && pass_len <= 63);
}

esp_err_t wifictl_mgmt_ap_set_creds(const char *ssid, const char *pass) {
    if (!mgmt_ap_creds_valid(ssid, pass)) {
        return ESP_ERR_INVALID_ARG;
    }

    nvs_handle_t nvs_h;
    esp_err_t err = nvs_open("storage", NVS_READWRITE, &nvs_h);
    if (err != ESP_OK) {
        return err;
    }

    err = nvs_set_str(nvs_h, "ap_ssid", ssid);
    if (err == ESP_OK) {
        err = nvs_set_str(nvs_h, "ap_pass", pass);
    }
    if (err == ESP_OK) {
        err = nvs_commit(nvs_h);
    }
    nvs_close(nvs_h);
    return err;
}

esp_err_t wifictl_mgmt_ap_clear_creds(void) {
    nvs_handle_t nvs_h;
    esp_err_t err = nvs_open("storage", NVS_READWRITE, &nvs_h);
    if (err != ESP_OK) {
        return err;
    }

    (void)nvs_erase_key(nvs_h, "ap_ssid");
    (void)nvs_erase_key(nvs_h, "ap_pass");
    err = nvs_commit(nvs_h);
    nvs_close(nvs_h);
    return err;
}


void wifictl_mgmt_ap_start() {
    esp_wifi_set_mode(WIFI_MODE_APSTA);

    char current_ssid[32] = {0};
    char current_pass[64] = {0};
    wifictl_get_mgmt_creds_unsafe(current_ssid, current_pass);

    wifi_config_t mgmt_wifi_config = {
        .ap = {
            .ssid_len = strlen(current_ssid),
            .channel = CONFIG_MGMT_AP_CHANNEL,
            .max_connection = CONFIG_MGMT_AP_MAX_CONNECTIONS,
            .authmode = (strlen(current_pass) >= 8) ? WIFI_AUTH_WPA2_PSK : WIFI_AUTH_OPEN
        },
    };
    memcpy(mgmt_wifi_config.ap.ssid, current_ssid, 32);
    memcpy(mgmt_wifi_config.ap.password, current_pass, 64);

    wifictl_ap_start(&mgmt_wifi_config);
}

void wifictl_mgmt_ap_stop(){
    ESP_LOGW(TAG, "Stopping Management AP...");

    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_STA));
}

void wifictl_prepare_for_scan(void)
{
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(NULL);
    esp_wifi_scan_stop();

    wifi_mode_t mode = WIFI_MODE_NULL;
    esp_wifi_get_mode(&mode);
    if (mode != WIFI_MODE_APSTA) {
        ESP_LOGW(TAG, "Restoring APSTA for scan (mode was %d)", mode);
        wifictl_mgmt_ap_start();
        vTaskDelay(pdMS_TO_TICKS(250));
    }

    /* Attacks that call esp_wifi_stop() leave wifi_init=true — restart radio. */
    esp_err_t err = esp_wifi_start();
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "esp_wifi_start during scan prep: %s", esp_err_to_name(err));
    }
    vTaskDelay(pdMS_TO_TICKS(100));
}
