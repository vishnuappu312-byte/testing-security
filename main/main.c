#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "webserver.h"
#include "wifi_scanner.h"
#include "attack_deauth.h"
#include "attack_deauth_detector.h"
#include "attack_beacon_spam.h"
#include "attack_dos.h"
#include "attack_handshake.h"
#include "attack_pmkid.h"
#include "attack_probe.h"
#include "attack_eviltwin.h"

static const char *TAG = "MAIN";

#define WEB_SSID "Omega_Solutions"
#define WEB_PASS "hacktheplanet"

void wifi_init_ap_sta(void) {
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    
    esp_netif_create_default_wifi_ap();
    esp_netif_create_default_wifi_sta();
    
    wifi_config_t ap_config = {
        .ap = {
            .ssid = WEB_SSID,
            .ssid_len = strlen(WEB_SSID),
            .password = WEB_PASS,
            .max_connection = 5,
            .authmode = WIFI_AUTH_WPA_WPA2_PSK,
            .channel = 6
        },
    };
    
    ESP_ERROR_CHECK(esp_wifi_set_mode(WIFI_MODE_APSTA));
    ESP_ERROR_CHECK(esp_wifi_set_config(WIFI_IF_AP, &ap_config));
    ESP_ERROR_CHECK(esp_wifi_start());
    
    ESP_LOGI(TAG, "==========================================");
    ESP_LOGI(TAG, "Omega Solutions - Complete Security Suite");
    ESP_LOGI(TAG, "AP SSID: %s", WEB_SSID);
    ESP_LOGI(TAG, "Password: %s", WEB_PASS);
    ESP_LOGI(TAG, "Web: http://192.168.4.1");
    ESP_LOGI(TAG, "Login: omega / solutions123");
    ESP_LOGI(TAG, "==========================================");
}

void app_main(void) {
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);
    
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    
    wifi_init_ap_sta();
    vTaskDelay(pdMS_TO_TICKS(1000));
    
    scanner_init();
    deauth_attack_init();
    deauth_detector_start();
    start_web_server();
    
    ESP_LOGI(TAG, "=========================================");
    ESP_LOGI(TAG, "🚀 Omega Solutions - All Attack Modules Ready! 🚀");
    ESP_LOGI(TAG, "=========================================");
    ESP_LOGI(TAG, "📡 Deauth Attack (with custom timer 1-999 min)");
    ESP_LOGI(TAG, "📡 Beacon Spam (4 modes: Common, Garbage, Rick Roll, Security)");
    ESP_LOGI(TAG, "💀 DoS Attack (Broadcast/Rogue AP/Combine All/Super Clone)");
    ESP_LOGI(TAG, "🤝 Handshake Capture (EAPOL frame capture)");
    ESP_LOGI(TAG, "🔐 PMKID Attack (WPA3 capture)");
    ESP_LOGI(TAG, "👻 Probe Sniffer (Ghost AP creator)");
    ESP_LOGI(TAG, "🎭 Evil Twin (Captive portal password capture)");
    ESP_LOGI(TAG, "=========================================");
    ESP_LOGI(TAG, "📱 Connect to WiFi: %s", WEB_SSID);
    ESP_LOGI(TAG, "🔑 Password: %s", WEB_PASS);
    ESP_LOGI(TAG, "🌐 Open browser: http://192.168.4.1");
    ESP_LOGI(TAG, "🔐 Username: omega | Password: solutions123");
    ESP_LOGI(TAG, "=========================================");
}