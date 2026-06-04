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
#include "wifi_controller.h"
#include "attack_deauth.h"
#include "attack_deauth_detector.h"
#include "attack_beacon_spam.h"
#include "attack_dos.h"
#include "attack_handshake.h"
#include "attack_pmkid.h"
#include "attack_probe.h"
#include "attack_eviltwin.h"
#include "attack.h"
#include "bt/attack_bt_spam.h"
#include "bt/ble_scan.h"
#include "bt/ble_spoof.h"
#include "bt/ble_connect_flood.h"
#include "bt/ble_l2cap_flood.h"
#include "bt/ble_gatt_probe.h"
#include "bt/ble_deauth.h"
#include "bt/ble_passkey.h"
#include "bt/ble_takeover.h"
static const char *TAG = "MAIN";

void app_main(void) {
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);
    
    ESP_ERROR_CHECK(esp_event_loop_create_default());
    
    wifictl_mgmt_ap_start();
    char ssid[33] = {0};
    char pass[64] = {0};
    if (wifictl_mgmt_ap_get_creds(ssid, sizeof(ssid), pass, sizeof(pass)) == ESP_OK) {
        ESP_LOGI(TAG, "Management AP SSID: %s", ssid);
    }
    
    scanner_init();

    ble_deauth_init();
        ble_passkey_init();

    ble_takeover_init();
    deauth_attack_init();
    deauth_detector_start();
    attack_init();
    attack_bt_spam_init();
    /* Initialize new BLE modules */
    ble_scan_init();
    ble_spoof_init();
    ble_connect_flood_init();
    ble_l2cap_flood_init();
    ble_gatt_probe_init();
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
    ESP_LOGI(TAG, "📱 Connect to WiFi: (management AP SSID shown above)");
    ESP_LOGI(TAG, "🌐 Open browser: http://192.168.4.1");
    ESP_LOGI(TAG, "🔐 Username: omega | Password: solutions123");
    ESP_LOGI(TAG, "=========================================");
}
