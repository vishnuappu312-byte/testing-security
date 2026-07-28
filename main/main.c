#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "heap_psram.h"
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
#include "attack_karma.h"
#include "attack_csa.h"
#include "attack_pmf.h"
#include "attack_wps.h"
#include "attack_eap_audit.h"
#include "wifi_radio_claim.h"
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
#include "mesh.h"
#include "node_scanner.h"
#include "mesh_packet_inject.h"
#include "mesh_mitm.h"
#include "mesh_dos.h"
#include "mesh_eavesdrop.h"
#include "mesh_replay.h"
#include "mesh_wormhole.h"
#include "mesh_l2_deauth.h"
#include "mesh_route_poison.h"
#include "espnow_attack.h"
#include "ota_common.h"
#include "ota_mqtt_sniff.h"
#include "ota_inject.h"
#include "ota_fetch.h"
#include "ota_poll_sniff.h"
#include "ota_provision.h"
#include "ota_github.h"
#include "ota_rogue_broker.h"
#include "ota_fw_analyze.h"

static const char *TAG = "MAIN";

void app_main(void) {
    /* ---- NVS init (required for WiFi + BLE) ---- */
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    heap_psram_init();

    ESP_ERROR_CHECK(esp_event_loop_create_default());

    /* ---- WiFi: Management AP ---- */
    wifictl_mgmt_ap_start();
    char ssid[33] = {0};
    char pass[64] = {0};
    if (wifictl_mgmt_ap_get_creds(ssid, sizeof(ssid), pass, sizeof(pass)) == ESP_OK) {
        ESP_LOGI(TAG, "Management AP SSID: %s", ssid);
    }

    /* ---- WiFi: Scanner ---- */
    scanner_init();

    /* ---- WiFi: Attack modules ---- */
    wifi_radio_claim_init();
    deauth_attack_init();
    deauth_detector_start();
    attack_init();
    attack_eviltwin_init();
    attack_probe_init();
    attack_karma_init();
    attack_csa_init();
    attack_pmf_init();
    attack_wps_init();
    attack_eap_audit_init();

    /* ---- BLE: Attack modules ---- */
    attack_bt_spam_init();
    ble_scan_init();
    ble_spoof_init();
    ble_connect_flood_init();
    ble_l2cap_flood_init();
    ble_gatt_probe_init();
    ble_deauth_init();
    ble_passkey_init();
    ble_takeover_init();

    /* ---- OTA: Attack modules ---- */
    ota_common_init();
    ota_mqtt_sniff_init();
    ota_inject_init();
    ota_fetch_init();
    ota_poll_sniff_init();
    ota_provision_init();
    ota_github_init();
    ota_rogue_broker_init();
    ota_fw_analyze_init();

    /* ---- Mesh: Node scanner + mesh attacks ---- */
    node_scanner_init();
    mesh_init();
    mesh_packet_inject_init();
    mesh_mitm_init();
    mesh_dos_init();
    mesh_eavesdrop_init();
    mesh_replay_init();
    mesh_wormhole_init();
    mesh_l2_deauth_init();
    mesh_route_poison_init();
    espnow_attack_init();

    /* ---- Web server (serves dashboard + all API endpoints) ---- */
    start_web_server();

    /* ---- Boot summary ---- */
    ESP_LOGI(TAG, "=========================================");
    ESP_LOGI(TAG, "Omega Solutions - All Modules Ready");
    ESP_LOGI(TAG, "=========================================");
    ESP_LOGI(TAG, "WiFi Attacks:");
    ESP_LOGI(TAG, "  Deauth (timer 1-999 min)");
    ESP_LOGI(TAG, "  Beacon Spam (4 modes)");
    ESP_LOGI(TAG, "  DoS (Broadcast/Rogue AP/Combine/Clone)");
    ESP_LOGI(TAG, "  Handshake Capture (EAPOL)");
    ESP_LOGI(TAG, "  PMKID Attack (WPA3)");
    ESP_LOGI(TAG, "  Probe Sniffer (Ghost AP)");
    ESP_LOGI(TAG, "  Evil Twin (Captive portal)");
    ESP_LOGI(TAG, "  Karma/MANA Responder");
    ESP_LOGI(TAG, "  CSA Injection");
    ESP_LOGI(TAG, "  PMF / 802.11w Audit");
    ESP_LOGI(TAG, "  WPS Discovery Audit");
    ESP_LOGI(TAG, "  EAP Identity Audit");
    ESP_LOGI(TAG, "BLE Attacks:");
    ESP_LOGI(TAG, "  BLE Spam (NimBLE flood)");
    ESP_LOGI(TAG, "  BLE Scan (Discover devices)");
    ESP_LOGI(TAG, "  BLE Spoof (Name rotation)");
    ESP_LOGI(TAG, "  BLE Clone (Full device clone)");
    ESP_LOGI(TAG, "  Connect Flood");
    ESP_LOGI(TAG, "  L2CAP Flood");
    ESP_LOGI(TAG, "  GATT Probe");
    ESP_LOGI(TAG, "  BLE Deauth");
    ESP_LOGI(TAG, "  BLE Passkey Capture");
    ESP_LOGI(TAG, "  BLE Takeover");
    ESP_LOGI(TAG, "OTA Attacks:");
    ESP_LOGI(TAG, "  MQTT Sniff (passive + client subscribe)");
    ESP_LOGI(TAG, "  Inject (spoof OTA MQTT messages)");
    ESP_LOGI(TAG, "  Fetch (download firmware over HTTP)");
    ESP_LOGI(TAG, "  Poll Sniff (DNS/HTTP OTA discovery)");
    ESP_LOGI(TAG, "  Provision (credential capture)");
    ESP_LOGI(TAG, "  GitHub (repo access / firmware upload)");
    ESP_LOGI(TAG, "  Rogue Broker (MQTT republish / MITM)");
    ESP_LOGI(TAG, "  Firmware Analyze (secret scan)");
    ESP_LOGI(TAG, "Mesh:");
    ESP_LOGI(TAG, "  Node Scanner (nearby AP + soft-AP subnet)");
    ESP_LOGI(TAG, "  Node Spoof (MAC clone + traffic capture)");
    ESP_LOGI(TAG, "  Packet Injection (802.11 frame TX, 8 templates)");
    ESP_LOGI(TAG, "  Man-in-the-Middle (ARP poison + traffic capture)");
    ESP_LOGI(TAG, "  DoS (Child/Parent Deauth, Mesh Action, Auth/Probe/Beacon)");
    ESP_LOGI(TAG, "  Eavesdrop (promiscuous mesh capture)");
    ESP_LOGI(TAG, "  Replay (live / cycle frame replay)");
    ESP_LOGI(TAG, "  Wormhole (capture + tunnel/re-TX)");
    ESP_LOGI(TAG, "  L2 Deauth (mesh link teardown)");
    ESP_LOGI(TAG, "  Route Poison (mesh path disruption)");
    ESP_LOGI(TAG, "  ESP-NOW (monitor / replay / inject / flood)");
    ESP_LOGI(TAG, "=========================================");
    ESP_LOGI(TAG, "Connect to WiFi AP: %s", ssid);
    ESP_LOGI(TAG, "Open browser: http://192.168.4.1");
    ESP_LOGI(TAG, "Login: omega / solutions123");
    ESP_LOGI(TAG, "=========================================");
}

