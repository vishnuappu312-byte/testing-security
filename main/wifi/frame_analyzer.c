/**
 * @file frame_analyzer.c
 * @date 2021-04-05
 * @copyright Copyright (c) 2021
 * 
 * @brief Implements frame analysis
 */
#include "frame_analyzer.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define LOG_LOCAL_LEVEL ESP_LOG_DEBUG
#include "esp_log.h"
#include "esp_err.h"
#include "esp_event.h"

#include "wifi_controller.h"
#include "frame_analyzer_parser.h"
#include "sniffer.h"

static const char *TAG = "frame_analyzer";
static uint8_t target_bssid[6];
static search_type_t search_type = -1;
static bool data_handler_registered = false;
static bool mgmt_handler_registered = false;

static void free_pmkid_items(pmkid_item_t *pmkid_item) {
    while (pmkid_item != NULL) {
        pmkid_item_t *next = pmkid_item->next;
        free(pmkid_item);
        pmkid_item = next;
    }
}


/**
 * @brief Analyzes data frames from sniffer.
 *  
 * @param args 
 * @param event_base 
 * @param event_id 
 * @param event_data 
 */
static void data_frame_handler(void *args, esp_event_base_t event_base, int32_t event_id, void *event_data) {
    ESP_LOGV(TAG, "Handling DATA frame");
    wifi_promiscuous_pkt_t *frame = (wifi_promiscuous_pkt_t *) event_data;

    if(!is_frame_bssid_matching(frame, target_bssid)){
        ESP_LOGV(TAG, "Not matching BSSIDs.");
        return;
    }

    eapol_packet_t *eapol_packet = parse_eapol_packet((data_frame_t *) frame->payload);
    if(eapol_packet == NULL){
        ESP_LOGV(TAG, "Not an EAPOL packet.");
        return;
    }

    eapol_key_packet_t *eapol_key_packet = parse_eapol_key_packet(eapol_packet);
    if(eapol_key_packet == NULL){
        ESP_LOGV(TAG, "Not an EAPOL-Key packet");
        return;
    }

    if(search_type == SEARCH_HANDSHAKE){
        ESP_ERROR_CHECK_WITHOUT_ABORT(esp_event_post(FRAME_ANALYZER_EVENTS, DATA_FRAME_EVENT_EAPOLKEY_FRAME, frame, sizeof(wifi_promiscuous_pkt_t) + frame->rx_ctrl.sig_len, portMAX_DELAY));
        return;
    }

    if(search_type == SEARCH_PMKID){
        pmkid_item_t *pmkid_items;
        if((pmkid_items = parse_pmkid(eapol_key_packet)) == NULL){
            return;
        }
        esp_err_t err = esp_event_post(FRAME_ANALYZER_EVENTS, DATA_FRAME_EVENT_PMKID, &pmkid_items, sizeof(pmkid_item_t *), portMAX_DELAY);
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "PMKID event post failed: %s", esp_err_to_name(err));
            free_pmkid_items(pmkid_items);
        }
        return;
    }
}

/**
 * Probe requests are management frames — handle them on MGMT sniffer events.
 */
static void mgmt_frame_handler(void *args, esp_event_base_t event_base, int32_t event_id, void *event_data) {
    if (search_type != SEARCH_PROBE) {
        return;
    }

    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *) event_data;
    if (pkt->rx_ctrl.sig_len < 26) {
        return;
    }

    uint8_t *payload = pkt->payload;
    uint8_t frame_type = payload[0] & 0x0C;
    uint8_t frame_subtype = payload[0] & 0xF0;

    if (frame_type != 0x00 || frame_subtype != 0x40) {
        return;
    }

    /* Fixed mgmt header is 24 bytes; tagged params start at 24.
     * Probe Request has no fixed params beyond header — SSID is first tag. */
    if (pkt->rx_ctrl.sig_len < 26) return;
    uint8_t ssid_len = payload[25];
    if (ssid_len == 0 || ssid_len > 32) return;
    if (26 + ssid_len > pkt->rx_ctrl.sig_len) return;
    if (payload[24] != 0x00) return; /* SSID tag */

    uint8_t *ssid = &payload[26];
    ESP_LOGI(TAG, "Probe SSID: %.*s", ssid_len, ssid);
    ESP_ERROR_CHECK_WITHOUT_ABORT(
        esp_event_post(FRAME_ANALYZER_EVENTS, DATA_FRAME_EVENT_PROBE,
                       ssid, ssid_len, portMAX_DELAY));
}

void frame_analyzer_capture_start(search_type_t search_type_arg, const uint8_t *bssid){
    ESP_LOGI(TAG, "Frame analysis started...");
    search_type = search_type_arg;
    memcpy(&target_bssid, bssid, 6);

    if (search_type_arg == SEARCH_PROBE) {
        if (!mgmt_handler_registered) {
            esp_err_t err = esp_event_handler_register(SNIFFER_EVENTS, SNIFFER_EVENT_CAPTURED_MGMT,
                                                       &mgmt_frame_handler, NULL);
            if (err != ESP_OK) {
                ESP_LOGW(TAG, "MGMT handler register failed: %s", esp_err_to_name(err));
            } else {
                mgmt_handler_registered = true;
            }
        }
        return;
    }

    if (data_handler_registered) {
        return;
    }

    esp_err_t err = esp_event_handler_register(SNIFFER_EVENTS, SNIFFER_EVENT_CAPTURED_DATA, &data_frame_handler, NULL);
    if (err != ESP_OK) {
        ESP_LOGW(TAG, "Frame analyzer handler register failed: %s", esp_err_to_name(err));
        return;
    }

    data_handler_registered = true;
}

void frame_analyzer_capture_stop(){
    if (data_handler_registered) {
        esp_err_t err = esp_event_handler_unregister(SNIFFER_EVENTS, SNIFFER_EVENT_CAPTURED_DATA, &data_frame_handler);
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "Frame analyzer DATA handler unregister failed: %s", esp_err_to_name(err));
        } else {
            data_handler_registered = false;
        }
    }

    if (mgmt_handler_registered) {
        esp_err_t err = esp_event_handler_unregister(SNIFFER_EVENTS, SNIFFER_EVENT_CAPTURED_MGMT, &mgmt_frame_handler);
        if (err != ESP_OK) {
            ESP_LOGW(TAG, "Frame analyzer MGMT handler unregister failed: %s", esp_err_to_name(err));
        } else {
            mgmt_handler_registered = false;
        }
    }
}
