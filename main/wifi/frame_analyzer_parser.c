/**
 * @file frame_analyzer_parser.c
 * @date 2021-04-05
 * @copyright Copyright (c) 2021
 * 
 * @brief Implements parsing functionality
 */
#include "frame_analyzer_parser.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "arpa/inet.h"

#define LOG_LOCAL_LEVEL ESP_LOG_DEBUG
#include "esp_log.h"
#include "esp_wifi_types.h"

#include "frame_analyzer_types.h"

static const char *TAG = "frame_analyzer:parser";

ESP_EVENT_DEFINE_BASE(FRAME_ANALYZER_EVENTS);

/**
 * @brief Debug function to print raw frame to serial
 * 
 * @param frame 
 */
void print_raw_frame(const wifi_promiscuous_pkt_t *frame){
    for(unsigned i = 0; i < frame->rx_ctrl.sig_len; i++) {
        printf("%02x", frame->payload[i]);
    }
    printf("\n");
}

/**
 * @brief Debug functions to print MAC address from given buffer to serial
 * 
 * @param a mac address buffer
 */
void print_mac_address(const uint8_t *a){
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
    a[0], a[1], a[2], a[3], a[4], a[5]);
    printf("\n");
}

bool is_frame_bssid_matching(wifi_promiscuous_pkt_t *frame, uint8_t *bssid) {
    data_frame_mac_header_t *mac_header = (data_frame_mac_header_t *) frame->payload;
    return memcmp(mac_header->addr3, bssid, 6) == 0;
}

eapol_packet_t *parse_eapol_packet(data_frame_t *frame) {
    uint8_t *frame_buffer = frame->body;

    if(frame->mac_header.frame_control.protected_frame == 1) {
        ESP_LOGV(TAG, "Protected frame, skipping...");
        return NULL;
    }

    if(frame->mac_header.frame_control.subtype > 7) {
        ESP_LOGV(TAG, "QoS data frame");
        // Skipping QoS field (2 bytes)
        frame_buffer += 2;
    }

    // Skipping LLC SNAP header (6 bytes)
    frame_buffer += sizeof(llc_snap_header_t);

    // Check if frame is type of EAPoL
    if(ntohs(*(uint16_t *) frame_buffer) == ETHER_TYPE_EAPOL) {
        ESP_LOGD(TAG, "EAPOL packet");
        frame_buffer += 2;
        return (eapol_packet_t *) frame_buffer; 
    }
    return NULL;
}

eapol_key_packet_t *parse_eapol_key_packet(eapol_packet_t *eapol_packet){
    if(eapol_packet->header.packet_type != EAPOL_KEY){
        ESP_LOGD(TAG, "Not an EAPoL-Key packet.");
        return NULL;
    }
    return (eapol_key_packet_t *) eapol_packet->packet_body;
}

/**
 * @brief Parses all PMKIDs to linked list structure 
 * 
 * It crawlers through key data buffer and looks for PMKIDs.
 * If PMKID element is found, its saved into the list of PMKIDs.
 * @param key_data 
 * @param length of key data
 * @return pmkid_item_t* 
 */
static pmkid_item_t *parse_pmkid_from_key_data(uint8_t *key_data, const uint16_t length){
    uint8_t *key_data_index = key_data;
    uint8_t *key_data_max_index = key_data + length;
    pmkid_item_t *pmkid_item_head = NULL;

    while (key_data_index + 2 <= key_data_max_index) {
        uint8_t type = key_data_index[0];
        uint8_t field_len = key_data_index[1];
        uint8_t *next = key_data_index + 2 + field_len;

        if (next > key_data_max_index) {
            ESP_LOGW(TAG, "Key-Data IE exceeds buffer (type=%x len=%u)", type, field_len);
            break;
        }

        /* Vendor-specific KDE: type 0xDD, length >= 4 (OUI+data_type) + 16 PMKID */
        if (type == KEY_DATA_TYPE && field_len >= 20) {
            /* OUI 00-0F-AC, data_type PMKID_KDE */
            if (key_data_index[2] == 0x00 && key_data_index[3] == 0x0F &&
                key_data_index[4] == 0xAC &&
                key_data_index[5] == KEY_DATA_DATA_TYPE_PMKID_KDE) {
                pmkid_item_t *pmkid_item = (pmkid_item_t *) malloc(sizeof(pmkid_item_t));
                if (pmkid_item == NULL) {
                    ESP_LOGE(TAG, "PMKID item alloc failed");
                    break;
                }
                ESP_LOGI(TAG, "Found PMKID");
                pmkid_item->next = pmkid_item_head;
                pmkid_item_head = pmkid_item;
                memcpy(pmkid_item->pmkid, &key_data_index[6], 16);
            }
        }

        key_data_index = next;
    }

    return pmkid_item_head;
}

pmkid_item_t *parse_pmkid(eapol_key_packet_t *eapol_key){
    if(eapol_key->key_data_length == 0){
        ESP_LOGD(TAG, "Empty Key Data");
        return NULL;
    }

    if(eapol_key->key_information.encrypted_key_data == 1){
        ESP_LOGD(TAG, "Key Data encrypted");
        return NULL;
    }

    return parse_pmkid_from_key_data(eapol_key->key_data, ntohs(eapol_key->key_data_length));
}