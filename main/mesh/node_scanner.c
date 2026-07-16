/**
 * node_scanner.c
 *
 * Mesh node scanner module:
 *   1. Nearby AP scan — groups BSSIDs by SSID, flags likely mesh networks
 *   2. Local subnet scan — lists stations on the management soft-AP (AP-safe)
 */

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/select.h>

#include "lwip/sockets.h"
#include "lwip/inet.h"

#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_netif.h"
#include "esp_system.h"
#include "dhcpserver/dhcpserver.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "wifi_controller.h"
#include "ap_scanner.h"
#include "node_scanner.h"

static const char *TAG = "NODE_SCANNER";

static bool s_scanner_ready = false;

/* ── Known Espressif OUIs ─────────────────────────────────────── */

static const uint8_t espressif_ouis[][3] = {
    {0x30, 0xAE, 0xA4},
    {0x7C, 0xDF, 0xA1},
    {0xBC, 0xDD, 0xC2},
    {0x24, 0x0A, 0xC4},
    {0xA4, 0xCF, 0x12},
    {0x00, 0x1A, 0xC2},
};
#define OUI_COUNT (sizeof(espressif_ouis) / sizeof(espressif_ouis[0]))

void node_scanner_init(void)
{
    if (s_scanner_ready) return;
    s_scanner_ready = true;

    /* WiFi AP+STA already up via wifictl_mgmt_ap_start() — no mode changes here. */
    ESP_LOGI(TAG, "Node scanner ready (AP-safe, heap: %u bytes)",
             (unsigned)esp_get_free_heap_size());
}

/* Ensure APSTA + management AP before scan (restores after STA-only attacks). */
static void node_scanner_prepare_wifi(void)
{
    wifictl_prepare_for_scan();
}

bool node_scanner_is_espressif_oui(const uint8_t *bssid)
{
    if (!bssid) return false;
    for (int i = 0; i < OUI_COUNT; i++) {
        if (bssid[0] == espressif_ouis[i][0] &&
            bssid[1] == espressif_ouis[i][1] &&
            bssid[2] == espressif_ouis[i][2]) {
            return true;
        }
    }
    return false;
}

/* ================================================================== */
/*  1. AP SCANNER — groups WiFi APs by SSID                           */
/* ================================================================== */

esp_err_t mesh_scanner_scan(uint8_t channel, scan_result_t *result)
{
    if (!result) return ESP_ERR_INVALID_ARG;
    memset(result, 0, sizeof(scan_result_t));

    ESP_LOGI(TAG, "AP scan %s...",
             channel == 0 ? "all channels" : "single channel");

    node_scanner_prepare_wifi();

    uint16_t ap_count = 0;
    const wifi_ap_record_t *records = NULL;

    if (channel == 0) {
        wifictl_scan_nearby_aps();
        const wifictl_ap_records_t *scan = wifictl_get_ap_records();
        if (!scan || scan->count == 0) {
            ESP_LOGW(TAG, "No APs found.");
            return ESP_OK;
        }
        ap_count = scan->count;
        records = scan->records;
    } else {
        wifi_scan_config_t scan_cfg = {
            .ssid        = NULL,
            .bssid       = NULL,
            .channel     = channel,
            .show_hidden = true,
            .scan_type   = WIFI_SCAN_TYPE_ACTIVE,
            .scan_time   = {
                .active  = { .min = 120, .max = 300 },
                .passive = SCANNER_PASSIVE_DWELL
            }
        };

        esp_err_t ret = esp_wifi_scan_start(&scan_cfg, true);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Scan failed: %s", esp_err_to_name(ret));
            return ret;
        }

        ret = esp_wifi_scan_get_ap_num(&ap_count);
        if (ret != ESP_OK) {
            ESP_LOGE(TAG, "Scan count failed: %s", esp_err_to_name(ret));
            return ret;
        }

        if (ap_count == 0) {
            ESP_LOGW(TAG, "No APs found.");
            return ESP_OK;
        }
    }

    if (ap_count > SCANNER_MAX_AP) {
        ap_count = SCANNER_MAX_AP;
    }

    wifi_ap_record_t *heap_records = NULL;
    if (channel != 0) {
        heap_records = malloc(ap_count * sizeof(wifi_ap_record_t));
        if (!heap_records) return ESP_ERR_NO_MEM;
        esp_err_t ret = esp_wifi_scan_get_ap_records(&ap_count, heap_records);
        if (ret != ESP_OK) {
            free(heap_records);
            ESP_LOGE(TAG, "Scan records failed: %s", esp_err_to_name(ret));
            return ret;
        }
        records = heap_records;
    }

    result->total_aps = (uint8_t)ap_count;
    for (int i = 0; i < ap_count; i++) {
        scanner_ap_t *ap = &result->aps[i];
        memcpy(ap->bssid, records[i].bssid, 6);
        memcpy(ap->ssid,  records[i].ssid,  32);
        ap->ssid[32] = '\0';
        ap->channel      = records[i].primary;
        ap->rssi         = records[i].rssi;
        ap->authmode     = records[i].authmode;
        ap->is_hidden    = (records[i].ssid[0] == '\0');
        ap->is_espressif = node_scanner_is_espressif_oui(records[i].bssid);
    }
    if (heap_records) {
        free(heap_records);
    }

    bool matched[SCANNER_MAX_AP] = {false};

    for (int i = 0; i < ap_count && result->group_count < SCANNER_MAX_AP; i++) {
        if (matched[i]) continue;

        mesh_group_t *g = &result->groups[result->group_count];
        memset(g, 0, sizeof(mesh_group_t));
        strncpy(g->ssid, result->aps[i].ssid, 32);
        g->channel = result->aps[i].channel;
        matched[i] = true;

        memcpy(&g->nodes[g->node_count], &result->aps[i], sizeof(scanner_ap_t));
        g->node_count++;

        for (int j = i + 1; j < ap_count; j++) {
            if (matched[j]) continue;
            if (strcmp(result->aps[j].ssid, g->ssid) == 0) {
                memcpy(&g->nodes[g->node_count], &result->aps[j], sizeof(scanner_ap_t));
                g->node_count++;
                matched[j] = true;
            }
        }

        bool same_ch = true, all_esp = true;
        for (int k = 0; k < g->node_count; k++) {
            if (g->nodes[k].channel != g->channel) same_ch = false;
            if (!g->nodes[k].is_espressif)         all_esp = false;
        }
        g->all_same_channel = same_ch;
        g->all_espressif    = all_esp;
        g->likely_mesh      = (g->node_count >= SCANNER_MESH_THRESHOLD);

        if (g->likely_mesh) result->mesh_count++;
        result->group_count++;
    }

    ESP_LOGI(TAG, "AP scan done: %d APs, %d groups, %d potential mesh",
             result->total_aps, result->group_count, result->mesh_count);
    return ESP_OK;
}

void mesh_scanner_print_report(const scan_result_t *result)
{
    if (!result) return;

    printf("\n");
    printf("======================================================\n");
    printf("       ESP32-S3 MESH NETWORK SCANNER REPORT\n");
    printf("======================================================\n");
    printf("  Total APs Found      : %d\n", result->total_aps);
    printf("  SSID Groups          : %d\n", result->group_count);
    printf("  Potential Mesh Nets  : %d\n", result->mesh_count);
    printf("======================================================\n");

    printf("\n-- ALL ACCESS POINTS --------------------------------\n");
    printf("%-4s %-33s %3s %5s  %-17s %s\n",
           "#", "SSID", "CH", "RSSI", "BSSID", "VENDOR");
    printf("----  ----                                 ---  ----   -----------------  ------\n");

    for (int i = 0; i < result->total_aps; i++) {
        const scanner_ap_t *a = &result->aps[i];
        printf("%-4d %-33s %3d %5d  %02X:%02X:%02X:%02X:%02X:%02X  %s\n",
               i + 1,
               a->is_hidden ? "(hidden)" : a->ssid,
               a->channel, a->rssi,
               a->bssid[0], a->bssid[1], a->bssid[2],
               a->bssid[3], a->bssid[4], a->bssid[5],
               a->is_espressif ? "ESPRESSIF" : "other");
    }

    printf("\n-- MESH ANALYSIS ------------------------------------\n");
    for (int i = 0; i < result->group_count; i++) {
        const mesh_group_t *g = &result->groups[i];
        if (g->node_count < SCANNER_MESH_THRESHOLD) {
            printf("\n  [%s]  %d BSSID(s) -- single AP\n", g->ssid, g->node_count);
            continue;
        }
        printf("\n  +-- MESH DETECTED ---------------------------+\n");
        printf("  | SSID       : %-28s|\n", g->ssid);
        printf("  | Nodes      : %-28d|\n", g->node_count);
        printf("  | Channel    : %-28d|\n", g->channel);
        printf("  | Same CH    : %-28s|\n", g->all_same_channel ? "YES" : "NO");
        printf("  | All ESP    : %-28s|\n", g->all_espressif ? "YES" : "NO");
        printf("  +--------------------------------------------+\n");
        for (int j = 0; j < g->node_count; j++) {
            const scanner_ap_t *n = &g->nodes[j];
            printf("  |  Node %-3d  CH %-3d RSSI %-4d  %02X:%02X:%02X:%02X:%02X:%02X  |\n",
                   j + 1, n->channel, n->rssi,
                   n->bssid[0], n->bssid[1], n->bssid[2],
                   n->bssid[3], n->bssid[4], n->bssid[5]);
        }
        printf("  +--------------------------------------------+\n");
    }
    printf("\n======================================================\n\n");
}

/* ================================================================== */
/*  2. LOCAL SUBNET SCANNER — soft-AP stations (AP-safe)              */
/* ================================================================== */

static void u32_to_ip4(uint32_t v, uint8_t *out)
{
    out[0] = v & 0xFF;
    out[1] = (v >> 8) & 0xFF;
    out[2] = (v >> 16) & 0xFF;
    out[3] = (v >> 24) & 0xFF;
}

esp_err_t mesh_scan_local_subnet(mesh_scan_result_t *result)
{
    if (!result) return ESP_ERR_INVALID_ARG;
    memset(result, 0, sizeof(mesh_scan_result_t));

    node_scanner_prepare_wifi();

    uint32_t own_ip  = 0;
    uint32_t netmask = 0;
    esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
    if (!netif) {
        netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    }

    if (netif) {
        esp_netif_ip_info_t ip_info;
        if (esp_netif_get_ip_info(netif, &ip_info) == ESP_OK) {
            own_ip  = ip_info.ip.addr;
            netmask = ip_info.netmask.addr;
        }
    }

    if (own_ip == 0 || netmask == 0) {
        /* ESP soft-AP default when netif lookup fails after mode restore. */
        result->parent_ip[0] = 192;
        result->parent_ip[1] = 168;
        result->parent_ip[2] = 4;
        result->parent_ip[3] = 1;
        result->netmask[0] = 255;
        result->netmask[1] = 255;
        result->netmask[2] = 255;
        result->netmask[3] = 0;
        own_ip  = ESP_IP4TOADDR(192, 168, 4, 1);
        netmask = ESP_IP4TOADDR(255, 255, 255, 0);
        ESP_LOGW(TAG, "Using default soft-AP IP (netif lookup failed)");
    }

    u32_to_ip4(own_ip, result->parent_ip);
    u32_to_ip4(netmask, result->netmask);

    /* Soft-AP BSSID = gateway/parent MAC for local subnet results */
    if (esp_wifi_get_mac(WIFI_IF_AP, result->parent_mac) == ESP_OK) {
        result->parent_mac_set = true;
    } else {
        memset(result->parent_mac, 0, 6);
        result->parent_mac_set = false;
    }

    wifi_sta_list_t sta_list;
    memset(&sta_list, 0, sizeof(sta_list));
    esp_err_t ret = esp_wifi_ap_get_sta_list(&sta_list);
    if (ret != ESP_OK || sta_list.num == 0) {
        ESP_LOGI(TAG, "No stations connected to AP");
        result->total_nodes = 0;
        return ESP_OK;
    }

    ESP_LOGI(TAG, "AP has %d station(s) connected", sta_list.num);

    uint16_t found = 0;
    for (int i = 0; i < sta_list.num && found < MESH_MAX_NODES; i++) {
        mesh_node_t *node = &result->nodes[found];
        uint8_t *mac = sta_list.sta[i].mac;
        memcpy(node->mac, mac, 6);

        ip4_addr_t lease_ip;
        if (dhcp_search_ip_on_mac(mac, &lease_ip)) {
            node->ip[0] = ip4_addr1(&lease_ip);
            node->ip[1] = ip4_addr2(&lease_ip);
            node->ip[2] = ip4_addr3(&lease_ip);
            node->ip[3] = ip4_addr4(&lease_ip);
        } else {
            node->ip[0] = own_ip & 0xFF;
            node->ip[1] = (own_ip >> 8) & 0xFF;
            node->ip[2] = (own_ip >> 16) & 0xFF;
            node->ip[3] = (uint8_t)(i + 2);
        }

        ESP_LOGI(TAG, "  Child #%u: %u.%u.%u.%u MAC %02X:%02X:%02X:%02X:%02X:%02X",
                 (unsigned)(found + 1),
                 node->ip[0], node->ip[1], node->ip[2], node->ip[3],
                 mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);

        node->rtt_ms = 0;
        node->online = true;
        found++;
    }

    result->total_nodes = found;

    ESP_LOGI(TAG, "Subnet scan done: parent %u.%u.%u.%u, %u child node(s)",
             result->parent_ip[0], result->parent_ip[1],
             result->parent_ip[2], result->parent_ip[3],
             (unsigned)found);

    return ESP_OK;
}

esp_err_t mesh_scan_active_nearby(mesh_active_result_t *result)
{
    if (!result) return ESP_ERR_INVALID_ARG;
    memset(result, 0, sizeof(*result));

    esp_err_t nearby_err = mesh_scanner_scan(SCANNER_CHANNEL, &result->nearby);
    if (nearby_err != ESP_OK) {
        ESP_LOGW(TAG, "Nearby scan failed: %s", esp_err_to_name(nearby_err));
    }

    esp_err_t local_err = mesh_scan_local_subnet(&result->local);
    if (local_err != ESP_OK) {
        ESP_LOGW(TAG, "Local subnet scan failed: %s", esp_err_to_name(local_err));
    }

    result->active_count = result->local.total_nodes;

    /* Return partial success: nearby-only is still useful for the dashboard. */
    if (nearby_err != ESP_OK && local_err != ESP_OK) {
        return (nearby_err != ESP_OK) ? nearby_err : local_err;
    }
    return ESP_OK;
}

void mesh_active_print_report(const mesh_active_result_t *result)
{
    if (!result) return;
    mesh_scanner_print_report(&result->nearby);
    mesh_scan_print_report(&result->local);
}

void mesh_scan_print_report(const mesh_scan_result_t *result)
{
    if (!result) return;

    printf("\n");
    printf("======================================================\n");
    printf("       ESP32-S3 MESH NODE SCANNER REPORT\n");
    printf("======================================================\n");
    printf("  Parent IP       : %u.%u.%u.%u\n",
           result->parent_ip[0], result->parent_ip[1],
           result->parent_ip[2], result->parent_ip[3]);
    printf("  Subnet Mask     : %u.%u.%u.%u\n",
           result->netmask[0], result->netmask[1],
           result->netmask[2], result->netmask[3]);
    printf("  Child Nodes     : %u\n", (unsigned)result->total_nodes);
    printf("======================================================\n");

    if (result->total_nodes == 0) {
        printf("\n  No child nodes found on subnet.\n\n");
        return;
    }

    printf("\n-- DISCOVERED MESH NODES ------------------------------\n");
    printf("  %-4s  %-16s  %-8s  %s\n", "#", "IP Address", "Latency", "Status");
    printf("  ----  ----------------  --------  ------\n");

    for (int i = 0; i < result->total_nodes; i++) {
        const mesh_node_t *n = &result->nodes[i];
        printf("  %-4d  %u.%u.%u.%u      %-6d ms  Online\n",
               i + 1,
               n->ip[0], n->ip[1], n->ip[2], n->ip[3],
               n->rtt_ms);
    }

    printf("\n======================================================\n\n");
}
