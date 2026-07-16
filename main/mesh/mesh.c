/**
 * mesh.c
 *
 * ESP32-S3 Mesh Network Scanner & IP Discovery
 * ESP-IDF 4.4.6
 *
 * Features:
 *   1. AP Scanner        — groups nearby WiFi APs by SSID
 *   2. Local Subnet Scan — finds child nodes on THIS device's subnet (AP-safe)
 *   3. Remote IP Disc.   — connect to another SSID + probe (breaks AP!)
 *   4. Promiscuous Sniff — passive AUTH/ASSOC capture (channel hop)
 *   5. Remote Net Scan   — join cracked WiFi, find ESP32 devices, restore AP
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
#include "lwip/netdb.h"

#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_event.h"
#include "esp_netif.h"
#include "dhcpserver/dhcpserver.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "esp_timer.h"
#include "freertos/queue.h"

#include "mesh.h"
#include "node_scanner.h"

static const char *TAG = "MESH";

/* ================================================================== */
/*  0. MESH INIT — AP-safe, called from app_main                      */
/* ================================================================== */

static bool s_mesh_initialized = false;

void mesh_init(void)
{
    if (s_mesh_initialized) return;
    s_mesh_initialized = true;

    /* STA netif already created by wifictl_mgmt_ap_start().
       No WiFi mode changes needed — AP stays alive. */
    ESP_LOGI(TAG, "Mesh module initialized (heap: %u bytes)",
             (unsigned)esp_get_free_heap_size());
}

/* TCP port probe helper (used by remote scan paths) */
static int probe_port(uint32_t ip, uint16_t port, int timeout_ms)
{
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return 0;

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family      = AF_INET;
    sa.sin_port        = htons(port);
    sa.sin_addr.s_addr = ip;

    int flags = fcntl(sock, F_GETFL, 0);
    if (flags >= 0) {
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    }

    int ret = connect(sock, (struct sockaddr *)&sa, sizeof(sa));
    if (ret == 0) {
        close(sock);
        return 1;
    }

    if (ret < 0 && errno == EINPROGRESS) {
        fd_set wfds;
        struct timeval tv;
        FD_ZERO(&wfds);
        FD_SET(sock, &wfds);
        tv.tv_sec  = timeout_ms / 1000;
        tv.tv_usec = (timeout_ms % 1000) * 1000;

        ret = select(sock + 1, NULL, &wfds, NULL, &tv);
        if (ret > 0) {
            int err = 0;
            socklen_t elen = sizeof(err);
            getsockopt(sock, SOL_SOCKET, SO_ERROR, &err, &elen);
            if (err == 0) {
                close(sock);
                return 1;
            }
        }
    }

    close(sock);
    return 0;
}

static void u32_to_ip4(uint32_t v, uint8_t *out)
{
    out[0] = v & 0xFF;
    out[1] = (v >> 8) & 0xFF;
    out[2] = (v >> 16) & 0xFF;
    out[3] = (v >> 24) & 0xFF;
}

/* ================================================================== */
/*  3. REMOTE IP DISCOVERY — connect to SSID + probe                    */
/*                                                                     */
/*  WARNING: This changes WiFi mode to STA and kills the AP!         */
/*  Do NOT call this from the webserver. Use from serial CLI only.   */
/* ================================================================== */

esp_err_t mesh_get_ips(const char *ssid, const char *password,
                       uint8_t channel, char ***ips_out, int *count)
{
    if (!ssid || !ips_out || !count) return ESP_ERR_INVALID_ARG;
    *ips_out = NULL;
    *count   = 0;

    ESP_LOGW(TAG, "mesh_get_ips: This will disconnect AP mode!");

    /* ── 1. Switch to STA and connect ───────────────────────── */
    esp_wifi_disconnect();
    esp_wifi_stop();
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_start();

    wifi_config_t sta_config = {0};
    strncpy((char *)sta_config.sta.ssid, ssid, 32);
    strncpy((char *)sta_config.sta.password, password, 64);
    sta_config.sta.channel = channel;

    esp_wifi_set_config(WIFI_IF_STA, &sta_config);
    esp_wifi_connect();

    /* Wait for connection (up to 8 seconds) */
    int timeout = 0;
    while (timeout < 80) {
        vTaskDelay(pdMS_TO_TICKS(100));
        wifi_ap_record_t ap;
        if (esp_wifi_sta_get_ap_info(&ap) == ESP_OK) {
            break;
        }
        timeout++;
    }
    if (timeout >= 80) {
        ESP_LOGE(TAG, "Failed to connect to %s", ssid);
        return ESP_ERR_TIMEOUT;
    }

    /* Get our IP */
    esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
    if (!netif) {
        ESP_LOGE(TAG, "No STA netif");
        return ESP_ERR_NOT_SUPPORTED;
    }

    esp_netif_ip_info_t ip_info;
    esp_netif_get_ip_info(netif, &ip_info);
    if (ip_info.ip.addr == 0) {
        ESP_LOGE(TAG, "No IP assigned (DHCP timeout)");
        return ESP_ERR_TIMEOUT;
    }

    uint32_t own_ip  = ip_info.ip.addr;
    uint32_t subnet  = own_ip & ip_info.netmask.addr;
    uint32_t netmask = ip_info.netmask.addr;

    ESP_LOGI(TAG, "Connected! IP: %u.%u.%u.%u, Subnet: %u.%u.%u.%u",
             own_ip & 0xFF, (own_ip >> 8) & 0xFF,
             (own_ip >> 16) & 0xFF, (own_ip >> 24) & 0xFF,
             subnet & 0xFF, (subnet >> 8) & 0xFF,
             (subnet >> 16) & 0xFF, (subnet >> 24) & 0xFF);

    /* ── 2. TCP probe scan ── */
    char **ips = calloc(254, sizeof(char *));
    if (!ips) return ESP_ERR_NO_MEM;

    uint32_t host_start = subnet + 1;
    uint32_t host_end   = (subnet | ~netmask);
    int found = 0;

    for (uint32_t ip = host_start; ip < host_end && found < 254; ip++) {
        if (ip == own_ip) continue;

        int alive = 0;
        if (probe_port(ip, 80, 150)) alive = 1;
        if (!alive && probe_port(ip, 5555, 150)) alive = 1;

        if (alive) {
            ips[found] = malloc(16);
            if (ips[found]) {
                snprintf(ips[found], 16, "%u.%u.%u.%u",
                         ip & 0xFF, (ip >> 8) & 0xFF,
                         (ip >> 16) & 0xFF, (ip >> 24) & 0xFF);
                found++;
                ESP_LOGI(TAG, "  Found: %s", ips[found - 1]);
            }
        }
    }

    *ips_out = ips;
    *count   = found;
    ESP_LOGI(TAG, "Remote scan done. %d IPs found.", found);

    return ESP_OK;
}

/* ================================================================== */
/*  4. PROMISCUOUS MESH SNIFFER — passive child node discovery        */
/*                                                                     */
/*  Captures AUTH & ASSOC_REQ frames while channel-hopping to         */
/*  discover ESP32-S3 child nodes on nearby mesh networks.             */
/*  WARNING: Channel hopping disrupts the soft AP during scan.         */
/* ================================================================== */

static mesh_sniff_result_t s_sniff_result;
static volatile bool s_sniff_running = false;
static TaskHandle_t  s_sniff_task_handle = NULL;
static uint8_t       s_own_ap_bssid[6] = {0};

static bool sniff_parent_known(const uint8_t *bssid)
{
    for (int i = 0; i < s_sniff_result.parents_found; i++) {
        if (memcmp(s_sniff_result.parent_bssids[i], bssid, 6) == 0)
            return true;
    }
    return false;
}

static void sniff_add_parent(const uint8_t *bssid)
{
    if (s_sniff_result.parents_found < MESH_SNIFF_MAX_PARENTS) {
        memcpy(s_sniff_result.parent_bssids[s_sniff_result.parents_found],
               bssid, 6);
        s_sniff_result.parents_found++;
    }
}

static void IRAM_ATTR mesh_sniff_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (type != WIFI_PKT_MGMT) return;

    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
    const uint8_t *payload = pkt->payload;

    uint8_t fc0           = payload[0];
    uint8_t frame_type    = (fc0 >> 2) & 0x03;
    uint8_t frame_subtype = (fc0 >> 4) & 0x0F;

    if (frame_type != 0) return;

    uint8_t sniff_type = 0;
    if      (frame_subtype == 11) sniff_type = MESH_SNIFF_FRAME_AUTH;
    else if (frame_subtype ==  0) sniff_type = MESH_SNIFF_FRAME_ASSOC;
    else if (frame_subtype ==  2) sniff_type = MESH_SNIFF_FRAME_ASSOC;

    if (sniff_type == 0) return;

    /* 802.11 MAC header:
     *   [0]   Frame Control   [4]  Addr1 (dest/BSSID)
     *   [2]   Duration        [10] Addr2 (source/child)
     *   [16]  Addr3 (BSSID)
     */
    const uint8_t *child_mac    = &payload[10];
    const uint8_t *parent_bssid = &payload[16];
    int8_t  rssi    = pkt->rx_ctrl.rssi;
    uint8_t channel = (uint8_t)pkt->rx_ctrl.channel;

    if (rssi < -85) return;
    if (child_mac[0] & 0x01) return;
    if (memcmp(parent_bssid, s_own_ap_bssid, 6) == 0) return;

    /* Deduplicate */
    for (int i = 0; i < s_sniff_result.total_found; i++) {
        if (memcmp(s_sniff_result.nodes[i].child_mac, child_mac, 6) == 0) {
            if (rssi > s_sniff_result.nodes[i].rssi)
                s_sniff_result.nodes[i].rssi = rssi;
            return;
        }
    }

    if (s_sniff_result.total_found >= MESH_SNIFF_MAX_NODES) return;

    mesh_sniffed_node_t *node = &s_sniff_result.nodes[s_sniff_result.total_found];
    memcpy(node->child_mac,    child_mac,    6);
    memcpy(node->parent_bssid, parent_bssid, 6);
    node->rssi         = rssi;
    node->channel      = channel;
    node->is_espressif = node_scanner_is_espressif_oui(child_mac);
    node->frame_type   = sniff_type;

    s_sniff_result.total_found++;
    if (node->is_espressif) s_sniff_result.espressif_count++;

    if (!sniff_parent_known(parent_bssid))
        sniff_add_parent(parent_bssid);
}

static void mesh_sniff_task(void *arg)
{
    uint8_t scan_seconds = (uint8_t)(uintptr_t)arg;
    uint32_t total_ms    = (uint32_t)scan_seconds * 1000;

    ESP_LOGW(TAG, "SNIFF: Starting — AP disrupted for ~%d sec", scan_seconds);

    /* ── Step 1: Quick scan → find channels with Espressif APs ── */
    wifi_scan_config_t scan_cfg = {
        .show_hidden = true,
        .scan_type   = WIFI_SCAN_TYPE_ACTIVE,
        .scan_time   = { .active = { .min = 80, .max = 150 } }
    };

    uint8_t target_ch[13] = {0};
    int     target_cnt    = 0;

    if (esp_wifi_scan_start(&scan_cfg, true) == ESP_OK) {
        uint16_t ap_count = 0;
        esp_wifi_scan_get_ap_num(&ap_count);
        if (ap_count > 0) {
            wifi_ap_record_t *recs = malloc(ap_count * sizeof(wifi_ap_record_t));
            if (recs) {
                esp_wifi_scan_get_ap_records(&ap_count, recs);
                for (int i = 0; i < ap_count; i++) {
                    if (!node_scanner_is_espressif_oui(recs[i].bssid)) continue;
                    uint8_t ch = recs[i].primary;
                    bool dup = false;
                    for (int j = 0; j < target_cnt; j++)
                        if (target_ch[j] == ch) { dup = true; break; }
                    if (!dup && target_cnt < 13)
                        target_ch[target_cnt++] = ch;
                }
                free(recs);
            }
        }
    }

    if (target_cnt == 0) {
        for (int i = 0; i < 13; i++) target_ch[i] = i + 1;
        target_cnt = 13;
    }

    ESP_LOGI(TAG, "SNIFF: Hopping %d channels for %d sec", target_cnt, scan_seconds);

    /* ── Step 2: Kick all STAs so channel change is allowed ── */
    esp_wifi_deauth_sta(0);
    vTaskDelay(pdMS_TO_TICKS(200));

    /* ── Step 3: Enable promiscuous mode ── */
    wifi_promiscuous_filter_t pf = { .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT };
    esp_wifi_set_promiscuous_filter(&pf);
    esp_wifi_set_promiscuous_rx_cb(mesh_sniff_cb);
    esp_wifi_set_promiscuous(true);

    /* ── Step 4: Channel hop ── */
    int start_tick = xTaskGetTickCount() * portTICK_PERIOD_MS;
    int ch_idx     = 0;

    while (s_sniff_running) {
        int elapsed = (xTaskGetTickCount() * portTICK_PERIOD_MS) - start_tick;
        if (elapsed >= (int)total_ms) break;

        esp_wifi_set_channel(target_ch[ch_idx % target_cnt], WIFI_SECOND_CHAN_NONE);
        vTaskDelay(pdMS_TO_TICKS(MESH_SNIFF_CHAN_TIME_MS));
        ch_idx++;
    }

    /* ── Step 5: Cleanup ── */
    esp_wifi_set_promiscuous(false);

    s_sniff_result.scanning     = false;
    s_sniff_result.scan_time_ms = (xTaskGetTickCount() * portTICK_PERIOD_MS) - start_tick;

    ESP_LOGI(TAG, "SNIFF done: %u nodes (%u ESP), %u parents, %u ms",
             s_sniff_result.total_found, s_sniff_result.espressif_count,
             s_sniff_result.parents_found, s_sniff_result.scan_time_ms);

    for (int i = 0; i < s_sniff_result.total_found; i++) {
        const mesh_sniffed_node_t *n = &s_sniff_result.nodes[i];
        ESP_LOGI(TAG, "  #%u %02X:%02X:%02X:%02X:%02X:%02X -> %02X:%02X:%02X:%02X:%02X:%02X ch%d rssi%d %s",
                 (unsigned)(i + 1),
                 n->child_mac[0], n->child_mac[1], n->child_mac[2],
                 n->child_mac[3], n->child_mac[4], n->child_mac[5],
                 n->parent_bssid[0], n->parent_bssid[1], n->parent_bssid[2],
                 n->parent_bssid[3], n->parent_bssid[4], n->parent_bssid[5],
                 n->channel, (int)n->rssi,
                 n->is_espressif ? "ESP32" : "other");
    }

    s_sniff_running     = false;
    s_sniff_task_handle = NULL;
    vTaskDelete(NULL);
}

esp_err_t mesh_sniff_start(uint8_t scan_seconds)
{
    if (s_sniff_running) return ESP_ERR_INVALID_STATE;
    if (scan_seconds == 0) scan_seconds = MESH_SNIFF_DEFAULT_SEC;
    if (scan_seconds > 30) scan_seconds = 30;

    esp_wifi_get_mac(WIFI_IF_AP, s_own_ap_bssid);

    memset(&s_sniff_result, 0, sizeof(s_sniff_result));
    s_sniff_result.scanning = true;
    s_sniff_running = true;

    if (xTaskCreate(mesh_sniff_task, "mesh_sniff", 4096,
                    (void *)(uintptr_t)scan_seconds, 2,
                    &s_sniff_task_handle) != pdPASS) {
        s_sniff_running = false;
        s_sniff_result.scanning = false;
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

esp_err_t mesh_sniff_stop(void)
{
    if (!s_sniff_running) return ESP_OK;
    s_sniff_running = false;

    int w = 20;
    while (s_sniff_task_handle && w-- > 0) vTaskDelay(pdMS_TO_TICKS(100));
    if (s_sniff_task_handle) {
        vTaskDelete(s_sniff_task_handle);
        s_sniff_task_handle = NULL;
    }
    s_sniff_result.scanning = false;
    return ESP_OK;
}

bool mesh_sniff_is_running(void) { return s_sniff_running; }

const mesh_sniff_result_t *mesh_sniff_get_results(void) { return &s_sniff_result; }

/* ================================================================== */
/*  5. REMOTE NETWORK SCAN — join cracked WiFi, find ESP32 nodes     */
/*                                                                     */
/*  Flow: save AP config → join target → probe subnet → restore AP    */
/*  Dashboard unreachable for ~30-40 seconds during scan.              */
/* ================================================================== */

static mesh_remote_result_t s_remote_result;
static volatile bool s_remote_scanning = false;
static TaskHandle_t  s_remote_task_handle = NULL;
static wifi_config_t s_saved_ap_config;
static bool          s_ap_saved = false;

static void save_ap_config(void)
{
    if (esp_wifi_get_config(WIFI_IF_AP, &s_saved_ap_config) == ESP_OK)
        s_ap_saved = true;
}

static void restore_ap_mode(void)
{
    ESP_LOGI(TAG, "REMOTE: Restoring AP mode...");

    esp_wifi_disconnect();
    vTaskDelay(pdMS_TO_TICKS(300));

    esp_wifi_stop();
    vTaskDelay(pdMS_TO_TICKS(500));

    esp_wifi_set_mode(WIFI_MODE_APSTA);
    if (s_ap_saved) {
        esp_wifi_set_config(WIFI_IF_AP, &s_saved_ap_config);
    }
    esp_wifi_start();

    /* Restart DHCP server */
    esp_netif_t *ap_netif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
    if (ap_netif) {
        esp_netif_dhcps_stop(ap_netif);
        vTaskDelay(pdMS_TO_TICKS(100));
        esp_netif_dhcps_start(ap_netif);
    }

    ESP_LOGI(TAG, "REMOTE: AP restored — phone will reconnect in ~3s");
}

/* ── Promiscuous MAC capture (gets real MACs during remote scan) ── */

typedef struct { uint8_t mac[6]; int64_t time_us; int8_t rssi; } mac_cap_t;

static QueueHandle_t s_mac_queue = NULL;
static uint8_t       s_cap_own_mac[6];
static uint8_t       s_cap_ap_bssid[6];

static void promisc_mac_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (type != WIFI_PKT_DATA || !s_mac_queue) return;
    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *f = pkt->payload;

    /* Only AP→STA data frames: ToDS=0, FromDS=1 → Addr3 = real source MAC */
    if ((f[1] & 0x03) != 0x02) return;
    if (memcmp(f + 4,  s_cap_own_mac,  6) != 0) return;
    if (memcmp(f + 10, s_cap_ap_bssid, 6) != 0) return;

    mac_cap_t cap;
    memcpy(cap.mac, f + 16, 6);
    cap.time_us = esp_timer_get_time();
    cap.rssi = pkt->rx_ctrl.rssi;
    if (cap.mac[0] & 0x01) return;  /* skip broadcast */

    xQueueSend(s_mac_queue, &cap, 0);
}

static bool mac_capture_start(void)
{
    s_mac_queue = xQueueCreate(48, sizeof(mac_cap_t));
    if (!s_mac_queue) return false;
    esp_wifi_get_mac(WIFI_IF_STA, s_cap_own_mac);
    wifi_ap_record_t ap;
    if (esp_wifi_sta_get_ap_info(&ap) != ESP_OK) {
        vQueueDelete(s_mac_queue); s_mac_queue = NULL; return false;
    }
    memcpy(s_cap_ap_bssid, ap.bssid, 6);
    wifi_promiscuous_filter_t filt = { .filter_mask = WIFI_PROMIS_FILTER_MASK_DATA };
    esp_wifi_set_promiscuous_filter(&filt);
    esp_wifi_set_promiscuous_rx_cb(promisc_mac_cb);
    esp_wifi_set_promiscuous(true);
    return true;
}

static void mac_capture_stop(void)
{
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(NULL);
    if (s_mac_queue) { vQueueDelete(s_mac_queue); s_mac_queue = NULL; }
}

static bool get_captured_mac(int64_t after_us, uint8_t *mac_out, int8_t *rssi_out)
{
    if (!s_mac_queue) return false;
    mac_cap_t cap, first = { .time_us = INT64_MAX };
    bool found = false;
    while (xQueueReceive(s_mac_queue, &cap, 0)) {
        if (cap.time_us >= after_us && cap.time_us < first.time_us) {
            first = cap; found = true;
        }
    }
    if (found) {
        memcpy(mac_out, first.mac, 6);
        if (rssi_out) *rssi_out = first.rssi;
    }
    return found;
}

static void mesh_pivot_scan(mesh_remote_result_t *result) {
    // Find first ESP32 gateway candidate
    mesh_remote_node_t *gateway = NULL;
    for (int i = 0; i < result->total_found; i++) {
        if (result->nodes[i].is_esp32 && result->nodes[i].port80) {
            gateway = &result->nodes[i];
            break;
        }
    }
    if (!gateway) {
        ESP_LOGW(TAG, "PIVOT: No ESP32 gateway found for mesh pivot");
        strcpy(result->pivot_method, "none");
        return;
    }

    uint32_t gw_ip = (gateway->ip[0]<<24) | (gateway->ip[1]<<16) | 
                     (gateway->ip[2]<<8) | gateway->ip[3];
    ESP_LOGI(TAG, "PIVOT: Trying gateway %d.%d.%d.%d for mesh info",
             gateway->ip[0], gateway->ip[1], gateway->ip[2], gateway->ip[3]);

    // Try common ESP32 mesh HTTP endpoints
    const char *paths[] = {"/mesh/nodes", "/api/mesh", "/mesh", "/", NULL};
    for (int p = 0; paths[p]; p++) {
        int sock = socket(AF_INET, SOCK_STREAM, 0);
        if (sock < 0) break;

        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(80);
        addr.sin_addr.s_addr = htonl(gw_ip);

        if (connect(sock, (struct sockaddr*)&addr, sizeof(addr)) != 0) {
            close(sock);
            continue;
        }

        char req[128];
        snprintf(req, sizeof(req), 
                 "GET %s HTTP/1.0\r\nHost: %d.%d.%d.%d\r\n\r\n",
                 paths[p], gateway->ip[0], gateway->ip[1], 
                 gateway->ip[2], gateway->ip[3]);

        send(sock, req, strlen(req), 0);

        char buf[1024];
        int total = 0, r;
        while ((r = recv(sock, buf + total, sizeof(buf) - total - 1, 0)) > 0) {
            total += r;
            if (total >= (int)sizeof(buf) - 1) break;
        }
        buf[total] = 0;
        close(sock);

        if (total < 20) continue;

        // Parse response body (after \r\n\r\n)
        char *body = strstr(buf, "\r\n\r\n");
        if (!body) continue;
        body += 4;

        // Look for IP patterns like 10.0.0.x in the response
        char *ptr = body;
        while (*ptr && result->mesh_pivot_count < 8) {
            if (strncmp(ptr, "10.0.0.", 7) == 0) {
                uint8_t octet = atoi(ptr + 7);
                if (octet > 0 && octet < 255) {
                    mesh_remote_node_t *mn = 
                        &result->mesh_nodes[result->mesh_pivot_count];
                    mn->ip[0] = 10; mn->ip[1] = 0;
                    mn->ip[2] = 0; mn->ip[3] = octet;
                    mn->has_mac = false;
                    mn->port80 = false;
                    mn->port5555 = false;
                    mn->is_esp32 = true;
                    result->mesh_pivot_count++;
                    ESP_LOGI(TAG, "PIVOT: Found mesh node 10.0.0.%d", octet);
                    ptr += 7;
                    while (*ptr && (*ptr >= '0' && *ptr <= '9')) ptr++;
                    continue;
                }
            }
            ptr++;
        }

        if (result->mesh_pivot_count > 0) {
            strcpy(result->pivot_method, "http");
            ESP_LOGI(TAG, "PIVOT: Found %d mesh nodes via %s",
                     result->mesh_pivot_count, paths[p]);
            return;
        }
    }

    // If HTTP didn't work, try ADB (port 5555)
    for (int i = 0; i < result->total_found; i++) {
        if (result->nodes[i].is_esp32 && result->nodes[i].port5555) {
            gateway = &result->nodes[i];
            ESP_LOGI(TAG, "PIVOT: Trying ADB on %d.%d.%d.%d:5555",
                     gateway->ip[0], gateway->ip[1],
                     gateway->ip[2], gateway->ip[3]);

            int sock = socket(AF_INET, SOCK_STREAM, 0);
            if (sock < 0) break;

            // ... ADB handshake + shell command would go here
            // For now, mark as attempted
            close(sock);
            strcpy(result->pivot_method, "adb_attempt");
            return;
        }
    }

    strcpy(result->pivot_method, "none");
    ESP_LOGW(TAG, "PIVOT: Could not reach mesh network");
}

static void mesh_remote_scan_task(void *arg)
{
    typedef struct { char ssid[33]; char pass[65]; } scan_params_t;
    scan_params_t *p = (scan_params_t *)arg;
    int64_t scan_start = esp_timer_get_time();

    ESP_LOGW(TAG, "REMOTE: Joining '%s' (AP down ~30s)", p->ssid);

    save_ap_config();
    esp_wifi_stop();
    vTaskDelay(pdMS_TO_TICKS(500));
    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_start();

    wifi_config_t sta_cfg = {0};
    strncpy((char *)sta_cfg.sta.ssid, p->ssid, 32);
    strncpy((char *)sta_cfg.sta.password, p->pass, 64);
    esp_wifi_set_config(WIFI_IF_STA, &sta_cfg);
    esp_wifi_connect();

    int tout = 0;
    while (tout < 100) {
        vTaskDelay(pdMS_TO_TICKS(100));
        wifi_ap_record_t ap;
        if (esp_wifi_sta_get_ap_info(&ap) == ESP_OK) {
            memcpy(s_remote_result.gateway_mac, ap.bssid, 6);
            s_remote_result.channel = ap.primary;
            break;
        }
        tout++;
    }
    if (tout >= 100) { ESP_LOGE(TAG, "REMOTE: Cannot connect"); goto fail; }

    /* DHCP — poll every 500ms up to 15s */
    esp_netif_ip_info_t ip_info = {0};
    {
        esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_STA_DEF");
        bool got_ip = false;
        for (int w = 0; w < 30; w++) {
            vTaskDelay(pdMS_TO_TICKS(500));
            if (netif) { esp_netif_get_ip_info(netif, &ip_info);
                if (ip_info.ip.addr != 0) { got_ip = true; break; }
            }
        }
        if (!got_ip) { ESP_LOGE(TAG, "REMOTE: No DHCP IP after 15s"); goto fail; }
    }

    u32_to_ip4(ip_info.ip.addr, s_remote_result.target_ip);
    u32_to_ip4(ip_info.netmask.addr, s_remote_result.netmask);
    u32_to_ip4(ip_info.gw.addr, s_remote_result.gateway_ip);
    strncpy(s_remote_result.target_ssid, p->ssid, 32);

    /* Gateway reachability test */
    ESP_LOGI(TAG, "REMOTE: Testing gateway reachability...");
    {
        int ts = socket(AF_INET, SOCK_STREAM, 0);
        if (ts >= 0) {
            struct sockaddr_in sa = {0};
            sa.sin_family = AF_INET; sa.sin_port = htons(80);
            sa.sin_addr.s_addr = ip_info.gw.addr;
            int fl = fcntl(ts, F_GETFL, 0);
            if (fl >= 0) fcntl(ts, F_SETFL, fl | O_NONBLOCK);
            int r = connect(ts, (struct sockaddr *)&sa, sizeof(sa));
            if (r < 0 && errno == EINPROGRESS) {
                fd_set wf; struct timeval tv; FD_ZERO(&wf); FD_SET(ts, &wf);
                tv.tv_sec = 3; tv.tv_usec = 0; r = select(ts+1, NULL, &wf, NULL, &tv);
                if (r > 0) { int e=0; socklen_t el=sizeof(e);
                    getsockopt(ts, SOL_SOCKET, SO_ERROR, &e, &el);
                    ESP_LOGI(TAG, "REMOTE: Gateway port 80: %s", e==0?"OPEN":"closed");
                } else ESP_LOGW(TAG, "REMOTE: Gateway port 80: TIMEOUT");
            } else if (r == 0) ESP_LOGI(TAG, "REMOTE: Gateway port 80: OPEN (instant)");
            close(ts);
        }
    }

    uint32_t own_ip = ntohl(ip_info.ip.addr);
    uint32_t nm     = ntohl(ip_info.netmask.addr);
    uint32_t subnet = own_ip & nm;
    uint32_t start  = subnet + 1;
    uint32_t end    = subnet | ~nm;

    ESP_LOGI(TAG, "REMOTE: Connected IP=%u.%u.%u.%u scanning %u hosts",
             (own_ip>>24)&0xFF, (own_ip>>16)&0xFF, (own_ip>>8)&0xFF, own_ip&0xFF,
             (unsigned)(end - start - 1));

    /* Start promiscuous MAC capture */
    mac_capture_start();

    /* ── Probe all hosts ── */
    uint16_t alive = 0, found = 0;
    for (uint32_t hip = start; hip < end && found < MESH_REMOTE_MAX_NODES; hip++) {
        if (hip == own_ip) continue;

        if (((hip - start) & 0xF) == 0) {
            wifi_ap_record_t ap_info;
            if (esp_wifi_sta_get_ap_info(&ap_info) != ESP_OK) {
                ESP_LOGW(TAG, "REMOTE: WiFi link lost — stopping scan"); break;
            }
        }

        uint32_t ip_n = htonl(hip);
        int64_t probe_time = esp_timer_get_time();

        bool p80   = probe_port(ip_n, 80, 80) != 0;
        bool p5555 = (!p80) && (probe_port(ip_n, 5555, 80) != 0);

        if (!p80 && !p5555) continue;

        alive++;  /* count only hosts that responded */

        vTaskDelay(pdMS_TO_TICKS(10));  /* let promiscuous cb capture the response */

        mesh_remote_node_t *nd = &s_remote_result.nodes[found];
        nd->ip[0] = (hip>>24)&0xFF; nd->ip[1] = (hip>>16)&0xFF;
        nd->ip[2] = (hip>>8)&0xFF;  nd->ip[3] = hip&0xFF;
        nd->port80 = p80; nd->port5555 = p5555;
        nd->is_esp32 = false;

        /* Try to get MAC from promiscuous capture */
        if (get_captured_mac(probe_time, nd->mac, &nd->rssi)) {
            nd->has_mac = true;
            nd->is_esp32 = node_scanner_is_espressif_oui(nd->mac);

        } else {
            nd->has_mac = false;
            memset(nd->mac, 0, 6);
        }

        /* HTTP fingerprint */
        if (p80) {
            int s = socket(AF_INET, SOCK_STREAM, 0);
            if (s >= 0) {
                struct sockaddr_in sa = {0};
                sa.sin_family = AF_INET; sa.sin_port = htons(80);
                sa.sin_addr.s_addr = ip_n;
                if (connect(s, (struct sockaddr *)&sa, sizeof(sa)) == 0) {
                    const char *req = "GET / HTTP/1.0\r\nHost: target\r\nConnection: close\r\n\r\n";
                    send(s, req, strlen(req), 0);
                    char buf[512] = {0}; int total = 0;
                    while (total < 511) { int r = recv(s, buf+total, 511-total, 0);
                        if (r <= 0) break; 
                        total += r;
                     }
                    if (strstr(buf,"ESP32") || strstr(buf,"esp32") ||
                        strstr(buf,"ESP-IDF") || strstr(buf,"esp-idf") ||
                        strstr(buf,"Express") || strstr(buf,"express") ||  // ← ADD
                        strstr(buf,"lwip") || strstr(buf,"LWIP"))           // ← ADD
                        nd->is_esp32 = true;
                }
                close(s);
            }
        }

        ESP_LOGI(TAG, "  %u.%u.%u.%u  p80=%d p5555=%d esp=%d mac=%s",
                 nd->ip[0], nd->ip[1], nd->ip[2], nd->ip[3],
                 nd->port80, nd->port5555, nd->is_esp32,
                 nd->has_mac ? "yes" : "N/A");

        if (nd->is_esp32) s_remote_result.esp32_count++;
        found++;
    }
    s_remote_result.total_found = found;
    s_remote_result.total_alive = alive;
    s_remote_result.sweep_time_ms = (esp_timer_get_time() - scan_start) / 1000;

    mac_capture_stop();

    // Mesh pivot: discover 10.0.0.x nodes through gateway ESP32
    mesh_pivot_scan(&s_remote_result);

    ESP_LOGI(TAG, "REMOTE: Done. %u devices (%u ESP32), %u alive, %lu ms",
             s_remote_result.total_found, s_remote_result.esp32_count,
             s_remote_result.total_alive,
             (unsigned long)s_remote_result.sweep_time_ms);
    goto done;

fail:
    ESP_LOGE(TAG, "REMOTE: Scan failed");

done:
    free(p);
    restore_ap_mode();
    s_remote_scanning = false;
    s_remote_result.scanning = false;
    s_remote_result.done = true;
    s_remote_task_handle = NULL;
    vTaskDelete(NULL);
}

esp_err_t mesh_remote_scan_start(const char *ssid, const char *password)
{
    if (s_remote_scanning) return ESP_ERR_INVALID_STATE;
    if (!ssid || !password) return ESP_ERR_INVALID_ARG;

    typedef struct { char ssid[33]; char pass[65]; } scan_params_t;
    scan_params_t *p = malloc(sizeof(scan_params_t));
    if (!p) return ESP_ERR_NO_MEM;
    memset(p, 0, sizeof(*p));
    strncpy(p->ssid, ssid, 32);
    strncpy(p->pass, password, 64);

    memset(&s_remote_result, 0, sizeof(s_remote_result));
    s_remote_result.scanning = true;
    s_remote_result.done = false;
    s_remote_scanning = true;

    if (xTaskCreate(mesh_remote_scan_task, "remote_scan", 6144,
                    p, 2, &s_remote_task_handle) != pdPASS) { 
        free(p);
        s_remote_scanning = false;
        s_remote_result.scanning = false;
        return ESP_ERR_NO_MEM;
    }
    return ESP_OK;
}

bool mesh_remote_scan_is_running(void) { return s_remote_scanning; }
const mesh_remote_result_t *mesh_remote_scan_get_results(void) { return &s_remote_result; }
