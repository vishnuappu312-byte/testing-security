#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include "esp_err.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ── Nearby Wi-Fi mesh scanner (dashboard /api/mesh/scan) ───── */
#define SCANNER_CHANNEL          0       /* 0 = all channels (1-13) */
#define SCANNER_PASSIVE_DWELL    300     /* ms per channel (passive) */
#define SCANNER_RSSI_THRESHOLD   -85     /* min RSSI to keep          */
#define SCANNER_MESH_THRESHOLD   2       /* min BSSIDs to flag mesh  */
#define SCANNER_MAX_AP           16      /* max unique APs kept      */
#define SCANNER_MAX_GROUP_NODES  8       /* max nodes inside a group */
#define SCANNER_INTERVAL_SEC     5

/* ── Soft-AP subnet / active-node scanner ───────────────────── */
#define MESH_MAX_NODES           16
#define MESH_MAX_HOSTS           32
#define MESH_PROBE_TIMEOUT_MS    120
#define MESH_PROBE_PORT_COUNT    3
#define MESH_PORT_1              80
#define MESH_PORT_2              443
#define MESH_PORT_3              5555

/* ── ESP-WIFI-MESH (optional root/node networking) ──────────── */
#define MESH_MAC_STR_LEN         18
#define MESH_IP_STR_LEN          16
#define MESH_SSID_LEN            33
#define MESH_HELLO_INTERVAL_MS   5000
#define MESH_MAX_SCAN_APS        20

typedef struct {
    uint8_t  bssid[6];
    char     ssid[33];
    uint8_t  channel;
    int8_t   rssi;
    uint8_t  authmode;
    uint8_t  is_hidden;
    bool     is_espressif;
    uint8_t  ip[4];
    bool     has_ip;
    int      rtt_ms;
} scanner_ap_t;

typedef struct {
    char         ssid[33];
    uint8_t      channel;
    uint8_t      node_count;
    scanner_ap_t nodes[SCANNER_MAX_GROUP_NODES];
    bool         likely_mesh;
    bool         all_same_channel;
    bool         all_espressif;
} mesh_group_t;

typedef struct {
    uint8_t      total_aps;
    scanner_ap_t aps[SCANNER_MAX_AP];
    uint8_t      group_count;
    mesh_group_t groups[SCANNER_MAX_AP];
    uint8_t      mesh_count;
} scan_result_t;

typedef struct {
    uint8_t mac[6];
    uint8_t ip[4];
    int     rtt_ms;
    bool    online;
} mesh_node_t;

/** Local soft-AP / subnet scan result (used by webserver as result->local). */
typedef struct {
    uint8_t     parent_ip[4];
    uint8_t     parent_mac[6];
    bool        parent_mac_set;
    uint8_t     netmask[4];
    uint16_t    total_nodes;
    mesh_node_t nodes[MESH_MAX_NODES];
} mesh_scan_result_t;

typedef struct {
    scan_result_t      nearby;
    mesh_scan_result_t local;
    uint8_t            active_count;
} mesh_active_result_t;

/** Handheld Wi-Fi AP row for ESP-MESH helpers. */
typedef struct {
    char    ssid[MESH_SSID_LEN];
    char    bssid[MESH_MAC_STR_LEN];
    int8_t  rssi;
    uint8_t channel;
    bool    is_mesh;
} mesh_wifi_ap_t;

typedef struct {
    char    mac[MESH_MAC_STR_LEN];
    char    ip[MESH_IP_STR_LEN];
    int8_t  rssi;
    int64_t last_seen_ms;
} mesh_node_info_t;

typedef struct {
    const char *router_ssid;
    const char *router_password;
    const char *mesh_ap_password;
    uint8_t     mesh_id[6];
    int         channel;
    bool        is_root;
} mesh_config_t;

/* ── Promiscuous Mesh Sniffer (passive child node discovery) ── */
#define MESH_SNIFF_MAX_NODES       48
#define MESH_SNIFF_MAX_PARENTS     16
#define MESH_SNIFF_CHAN_TIME_MS    1000
#define MESH_SNIFF_DEFAULT_SEC     10
#define MESH_SNIFF_FRAME_AUTH      1
#define MESH_SNIFF_FRAME_ASSOC     2

typedef struct {
    uint8_t child_mac[6];
    uint8_t parent_bssid[6];
    int8_t  rssi;
    uint8_t channel;
    bool    is_espressif;
    uint8_t frame_type;
} mesh_sniffed_node_t;

typedef struct {
    uint16_t            total_found;
    uint16_t            espressif_count;
    uint16_t            parents_found;
    mesh_sniffed_node_t nodes[MESH_SNIFF_MAX_NODES];
    uint8_t             parent_bssids[MESH_SNIFF_MAX_PARENTS][6];
    uint16_t            scan_time_ms;
    bool                scanning;
} mesh_sniff_result_t;

/* ── Remote Network Scan — join target WiFi, find ESP32 devices ── */
#define MESH_REMOTE_MAX_NODES 32

typedef struct {
    uint8_t ip[4];
    uint8_t mac[6];
    bool    has_mac;
    bool    port80;
    bool    port5555;
    bool    is_esp32;
    int8_t  rssi;
} mesh_remote_node_t;

typedef struct {
    char                target_ssid[33];
    uint8_t             target_ip[4];
    uint8_t             gateway_ip[4];
    uint8_t             gateway_mac[6];
    uint8_t             netmask[4];
    uint8_t             channel;
    uint16_t            total_found;
    uint16_t            total_alive;      // ← ADD THIS
    uint32_t            sweep_time_ms;    // ← ADD THIS
    uint16_t            esp32_count;
    uint16_t            mesh_pivot_count;     // nodes found via gateway pivot
    char                pivot_method[32];     // "http" or "adb" or "none"
    mesh_remote_node_t  mesh_nodes[8];        // mesh subnet nodes (10.0.0.x)
    mesh_remote_node_t  nodes[MESH_REMOTE_MAX_NODES];
    bool                scanning;
    bool                done;
    char                error[64];
} mesh_remote_result_t;
/* ── Dashboard init ─────────────────────────────────────────── */
void mesh_init(void);

esp_err_t mesh_get_ips(const char *ssid, const char *password,
                       uint8_t channel, char ***ips_out, int *count);

esp_err_t mesh_sniff_start(uint8_t scan_seconds);
esp_err_t mesh_sniff_stop(void);
bool      mesh_sniff_is_running(void);
const mesh_sniff_result_t *mesh_sniff_get_results(void);

esp_err_t mesh_remote_scan_start(const char *ssid, const char *password);
bool      mesh_remote_scan_is_running(void);
const mesh_remote_result_t *mesh_remote_scan_get_results(void);

/* ── ESP-WIFI-MESH networking (mutually exclusive with soft-AP) */
esp_err_t mesh_espmesh_init(const mesh_config_t *cfg);
esp_err_t mesh_wifi_scan(mesh_wifi_ap_t *out, int *count, uint32_t timeout_ms);
esp_err_t mesh_connect_wifi(const char *ssid, const char *password, uint32_t timeout_ms);
esp_err_t mesh_start(void);
esp_err_t mesh_stop(void);
bool mesh_is_connected(void);
bool mesh_is_root(void);
esp_err_t mesh_get_own_mac(char *out, size_t out_len);
esp_err_t mesh_get_own_ip(char *out, size_t out_len);
int mesh_get_node_table(mesh_node_info_t *out, int max_out);
void mesh_print_scan(const mesh_wifi_ap_t *list, int count);
void mesh_print_node_table(void);

#include "node_scanner.h"
#include "mesh_packet_inject.h"
#include "mesh_mitm.h"
#include "mesh_dos.h"
#include "mesh_eavesdrop.h"
#include "mesh_replay.h"
#include "mesh_wormhole.h"
#include "mesh_l2_deauth.h"
#include "mesh_route_poison.h"

#ifdef __cplusplus
}
#endif