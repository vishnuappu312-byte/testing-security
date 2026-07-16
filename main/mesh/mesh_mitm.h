/**
 * mesh_mitm.h
 *
 * Mesh Man-in-the-Middle — raw-frame ARP-poison victim ↔ gateway (parent)
 * on the mesh channel (unassociated), and capture intercepted traffic.
 */

#ifndef MESH_MITM_H
#define MESH_MITM_H

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"
#include "cJSON.h"

#define MESH_MITM_MAX_LOG          32
#define MESH_MITM_PAYLOAD_MAX      64
#define MESH_MITM_TIMEOUT_SEC      180
#define MESH_MITM_TIMEOUT_US       (MESH_MITM_TIMEOUT_SEC * 1000000ULL)
#define MESH_MITM_ARP_INTERVAL_MS  1000

typedef struct {
    char     ssid[33];
    char     password[65];
    uint8_t  victim_mac[6];
    uint8_t  victim_ip[4];
    uint8_t  gateway_mac[6];
    uint8_t  gateway_ip[4];
    bool     gateway_mac_set;
    bool     gateway_ip_set;
    uint8_t  channel;
    bool     deauth_first;
    uint16_t arp_interval_ms;
} mesh_mitm_config_t;

typedef struct {
    uint32_t time_ms;
    uint8_t  frame_type;   /* 0=mgmt 1=data 2=arp */
    uint8_t  subtype;
    uint8_t  src_mac[6];
    uint8_t  dst_mac[6];
    int8_t   rssi;
    uint8_t  channel;
    uint16_t len;
    uint16_t payload_len;
    uint8_t  payload[MESH_MITM_PAYLOAD_MAX];
} mesh_mitm_log_t;

typedef struct {
    bool     active;
    bool     connected;
    bool     arp_active;
    bool     capturing;
    bool     timeout;
    uint32_t arp_sent;
    uint32_t packets_rx;
    uint32_t frames_seen;  /* any mgmt/data on channel (sniffer alive?) */
    uint32_t uptime_ms;
    uint8_t  our_mac[6];
    uint8_t  our_ip[4];
    uint8_t  victim_mac[6];
    uint8_t  victim_ip[4];
    uint8_t  gateway_mac[6];
    uint8_t  gateway_ip[4];
    uint8_t  ap_bssid[6];
    uint8_t  channel;
    int8_t   rssi;
    char     ssid[33];
    uint16_t log_count;
    mesh_mitm_log_t log[MESH_MITM_MAX_LOG];
    char     error[64];
} mesh_mitm_state_t;

void      mesh_mitm_init(void);
esp_err_t mesh_mitm_start(const mesh_mitm_config_t *cfg);
esp_err_t mesh_mitm_stop(void);
bool      mesh_mitm_is_active(void);
const mesh_mitm_state_t *mesh_mitm_get_state(void);
cJSON    *mesh_mitm_get_status_json(void);

#endif /* MESH_MITM_H */
