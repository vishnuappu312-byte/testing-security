/**
 * mesh_packet_inject.h
 *
 * Mesh Packet Injection — forge and transmit raw 802.11 frames
 * targeting mesh parent/child nodes discovered by the mesh scanner.
 */

#ifndef MESH_PACKET_INJECT_H
#define MESH_PACKET_INJECT_H

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"
#include "cJSON.h"

#define MESH_INJECT_MAX_FRAME     256
#define MESH_INJECT_MAX_LOG       32
#define MESH_INJECT_TIMEOUT_SEC   120
#define MESH_INJECT_TIMEOUT_US    (MESH_INJECT_TIMEOUT_SEC * 1000000ULL)

typedef enum {
    MESH_INJECT_TEMPLATE_DEAUTH = 0,
    MESH_INJECT_TEMPLATE_DISASSOC,
    MESH_INJECT_TEMPLATE_AUTH,
    MESH_INJECT_TEMPLATE_ASSOC_REQ,
    MESH_INJECT_TEMPLATE_PROBE_REQ,
    MESH_INJECT_TEMPLATE_BEACON,
    MESH_INJECT_TEMPLATE_MESH_ACTION,
    MESH_INJECT_TEMPLATE_CUSTOM_HEX,
    MESH_INJECT_TEMPLATE_COUNT
} mesh_inject_template_t;

typedef struct {
    uint8_t  target_bssid[6];
    uint8_t  dest_mac[6];
    uint8_t  src_mac[6];
    bool     src_mac_set;
    uint8_t  channel;
    mesh_inject_template_t template_id;
    char     custom_hex[MESH_INJECT_MAX_FRAME * 2 + 1];
    uint16_t burst_count;
    uint16_t interval_ms;
    uint16_t reason_code;
    char     ssid[33];
} mesh_inject_config_t;

typedef struct {
    uint32_t time_ms;
    uint8_t  template_id;
    uint8_t  channel;
    uint16_t frame_len;
    bool     tx_ok;
    char     frame_hex[MESH_INJECT_MAX_FRAME * 2 + 1];
} mesh_inject_log_t;

typedef struct {
    bool     active;
    bool     timeout;
    uint32_t packets_sent;
    uint32_t packets_failed;
    uint32_t uptime_ms;
    uint8_t  target_bssid[6];
    uint8_t  dest_mac[6];
    uint8_t  channel;
    mesh_inject_template_t template_id;
    uint16_t burst_count;
    uint16_t interval_ms;
    uint16_t log_count;
    mesh_inject_log_t log[MESH_INJECT_MAX_LOG];
    char     error[64];
} mesh_inject_state_t;

void      mesh_packet_inject_init(void);
esp_err_t mesh_packet_inject_start(const mesh_inject_config_t *cfg);
esp_err_t mesh_packet_inject_stop(void);
bool      mesh_packet_inject_is_active(void);
const mesh_inject_state_t *mesh_packet_inject_get_state(void);
const char *mesh_packet_inject_template_str(mesh_inject_template_t t);
cJSON *mesh_packet_inject_get_status_json(void);

#endif /* MESH_PACKET_INJECT_H */
