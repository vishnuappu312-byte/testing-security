/**
 * mesh_wormhole.h
 *
 * Mesh wormhole — capture frames near one mesh endpoint and tunnel/re-TX
 * them toward another endpoint to create a false short path.
 */

#ifndef MESH_WORMHOLE_H
#define MESH_WORMHOLE_H

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"
#include "cJSON.h"

#define MESH_WORMHOLE_TIMEOUT_SEC     120
#define MESH_WORMHOLE_TIMEOUT_US      (MESH_WORMHOLE_TIMEOUT_SEC * 1000000ULL)
#define MESH_WORMHOLE_FRAME_MAX       256
#define MESH_WORMHOLE_MAX_LOG         48
#define MESH_WORMHOLE_PAYLOAD_LOG_MAX 64

typedef enum {
    MESH_WORMHOLE_MODE_A_TO_B = 0, /* capture near A, inject toward B */
    MESH_WORMHOLE_MODE_B_TO_A,     /* capture near B, inject toward A */
    MESH_WORMHOLE_MODE_BIDIR,      /* both directions */
    MESH_WORMHOLE_MODE_COUNT
} mesh_wormhole_mode_t;

typedef enum {
    MESH_WORMHOLE_ACTION_RELAY = 0, /* re-TX frame bytes as-is (hidden wormhole) */
    MESH_WORMHOLE_ACTION_REWRITE,   /* rewrite addr1 toward peer endpoint */
    MESH_WORMHOLE_ACTION_COUNT
} mesh_wormhole_action_t;

typedef enum {
    MESH_WORMHOLE_FILTER_ALL = 0,
    MESH_WORMHOLE_FILTER_MGMT,
    MESH_WORMHOLE_FILTER_DATA,
    MESH_WORMHOLE_FILTER_MESH_ACTION,
    MESH_WORMHOLE_FILTER_COUNT
} mesh_wormhole_filter_t;

typedef struct {
    uint8_t                 channel;
    uint8_t                 endpoint_a[6];
    uint8_t                 endpoint_b[6];
    uint8_t                 parent_bssid[6];
    bool                    parent_bssid_set;
    char                    ssid[33];
    mesh_wormhole_mode_t    mode;
    mesh_wormhole_action_t  action;
    mesh_wormhole_filter_t  filter;
    uint16_t                tunnel_delay_ms;
} mesh_wormhole_config_t;

typedef struct {
    uint32_t time_ms;
    uint8_t  frame_type;
    uint8_t  subtype;
    uint8_t  src_mac[6];
    uint8_t  dst_mac[6];
    uint8_t  bssid[6];
    int8_t   rssi;
    uint16_t len;
    uint16_t payload_len;
    uint8_t  payload[MESH_WORMHOLE_PAYLOAD_LOG_MAX];
    uint8_t  direction; /* 0 = A→B, 1 = B→A */
    bool     tunneled;
    bool     tx_ok;
} mesh_wormhole_log_t;

typedef struct {
    bool                    active;
    bool                    tunneling;
    bool                    timeout;
    mesh_wormhole_mode_t    mode;
    mesh_wormhole_action_t  action;
    mesh_wormhole_filter_t  filter;
    uint32_t                frames_seen;
    uint32_t                frames_captured;
    uint32_t                frames_tunneled;
    uint32_t                tunnel_ok;
    uint32_t                tunnel_failed;
    uint32_t                a_to_b;
    uint32_t                b_to_a;
    uint32_t                uptime_ms;
    uint8_t                 channel;
    uint8_t                 endpoint_a[6];
    uint8_t                 endpoint_b[6];
    uint8_t                 parent_bssid[6];
    int8_t                  rssi;
    char                    ssid[33];
    char                    mode_str[16];
    char                    action_str[16];
    char                    filter_str[24];
    uint16_t                log_count;
    mesh_wormhole_log_t     log[MESH_WORMHOLE_MAX_LOG];
    char                    error[64];
} mesh_wormhole_state_t;

void      mesh_wormhole_init(void);
esp_err_t mesh_wormhole_start(const mesh_wormhole_config_t *cfg);
esp_err_t mesh_wormhole_stop(void);
bool      mesh_wormhole_is_active(void);
const mesh_wormhole_state_t *mesh_wormhole_get_state(void);
const char *mesh_wormhole_mode_str(mesh_wormhole_mode_t m);
const char *mesh_wormhole_action_str(mesh_wormhole_action_t a);
const char *mesh_wormhole_filter_str(mesh_wormhole_filter_t f);
cJSON    *mesh_wormhole_get_status_json(void);

#endif /* MESH_WORMHOLE_H */
