/**
 * mesh_eavesdrop.h
 *
 * Passive mesh eavesdropping — promiscuous 802.11 capture on the mesh
 * channel without association, ARP poisoning, or frame injection.
 */

#ifndef MESH_EAVESDROP_H
#define MESH_EAVESDROP_H

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"
#include "cJSON.h"

#define MESH_EAVESDROP_MAX_LOG     48
#define MESH_EAVESDROP_PAYLOAD_MAX 64
#define MESH_EAVESDROP_TIMEOUT_SEC 180
#define MESH_EAVESDROP_TIMEOUT_US  (MESH_EAVESDROP_TIMEOUT_SEC * 1000000ULL)

typedef enum {
    MESH_EAVES_FILTER_ALL = 0,
    MESH_EAVES_FILTER_MGMT,
    MESH_EAVES_FILTER_DATA,
    MESH_EAVES_FILTER_MESH_ACTION,
    MESH_EAVES_FILTER_COUNT
} mesh_eavesdrop_filter_t;

typedef struct {
    uint8_t                 channel;
    uint8_t                 parent_bssid[6];
    bool                    parent_bssid_set;
    uint8_t                 target_mac[6];
    bool                    target_mac_set;
    char                    ssid[33];
    mesh_eavesdrop_filter_t filter;
    bool                    skip_beacons;
} mesh_eavesdrop_config_t;

typedef struct {
    uint32_t time_ms;
    uint8_t  frame_type;   /* 0=mgmt 1=data 2=mesh_action */
    uint8_t  subtype;
    uint8_t  src_mac[6];
    uint8_t  dst_mac[6];
    uint8_t  bssid[6];
    int8_t   rssi;
    uint8_t  channel;
    uint16_t len;
    uint16_t payload_len;
    uint8_t  payload[MESH_EAVESDROP_PAYLOAD_MAX];
} mesh_eavesdrop_log_t;

typedef struct {
    bool                    active;
    bool                    capturing;
    bool                    timeout;
    mesh_eavesdrop_filter_t filter;
    uint32_t                packets_rx;
    uint32_t                frames_seen;
    uint32_t                mgmt_count;
    uint32_t                data_count;
    uint32_t                mesh_action_count;
    uint32_t                uptime_ms;
    uint8_t                 channel;
    uint8_t                 parent_bssid[6];
    uint8_t                 target_mac[6];
    int8_t                  rssi;
    char                    ssid[33];
    char                    filter_str[24];
    uint16_t                log_count;
    mesh_eavesdrop_log_t    log[MESH_EAVESDROP_MAX_LOG];
    char                    error[64];
} mesh_eavesdrop_state_t;

void      mesh_eavesdrop_init(void);
esp_err_t mesh_eavesdrop_start(const mesh_eavesdrop_config_t *cfg);
esp_err_t mesh_eavesdrop_stop(void);
bool      mesh_eavesdrop_is_active(void);
const mesh_eavesdrop_state_t *mesh_eavesdrop_get_state(void);
const char *mesh_eavesdrop_filter_str(mesh_eavesdrop_filter_t f);
cJSON    *mesh_eavesdrop_get_status_json(void);

#endif /* MESH_EAVESDROP_H */
