/**
 * mesh_replay.h
 *
 * Mesh frame replay — promiscuous capture of mesh/management frames followed
 * by re-transmission to test duplicate-processing and routing resilience.
 */

#ifndef MESH_REPLAY_H
#define MESH_REPLAY_H

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"
#include "cJSON.h"

#define MESH_REPLAY_TIMEOUT_SEC    120
#define MESH_REPLAY_TIMEOUT_US       (MESH_REPLAY_TIMEOUT_SEC * 1000000ULL)
#define MESH_REPLAY_MAX_STORED       32
#define MESH_REPLAY_FRAME_MAX        256
#define MESH_REPLAY_MAX_LOG          48
#define MESH_REPLAY_PAYLOAD_LOG_MAX  64

typedef enum {
    MESH_REPLAY_FILTER_ALL = 0,
    MESH_REPLAY_FILTER_MGMT,
    MESH_REPLAY_FILTER_DATA,
    MESH_REPLAY_FILTER_MESH_ACTION,
    MESH_REPLAY_FILTER_COUNT
} mesh_replay_filter_t;

typedef enum {
    MESH_REPLAY_MODE_LIVE = 0,   /* replay each frame immediately on capture */
    MESH_REPLAY_MODE_CYCLE,      /* buffer frames and cycle-replay on interval */
    MESH_REPLAY_MODE_COUNT
} mesh_replay_mode_t;

typedef struct {
    uint8_t               channel;
    uint8_t               parent_bssid[6];
    bool                  parent_bssid_set;
    uint8_t               target_mac[6];
    bool                  target_mac_set;
    char                  ssid[33];
    mesh_replay_filter_t  filter;
    mesh_replay_mode_t    mode;
    uint16_t              replay_interval_ms;
    uint8_t               replay_per_frame;
} mesh_replay_config_t;

typedef struct {
    uint16_t len;
    uint8_t  data[MESH_REPLAY_FRAME_MAX];
    uint32_t captured_ms;
    uint8_t  frame_type;
    uint8_t  subtype;
    uint8_t  src_mac[6];
    uint8_t  dst_mac[6];
    uint8_t  bssid[6];
    int8_t   rssi;
} mesh_replay_frame_t;

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
    uint8_t  payload[MESH_REPLAY_PAYLOAD_LOG_MAX];
    bool     replayed;
    bool     tx_ok;
} mesh_replay_log_t;

typedef struct {
    bool                  active;
    bool                  capturing;
    bool                  replaying;
    bool                  timeout;
    mesh_replay_filter_t  filter;
    mesh_replay_mode_t    mode;
    uint32_t              frames_captured;
    uint32_t              frames_seen;
    uint32_t              frames_replayed;
    uint32_t              replay_ok;
    uint32_t              replay_failed;
    uint32_t              stored_count;
    uint32_t              uptime_ms;
    uint8_t               channel;
    uint8_t               parent_bssid[6];
    uint8_t               target_mac[6];
    int8_t                rssi;
    char                  ssid[33];
    char                  filter_str[24];
    char                  mode_str[16];
    uint16_t              log_count;
    mesh_replay_log_t     log[MESH_REPLAY_MAX_LOG];
    char                  error[64];
} mesh_replay_state_t;

void      mesh_replay_init(void);
esp_err_t mesh_replay_start(const mesh_replay_config_t *cfg);
esp_err_t mesh_replay_stop(void);
bool      mesh_replay_is_active(void);
const mesh_replay_state_t *mesh_replay_get_state(void);
const char *mesh_replay_filter_str(mesh_replay_filter_t f);
const char *mesh_replay_mode_str(mesh_replay_mode_t m);
cJSON    *mesh_replay_get_status_json(void);

#endif /* MESH_REPLAY_H */
