/**
 * mesh_l2_deauth.h
 *
 * Layer 2 Deauthentication — continuous 802.11 deauth/disassoc frame
 * injection against ESP-WIFI-MESH parent/child links.
 */

#ifndef MESH_L2_DEAUTH_H
#define MESH_L2_DEAUTH_H

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"
#include "cJSON.h"

#define MESH_L2_DEAUTH_TIMEOUT_SEC   120
#define MESH_L2_DEAUTH_TIMEOUT_US    (MESH_L2_DEAUTH_TIMEOUT_SEC * 1000000ULL)
#define MESH_L2_DEAUTH_MAX_TARGETS   8

typedef enum {
    MESH_L2_DEAUTH_MODE_NONE = 0,
    MESH_L2_DEAUTH_MODE_TARGETED,       /* Unicast deauth to child */
    MESH_L2_DEAUTH_MODE_BROADCAST,      /* Broadcast via parent BSSID */
    MESH_L2_DEAUTH_MODE_BIDIRECTIONAL,  /* AP→STA and STA→AP both ways */
    MESH_L2_DEAUTH_MODE_DEAUTH_DISASSOC,/* Deauth + disassoc pair */
    MESH_L2_DEAUTH_MODE_MULTI_TARGET,   /* Rotate extra child MACs */
    MESH_L2_DEAUTH_MODE_COUNT
} mesh_l2_deauth_mode_t;

typedef struct {
    uint8_t               parent_bssid[6];
    uint8_t               target_mac[6];     /* child MAC; FF:FF.. = broadcast */
    bool                  target_mac_set;
    uint8_t               channel;
    mesh_l2_deauth_mode_t mode;
    char                  ssid[33];
    uint16_t              interval_ms;
    uint16_t              burst_size;
    uint16_t              reason_code;
    uint8_t               extra_targets[MESH_L2_DEAUTH_MAX_TARGETS][6];
    uint8_t               extra_target_count;
} mesh_l2_deauth_config_t;

typedef struct {
    bool                  active;
    bool                  timeout;
    mesh_l2_deauth_mode_t mode;
    uint32_t              packets_sent;
    uint32_t              packets_failed;
    uint32_t              deauth_sent;
    uint32_t              disassoc_sent;
    uint32_t              uptime_ms;
    uint8_t               channel;
    uint8_t               parent_bssid[6];
    uint8_t               target_mac[6];
    char                  ssid[33];
    char                  mode_str[32];
    char                  error[64];
} mesh_l2_deauth_state_t;

void      mesh_l2_deauth_init(void);
esp_err_t mesh_l2_deauth_start(const mesh_l2_deauth_config_t *cfg);
esp_err_t mesh_l2_deauth_stop(void);
bool      mesh_l2_deauth_is_active(void);
const mesh_l2_deauth_state_t *mesh_l2_deauth_get_state(void);
const char *mesh_l2_deauth_mode_str(mesh_l2_deauth_mode_t m);
cJSON    *mesh_l2_deauth_get_status_json(void);

#endif /* MESH_L2_DEAUTH_H */
