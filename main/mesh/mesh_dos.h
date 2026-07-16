/**
 * mesh_dos.h
 *
 * Mesh Denial-of-Service — continuous 802.11 frame floods targeting
 * ESP-WIFI-MESH parent/child nodes discovered by the mesh scanner.
 */

#ifndef MESH_DOS_H
#define MESH_DOS_H

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"
#include "cJSON.h"

#define MESH_DOS_TIMEOUT_SEC   120
#define MESH_DOS_TIMEOUT_US    (MESH_DOS_TIMEOUT_SEC * 1000000ULL)
#define MESH_DOS_MAX_TARGETS   8

typedef enum {
    MESH_DOS_METHOD_NONE = 0,
    MESH_DOS_METHOD_CHILD_DEAUTH,       /* Deauth specific child node */
    MESH_DOS_METHOD_PARENT_DEAUTH,      /* Broadcast deauth via parent BSSID */
    MESH_DOS_METHOD_MESH_ACTION_FLOOD,  /* Espressif vendor mesh action frames */
    MESH_DOS_METHOD_AUTH_FLOOD,         /* Auth flood toward parent */
    MESH_DOS_METHOD_PROBE_FLOOD,        /* Probe requests for mesh SSID */
    MESH_DOS_METHOD_BEACON_FLOOD,       /* Fake beacons on mesh channel */
    MESH_DOS_METHOD_COMBINE_ALL,        /* Rotate all methods */
    MESH_DOS_METHOD_COUNT
} mesh_dos_method_t;

typedef struct {
    uint8_t           parent_bssid[6];
    uint8_t           target_mac[6];     /* child MAC; FF:FF:FF:FF:FF:FF = broadcast */
    bool              target_mac_set;
    uint8_t           channel;
    mesh_dos_method_t method;
    char              ssid[33];
    uint16_t          interval_ms;       /* delay between TX bursts */
    uint16_t          burst_size;        /* frames per burst (1–32) */
    uint16_t          reason_code;
    /* Optional multi-target (child deauth / combine) */
    uint8_t           extra_targets[MESH_DOS_MAX_TARGETS][6];
    uint8_t           extra_target_count;
} mesh_dos_config_t;

typedef struct {
    bool              active;
    bool              timeout;
    mesh_dos_method_t method;
    uint32_t          packets_sent;
    uint32_t          packets_failed;
    uint32_t          uptime_ms;
    uint8_t           channel;
    uint8_t           parent_bssid[6];
    uint8_t           target_mac[6];
    char              ssid[33];
    char              method_str[32];
    char              error[64];
} mesh_dos_state_t;

void      mesh_dos_init(void);
esp_err_t mesh_dos_start(const mesh_dos_config_t *cfg);
esp_err_t mesh_dos_stop(void);
bool      mesh_dos_is_active(void);
const mesh_dos_state_t *mesh_dos_get_state(void);
const char *mesh_dos_method_str(mesh_dos_method_t m);
cJSON    *mesh_dos_get_status_json(void);

#endif /* MESH_DOS_H */
