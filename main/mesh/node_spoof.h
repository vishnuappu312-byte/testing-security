/**
 * node_spoof.h
 *
 * ESP32-S3 Node Spoofing Attack Module
 * Spoof a mesh node's MAC → join target AP → capture traffic
 */

#ifndef NODE_SPOOF_H
#define NODE_SPOOF_H

#include <stdint.h>
#include <stdbool.h>

/* ── Config ── */
#define SPOOF_DEAUTH_COUNT      5
#define SPOOF_MAX_LOG           32
#define SPOOF_CAPTURE_TIMEOUT   60   /* seconds */
#define SPOOF_PAYLOAD_MAX   64    /* capture first 64 bytes of payload */
/* ── Captured frame log ── */
typedef struct {
    uint8_t  frame_type;       /* 0=mgmt, 1=data */
    uint8_t  subtype;          /* auth/assoc/data subtype */
    uint8_t  src_mac[6];
    uint8_t  dst_mac[6];
    int8_t   rssi;
    uint8_t  channel;
    uint32_t time_ms;
    uint16_t len;
    uint16_t payload_len;              /* NEW: how many payload bytes stored */
    uint8_t  payload[SPOOF_PAYLOAD_MAX]; /* NEW: first N bytes of frame data */
} spoof_log_t;

/* ── Spoof state ── */
typedef struct {
    uint8_t  target_mac[6];    /* MAC being spoofed */
    uint8_t  original_mac[6];  /* our real MAC (saved for restore) */
    char     ap_ssid[33];      /* target AP SSID */
    char     ap_pass[65];      /* target AP password */
    uint8_t  ap_channel;
    int8_t   ap_rssi;
    bool     active;
    bool     connected;
    bool     capturing;
    uint32_t deauth_sent;
    uint32_t packets_rx;
    uint32_t uptime_ms;
    uint16_t log_count;
    spoof_log_t log[SPOOF_MAX_LOG];
    char     error[64];
} spoof_state_t;

/* ── API ── */
esp_err_t node_spoof_start(const uint8_t *target_mac,
                            const char *ssid,
                            const char *password);
esp_err_t node_spoof_stop(void);
bool     node_spoof_is_active(void);
const spoof_state_t *node_spoof_get_state(void);

#endif /* NODE_SPOOF_H */


