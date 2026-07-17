/**
 * espnow_attack.h
 *
 * ESP-NOW mesh lab module for owned fleets:
 *   - fixed-channel monitor / peer discovery / payload capture
 *   - raw-frame replay
 *   - unencrypted custom payload injection (esp_now_send)
 *   - rate-limited flood
 *
 * Encrypted ESP-NOW payloads remain opaque without peer keys.
 */

#ifndef ESPNOW_ATTACK_H
#define ESPNOW_ATTACK_H

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"
#include "cJSON.h"

#define ESPNOW_ATTACK_MAX_PEERS       32
#define ESPNOW_ATTACK_MAX_FRAMES      48
#define ESPNOW_ATTACK_MAX_LOG         48
#define ESPNOW_ATTACK_FRAME_MAX       256
#define ESPNOW_ATTACK_PAYLOAD_MAX     250
#define ESPNOW_ATTACK_PAYLOAD_LOG_MAX 64
#define ESPNOW_ATTACK_BURST_MAX       200
#define ESPNOW_ATTACK_INTERVAL_MIN_MS 20
#define ESPNOW_ATTACK_TIMEOUT_SEC     120
#define ESPNOW_ATTACK_TIMEOUT_MAX_SEC 180
#define ESPNOW_ATTACK_TIMEOUT_US      (ESPNOW_ATTACK_TIMEOUT_SEC * 1000000ULL)

typedef enum {
    ESPNOW_MODE_MONITOR = 0,
    ESPNOW_MODE_REPLAY,
    ESPNOW_MODE_INJECT,
    ESPNOW_MODE_FLOOD,
    ESPNOW_MODE_COUNT
} espnow_attack_mode_t;

typedef struct {
    uint8_t              channel;          /* required, 1-13 */
    espnow_attack_mode_t mode;
    uint8_t              target_mac[6];
    bool                 target_mac_set;
    bool                 broadcast;        /* inject/flood to FF:FF:FF:FF:FF:FF */
    int16_t              frame_index;      /* replay index; -1 = latest/all */
    uint8_t              payload[ESPNOW_ATTACK_PAYLOAD_MAX];
    uint16_t             payload_len;
    uint16_t             burst_count;      /* 1..ESPNOW_ATTACK_BURST_MAX */
    uint16_t             interval_ms;      /* >= ESPNOW_ATTACK_INTERVAL_MIN_MS */
    uint16_t             timeout_sec;      /* 1..ESPNOW_ATTACK_TIMEOUT_MAX_SEC */
} espnow_attack_config_t;

typedef struct {
    uint8_t  mac[6];
    int8_t   rssi;
    uint8_t  channel;
    uint32_t rx_count;
    uint32_t last_seen_ms;
} espnow_peer_t;

typedef struct {
    uint16_t len;
    uint8_t  data[ESPNOW_ATTACK_FRAME_MAX];
    uint8_t  src_mac[6];
    uint8_t  dst_mac[6];
    uint16_t payload_len;
    uint8_t  payload[ESPNOW_ATTACK_PAYLOAD_MAX];
    int8_t   rssi;
    uint32_t captured_ms;
    bool     encrypted_hint;
} espnow_stored_frame_t;

typedef struct {
    uint32_t time_ms;
    uint8_t  src_mac[6];
    uint8_t  dst_mac[6];
    int8_t   rssi;
    uint16_t len;
    uint16_t payload_len;
    uint8_t  payload[ESPNOW_ATTACK_PAYLOAD_LOG_MAX];
    bool     replayed;
    bool     injected;
    bool     tx_ok;
    bool     encrypted_hint;
} espnow_log_t;

typedef struct {
    bool                 active;
    bool                 capturing;
    bool                 transmitting;
    bool                 timeout;
    espnow_attack_mode_t mode;
    uint8_t              channel;
    uint32_t             frames_seen;
    uint32_t             frames_captured;
    uint32_t             peers_seen;
    uint32_t             tx_ok;
    uint32_t             tx_fail;
    uint32_t             uptime_ms;
    int8_t               rssi;
    uint16_t             peer_count;
    uint16_t             stored_count;
    uint16_t             log_count;
    uint16_t             burst_count;
    uint16_t             interval_ms;
    char                 mode_str[16];
    char                 error[64];
    espnow_peer_t        peers[ESPNOW_ATTACK_MAX_PEERS];
    espnow_log_t         log[ESPNOW_ATTACK_MAX_LOG];
} espnow_attack_state_t;

void      espnow_attack_init(void);
esp_err_t espnow_attack_start(const espnow_attack_config_t *cfg);
esp_err_t espnow_attack_stop(void);
bool      espnow_attack_is_active(void);
const espnow_attack_state_t *espnow_attack_get_state(void);
const char *espnow_attack_mode_str(espnow_attack_mode_t mode);
cJSON    *espnow_attack_get_status_json(void);
bool      espnow_attack_parse_hex_payload(const char *hex, uint8_t *out, uint16_t *out_len);

#endif /* ESPNOW_ATTACK_H */
