/**
 * ota_provision.h - bounded HTTP provisioning capture
 */

#ifndef OTA_PROVISION_H
#define OTA_PROVISION_H

#include <stdbool.h>
#include <stdint.h>
#include "esp_err.h"
#include "cJSON.h"

#define OTA_PROV_MAX_PORTS 4
#define OTA_PROV_MAX_FIELDS 8
#define OTA_PROV_MAX_PREVIEW 24
#define OTA_PROV_DEFAULT_PCAP_BYTES (256U * 1024U)
#define OTA_PROV_MAX_PCAP_BYTES (1024U * 1024U)
#define OTA_PROV_PORTAL_HTML_MAX 4096

typedef struct {
    uint8_t channel;
    uint16_t ports[OTA_PROV_MAX_PORTS];
    uint8_t port_count;
    uint32_t max_pcap_bytes;
    uint32_t timeout_sec;
} ota_provision_config_t;

typedef struct {
    bool active;
    bool timeout;
    uint8_t channel;
    uint16_t ports[OTA_PROV_MAX_PORTS];
    uint8_t port_count;
    uint32_t packets_seen;
    uint32_t packets_matched;
    uint32_t packets_captured;
    uint32_t packets_dropped;
    uint32_t malformed_packets;
    uint32_t timeout_count;
    uint32_t preview_count;
    uint32_t pcap_bytes;
    uint32_t pcap_capacity;
    uint32_t elapsed_sec;
    uint32_t remaining_sec;
    char state[32];
    char error[64];
} ota_provision_state_t;

void ota_provision_init(void);
esp_err_t ota_provision_start(const ota_provision_config_t *cfg);
esp_err_t ota_provision_stop(void);
bool ota_provision_is_active(void);
const ota_provision_state_t *ota_provision_get_state(void);
cJSON *ota_provision_get_status_json(void);
const char *ota_provision_get_preview_json(void);
const char *ota_provision_get_summary_json(void);
esp_err_t ota_provision_get_pcap(const uint8_t **data, size_t *size);
void ota_provision_clear(void);

/**
 * Build a synthetic captive-portal page from captured request metadata.
 * Uses field names only — captured values are never copied into HTML.
 * Compatible with evil twin's /password POST handler (password-like fields
 * are posted as name="password").
 */
esp_err_t ota_provision_build_portal(void);
bool ota_provision_has_portal(void);
const char *ota_provision_get_portal_html(void);
const char *ota_provision_get_portal_wrong_html(void);
cJSON *ota_provision_get_portal_meta_json(void);

#endif /* OTA_PROVISION_H */
