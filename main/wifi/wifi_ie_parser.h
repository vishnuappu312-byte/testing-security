/**
 * @file wifi_ie_parser.h
 * @brief Bounded 802.11 information-element helpers for Wi-Fi audit modules.
 */
#ifndef WIFI_IE_PARSER_H
#define WIFI_IE_PARSER_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WIFI_IE_SSID_MAX      32
#define WIFI_IE_VENDOR_OUI_LEN 3

typedef struct {
    const uint8_t *data;
    uint8_t        len;
} wifi_ie_t;

typedef struct {
    bool     present;
    bool     mfpc;
    bool     mfpr;
    uint16_t version;
    uint32_t group_cipher;
    uint16_t pairwise_count;
    uint16_t akm_count;
} wifi_rsn_info_t;

typedef enum {
    WIFI_PMF_UNSUPPORTED = 0,
    WIFI_PMF_CAPABLE,
    WIFI_PMF_REQUIRED
} wifi_pmf_state_t;

typedef struct {
    bool     present;
    uint8_t  version;          /* WPS version (often 0x10) */
    bool     configured;
    bool     locked;
    uint16_t config_methods;
    char     manufacturer[32];
    char     model[32];
    char     device_name[32];
    char     uuid[37];         /* dashed string if available */
} wifi_wps_info_t;

typedef struct {
    bool    present;
    uint8_t mode;              /* 0=no switch, 1=switch without quiet, etc */
    uint8_t new_channel;
    uint8_t count;             /* TBTTs until switch */
} wifi_csa_info_t;

/**
 * Walk tagged IEs starting at `ies` for `ies_len` bytes.
 * Invokes cb for each well-formed tag. cb returns false to stop early.
 */
typedef bool (*wifi_ie_walk_cb_t)(uint8_t tag, const uint8_t *data, uint8_t len, void *ctx);
bool wifi_ie_walk(const uint8_t *ies, size_t ies_len, wifi_ie_walk_cb_t cb, void *ctx);

/** Find first IE with given tag. */
bool wifi_ie_find(const uint8_t *ies, size_t ies_len, uint8_t tag, wifi_ie_t *out);

/** Find vendor IE matching OUI (+ optional type byte when type >= 0). */
bool wifi_ie_find_vendor(const uint8_t *ies, size_t ies_len,
                         const uint8_t oui[3], int type, wifi_ie_t *out);

/** Extract printable SSID (tag 0). Returns false for broadcast/hidden empty. */
bool wifi_ie_extract_ssid(const uint8_t *ies, size_t ies_len,
                          char *ssid_out, size_t ssid_out_len, uint8_t *ssid_len_out);

bool wifi_ie_parse_rsn(const uint8_t *ies, size_t ies_len, wifi_rsn_info_t *out);
wifi_pmf_state_t wifi_rsn_to_pmf_state(const wifi_rsn_info_t *rsn);

bool wifi_ie_parse_wps(const uint8_t *ies, size_t ies_len, wifi_wps_info_t *out);
bool wifi_ie_parse_csa(const uint8_t *ies, size_t ies_len, wifi_csa_info_t *out);

/** Management frame helpers */
bool wifi_mgmt_is_beacon(const uint8_t *frame, size_t len);
bool wifi_mgmt_is_probe_req(const uint8_t *frame, size_t len);
bool wifi_mgmt_is_probe_resp(const uint8_t *frame, size_t len);
bool wifi_mgmt_is_action(const uint8_t *frame, size_t len);

/**
 * Locate tagged IE region of a management frame.
 * For beacon/probe-resp: after fixed params. For probe-req: after MAC header.
 */
bool wifi_mgmt_get_ies(const uint8_t *frame, size_t len,
                       const uint8_t **ies_out, size_t *ies_len_out);

void wifi_mac_to_str(const uint8_t mac[6], char out[18]);
bool wifi_mac_is_broadcast(const uint8_t mac[6]);
bool wifi_mac_is_zero(const uint8_t mac[6]);

#ifdef __cplusplus
}
#endif

#endif /* WIFI_IE_PARSER_H */
