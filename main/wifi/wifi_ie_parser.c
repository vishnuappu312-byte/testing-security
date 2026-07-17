#include "wifi_ie_parser.h"

#include <string.h>
#include <stdio.h>

bool wifi_ie_walk(const uint8_t *ies, size_t ies_len, wifi_ie_walk_cb_t cb, void *ctx)
{
    if (ies == NULL || cb == NULL) {
        return false;
    }
    size_t off = 0;
    while (off + 2 <= ies_len) {
        uint8_t tag = ies[off];
        uint8_t len = ies[off + 1];
        if (off + 2 + len > ies_len) {
            return false;
        }
        if (!cb(tag, ies + off + 2, len, ctx)) {
            return true;
        }
        off += 2u + len;
    }
    return true;
}

typedef struct {
    uint8_t        tag;
    wifi_ie_t     *out;
    bool           found;
} find_ctx_t;

static bool find_cb(uint8_t tag, const uint8_t *data, uint8_t len, void *ctx)
{
    find_ctx_t *f = (find_ctx_t *)ctx;
    if (tag == f->tag) {
        f->out->data = data;
        f->out->len = len;
        f->found = true;
        return false;
    }
    return true;
}

bool wifi_ie_find(const uint8_t *ies, size_t ies_len, uint8_t tag, wifi_ie_t *out)
{
    if (out == NULL) {
        return false;
    }
    memset(out, 0, sizeof(*out));
    find_ctx_t ctx = { .tag = tag, .out = out, .found = false };
    wifi_ie_walk(ies, ies_len, find_cb, &ctx);
    return ctx.found;
}

typedef struct {
    const uint8_t *oui;
    int            type;
    wifi_ie_t     *out;
    bool           found;
} vendor_ctx_t;

static bool vendor_cb(uint8_t tag, const uint8_t *data, uint8_t len, void *ctx)
{
    vendor_ctx_t *v = (vendor_ctx_t *)ctx;
    if (tag != 0xDD || len < 3) {
        return true;
    }
    if (memcmp(data, v->oui, 3) != 0) {
        return true;
    }
    if (v->type >= 0) {
        if (len < 4 || data[3] != (uint8_t)v->type) {
            return true;
        }
    }
    v->out->data = data;
    v->out->len = len;
    v->found = true;
    return false;
}

bool wifi_ie_find_vendor(const uint8_t *ies, size_t ies_len,
                         const uint8_t oui[3], int type, wifi_ie_t *out)
{
    if (out == NULL || oui == NULL) {
        return false;
    }
    memset(out, 0, sizeof(*out));
    vendor_ctx_t ctx = { .oui = oui, .type = type, .out = out, .found = false };
    wifi_ie_walk(ies, ies_len, vendor_cb, &ctx);
    return ctx.found;
}

bool wifi_ie_extract_ssid(const uint8_t *ies, size_t ies_len,
                          char *ssid_out, size_t ssid_out_len, uint8_t *ssid_len_out)
{
    wifi_ie_t ie;
    if (!wifi_ie_find(ies, ies_len, 0x00, &ie) || ie.len == 0 || ie.len > WIFI_IE_SSID_MAX) {
        return false;
    }
    for (uint8_t i = 0; i < ie.len; i++) {
        if (ie.data[i] < 0x20 || ie.data[i] > 0x7E) {
            return false;
        }
    }
    if (ssid_out == NULL || ssid_out_len == 0) {
        return false;
    }
    size_t copy = ie.len;
    if (copy >= ssid_out_len) {
        copy = ssid_out_len - 1;
    }
    memcpy(ssid_out, ie.data, copy);
    ssid_out[copy] = '\0';
    if (ssid_len_out) {
        *ssid_len_out = (uint8_t)ie.len;
    }
    return true;
}

bool wifi_ie_parse_rsn(const uint8_t *ies, size_t ies_len, wifi_rsn_info_t *out)
{
    if (out == NULL) {
        return false;
    }
    memset(out, 0, sizeof(*out));
    wifi_ie_t ie;
    if (!wifi_ie_find(ies, ies_len, 0x30, &ie) || ie.len < 8) {
        return false;
    }
    const uint8_t *p = ie.data;
    size_t left = ie.len;

    out->version = (uint16_t)(p[0] | (p[1] << 8));
    p += 2; left -= 2;
    if (left < 4) {
        return false;
    }
    out->group_cipher = (uint32_t)(p[0] | (p[1] << 8) | (p[2] << 16) | (p[3] << 24));
    p += 4; left -= 4;

    if (left < 2) {
        return false;
    }
    out->pairwise_count = (uint16_t)(p[0] | (p[1] << 8));
    p += 2; left -= 2;
    size_t need = (size_t)out->pairwise_count * 4u;
    if (left < need) {
        return false;
    }
    p += need; left -= need;

    if (left < 2) {
        return false;
    }
    out->akm_count = (uint16_t)(p[0] | (p[1] << 8));
    p += 2; left -= 2;
    need = (size_t)out->akm_count * 4u;
    if (left < need) {
        return false;
    }
    p += need; left -= need;

    if (left >= 2) {
        uint16_t caps = (uint16_t)(p[0] | (p[1] << 8));
        out->mfpc = (caps & 0x0080) != 0;
        out->mfpr = (caps & 0x0040) != 0;
    }
    out->present = true;
    return true;
}

wifi_pmf_state_t wifi_rsn_to_pmf_state(const wifi_rsn_info_t *rsn)
{
    if (rsn == NULL || !rsn->present) {
        return WIFI_PMF_UNSUPPORTED;
    }
    if (rsn->mfpr) {
        return WIFI_PMF_REQUIRED;
    }
    if (rsn->mfpc) {
        return WIFI_PMF_CAPABLE;
    }
    return WIFI_PMF_UNSUPPORTED;
}

static void copy_ascii_field(char *dst, size_t dst_len, const uint8_t *src, uint16_t len)
{
    if (dst == NULL || dst_len == 0) {
        return;
    }
    size_t n = len;
    if (n >= dst_len) {
        n = dst_len - 1;
    }
    size_t j = 0;
    for (size_t i = 0; i < n; i++) {
        uint8_t c = src[i];
        if (c < 0x20 || c > 0x7E) {
            continue;
        }
        dst[j++] = (char)c;
    }
    dst[j] = '\0';
}

bool wifi_ie_parse_wps(const uint8_t *ies, size_t ies_len, wifi_wps_info_t *out)
{
    if (out == NULL) {
        return false;
    }
    memset(out, 0, sizeof(*out));
    static const uint8_t wps_oui[3] = { 0x00, 0x50, 0xF2 };
    wifi_ie_t ie;
    if (!wifi_ie_find_vendor(ies, ies_len, wps_oui, 0x04, &ie) || ie.len < 4) {
        return false;
    }
    /* Vendor payload after OUI+type */
    const uint8_t *p = ie.data + 4;
    size_t left = ie.len - 4;
    out->present = true;

    while (left >= 4) {
        uint16_t type = (uint16_t)((p[0] << 8) | p[1]);
        uint16_t len  = (uint16_t)((p[2] << 8) | p[3]);
        p += 4; left -= 4;
        if (left < len) {
            break;
        }
        switch (type) {
            case 0x104A: /* Version */
                if (len >= 1) {
                    out->version = p[0];
                }
                break;
            case 0x1044: /* Wi-Fi Protected Setup State */
                if (len >= 1) {
                    out->configured = (p[0] == 0x02);
                }
                break;
            case 0x1057: /* AP Setup Locked */
                if (len >= 1) {
                    out->locked = (p[0] != 0);
                }
                break;
            case 0x1008: /* Config Methods */
                if (len >= 2) {
                    out->config_methods = (uint16_t)((p[0] << 8) | p[1]);
                }
                break;
            case 0x1021:
                copy_ascii_field(out->manufacturer, sizeof(out->manufacturer), p, len);
                break;
            case 0x1023:
                copy_ascii_field(out->model, sizeof(out->model), p, len);
                break;
            case 0x1011:
                copy_ascii_field(out->device_name, sizeof(out->device_name), p, len);
                break;
            case 0x1047: /* UUID-E */
                if (len >= 16) {
                    snprintf(out->uuid, sizeof(out->uuid),
                             "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                             p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7],
                             p[8], p[9], p[10], p[11], p[12], p[13], p[14], p[15]);
                }
                break;
            default:
                break;
        }
        p += len;
        left -= len;
    }
    return true;
}

bool wifi_ie_parse_csa(const uint8_t *ies, size_t ies_len, wifi_csa_info_t *out)
{
    if (out == NULL) {
        return false;
    }
    memset(out, 0, sizeof(*out));
    wifi_ie_t ie;
    if (!wifi_ie_find(ies, ies_len, 0x25, &ie) || ie.len < 3) {
        return false;
    }
    out->present = true;
    out->mode = ie.data[0];
    out->new_channel = ie.data[1];
    out->count = ie.data[2];
    return true;
}

bool wifi_mgmt_is_beacon(const uint8_t *frame, size_t len)
{
    return frame && len >= 24 && frame[0] == 0x80;
}

bool wifi_mgmt_is_probe_req(const uint8_t *frame, size_t len)
{
    return frame && len >= 24 && frame[0] == 0x40;
}

bool wifi_mgmt_is_probe_resp(const uint8_t *frame, size_t len)
{
    return frame && len >= 24 && frame[0] == 0x50;
}

bool wifi_mgmt_is_action(const uint8_t *frame, size_t len)
{
    return frame && len >= 24 && frame[0] == 0xD0;
}

bool wifi_mgmt_get_ies(const uint8_t *frame, size_t len,
                       const uint8_t **ies_out, size_t *ies_len_out)
{
    if (frame == NULL || ies_out == NULL || ies_len_out == NULL || len < 24) {
        return false;
    }
    size_t hdr = 24;
    /* QoS / HT control not expected on beacons we care about */
    size_t fixed = 0;
    uint8_t subtype = (frame[0] >> 4) & 0x0F;
    if (subtype == 0x08 || subtype == 0x05) {
        /* Beacon / Probe Response fixed params: timestamp(8)+interval(2)+cap(2) */
        fixed = 12;
    } else if (subtype == 0x04) {
        /* Probe Request: IEs start immediately after header */
        fixed = 0;
    } else {
        return false;
    }
    if (len < hdr + fixed + 4) {
        /* allow missing FCS */
        if (len < hdr + fixed) {
            return false;
        }
    }
    size_t body_end = len;
    /* Strip FCS if present (ESP32 sig_len usually includes FCS) */
    if (body_end >= hdr + fixed + 4) {
        body_end -= 4;
    }
    *ies_out = frame + hdr + fixed;
    *ies_len_out = body_end - (hdr + fixed);
    return true;
}

void wifi_mac_to_str(const uint8_t mac[6], char out[18])
{
    if (mac == NULL || out == NULL) {
        return;
    }
    snprintf(out, 18, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

bool wifi_mac_is_broadcast(const uint8_t mac[6])
{
    return mac && mac[0] == 0xFF && mac[1] == 0xFF && mac[2] == 0xFF &&
           mac[3] == 0xFF && mac[4] == 0xFF && mac[5] == 0xFF;
}

bool wifi_mac_is_zero(const uint8_t mac[6])
{
    return mac && mac[0] == 0 && mac[1] == 0 && mac[2] == 0 &&
           mac[3] == 0 && mac[4] == 0 && mac[5] == 0;
}
