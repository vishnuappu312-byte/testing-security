/**
 * mesh_eavesdrop.c
 *
 * Passive mesh eavesdropping — locks onto the mesh RF channel, enables
 * promiscuous mode (unassociated), and logs management/data/mesh-action
 * frames matching optional BSSID and target MAC filters.
 */

#include "mesh_eavesdrop.h"

#include <string.h>
#include <stdio.h>

#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_netif.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"

#include "wifi_controller.h"

static const char *TAG = "MESH_EAVES";

static const char *filter_strings[] = {
    [MESH_EAVES_FILTER_ALL]         = "All Frames",
    [MESH_EAVES_FILTER_MGMT]        = "Management",
    [MESH_EAVES_FILTER_DATA]        = "Data",
    [MESH_EAVES_FILTER_MESH_ACTION] = "Mesh Action",
};

static mesh_eavesdrop_state_t  s_state;
static mesh_eavesdrop_config_t s_cfg;
static volatile bool           s_running = false;
static TaskHandle_t            s_task = NULL;
static esp_timer_handle_t      s_timeout_timer = NULL;
static bool                    s_ap_was_stopped = false;
static wifi_config_t           s_saved_ap;
static int64_t                 s_start_us = 0;

const char *mesh_eavesdrop_filter_str(mesh_eavesdrop_filter_t f)
{
    if (f >= MESH_EAVES_FILTER_COUNT) return "Unknown";
    return filter_strings[f];
}

static void mac_to_str(const uint8_t *mac, char *out, size_t out_sz)
{
    snprintf(out, out_sz, "%02X:%02X:%02X:%02X:%02X:%02X",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

static void payload_to_hex(const uint8_t *data, uint16_t len, char *out, size_t out_sz)
{
    if (!data || !out || out_sz < 3) {
        if (out && out_sz) out[0] = '\0';
        return;
    }
    size_t max_bytes = (out_sz - 1) / 2;
    if (len > max_bytes) len = (uint16_t)max_bytes;
    for (uint16_t i = 0; i < len; i++) {
        snprintf(out + i * 2, 3, "%02x", data[i]);
    }
    out[len * 2] = '\0';
}

static bool mac_matches_filter(const uint8_t *a, const uint8_t *b)
{
    return memcmp(a, b, 6) == 0;
}

static bool frame_involves_mac(const uint8_t *addr1, const uint8_t *addr2,
                               const uint8_t *addr3, const uint8_t *target)
{
    return mac_matches_filter(addr1, target) ||
           mac_matches_filter(addr2, target) ||
           mac_matches_filter(addr3, target);
}

static bool is_mesh_vendor_action(const uint8_t *f, uint16_t sig_len, uint8_t subtype)
{
    if (subtype != 13 || sig_len < 32) return false;
    return f[26] == 0xE0 && f[27] == 0x9A && f[28] == 0xF6;
}

static bool passes_filter(wifi_promiscuous_pkt_type_t type,
                          const uint8_t *f, uint16_t sig_len,
                          uint8_t subtype, bool *is_mesh_action)
{
    *is_mesh_action = false;

    if (type == WIFI_PKT_MGMT) {
        if (s_cfg.skip_beacons && (subtype == 8 || subtype == 4)) {
            return false;
        }
        if (s_cfg.filter == MESH_EAVES_FILTER_DATA) {
            return false;
        }
        if (s_cfg.filter == MESH_EAVES_FILTER_MESH_ACTION) {
            if (!is_mesh_vendor_action(f, sig_len, subtype)) {
                return false;
            }
            *is_mesh_action = true;
        }
        return true;
    }

    if (type == WIFI_PKT_DATA) {
        if (s_cfg.filter == MESH_EAVES_FILTER_MGMT ||
            s_cfg.filter == MESH_EAVES_FILTER_MESH_ACTION) {
            return false;
        }
        return true;
    }

    return false;
}

static void append_log(wifi_promiscuous_pkt_type_t type,
                       const uint8_t *f, const wifi_promiscuous_pkt_t *pkt,
                       uint8_t subtype, bool is_mesh_action)
{
    if (s_state.log_count >= MESH_EAVESDROP_MAX_LOG) return;

    uint8_t addr1[6], addr2[6], addr3[6];
    uint8_t ftype = 0;

    if (type == WIFI_PKT_MGMT) {
        ftype = is_mesh_action ? 2 : 0;
        memcpy(addr1, f + 4, 6);
        memcpy(addr2, f + 10, 6);
        memcpy(addr3, f + 16, 6);
    } else {
        ftype = 1;
        uint8_t ds = f[1] & 0x03;
        if (ds == 0x02) {
            memcpy(addr1, f + 4, 6);
            memcpy(addr2, f + 10, 6);
            memcpy(addr3, f + 16, 6);
        } else if (ds == 0x01) {
            memcpy(addr1, f + 4, 6);
            memcpy(addr2, f + 10, 6);
            memcpy(addr3, f + 16, 6);
        } else {
            memcpy(addr1, f + 4, 6);
            memcpy(addr2, f + 10, 6);
            memcpy(addr3, f + 16, 6);
        }
    }

    if (s_cfg.parent_bssid_set &&
        !frame_involves_mac(addr1, addr2, addr3, s_cfg.parent_bssid)) {
        return;
    }

    if (s_cfg.target_mac_set &&
        !frame_involves_mac(addr1, addr2, addr3, s_cfg.target_mac)) {
        return;
    }

    mesh_eavesdrop_log_t entry;
    memset(&entry, 0, sizeof(entry));
    entry.time_ms    = (uint32_t)((esp_timer_get_time() - s_start_us) / 1000);
    entry.frame_type = ftype;
    entry.subtype    = subtype;
    memcpy(entry.src_mac, addr2, 6);
    memcpy(entry.dst_mac, addr1, 6);
    memcpy(entry.bssid, addr3, 6);
    entry.rssi    = pkt->rx_ctrl.rssi;
    entry.channel = (uint8_t)pkt->rx_ctrl.channel;
    entry.len     = (uint16_t)pkt->rx_ctrl.sig_len;
    s_state.rssi  = entry.rssi;

    uint16_t hdr_len = 24;
    if (type == WIFI_PKT_DATA && (f[0] & 0x8C) == 0x88) {
        hdr_len = 26;
    }

    uint16_t pay_total = 0;
    if (pkt->rx_ctrl.sig_len > hdr_len) {
        pay_total = (uint16_t)(pkt->rx_ctrl.sig_len - hdr_len);
        if (pay_total > MESH_EAVESDROP_PAYLOAD_MAX) {
            pay_total = MESH_EAVESDROP_PAYLOAD_MAX;
        }
        memcpy(entry.payload, f + hdr_len, pay_total);
    }
    entry.payload_len = pay_total;

    s_state.log[s_state.log_count++] = entry;
    s_state.packets_rx++;

    if (ftype == 0) s_state.mgmt_count++;
    else if (ftype == 1) s_state.data_count++;
    else s_state.mesh_action_count++;
}

static void IRAM_ATTR eavesdrop_capture_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (!s_running || !s_state.capturing) return;

    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
    const uint8_t *f = pkt->payload;
    if (pkt->rx_ctrl.sig_len < 24) return;

    if (type == WIFI_PKT_MGMT || type == WIFI_PKT_DATA) {
        s_state.frames_seen++;
    } else {
        return;
    }

    uint8_t subtype = (f[0] >> 4) & 0x0F;
    bool is_mesh_action = false;
    if (!passes_filter(type, f, pkt->rx_ctrl.sig_len, subtype, &is_mesh_action)) {
        return;
    }

    append_log(type, f, pkt, subtype, is_mesh_action);
}

static bool prepare_radio(void)
{
    wifi_mode_t mode;
    esp_wifi_get_mode(&mode);

    if (mode == WIFI_MODE_AP || mode == WIFI_MODE_APSTA) {
        esp_wifi_get_config(WIFI_IF_AP, &s_saved_ap);
        wifictl_mgmt_ap_stop();
        s_ap_was_stopped = true;
        vTaskDelay(pdMS_TO_TICKS(200));
    }

    esp_wifi_set_mode(WIFI_MODE_STA);
    esp_wifi_start();
    vTaskDelay(pdMS_TO_TICKS(100));

    wifi_config_t empty_sta = {0};
    esp_wifi_set_config(WIFI_IF_STA, &empty_sta);
    esp_wifi_disconnect();

    uint8_t ch = s_cfg.channel > 0 ? s_cfg.channel : 6;
    esp_wifi_set_channel(ch, WIFI_SECOND_CHAN_NONE);
    esp_wifi_set_ps(WIFI_PS_MIN_MODEM);

    s_state.channel = ch;
    return true;
}

static void restore_radio(void)
{
    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(NULL);
    vTaskDelay(pdMS_TO_TICKS(100));

    if (s_ap_was_stopped) {
        esp_wifi_set_mode(WIFI_MODE_APSTA);
        esp_wifi_set_config(WIFI_IF_AP, &s_saved_ap);
        esp_wifi_start();
        wifictl_mgmt_ap_start();

        esp_netif_t *ap_netif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
        if (ap_netif) {
            esp_netif_dhcps_stop(ap_netif);
            vTaskDelay(pdMS_TO_TICKS(50));
            esp_netif_dhcps_start(ap_netif);
        }
        s_ap_was_stopped = false;
    }

    esp_wifi_set_ps(WIFI_PS_MIN_MODEM);
}

static void stop_timeout_timer(void)
{
    if (s_timeout_timer != NULL) {
        esp_timer_stop(s_timeout_timer);
        esp_timer_delete(s_timeout_timer);
        s_timeout_timer = NULL;
    }
}

static void timeout_cb(void *arg)
{
    (void)arg;
    ESP_LOGW(TAG, "Eavesdrop timeout (%d s)", MESH_EAVESDROP_TIMEOUT_SEC);
    s_state.timeout = true;
    s_running = false;
}

static void start_timeout_timer(void)
{
    stop_timeout_timer();
    const esp_timer_create_args_t args = {
        .callback = timeout_cb,
        .name     = "mesh_eaves_to",
    };
    if (esp_timer_create(&args, &s_timeout_timer) == ESP_OK) {
        esp_timer_start_once(s_timeout_timer, MESH_EAVESDROP_TIMEOUT_US);
    }
}

static void eavesdrop_task(void *arg)
{
    (void)arg;
    s_start_us = esp_timer_get_time();

    ESP_LOGW(TAG, "═══ MESH EAVESDROP START ═══ ch=%u filter=%s",
             s_cfg.channel, mesh_eavesdrop_filter_str(s_cfg.filter));

    if (!prepare_radio()) {
        snprintf(s_state.error, sizeof(s_state.error), "Radio prepare failed");
        ESP_LOGE(TAG, "%s", s_state.error);
        goto done;
    }

    wifi_promiscuous_filter_t filt = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_DATA | WIFI_PROMIS_FILTER_MASK_MGMT
    };
    esp_wifi_set_promiscuous_filter(&filt);
    esp_wifi_set_promiscuous_rx_cb(eavesdrop_capture_cb);
    esp_wifi_set_promiscuous(true);
    s_state.capturing = true;

    uint32_t loops = 0;
    while (s_running) {
        s_state.uptime_ms = (uint32_t)((esp_timer_get_time() - s_start_us) / 1000);
        loops++;
        if ((loops % 10) == 0) {
            ESP_LOGI(TAG, "listening ch=%u rx=%lu seen=%lu mgmt=%lu data=%lu mesh=%lu uptime=%lus",
                     s_state.channel,
                     (unsigned long)s_state.packets_rx,
                     (unsigned long)s_state.frames_seen,
                     (unsigned long)s_state.mgmt_count,
                     (unsigned long)s_state.data_count,
                     (unsigned long)s_state.mesh_action_count,
                     (unsigned long)(s_state.uptime_ms / 1000));
        }
        vTaskDelay(pdMS_TO_TICKS(500));
    }

done:
    s_state.capturing = false;
    s_state.active = false;
    s_running = false;
    stop_timeout_timer();
    restore_radio();
    ESP_LOGW(TAG, "═══ MESH EAVESDROP STOP ═══ rx=%lu seen=%lu timeout=%d",
             (unsigned long)s_state.packets_rx,
             (unsigned long)s_state.frames_seen,
             (int)s_state.timeout);
    s_task = NULL;
    vTaskDelete(NULL);
}

void mesh_eavesdrop_init(void)
{
    memset(&s_state, 0, sizeof(s_state));
    s_running = false;
    ESP_LOGI(TAG, "Mesh eavesdrop ready");
}

esp_err_t mesh_eavesdrop_start(const mesh_eavesdrop_config_t *cfg)
{
    if (!cfg) return ESP_ERR_INVALID_ARG;
    if (s_running) return ESP_ERR_INVALID_STATE;
    if (cfg->channel == 0) return ESP_ERR_INVALID_ARG;
    if (cfg->filter >= MESH_EAVES_FILTER_COUNT) return ESP_ERR_INVALID_ARG;

    memset(&s_state, 0, sizeof(s_state));
    memcpy(&s_cfg, cfg, sizeof(s_cfg));
    s_cfg.skip_beacons = true;

    s_state.active = true;
    s_state.filter = s_cfg.filter;
    s_state.channel = s_cfg.channel;
    strncpy(s_state.ssid, s_cfg.ssid, sizeof(s_state.ssid) - 1);
    strncpy(s_state.filter_str, mesh_eavesdrop_filter_str(s_cfg.filter),
            sizeof(s_state.filter_str) - 1);

    if (s_cfg.parent_bssid_set) {
        memcpy(s_state.parent_bssid, s_cfg.parent_bssid, 6);
    }
    if (s_cfg.target_mac_set) {
        memcpy(s_state.target_mac, s_cfg.target_mac, 6);
    }

    s_running = true;
    start_timeout_timer();

    if (xTaskCreate(eavesdrop_task, "mesh_eaves", 6144, NULL, 2, &s_task) != pdPASS) {
        s_running = false;
        s_state.active = false;
        stop_timeout_timer();
        return ESP_ERR_NO_MEM;
    }

    return ESP_OK;
}

esp_err_t mesh_eavesdrop_stop(void)
{
    if (!s_running && !s_state.active) {
        restore_radio();
        return ESP_OK;
    }

    s_running = false;
    stop_timeout_timer();

    int wait = 30;
    while (s_task && wait-- > 0) {
        vTaskDelay(pdMS_TO_TICKS(100));
    }

    if (s_state.active) {
        restore_radio();
        s_state.active = false;
        s_state.capturing = false;
    }

    return ESP_OK;
}

bool mesh_eavesdrop_is_active(void)
{
    return s_running || s_state.active;
}

const mesh_eavesdrop_state_t *mesh_eavesdrop_get_state(void)
{
    return &s_state;
}

cJSON *mesh_eavesdrop_get_status_json(void)
{
    cJSON *root = cJSON_CreateObject();
    if (!root) return NULL;

    const mesh_eavesdrop_state_t *st = &s_state;
    cJSON_AddBoolToObject(root, "active", st->active || s_running);
    cJSON_AddBoolToObject(root, "capturing", st->capturing);
    cJSON_AddBoolToObject(root, "timeout", st->timeout);
    cJSON_AddNumberToObject(root, "packets_rx", st->packets_rx);
    cJSON_AddNumberToObject(root, "frames_seen", st->frames_seen);
    cJSON_AddNumberToObject(root, "mgmt_count", st->mgmt_count);
    cJSON_AddNumberToObject(root, "data_count", st->data_count);
    cJSON_AddNumberToObject(root, "mesh_action_count", st->mesh_action_count);
    cJSON_AddNumberToObject(root, "uptime_ms", st->uptime_ms);
    cJSON_AddNumberToObject(root, "channel", st->channel);
    cJSON_AddNumberToObject(root, "rssi", st->rssi);
    cJSON_AddNumberToObject(root, "filter", st->filter);
    cJSON_AddStringToObject(root, "filter_str", st->filter_str);
    cJSON_AddStringToObject(root, "ssid", st->ssid);
    cJSON_AddNumberToObject(root, "log_count", st->log_count);

    char buf[18];
    mac_to_str(st->parent_bssid, buf, sizeof(buf));
    cJSON_AddStringToObject(root, "parent_bssid", buf);
    mac_to_str(st->target_mac, buf, sizeof(buf));
    cJSON_AddStringToObject(root, "target_mac", buf);

    if (st->error[0]) {
        cJSON_AddStringToObject(root, "error", st->error);
    }

    cJSON_AddStringToObject(root, "status",
        (st->active || s_running) ?
            (st->capturing ? "Listening" : "Preparing") :
            (st->timeout ? "Timeout" : "Idle"));

    cJSON *logs = cJSON_CreateArray();
    for (int i = 0; i < st->log_count; i++) {
        const mesh_eavesdrop_log_t *e = &st->log[i];
        cJSON *item = cJSON_CreateObject();
        const char *type_str = e->frame_type == 2 ? "MESH" :
                               e->frame_type == 1 ? "DATA" : "MGMT";
        cJSON_AddStringToObject(item, "type", type_str);
        cJSON_AddNumberToObject(item, "subtype", e->subtype);
        cJSON_AddNumberToObject(item, "rssi", e->rssi);
        cJSON_AddNumberToObject(item, "channel", e->channel);
        cJSON_AddNumberToObject(item, "time_ms", e->time_ms);
        cJSON_AddNumberToObject(item, "len", e->len);

        mac_to_str(e->src_mac, buf, sizeof(buf));
        cJSON_AddStringToObject(item, "src_mac", buf);
        mac_to_str(e->dst_mac, buf, sizeof(buf));
        cJSON_AddStringToObject(item, "dst_mac", buf);
        mac_to_str(e->bssid, buf, sizeof(buf));
        cJSON_AddStringToObject(item, "bssid", buf);

        char hex[MESH_EAVESDROP_PAYLOAD_MAX * 2 + 1];
        payload_to_hex(e->payload, e->payload_len, hex, sizeof(hex));
        cJSON_AddStringToObject(item, "payload", hex);
        cJSON_AddNumberToObject(item, "payload_len", e->payload_len);
        cJSON_AddItemToArray(logs, item);
    }
    cJSON_AddItemToObject(root, "logs", logs);

    return root;
}
