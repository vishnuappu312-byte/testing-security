/**
 * mesh_wormhole.c
 *
 * Captures 802.11 frames involving one mesh endpoint and tunnels them toward
 * another endpoint (relay as-is or rewrite destination), simulating a
 * wormhole link that can distort mesh routing.
 */

#include "mesh_wormhole.h"

#include <string.h>
#include <stdio.h>

#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_netif.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include "wifi_controller.h"
#include "wsl_bypasser.h"

static const char *TAG = "MESH_WORMHOLE";

static const char *mode_strings[] = {
    [MESH_WORMHOLE_MODE_A_TO_B] = "A → B",
    [MESH_WORMHOLE_MODE_B_TO_A] = "B → A",
    [MESH_WORMHOLE_MODE_BIDIR]  = "Bidirectional",
};

static const char *action_strings[] = {
    [MESH_WORMHOLE_ACTION_RELAY]   = "Relay",
    [MESH_WORMHOLE_ACTION_REWRITE] = "Rewrite",
};

static const char *filter_strings[] = {
    [MESH_WORMHOLE_FILTER_ALL]         = "All Frames",
    [MESH_WORMHOLE_FILTER_MGMT]        = "Management",
    [MESH_WORMHOLE_FILTER_DATA]        = "Data",
    [MESH_WORMHOLE_FILTER_MESH_ACTION] = "Mesh Action",
};

typedef struct {
    uint16_t len;
    uint8_t  data[MESH_WORMHOLE_FRAME_MAX];
    uint8_t  frame_type;
    uint8_t  subtype;
    uint8_t  src_mac[6];
    uint8_t  dst_mac[6];
    uint8_t  bssid[6];
    int8_t   rssi;
    uint8_t  direction;
} mesh_wormhole_pending_t;

#define MESH_WORMHOLE_PENDING_MAX 16

static mesh_wormhole_state_t  s_state;
static mesh_wormhole_config_t s_cfg;
static mesh_wormhole_pending_t s_pending[MESH_WORMHOLE_PENDING_MAX];
static volatile uint16_t      s_pending_count = 0;
static volatile bool          s_running = false;
static TaskHandle_t           s_task = NULL;
static esp_timer_handle_t     s_timeout_timer = NULL;
static SemaphoreHandle_t      s_mutex = NULL;
static bool                   s_ap_was_stopped = false;
static wifi_config_t          s_saved_ap;
static int64_t                s_start_us = 0;

const char *mesh_wormhole_mode_str(mesh_wormhole_mode_t m)
{
    if (m >= MESH_WORMHOLE_MODE_COUNT) return "Unknown";
    return mode_strings[m];
}

const char *mesh_wormhole_action_str(mesh_wormhole_action_t a)
{
    if (a >= MESH_WORMHOLE_ACTION_COUNT) return "Unknown";
    return action_strings[a];
}

const char *mesh_wormhole_filter_str(mesh_wormhole_filter_t f)
{
    if (f >= MESH_WORMHOLE_FILTER_COUNT) return "Unknown";
    return filter_strings[f];
}

static bool mutex_take(void)
{
    if (s_mutex == NULL) {
        s_mutex = xSemaphoreCreateMutex();
        if (s_mutex == NULL) return false;
    }
    return xSemaphoreTake(s_mutex, pdMS_TO_TICKS(2000)) == pdTRUE;
}

static void mutex_give(void)
{
    if (s_mutex != NULL) {
        xSemaphoreGive(s_mutex);
    }
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

static bool mac_eq(const uint8_t *a, const uint8_t *b)
{
    return memcmp(a, b, 6) == 0;
}

static bool frame_involves_mac(const uint8_t *addr1, const uint8_t *addr2,
                               const uint8_t *addr3, const uint8_t *target)
{
    return mac_eq(addr1, target) || mac_eq(addr2, target) || mac_eq(addr3, target);
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
        if (s_cfg.filter == MESH_WORMHOLE_FILTER_DATA) {
            return false;
        }
        if (s_cfg.filter == MESH_WORMHOLE_FILTER_MESH_ACTION) {
            if (!is_mesh_vendor_action(f, sig_len, subtype)) {
                return false;
            }
            *is_mesh_action = true;
        }
        return true;
    }

    if (type == WIFI_PKT_DATA) {
        if (s_cfg.filter == MESH_WORMHOLE_FILTER_MGMT ||
            s_cfg.filter == MESH_WORMHOLE_FILTER_MESH_ACTION) {
            return false;
        }
        return true;
    }

    return false;
}

static void extract_addrs(wifi_promiscuous_pkt_type_t type, const uint8_t *f,
                          uint8_t addr1[6], uint8_t addr2[6], uint8_t addr3[6],
                          uint8_t *ftype, bool is_mesh_action)
{
    if (type == WIFI_PKT_MGMT) {
        *ftype = is_mesh_action ? 2 : 0;
    } else {
        *ftype = 1;
    }
    memcpy(addr1, f + 4, 6);
    memcpy(addr2, f + 10, 6);
    memcpy(addr3, f + 16, 6);
}

static void append_log(uint8_t ftype, uint8_t subtype,
                       const uint8_t *addr1, const uint8_t *addr2, const uint8_t *addr3,
                       const uint8_t *f, uint16_t sig_len, int8_t rssi,
                       uint8_t direction, bool tunneled, bool tx_ok)
{
    if (s_state.log_count >= MESH_WORMHOLE_MAX_LOG) return;

    mesh_wormhole_log_t entry;
    memset(&entry, 0, sizeof(entry));
    entry.time_ms    = (uint32_t)((esp_timer_get_time() - s_start_us) / 1000);
    entry.frame_type = ftype;
    entry.subtype    = subtype;
    memcpy(entry.src_mac, addr2, 6);
    memcpy(entry.dst_mac, addr1, 6);
    memcpy(entry.bssid, addr3, 6);
    entry.rssi      = rssi;
    entry.len       = sig_len;
    entry.direction = direction;
    entry.tunneled  = tunneled;
    entry.tx_ok     = tx_ok;

    uint16_t hdr_len = 24;
    if (ftype == 1 && (f[0] & 0x8C) == 0x88) {
        hdr_len = 26;
    }
    uint16_t pay_total = 0;
    if (sig_len > hdr_len) {
        pay_total = (uint16_t)(sig_len - hdr_len);
        if (pay_total > MESH_WORMHOLE_PAYLOAD_LOG_MAX) {
            pay_total = MESH_WORMHOLE_PAYLOAD_LOG_MAX;
        }
        memcpy(entry.payload, f + hdr_len, pay_total);
    }
    entry.payload_len = pay_total;
    s_state.log[s_state.log_count++] = entry;
}

static bool enqueue_pending(const uint8_t *f, uint16_t len, uint8_t ftype, uint8_t subtype,
                            const uint8_t *addr1, const uint8_t *addr2, const uint8_t *addr3,
                            int8_t rssi, uint8_t direction)
{
    if (len < 24 || len > MESH_WORMHOLE_FRAME_MAX) return false;
    if (s_pending_count >= MESH_WORMHOLE_PENDING_MAX) return false;

    mesh_wormhole_pending_t *slot = &s_pending[s_pending_count++];
    slot->len = len;
    memcpy(slot->data, f, len);
    slot->frame_type = ftype;
    slot->subtype    = subtype;
    memcpy(slot->src_mac, addr2, 6);
    memcpy(slot->dst_mac, addr1, 6);
    memcpy(slot->bssid, addr3, 6);
    slot->rssi      = rssi;
    slot->direction = direction;
    return true;
}

static bool tx_frame(uint8_t *frame, uint16_t len)
{
    if (!frame || len < 24) return false;
    return wsl_bypasser_send_raw_frame(frame, len);
}

static void tunnel_one(mesh_wormhole_pending_t *slot)
{
    if (!slot || slot->len < 24) return;

    uint8_t txbuf[MESH_WORMHOLE_FRAME_MAX];
    memcpy(txbuf, slot->data, slot->len);

    const uint8_t *peer = (slot->direction == 0) ? s_cfg.endpoint_b : s_cfg.endpoint_a;

    if (s_cfg.action == MESH_WORMHOLE_ACTION_REWRITE) {
        /* addr1 (destination) → peer endpoint; keep original source */
        memcpy(txbuf + 4, peer, 6);
    }

    if (s_cfg.tunnel_delay_ms > 0) {
        vTaskDelay(pdMS_TO_TICKS(s_cfg.tunnel_delay_ms));
    }

    bool ok = tx_frame(txbuf, slot->len);
    s_state.frames_tunneled++;
    if (ok) {
        s_state.tunnel_ok++;
    } else {
        s_state.tunnel_failed++;
    }

    if (slot->direction == 0) {
        s_state.a_to_b++;
    } else {
        s_state.b_to_a++;
    }

    append_log(slot->frame_type, slot->subtype,
               (s_cfg.action == MESH_WORMHOLE_ACTION_REWRITE) ? peer : slot->dst_mac,
               slot->src_mac, slot->bssid,
               txbuf, slot->len, slot->rssi,
               slot->direction, true, ok);
}

static void IRAM_ATTR wormhole_capture_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (!s_running) return;

    const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
    const uint8_t *f = pkt->payload;
    uint16_t sig_len = (uint16_t)pkt->rx_ctrl.sig_len;
    if (sig_len < 24) return;

    if (type == WIFI_PKT_MGMT || type == WIFI_PKT_DATA) {
        s_state.frames_seen++;
    } else {
        return;
    }

    uint8_t subtype = (f[0] >> 4) & 0x0F;
    bool is_mesh_action = false;
    if (!passes_filter(type, f, sig_len, subtype, &is_mesh_action)) {
        return;
    }

    uint8_t addr1[6], addr2[6], addr3[6], ftype = 0;
    extract_addrs(type, f, addr1, addr2, addr3, &ftype, is_mesh_action);

    if (s_cfg.parent_bssid_set &&
        !frame_involves_mac(addr1, addr2, addr3, s_cfg.parent_bssid)) {
        return;
    }

    bool involves_a = frame_involves_mac(addr1, addr2, addr3, s_cfg.endpoint_a);
    bool involves_b = frame_involves_mac(addr1, addr2, addr3, s_cfg.endpoint_b);
    if (!involves_a && !involves_b) {
        return;
    }

    /* Skip frames that already involve both ends (already on the short path). */
    if (involves_a && involves_b) {
        return;
    }

    int direction = -1;
    if (involves_a &&
        (s_cfg.mode == MESH_WORMHOLE_MODE_A_TO_B ||
         s_cfg.mode == MESH_WORMHOLE_MODE_BIDIR)) {
        direction = 0;
    } else if (involves_b &&
               (s_cfg.mode == MESH_WORMHOLE_MODE_B_TO_A ||
                s_cfg.mode == MESH_WORMHOLE_MODE_BIDIR)) {
        direction = 1;
    }

    if (direction < 0) {
        return;
    }

    s_state.frames_captured++;
    s_state.rssi = pkt->rx_ctrl.rssi;

    if (mutex_take()) {
        enqueue_pending(f, sig_len, ftype, subtype, addr1, addr2, addr3,
                        pkt->rx_ctrl.rssi, (uint8_t)direction);
        mutex_give();
    }
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
    ESP_LOGW(TAG, "Wormhole timeout (%d s)", MESH_WORMHOLE_TIMEOUT_SEC);
    s_state.timeout = true;
    s_running = false;
}

static void start_timeout_timer(void)
{
    stop_timeout_timer();
    const esp_timer_create_args_t args = {
        .callback = timeout_cb,
        .name     = "mesh_wormhole_to",
    };
    if (esp_timer_create(&args, &s_timeout_timer) == ESP_OK) {
        esp_timer_start_once(s_timeout_timer, MESH_WORMHOLE_TIMEOUT_US);
    }
}

static void drain_pending(void)
{
    if (s_pending_count == 0) return;
    if (!mutex_take()) return;

    uint16_t n = s_pending_count;
    mesh_wormhole_pending_t local[MESH_WORMHOLE_PENDING_MAX];
    memcpy(local, s_pending, n * sizeof(mesh_wormhole_pending_t));
    s_pending_count = 0;
    mutex_give();

    s_state.tunneling = true;
    for (uint16_t i = 0; i < n && s_running; i++) {
        tunnel_one(&local[i]);
    }
}

static void wormhole_task(void *arg)
{
    (void)arg;
    s_start_us = esp_timer_get_time();

    char a_str[18], b_str[18];
    mac_to_str(s_cfg.endpoint_a, a_str, sizeof(a_str));
    mac_to_str(s_cfg.endpoint_b, b_str, sizeof(b_str));

    ESP_LOGW(TAG, "═══ MESH WORMHOLE START ═══ ch=%u mode=%s action=%s A=%s B=%s",
             s_cfg.channel,
             mesh_wormhole_mode_str(s_cfg.mode),
             mesh_wormhole_action_str(s_cfg.action),
             a_str, b_str);

    if (!prepare_radio()) {
        snprintf(s_state.error, sizeof(s_state.error), "Radio prepare failed");
        ESP_LOGE(TAG, "%s", s_state.error);
        goto done;
    }

    wifi_promiscuous_filter_t filt = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_DATA | WIFI_PROMIS_FILTER_MASK_MGMT
    };
    esp_wifi_set_promiscuous_filter(&filt);
    esp_wifi_set_promiscuous_rx_cb(wormhole_capture_cb);
    esp_wifi_set_promiscuous(true);

    uint32_t loops = 0;
    while (s_running) {
        s_state.uptime_ms = (uint32_t)((esp_timer_get_time() - s_start_us) / 1000);
        loops++;
        drain_pending();

        if ((loops % 10) == 0) {
            ESP_LOGI(TAG, "wormhole ch=%u cap=%lu tun=%lu ok=%lu fail=%lu a2b=%lu b2a=%lu",
                     s_state.channel,
                     (unsigned long)s_state.frames_captured,
                     (unsigned long)s_state.frames_tunneled,
                     (unsigned long)s_state.tunnel_ok,
                     (unsigned long)s_state.tunnel_failed,
                     (unsigned long)s_state.a_to_b,
                     (unsigned long)s_state.b_to_a);
        }
        vTaskDelay(pdMS_TO_TICKS(50));
    }

done:
    s_state.tunneling = false;
    s_state.active = false;
    s_running = false;
    stop_timeout_timer();
    restore_radio();
    ESP_LOGW(TAG, "═══ MESH WORMHOLE STOP ═══ cap=%lu tun=%lu timeout=%d",
             (unsigned long)s_state.frames_captured,
             (unsigned long)s_state.frames_tunneled,
             (int)s_state.timeout);
    s_task = NULL;
    vTaskDelete(NULL);
}

void mesh_wormhole_init(void)
{
    memset(&s_state, 0, sizeof(s_state));
    s_pending_count = 0;
    s_running = false;
    ESP_LOGI(TAG, "Mesh wormhole ready");
}

esp_err_t mesh_wormhole_start(const mesh_wormhole_config_t *cfg)
{
    if (!cfg) return ESP_ERR_INVALID_ARG;
    if (s_running) return ESP_ERR_INVALID_STATE;
    if (cfg->channel == 0) return ESP_ERR_INVALID_ARG;
    if (cfg->mode >= MESH_WORMHOLE_MODE_COUNT) return ESP_ERR_INVALID_ARG;
    if (cfg->action >= MESH_WORMHOLE_ACTION_COUNT) return ESP_ERR_INVALID_ARG;
    if (cfg->filter >= MESH_WORMHOLE_FILTER_COUNT) return ESP_ERR_INVALID_ARG;

    uint8_t zero[6] = {0};
    if (memcmp(cfg->endpoint_a, zero, 6) == 0 ||
        memcmp(cfg->endpoint_b, zero, 6) == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    if (memcmp(cfg->endpoint_a, cfg->endpoint_b, 6) == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    memset(&s_state, 0, sizeof(s_state));
    s_pending_count = 0;
    memcpy(&s_cfg, cfg, sizeof(s_cfg));

    s_state.active = true;
    s_state.mode   = s_cfg.mode;
    s_state.action = s_cfg.action;
    s_state.filter = s_cfg.filter;
    s_state.channel = s_cfg.channel;
    memcpy(s_state.endpoint_a, s_cfg.endpoint_a, 6);
    memcpy(s_state.endpoint_b, s_cfg.endpoint_b, 6);
    strncpy(s_state.ssid, s_cfg.ssid, sizeof(s_state.ssid) - 1);
    strncpy(s_state.mode_str, mesh_wormhole_mode_str(s_cfg.mode),
            sizeof(s_state.mode_str) - 1);
    strncpy(s_state.action_str, mesh_wormhole_action_str(s_cfg.action),
            sizeof(s_state.action_str) - 1);
    strncpy(s_state.filter_str, mesh_wormhole_filter_str(s_cfg.filter),
            sizeof(s_state.filter_str) - 1);

    if (s_cfg.parent_bssid_set) {
        memcpy(s_state.parent_bssid, s_cfg.parent_bssid, 6);
    }

    s_running = true;
    start_timeout_timer();

    if (xTaskCreate(wormhole_task, "mesh_wormhole", 6144, NULL, 2, &s_task) != pdPASS) {
        s_running = false;
        s_state.active = false;
        stop_timeout_timer();
        return ESP_ERR_NO_MEM;
    }

    return ESP_OK;
}

esp_err_t mesh_wormhole_stop(void)
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
        s_state.tunneling = false;
    }

    return ESP_OK;
}

bool mesh_wormhole_is_active(void)
{
    return s_running || s_state.active;
}

const mesh_wormhole_state_t *mesh_wormhole_get_state(void)
{
    return &s_state;
}

cJSON *mesh_wormhole_get_status_json(void)
{
    cJSON *root = cJSON_CreateObject();
    if (!root) return NULL;

    const mesh_wormhole_state_t *st = &s_state;
    cJSON_AddBoolToObject(root, "active", st->active || s_running);
    cJSON_AddBoolToObject(root, "tunneling", st->tunneling);
    cJSON_AddBoolToObject(root, "timeout", st->timeout);
    cJSON_AddNumberToObject(root, "frames_seen", st->frames_seen);
    cJSON_AddNumberToObject(root, "frames_captured", st->frames_captured);
    cJSON_AddNumberToObject(root, "frames_tunneled", st->frames_tunneled);
    cJSON_AddNumberToObject(root, "tunnel_ok", st->tunnel_ok);
    cJSON_AddNumberToObject(root, "tunnel_failed", st->tunnel_failed);
    cJSON_AddNumberToObject(root, "a_to_b", st->a_to_b);
    cJSON_AddNumberToObject(root, "b_to_a", st->b_to_a);
    cJSON_AddNumberToObject(root, "uptime_ms", st->uptime_ms);
    cJSON_AddNumberToObject(root, "channel", st->channel);
    cJSON_AddNumberToObject(root, "rssi", st->rssi);
    cJSON_AddNumberToObject(root, "mode", st->mode);
    cJSON_AddNumberToObject(root, "action", st->action);
    cJSON_AddNumberToObject(root, "filter", st->filter);
    cJSON_AddStringToObject(root, "mode_str", st->mode_str);
    cJSON_AddStringToObject(root, "action_str", st->action_str);
    cJSON_AddStringToObject(root, "filter_str", st->filter_str);
    cJSON_AddStringToObject(root, "ssid", st->ssid);
    cJSON_AddNumberToObject(root, "log_count", st->log_count);

    char buf[18];
    mac_to_str(st->endpoint_a, buf, sizeof(buf));
    cJSON_AddStringToObject(root, "endpoint_a", buf);
    mac_to_str(st->endpoint_b, buf, sizeof(buf));
    cJSON_AddStringToObject(root, "endpoint_b", buf);
    mac_to_str(st->parent_bssid, buf, sizeof(buf));
    cJSON_AddStringToObject(root, "parent_bssid", buf);

    if (st->error[0]) {
        cJSON_AddStringToObject(root, "error", st->error);
    }

    cJSON_AddStringToObject(root, "status",
        (st->active || s_running) ?
            (st->tunneling ? "Tunneling" : "Listening") :
            (st->timeout ? "Timeout" : "Idle"));

    cJSON *logs = cJSON_CreateArray();
    for (int i = 0; i < st->log_count; i++) {
        const mesh_wormhole_log_t *e = &st->log[i];
        cJSON *item = cJSON_CreateObject();
        const char *type_str = e->frame_type == 2 ? "MESH" :
                               e->frame_type == 1 ? "DATA" : "MGMT";
        cJSON_AddStringToObject(item, "type", type_str);
        cJSON_AddNumberToObject(item, "subtype", e->subtype);
        cJSON_AddNumberToObject(item, "rssi", e->rssi);
        cJSON_AddNumberToObject(item, "time_ms", e->time_ms);
        cJSON_AddNumberToObject(item, "len", e->len);
        cJSON_AddStringToObject(item, "dir", e->direction == 0 ? "A→B" : "B→A");
        cJSON_AddBoolToObject(item, "tunneled", e->tunneled);
        cJSON_AddBoolToObject(item, "tx_ok", e->tx_ok);

        mac_to_str(e->src_mac, buf, sizeof(buf));
        cJSON_AddStringToObject(item, "src_mac", buf);
        mac_to_str(e->dst_mac, buf, sizeof(buf));
        cJSON_AddStringToObject(item, "dst_mac", buf);
        mac_to_str(e->bssid, buf, sizeof(buf));
        cJSON_AddStringToObject(item, "bssid", buf);

        char hex[MESH_WORMHOLE_PAYLOAD_LOG_MAX * 2 + 1];
        payload_to_hex(e->payload, e->payload_len, hex, sizeof(hex));
        cJSON_AddStringToObject(item, "payload", hex);
        cJSON_AddNumberToObject(item, "payload_len", e->payload_len);
        cJSON_AddItemToArray(logs, item);
    }
    cJSON_AddItemToObject(root, "logs", logs);

    return root;
}
