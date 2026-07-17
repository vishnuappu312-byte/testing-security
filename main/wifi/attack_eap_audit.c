#include "attack_eap_audit.h"

#include <string.h>

#include "esp_log.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

#include "heap_psram.h"
#include "wifi_ie_parser.h"
#include "wifi_radio_claim.h"
#include "wifi_controller.h"

static const char *TAG = "eap_audit";

/* LLC/SNAP + EAPOL */
#define ETH_TYPE_EAPOL 0x888E

static SemaphoreHandle_t s_mutex;
static bool s_running;
static eap_audit_entry_t *s_entries;
static int s_count;
static uint32_t s_eapol_frames;
static uint32_t s_identity_hits;
static wifi_ap_record_t s_target;
static bool s_has_target;
static uint16_t s_timeout_sec;
static TaskHandle_t s_hop_task;
static esp_timer_handle_t s_timeout_timer;

static void ensure_mutex(void)
{
    if (s_mutex == NULL) {
        s_mutex = xSemaphoreCreateMutex();
    }
}

static int find_pair(const uint8_t bssid[6], const uint8_t sta[6])
{
    for (int i = 0; i < s_count; i++) {
        if (memcmp(s_entries[i].bssid, bssid, 6) == 0 &&
            memcmp(s_entries[i].sta_mac, sta, 6) == 0) {
            return i;
        }
    }
    return -1;
}

static void timeout_cb(void *arg)
{
    (void)arg;
    attack_eap_audit_stop();
}

static void hop_task(void *arg)
{
    (void)arg;
    uint8_t channels[] = {1, 6, 11, 2, 7, 12, 3, 8, 13, 4, 9, 5, 10};
    int idx = 0;
    while (s_running) {
        if (!s_has_target) {
            esp_wifi_set_channel(channels[idx], WIFI_SECOND_CHAN_NONE);
            idx = (idx + 1) % (int)sizeof(channels);
        }
        vTaskDelay(pdMS_TO_TICKS(250));
    }
    s_hop_task = NULL;
    vTaskDelete(NULL);
}

static bool parse_eapol_identity(const uint8_t *payload, size_t len,
                                 uint8_t *code_out, uint8_t *type_out,
                                 char *identity, size_t identity_len)
{
    /* Find LLC/SNAP EAPOL inside 802.11 data frame */
    if (len < 32) {
        return false;
    }

    /* Skip 802.11 header — handle QoS (26) vs non-QoS (24) */
    size_t hdr = 24;
    uint16_t fc = (uint16_t)(payload[0] | (payload[1] << 8));
    bool to_ds = (fc & 0x0100) != 0;
    bool from_ds = (fc & 0x0200) != 0;
    if (to_ds && from_ds) {
        hdr = 30; /* WDS */
    }
    if (fc & 0x0080) {
        hdr += 2; /* QoS */
    }
    if (len < hdr + 8) {
        return false;
    }

    const uint8_t *p = payload + hdr;
    size_t left = len - hdr;
    /* Optionally strip FCS */
    if (left >= 4) {
        left -= 4;
    }

    /* LLC/SNAP: AA AA 03 00 00 00 88 8E */
    if (left < 8) {
        return false;
    }
    if (!(p[0] == 0xAA && p[1] == 0xAA && p[2] == 0x03 &&
          p[6] == 0x88 && p[7] == 0x8E)) {
        return false;
    }
    p += 8;
    left -= 8;

    /* EAPOL header: ver(1) type(1) len(2) */
    if (left < 4) {
        return false;
    }
    uint8_t eapol_type = p[1];
    uint16_t eapol_len = (uint16_t)((p[2] << 8) | p[3]);
    p += 4;
    left -= 4;
    if (eapol_type != 0x00) {
        /* Not EAP-Packet */
        return false;
    }
    if (eapol_len > left) {
        eapol_len = (uint16_t)left;
    }
    if (eapol_len < 5) {
        return false;
    }

    uint8_t code = p[0];
    uint8_t type = p[4];
    if (code_out) {
        *code_out = code;
    }
    if (type_out) {
        *type_out = type;
    }

    /* EAP Identity Request/Response type=1 */
    if (type == 1 && eapol_len > 5 && identity && identity_len > 0) {
        size_t id_len = eapol_len - 5;
        if (id_len >= identity_len) {
            id_len = identity_len - 1;
        }
        size_t j = 0;
        for (size_t i = 0; i < id_len; i++) {
            uint8_t c = p[5 + i];
            if (c < 0x20 || c > 0x7E) {
                continue;
            }
            identity[j++] = (char)c;
        }
        identity[j] = '\0';
        return j > 0 || code == 1; /* request may have empty identity */
    }
    return true;
}

static void resolve_addrs(const uint8_t *frame, uint8_t bssid[6], uint8_t sta[6])
{
    uint16_t fc = (uint16_t)(frame[0] | (frame[1] << 8));
    bool to_ds = (fc & 0x0100) != 0;
    bool from_ds = (fc & 0x0200) != 0;
    const uint8_t *addr1 = frame + 4;
    const uint8_t *addr2 = frame + 10;
    const uint8_t *addr3 = frame + 16;

    if (to_ds && !from_ds) {
        /* STA -> AP */
        memcpy(bssid, addr1, 6);
        memcpy(sta, addr2, 6);
    } else if (!to_ds && from_ds) {
        /* AP -> STA */
        memcpy(sta, addr1, 6);
        memcpy(bssid, addr2, 6);
    } else {
        memcpy(bssid, addr3, 6);
        memcpy(sta, addr2, 6);
    }
}

static void handle_data(wifi_promiscuous_pkt_t *pkt)
{
    const uint8_t *frame = pkt->payload;
    size_t len = pkt->rx_ctrl.sig_len;
    if (len < 32) {
        return;
    }
    /* Data frame type=2 */
    if ((frame[0] & 0x0C) != 0x08) {
        return;
    }

    uint8_t code = 0, type = 0;
    char identity[EAP_IDENTITY_MAX] = {0};
    if (!parse_eapol_identity(frame, len, &code, &type, identity, sizeof(identity))) {
        return;
    }

    uint8_t bssid[6], sta[6];
    resolve_addrs(frame, bssid, sta);

    if (s_has_target && memcmp(bssid, s_target.bssid, 6) != 0) {
        return;
    }

    if (xSemaphoreTake(s_mutex, pdMS_TO_TICKS(5)) != pdTRUE) {
        return;
    }
    s_eapol_frames++;

    int idx = find_pair(bssid, sta);
    if (idx < 0) {
        if (s_count >= EAP_AUDIT_MAX_ENTRIES) {
            xSemaphoreGive(s_mutex);
            return;
        }
        idx = s_count++;
        memset(&s_entries[idx], 0, sizeof(s_entries[idx]));
        memcpy(s_entries[idx].bssid, bssid, 6);
        memcpy(s_entries[idx].sta_mac, sta, 6);
        if (s_has_target) {
            strncpy(s_entries[idx].ssid, (char *)s_target.ssid, sizeof(s_entries[idx].ssid) - 1);
        }
        s_entries[idx].channel = pkt->rx_ctrl.channel;
        s_entries[idx].rssi = pkt->rx_ctrl.rssi;
    }

    s_entries[idx].eapol_count++;
    s_entries[idx].eap_code = code;
    s_entries[idx].eap_type = type;
    if (identity[0]) {
        strncpy(s_entries[idx].identity, identity, sizeof(s_entries[idx].identity) - 1);
        if (!s_entries[idx].has_identity) {
            s_entries[idx].has_identity = true;
            s_identity_hits++;
            ESP_LOGI(TAG, "EAP Identity: %s", identity);
        }
    }
    xSemaphoreGive(s_mutex);
}

static void sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (!s_running) {
        return;
    }
    if (type == WIFI_PKT_DATA) {
        handle_data((wifi_promiscuous_pkt_t *)buf);
    }
}

void attack_eap_audit_init(void)
{
    ensure_mutex();
    if (s_entries == NULL) {
        s_entries = heap_psram_calloc(EAP_AUDIT_MAX_ENTRIES, sizeof(eap_audit_entry_t));
    }
    ESP_LOGI(TAG, "EAP audit initialized");
}

esp_err_t attack_eap_audit_start(const wifi_ap_record_t *target_or_null, uint16_t timeout_sec)
{
    ensure_mutex();
    if (s_running) {
        return ESP_ERR_INVALID_STATE;
    }
    if (s_entries == NULL) {
        attack_eap_audit_init();
        if (s_entries == NULL) {
            return ESP_ERR_NO_MEM;
        }
    }

    esp_err_t err = wifi_radio_claim(WIFI_RADIO_OWNER_EAP_AUDIT);
    if (err != ESP_OK) {
        return err;
    }

    s_has_target = false;
    memset(&s_target, 0, sizeof(s_target));
    if (target_or_null) {
        memcpy(&s_target, target_or_null, sizeof(s_target));
        s_has_target = true;
        wifictl_set_channel(s_target.primary);
    }

    s_timeout_sec = timeout_sec ? timeout_sec : EAP_AUDIT_TIMEOUT_SEC;
    if (s_timeout_sec > 600) {
        s_timeout_sec = 600;
    }
    s_count = 0;
    s_eapol_frames = 0;
    s_identity_hits = 0;
    memset(s_entries, 0, sizeof(eap_audit_entry_t) * EAP_AUDIT_MAX_ENTRIES);

    esp_wifi_set_promiscuous_rx_cb(&sniffer_cb);
    wifi_promiscuous_filter_t filter = { .filter_mask = WIFI_PROMIS_FILTER_MASK_DATA };
    esp_wifi_set_promiscuous_filter(&filter);
    esp_wifi_set_promiscuous(true);

    s_running = true;
    if (!s_has_target && s_hop_task == NULL) {
        xTaskCreatePinnedToCore(hop_task, "eap_hop", 3072, NULL, 3, &s_hop_task, 1);
    }

    const esp_timer_create_args_t targs = { .callback = &timeout_cb, .name = "eap_timeout" };
    if (s_timeout_timer == NULL) {
        esp_timer_create(&targs, &s_timeout_timer);
    }
    esp_timer_start_once(s_timeout_timer, (uint64_t)s_timeout_sec * 1000000ULL);
    ESP_LOGI(TAG, "EAP audit started (targeted=%d)", s_has_target);
    return ESP_OK;
}

void attack_eap_audit_stop(void)
{
    if (!s_running) {
        return;
    }
    s_running = false;
    if (s_timeout_timer) {
        if (esp_timer_is_active(s_timeout_timer)) {
            esp_timer_stop(s_timeout_timer);
        }
        esp_timer_delete(s_timeout_timer);
        s_timeout_timer = NULL;
    }
    esp_wifi_set_promiscuous_rx_cb(NULL);
    esp_wifi_set_promiscuous(false);
    vTaskDelay(pdMS_TO_TICKS(250));
    if (s_hop_task) {
        vTaskDelete(s_hop_task);
        s_hop_task = NULL;
    }
    wifi_radio_release(WIFI_RADIO_OWNER_EAP_AUDIT);
    ESP_LOGI(TAG, "EAP audit stopped (identities=%u)", (unsigned)s_identity_hits);
}

bool attack_eap_audit_is_running(void)
{
    return s_running;
}

void attack_eap_audit_clear(void)
{
    ensure_mutex();
    if (xSemaphoreTake(s_mutex, portMAX_DELAY) == pdTRUE) {
        s_count = 0;
        s_eapol_frames = 0;
        s_identity_hits = 0;
        if (s_entries) {
            memset(s_entries, 0, sizeof(eap_audit_entry_t) * EAP_AUDIT_MAX_ENTRIES);
        }
        xSemaphoreGive(s_mutex);
    }
}

static const char *eap_code_str(uint8_t c)
{
    switch (c) {
        case 1: return "Request";
        case 2: return "Response";
        case 3: return "Success";
        case 4: return "Failure";
        default: return "Unknown";
    }
}

cJSON *attack_eap_audit_get_status_json(void)
{
    cJSON *root = cJSON_CreateObject();
    if (!root) {
        return NULL;
    }
    ensure_mutex();
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    cJSON_AddBoolToObject(root, "running", s_running);
    cJSON_AddNumberToObject(root, "entry_count", s_count);
    cJSON_AddNumberToObject(root, "eapol_frames", s_eapol_frames);
    cJSON_AddNumberToObject(root, "identity_hits", s_identity_hits);
    cJSON_AddBoolToObject(root, "targeted", s_has_target);
    if (s_has_target) {
        char bssid[18];
        wifi_mac_to_str(s_target.bssid, bssid);
        cJSON_AddStringToObject(root, "ssid", (char *)s_target.ssid);
        cJSON_AddStringToObject(root, "bssid", bssid);
        cJSON_AddNumberToObject(root, "channel", s_target.primary);
    }
    cJSON_AddNumberToObject(root, "timeout_sec", s_timeout_sec);
    cJSON_AddStringToObject(root, "status", s_running ? "Running" : "Stopped");
    xSemaphoreGive(s_mutex);
    return root;
}

cJSON *attack_eap_audit_get_results_json(void)
{
    cJSON *root = cJSON_CreateObject();
    cJSON *arr = cJSON_CreateArray();
    if (!root || !arr) {
        cJSON_Delete(root);
        cJSON_Delete(arr);
        return NULL;
    }
    ensure_mutex();
    xSemaphoreTake(s_mutex, portMAX_DELAY);
    for (int i = 0; i < s_count; i++) {
        cJSON *item = cJSON_CreateObject();
        char bssid[18], sta[18];
        wifi_mac_to_str(s_entries[i].bssid, bssid);
        wifi_mac_to_str(s_entries[i].sta_mac, sta);
        cJSON_AddStringToObject(item, "ssid", s_entries[i].ssid);
        cJSON_AddStringToObject(item, "bssid", bssid);
        cJSON_AddStringToObject(item, "sta", sta);
        cJSON_AddStringToObject(item, "identity", s_entries[i].identity);
        cJSON_AddBoolToObject(item, "has_identity", s_entries[i].has_identity);
        cJSON_AddStringToObject(item, "eap_code", eap_code_str(s_entries[i].eap_code));
        cJSON_AddNumberToObject(item, "eap_type", s_entries[i].eap_type);
        cJSON_AddNumberToObject(item, "channel", s_entries[i].channel);
        cJSON_AddNumberToObject(item, "rssi", s_entries[i].rssi);
        cJSON_AddNumberToObject(item, "eapol_count", s_entries[i].eapol_count);
        cJSON_AddItemToArray(arr, item);
    }
    cJSON_AddItemToObject(root, "entries", arr);
    cJSON_AddNumberToObject(root, "count", s_count);
    xSemaphoreGive(s_mutex);
    return root;
}
