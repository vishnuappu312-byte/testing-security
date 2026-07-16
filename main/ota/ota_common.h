/*
 * ota_common.h - Shared types and helpers for OTA attack modules
 */

#ifndef OTA_COMMON_H
#define OTA_COMMON_H

#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "esp_err.h"
#include "esp_event.h"
#include "mqtt_client.h"
#include "cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/*  Buffer sizes                                                       */
/* ------------------------------------------------------------------ */

#define OTA_MAX_CAPTURED_MSGS     4
#define OTA_MAX_PAYLOAD_LEN       256
#define OTA_MAX_TOPIC_LEN         64
#define OTA_MAX_URL_LEN           128
#define OTA_MAX_FIRMWARE_SIZE     (512 * 1024)

#define OTA_MAX_CAPTURED_URLS     4
#define OTA_MAX_DNS_ENTRIES       4
#define OTA_MAX_DNS_NAME_LEN      32
#define OTA_MAX_HTTP_ENTRIES      4
#define OTA_MAX_HTTP_URL_LEN      128
/* scheme ("https://") + host + path + NUL; keeps snprintf from truncating */
#define OTA_MAX_HTTP_FULL_URL_LEN (8 + 48 + OTA_MAX_HTTP_URL_LEN)

#define OTA_MAX_PROV_CREDS        4
#define OTA_MAX_CRED_KEY_LEN      24
#define OTA_MAX_CRED_VALUE_LEN    128

#define OTA_MAX_MITM_MSGS         4
#define OTA_MAX_MITM_TOPIC_LEN    32
#define OTA_MAX_MITM_PAYLOAD_LEN  256

#define OTA_MAX_FW_SECRETS        4
#define OTA_MAX_SECRET_TYPE_LEN   16
#define OTA_MAX_SECRET_VALUE_LEN  128
#define OTA_MAX_SECRET_CONTEXT_LEN 16

#define OTA_GH_OWNER_LEN          48
#define OTA_GH_REPO_LEN           48
#define OTA_GH_PATH_LEN           96
#define OTA_GH_BRANCH_LEN         24
#define OTA_GH_TOKEN_LEN          96
#define OTA_GH_SHA_LEN            41
#define OTA_GH_API_RESP_LEN       (4 * 1024)

#define OTA_DEFAULT_TIMEOUT_SEC   300
#define OTA_DEFAULT_MQTT_PORT     1883
#define OTA_WIFI_CONNECT_TIMEOUT_MS 15000
#define OTA_MQTT_CONNECT_TIMEOUT_MS 15000
#define OTA_HTTP_RECV_BUFFER_SIZE 4096
#define OTA_MAX_FIRMWARE_DOWNLOAD_SIZE (512 * 1024)
#define OTA_TASK_STACK_SIZE       8192
#define OTA_TASK_PRIORITY         5
#define OTA_STOP_SEM_TIMEOUT_MS   5000

#define OTA_JSON_SMALL_SZ         4096
#define OTA_JSON_MED_SZ           8192
#define OTA_JSON_LARGE_SZ         16384
#define OTA_JSON_TINY_SZ          1024
#define OTA_JSON_2K_SZ            2048

/* ------------------------------------------------------------------ */
/*  Shared capture structs                                             */
/* ------------------------------------------------------------------ */

typedef struct {
    char topic[OTA_MAX_TOPIC_LEN];
    char payload[OTA_MAX_PAYLOAD_LEN];
    int64_t timestamp_ms;
} ota_msg_entry_t;

typedef struct {
    char url[OTA_MAX_URL_LEN];
    char source_topic[OTA_MAX_TOPIC_LEN];
    int64_t timestamp_ms;
    bool has_github_token; /* true only if URL embeds a token= / access_token= query */
    bool downloaded;
    uint32_t firmware_size;
} ota_url_entry_t;

typedef struct {
    char domain[OTA_MAX_DNS_NAME_LEN];
    uint8_t client_ip[4];
    uint8_t server_ip[4];
    int64_t timestamp_ms;
    bool is_ota_related;
} ota_dns_entry_t;

typedef struct {
    char method[8];
    char host[48];
    char path[OTA_MAX_HTTP_URL_LEN];
    char full_url[OTA_MAX_HTTP_FULL_URL_LEN];
    uint8_t client_ip[4];
    int64_t timestamp_ms;
    bool is_ota_related;
} ota_http_entry_t;

typedef struct {
    char key[OTA_MAX_CRED_KEY_LEN];
    char value[OTA_MAX_CRED_VALUE_LEN];
    char source_ip[16];
    int64_t timestamp_ms;
    bool is_sensitive;
} ota_prov_cred_t;

typedef struct {
    char wifi_ssid[33];
    char wifi_password[64];
    char mqtt_broker[96];
    uint16_t mqtt_port;
    char mqtt_username[48];
    char mqtt_password[48];
    char modbus_driver_url[128];
    char custom_time[24];
    char device_id[48];
    char ap_password[48];
    int total_creds_captured;
    int sensitive_creds_captured;
    int64_t first_capture_ms;
    int64_t last_capture_ms;
} ota_prov_summary_t;

typedef struct {
    char original_topic[OTA_MAX_MITM_TOPIC_LEN];
    char original_payload[OTA_MAX_MITM_PAYLOAD_LEN];
    char modified_topic[OTA_MAX_MITM_TOPIC_LEN];
    char modified_payload[OTA_MAX_MITM_PAYLOAD_LEN];
    char client_id[48];
    bool was_modified;
    bool direction_upload;
    int64_t timestamp_ms;
} ota_mitm_entry_t;

typedef struct {
    char target_client_id[48];
    char real_broker_ip[96];
    uint16_t real_broker_port;
    uint16_t rogue_port;
    int devices_connected;
    int messages_intercepted;
    int messages_modified;
    int messages_forwarded;
    bool arp_spoof_active;
} ota_rogue_broker_summary_t;

typedef struct {
    char type[OTA_MAX_SECRET_TYPE_LEN];
    char value[OTA_MAX_SECRET_VALUE_LEN];
    char context[OTA_MAX_SECRET_CONTEXT_LEN];
    uint32_t offset;
    int confidence;
} ota_fw_secret_t;

typedef struct {
    uint32_t firmware_size;
    uint32_t secrets_found;
    uint32_t high_confidence_count;
    char firmware_sha256[65];
    bool has_wifi_creds;
    bool has_mqtt_creds;
    bool has_api_keys;
    bool has_certificates;
    bool has_private_keys;
    bool has_hardcoded_urls;
    bool has_modbus_config;
} ota_fw_analysis_summary_t;

typedef struct {
    char owner[OTA_GH_OWNER_LEN];
    char repo[OTA_GH_REPO_LEN];
    char path[OTA_GH_PATH_LEN];
    char branch[OTA_GH_BRANCH_LEN];
    char token[OTA_GH_TOKEN_LEN];
    char file_sha[OTA_GH_SHA_LEN];
    bool token_valid;
    bool parsed;
} ota_github_repo_t;

/* WiFi/MQTT connection parameters used by helpers */
typedef struct {
    char wifi_ssid[33];
    char wifi_password[64];
    char mqtt_broker[96];
    uint16_t mqtt_port;
    char mqtt_username[48];
    char mqtt_password[48];
    char mqtt_client_id[24];
    char subscribe_topic[64];
    bool verify_ssl;
    bool auto_subscribe;
} ota_conn_params_t;

/* Sniffer options for poll / provision / optional MQTT sniff */
typedef struct {
    bool capture_dns;
    bool capture_http;
    bool provision_mode;
    bool post_only;
    bool auto_parse_json;
    uint8_t target_device_ip[4];
    uint16_t sniff_port; /* provision focus port; 0 = any */
} ota_sniffer_opts_t;

typedef void (*ota_mqtt_data_hook_t)(const char *topic, const char *data, int data_len);

/* ------------------------------------------------------------------ */
/*  Lifecycle / mutual exclusion                                       */
/* ------------------------------------------------------------------ */

void ota_common_init(void);

/** Claim exclusive OTA runner slot. Returns ESP_ERR_INVALID_STATE if busy. */
esp_err_t ota_common_try_claim(const char *owner);

void ota_common_release(void);

bool ota_common_is_claimed(void);

const char *ota_common_claim_owner(void);

int64_t ota_common_now_ms(void);

/* ------------------------------------------------------------------ */
/*  PSRAM JSON scratch                                                 */
/* ------------------------------------------------------------------ */

char *ota_common_json_slot(int idx);
char *ota_common_json_med(void);
char *ota_common_json_med_b(void);
char *ota_common_json_large_a(void);
char *ota_common_json_large_b(void);
char *ota_common_json_tiny(void);
char *ota_common_json_2k(void);
char *ota_common_json_result(void);
char *ota_common_http_recv_buffer(void);
char *ota_common_gh_api_resp_buf(void);
int  *ota_common_gh_api_resp_len_ptr(void);

/* ------------------------------------------------------------------ */
/*  WiFi / MQTT helpers                                                */
/* ------------------------------------------------------------------ */

esp_err_t ota_common_wifi_connect(const ota_conn_params_t *p);
void ota_common_wifi_restore_ap(void);
bool ota_common_wifi_has_ip(void);

esp_err_t ota_common_mqtt_connect(const ota_conn_params_t *p, ota_mqtt_data_hook_t hook);
void ota_common_mqtt_disconnect(void);
bool ota_common_mqtt_is_connected(void);
esp_mqtt_client_handle_t ota_common_mqtt_client(void);
esp_err_t ota_common_mqtt_publish(const char *topic, const char *payload, int qos);

/* ------------------------------------------------------------------ */
/*  Capture store                                                      */
/* ------------------------------------------------------------------ */

void ota_common_capture_reset(void);
void ota_common_store_message(const char *topic, int topic_len,
                              const char *payload, int payload_len);
void ota_common_scan_payload_for_urls(const char *topic, const char *payload, int payload_len);

uint32_t ota_common_get_mqtt_msg_count(void);
uint32_t ota_common_get_url_count(void);
uint32_t ota_common_get_github_url_count(void);
int ota_common_get_msg_count(void);
int ota_common_get_url_entries(void);
const ota_msg_entry_t *ota_common_get_msgs(void);
ota_url_entry_t *ota_common_get_urls(void);

const char *ota_common_get_messages_json(void);
const char *ota_common_get_urls_json(void);
const char *ota_common_get_github_urls_json(void);

bool ota_common_is_github_url(const char *url);
void ota_common_extract_github_token(const char *url, char *token_out, size_t token_len);
bool ota_common_is_ota_domain(const char *domain);
bool ota_common_is_ota_http_url(const char *url);

/* Firmware download buffer */
esp_err_t ota_common_download_firmware(const char *url, bool verify_ssl);
const char *ota_common_get_download_result_json(void);
uint8_t *ota_common_get_firmware_buffer(uint32_t *size_out);
uint32_t ota_common_get_download_count(void);
void ota_common_clear_firmware(void);

/* DNS / HTTP capture (poll sniff) */
void ota_common_dns_http_reset(void);
ota_dns_entry_t *ota_common_get_dns_entries(int *count_out);
ota_http_entry_t *ota_common_get_http_entries(int *count_out);
uint32_t ota_common_get_dns_count(void);
uint32_t ota_common_get_http_count(void);
uint32_t ota_common_get_ota_dns_count(void);
uint32_t ota_common_get_ota_http_count(void);
const char *ota_common_get_dns_entries_json(void);
const char *ota_common_get_http_entries_json(void);

void ota_common_add_dns_entry(const ota_dns_entry_t *e);
void ota_common_add_http_entry(const ota_http_entry_t *e);
void ota_common_add_url_from_sniff(const char *url, const char *source);

/* Sniffer */
void ota_common_sniffer_set_opts(const ota_sniffer_opts_t *opts);
void ota_common_sniffer_set_provision_sink(ota_prov_cred_t *creds, int *cred_count,
                                           volatile uint32_t *sensitive_count,
                                           ota_prov_summary_t *summary,
                                           void (*on_captured)(void));
void ota_common_sniffer_enable(bool enable);

#ifdef __cplusplus
}
#endif

#endif /* OTA_COMMON_H */
