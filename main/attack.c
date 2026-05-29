#include "attack.h"
#include <stdlib.h>
#include <string.h>
#include "esp_log.h"

static const char *TAG = "attack";
static attack_status_t current_status = ATTACK_STATUS_STOPPED;
static char *result_content = NULL;
static size_t result_size = 0;

void attack_update_status(attack_status_t status) {
    current_status = status;
    ESP_LOGI(TAG, "Attack status updated to: %d", status);
}

char* attack_alloc_result_content(size_t size) {
    if (result_content) {
        free(result_content);
    }
    result_content = malloc(size);
    result_size = size;
    if (result_content) {
        memset(result_content, 0, size);
    }
    return result_content;
}

void attack_append_status_content(const uint8_t *data, size_t len) {
    // Stub - can be implemented to save captured data
    ESP_LOGD(TAG, "Appending %d bytes to status", len);
}