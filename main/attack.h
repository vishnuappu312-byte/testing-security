#ifndef ATTACK_H
#define ATTACK_H

#include "esp_wifi_types.h"

typedef enum {
    ATTACK_TYPE_DOS,
    ATTACK_TYPE_HANDSHAKE,
    ATTACK_TYPE_PMKID,
    ATTACK_TYPE_EVIL_TWIN,
    ATTACK_TYPE_PROBE,
    ATTACK_TYPE_BEACON
} attack_type_t;

typedef enum {
    ATTACK_STATUS_RUNNING,
    ATTACK_STATUS_FINISHED,
    ATTACK_STATUS_STOPPED,
    ATTACK_STATUS_ERROR
} attack_status_t;

typedef struct {
    int target_count;
    const wifi_ap_record_t **ap_records;
    int method;
    attack_type_t type;
} attack_config_t;

void attack_update_status(attack_status_t status);
char* attack_alloc_result_content(size_t size);
void attack_append_status_content(const uint8_t *data, size_t len);

#endif