#ifndef ATTACK_EVILTWIN_H
#define ATTACK_EVILTWIN_H

#include "esp_wifi_types.h"

void attack_method_evil_twin(const wifi_ap_record_t *ap_record);
bool is_evil_twin_active(void);
void attack_method_evil_twin_stop(void);
const char* get_evil_twin_password(void);
int get_wrong_attempts_count(void);
void get_wrong_passwords(char *buffer, size_t max_len);

#endif