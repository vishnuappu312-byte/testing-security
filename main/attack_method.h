#ifndef ATTACK_METHOD_H
#define ATTACK_METHOD_H

#include "esp_wifi_types.h"

#define MAX_ATTACK_TARGETS 5

void attack_method_broadcast(const wifi_ap_record_t *ap_record, unsigned period_sec);
void attack_method_broadcast_stop(void);
void attack_method_rogueap(const wifi_ap_record_t *ap_record);
void attack_method_super_clone(const wifi_ap_record_t *ap_record);
void attack_method_super_clone_stop(void);

#endif