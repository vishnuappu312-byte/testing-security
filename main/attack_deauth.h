#ifndef ATTACK_DEAUTH_H
#define ATTACK_DEAUTH_H

#include <stdint.h>
#include <stdbool.h>

void deauth_attack_init(void);
void start_deauth_attack(const uint8_t *bssid, int channel);
void stop_deauth_attack(void);
bool is_attack_active(void);
void get_attack_target(char *buffer);

#define deauth_init deauth_attack_init

#endif
