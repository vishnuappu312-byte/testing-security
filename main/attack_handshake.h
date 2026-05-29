#ifndef ATTACK_HANDSHAKE_H
#define ATTACK_HANDSHAKE_H

#include "attack.h"
#include <stdint.h>

typedef enum {
    ATTACK_HANDSHAKE_METHOD_BROADCAST,
    ATTACK_HANDSHAKE_METHOD_ROGUE_AP,
    ATTACK_HANDSHAKE_METHOD_PASSIVE
} attack_handshake_methods_t;

void attack_handshake_start(attack_config_t *attack_config);
void attack_handshake_stop(void);
int get_captured_eapol_count(void);
void get_captured_eapol_frame(int index, uint8_t *buffer, uint32_t *len);

#endif