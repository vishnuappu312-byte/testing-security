#ifndef ATTACK_DOS_H
#define ATTACK_DOS_H

#include "attack.h"

typedef enum {
    ATTACK_DOS_METHOD_BROADCAST,
    ATTACK_DOS_METHOD_ROGUE_AP,
    ATTACK_DOS_METHOD_COMBINE_ALL,
    ATTACK_DOS_METHOD_SUPER_CLONE
} attack_dos_methods_t;

void attack_dos_start(attack_config_t *attack_config);
void attack_dos_stop(void);

#endif