#ifndef ATTACK_PMKID_H
#define ATTACK_PMKID_H

#include "attack.h"

// typedef enum {
//     ATTACK_PMKID_METHOD_BROADCAST,
//     ATTACK_PMKID_METHOD_ROGUE_AP
// } attack_pmkid_methods_t;

void attack_pmkid_start(attack_config_t *attack_config);
void attack_pmkid_stop(void);

#endif