#ifndef ATTACK_PMKID_H
#define ATTACK_PMKID_H

#include "attack.h"
#include <stdint.h>
#include <stdbool.h>

void attack_pmkid_start(attack_config_t *attack_config);
void attack_pmkid_stop(void);

/* Webserver API */
bool attack_pmkid_is_running(void);
bool attack_pmkid_has_capture(void);
const char* attack_pmkid_get_hash(void);
const char* attack_pmkid_get_ssid(void);
const uint8_t* attack_pmkid_get_bssid(void);
bool attack_pmkid_was_timeout(void);
char* attack_pmkid_get_status_json(void);  // caller must free()

#endif // ATTACK_PMKID_H