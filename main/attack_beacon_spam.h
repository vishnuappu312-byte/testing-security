#ifndef ATTACK_BEACON_SPAM_H
#define ATTACK_BEACON_SPAM_H

#include <stdint.h>
typedef enum {
    BEACON_MODE_COMMON = 0,
    BEACON_MODE_GARBAGE,
    BEACON_MODE_RICK_ROLL,
    BEACON_MODE_SECURITY
} beacon_spam_mode_t;

void attack_beacon_spam_start(uint8_t count, beacon_spam_mode_t mode);
void attack_beacon_spam_stop(void);

#endif