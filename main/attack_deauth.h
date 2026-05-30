#ifndef ATTACK_DEAUTH_H
#define ATTACK_DEAUTH_H

#ifdef __cplusplus
extern "C" {
#endif

void deauth_attack_init(void);
void start_deauth_attack(const char *bssid, int channel);
void stop_deauth_attack(void);

#ifdef __cplusplus
}
#endif

#endif // ATTACK_DEAUTH_H
