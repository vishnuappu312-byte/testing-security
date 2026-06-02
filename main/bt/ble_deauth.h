#ifndef BLE_DEAUTH_H
#define BLE_DEAUTH_H

#include <stdbool.h>

void ble_deauth_init(void);
void ble_deauth_start(const char *target_addr);
void ble_deauth_stop(void);
bool ble_deauth_is_running(void);

#endif /* BLE_DEAUTH_H */