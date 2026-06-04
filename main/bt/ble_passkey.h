/* BLE Passkey Capture Header - Copy to: main/bt/ble_passkey.h */
#ifndef BLE_PASSKEY_H
#define BLE_PASSKEY_H

#include <stdbool.h>

void ble_passkey_init(void);
void ble_passkey_start(const char *target_addr);
void ble_passkey_stop(void);
bool ble_passkey_is_running(void);
const char* ble_passkey_get_info(void);

#endif
