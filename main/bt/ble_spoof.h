#ifndef BLE_SPOOF_H
#define BLE_SPOOF_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

void ble_spoof_init(void);
void ble_spoof_start(const char *name);
void ble_spoof_stop(void);
bool ble_spoof_is_running(void);

#ifdef __cplusplus
}
#endif

#endif // BLE_SPOOF_H
