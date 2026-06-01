#ifndef BLE_GATT_PROBE_H
#define BLE_GATT_PROBE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

void ble_gatt_probe_init(void);
void ble_gatt_probe_start(const char *target_addr);
void ble_gatt_probe_stop(void);
bool ble_gatt_probe_is_running(void);
bool ble_gatt_probe_target_found(void);   // ← Add this line
#ifdef __cplusplus
}
#endif

#endif // BLE_GATT_PROBE_H
