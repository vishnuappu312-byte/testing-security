#ifndef BLE_CONNECT_FLOOD_H
#define BLE_CONNECT_FLOOD_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

void ble_connect_flood_init(void);
void ble_connect_flood_start(const char *target_addr);
void ble_connect_flood_stop(void);
bool ble_connect_flood_is_running(void);

#ifdef __cplusplus
}
#endif

#endif // BLE_CONNECT_FLOOD_H
