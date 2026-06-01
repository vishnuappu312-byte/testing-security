#ifndef BLE_L2CAP_FLOOD_H
#define BLE_L2CAP_FLOOD_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>

void ble_l2cap_flood_init(void);
void ble_l2cap_start(const char *target_addr);
void ble_l2cap_stop(void);
bool ble_l2cap_is_running(void);

#ifdef __cplusplus
}
#endif

#endif // BLE_L2CAP_FLOOD_H
