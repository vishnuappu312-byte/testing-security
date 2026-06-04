/* BLE Device Takeover Header - Copy to: main/bt/ble_takeover.h */
#ifndef BLE_TAKEOVER_H
#define BLE_TAKEOVER_H

#include <stdbool.h>
#include <stdint.h>

void ble_takeover_init(void);
void ble_takeover_start(const char *target_addr);
void ble_takeover_stop(void);
bool ble_takeover_is_running(void);
const char* ble_takeover_get_status(void);
const char* ble_takeover_get_services_json(void);
bool ble_takeover_read_chr(uint16_t handle);
const char* ble_takeover_get_read_result(void);
bool ble_takeover_write_chr(uint16_t handle, const char *hex_value);
bool ble_takeover_enable_notify(uint16_t val_handle, bool enable);
const char* ble_takeover_get_notifications_json(void);

#endif
