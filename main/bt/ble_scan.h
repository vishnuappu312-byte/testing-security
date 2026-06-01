#ifndef BLE_SCAN_H
#define BLE_SCAN_H

#include "cJSON.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Initialize scan module (idempotent) */
void ble_scan_init(void);

/** Perform a BLE scan and return a cJSON array of discovered devices.
 * Caller must free the returned cJSON with cJSON_Delete().
 */
cJSON *ble_scan_perform(int timeout_ms);

#ifdef __cplusplus
}
#endif

#endif // BLE_SCAN_H
