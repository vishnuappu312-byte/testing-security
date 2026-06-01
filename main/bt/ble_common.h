// #ifndef BLE_COMMON_H
// #define BLE_COMMON_H

// #include <stdint.h>

// /**
//  * @brief Determines the best address type to use for GAP procedures.
//  *
//  * Uses NimBLE's ble_hs_id_infer_auto(). Returns BLE_ADDR_TYPE_* value.
//  * If inference fails, falls back to BLE_ADDR_TYPE_PUBLIC.
//  */
// uint8_t ble_common_own_addr_type(void);

// /**
//  * @brief Ensures a random address is configured for BLE_OWN_ADDR_RANDOM flows.
//  *
//  * Safe to call multiple times; if it fails, callers can still use
//  * ble_common_own_addr_type() and proceed with a public address type.
//  */
// void ble_common_ensure_rnd_addr(void);

// #endif

#ifndef BLE_COMMON_H
#define BLE_COMMON_H

#include <stdbool.h>
#include <stdint.h>

/* One-time NimBLE initialization. Safe to call from any component.
 * Returns true if NimBLE is ready to use. */
bool ble_common_init(void);

/* Check if NimBLE has been initialized */
bool ble_common_is_initialized(void);

/* Get the appropriate own address type for GAP operations */
uint8_t ble_common_own_addr_type(void);

/* Generate and set a random BLE address */
void ble_common_ensure_rnd_addr(void);

#endif /* BLE_COMMON_H */