/**
 * node_scanner.h
 *
 * Mesh node scanner — nearby AP grouping + local soft-AP subnet discovery.
 * AP-safe: does not change WiFi mode (management AP stays up).
 */

#ifndef NODE_SCANNER_H
#define NODE_SCANNER_H

#include "mesh.h"

#ifdef __cplusplus
extern "C" {
#endif

void node_scanner_init(void);

bool node_scanner_is_espressif_oui(const uint8_t *bssid);

esp_err_t mesh_scanner_scan(uint8_t channel, scan_result_t *result);
void      mesh_scanner_print_report(const scan_result_t *result);

esp_err_t mesh_scan_local_subnet(mesh_scan_result_t *result);
void      mesh_scan_print_report(const mesh_scan_result_t *result);

esp_err_t mesh_scan_active_nearby(mesh_active_result_t *result);
void      mesh_active_print_report(const mesh_active_result_t *result);

#ifdef __cplusplus
}
#endif

#endif /* NODE_SCANNER_H */
