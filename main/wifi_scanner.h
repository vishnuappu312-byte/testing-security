#ifndef WIFI_SCANNER_H
#define WIFI_SCANNER_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include "ap_scanner.h"

void scanner_init(void);
void scanner_scan(void);
const wifictl_ap_records_t *scanner_get_records(void);
const wifi_ap_record_t *scanner_get_record(uint16_t index);

#ifdef __cplusplus
}
#endif

#endif // WIFI_SCANNER_H
