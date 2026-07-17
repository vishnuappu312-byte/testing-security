/**
 * @file attack_eap_audit.h
 * @brief Passiveive EAP identity / capability audit (no password collection).
 */
#ifndef ATTACK_EAP_AUDIT_H
#define ATTACK_EAP_AUDIT_H

#include <stdbool.h>
#include <stdint.h>
#include "cJSON.h"
#include "esp_err.h"
#include "esp_wifi_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define EAP_AUDIT_MAX_ENTRIES  32
#define EAP_AUDIT_TIMEOUT_SEC  120
#define EAP_IDENTITY_MAX       64

typedef struct {
    uint8_t  bssid[6];
    uint8_t  sta_mac[6];
    char     ssid[33];
    char     identity[EAP_IDENTITY_MAX];
    uint8_t  eap_code;      /* 1=Request 2=Response 3=Success 4=Failure */
    uint8_t  eap_type;      /* Identity=1, Notification=2, ... */
    uint8_t  channel;
    int8_t   rssi;
    uint32_t eapol_count;
    bool     has_identity;
} eap_audit_entry_t;

void attack_eap_audit_init(void);
esp_err_t attack_eap_audit_start(const wifi_ap_record_t *target_or_null,
                                 uint16_t timeout_sec);
void attack_eap_audit_stop(void);
bool attack_eap_audit_is_running(void);
void attack_eap_audit_clear(void);
cJSON *attack_eap_audit_get_status_json(void);
cJSON *attack_eap_audit_get_results_json(void);

#ifdef __cplusplus
}
#endif

#endif /* ATTACK_EAP_AUDIT_H */
