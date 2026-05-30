#include "attack_deauth.h"
#include "esp_log.h"
#include <stdio.h>
#include <string.h>

static const char *TAG = "attack_deauth";
static bool deauth_active = false;
static char current_deauth_target[64] = {0};

void deauth_attack_init(void) {
    ESP_LOGI(TAG, "Stub deauth attack initialized");
    deauth_active = false;
    current_deauth_target[0] = '\0';
}

void start_deauth_attack(const char *bssid, int channel) {
    deauth_active = true;
    snprintf(current_deauth_target, sizeof(current_deauth_target), "%s ch:%d", bssid, channel);
    ESP_LOGI(TAG, "Stub start deauth attack: %s", current_deauth_target);
}

void stop_deauth_attack(void) {
    if (deauth_active) {
        deauth_active = false;
        ESP_LOGI(TAG, "Stub stop deauth attack");
    }
}
