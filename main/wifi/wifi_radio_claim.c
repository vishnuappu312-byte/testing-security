#include "wifi_radio_claim.h"

#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"
#include "esp_log.h"
#include "attack_deauth_detector.h"

static const char *TAG = "wifi_radio";

static SemaphoreHandle_t s_mutex;
static wifi_radio_owner_t s_owner = WIFI_RADIO_OWNER_NONE;
static bool s_detector_paused = false;

void wifi_radio_claim_init(void)
{
    if (s_mutex == NULL) {
        s_mutex = xSemaphoreCreateMutex();
    }
}

const char *wifi_radio_owner_str(wifi_radio_owner_t owner)
{
    switch (owner) {
        case WIFI_RADIO_OWNER_NONE:      return "none";
        case WIFI_RADIO_OWNER_PROBE:     return "probe";
        case WIFI_RADIO_OWNER_DETECTOR:  return "detector";
        case WIFI_RADIO_OWNER_KARMA:     return "karma";
        case WIFI_RADIO_OWNER_CSA:       return "csa";
        case WIFI_RADIO_OWNER_PMF:       return "pmf";
        case WIFI_RADIO_OWNER_WPS:       return "wps";
        case WIFI_RADIO_OWNER_EAP_AUDIT: return "eap_audit";
        case WIFI_RADIO_OWNER_ESPNOW:    return "espnow";
        case WIFI_RADIO_OWNER_OTHER:     return "other";
        default:                         return "unknown";
    }
}

wifi_radio_owner_t wifi_radio_owner(void)
{
    return s_owner;
}

bool wifi_radio_is_free(void)
{
    return s_owner == WIFI_RADIO_OWNER_NONE;
}

esp_err_t wifi_radio_claim(wifi_radio_owner_t owner)
{
    if (owner == WIFI_RADIO_OWNER_NONE) {
        return ESP_ERR_INVALID_ARG;
    }
    wifi_radio_claim_init();
    if (xSemaphoreTake(s_mutex, pdMS_TO_TICKS(500)) != pdTRUE) {
        return ESP_ERR_TIMEOUT;
    }

    if (s_owner != WIFI_RADIO_OWNER_NONE && s_owner != owner) {
        ESP_LOGW(TAG, "Radio busy: owner=%s requested=%s",
                 wifi_radio_owner_str(s_owner), wifi_radio_owner_str(owner));
        xSemaphoreGive(s_mutex);
        return ESP_ERR_INVALID_STATE;
    }

    if (s_owner == WIFI_RADIO_OWNER_NONE) {
        /* Pause detector so it does not fight for promiscuous CB */
        if (deauth_detector_is_running()) {
            ESP_LOGI(TAG, "Pausing deauth detector for %s", wifi_radio_owner_str(owner));
            deauth_detector_stop();
            s_detector_paused = true;
        } else {
            s_detector_paused = false;
        }
        s_owner = owner;
        ESP_LOGI(TAG, "Radio claimed by %s", wifi_radio_owner_str(owner));
    }

    xSemaphoreGive(s_mutex);
    return ESP_OK;
}

void wifi_radio_release(wifi_radio_owner_t owner)
{
    wifi_radio_claim_init();
    if (xSemaphoreTake(s_mutex, pdMS_TO_TICKS(500)) != pdTRUE) {
        return;
    }

    if (s_owner != owner) {
        xSemaphoreGive(s_mutex);
        return;
    }

    s_owner = WIFI_RADIO_OWNER_NONE;
    ESP_LOGI(TAG, "Radio released by %s", wifi_radio_owner_str(owner));

    bool restart = s_detector_paused;
    s_detector_paused = false;
    xSemaphoreGive(s_mutex);

    if (restart) {
        ESP_LOGI(TAG, "Restoring deauth detector");
        deauth_detector_start();
    }
}
