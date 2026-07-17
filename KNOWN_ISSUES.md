# Known issues (local)

Related: [README.md](README.md) · [overview.md](overview.md) · [MEMORY.md](MEMORY.md) · [Android console](android-console/README.md)

Verified against current tree (2026-07-17). Status reflects whether the listed problem still applies after local fixes across **OTA**, **BLE**, **WiFi**, and **ESP-NOW**.

---

## Summary

| Area | Fixed | Still open |
|------|------:|-----------:|
| OTA | 5 | 3 |
| BLE | 12 | 2 |
| WiFi | 15 | 4 |
| ESP-NOW | 0 | 2 |

---

## OTA

| Issue | Where | Status | Notes |
|-------|-------|--------|-------|
| `has_github_token` set from domain match, not actual token | `ota_common_add_url_from_sniff` | **Fixed** | Flag is true only when `token=` / `access_token=` / `private_token=` is present. GitHub URL count still uses domain match; `/api/ota/github/urls` lists all GitHub URLs and includes `has_github_token`. |
| `ota_fetch_download_by_index()` downloads without WiFi connect | `ota_fetch.c` + webserver | **Fixed** | `/api/ota/download` accepts optional `wifi_ssid` / `wifi_password` and starts the fetch task with STA connect. Sync path without creds still requires an existing association. |
| Mode 0 and mode 1 both start the same MQTT sniff task | `webserver.c` | **Fixed** | Mode 0 (SNIFF): MQTT + promiscuous DNS/HTTP. Mode 1 (CLIENT): MQTT subscribe only. |
| GitHub upload JSON body can overflow for large firmware | `ota_github_upload_firmware` | **Fixed** | Body buffer is heap-allocated from base64 + message/branch/sha lengths. |
| `main.c` still called deleted `ota_attack_init()` | `main.c` | **Fixed** | Wired to modular OTA inits (`ota_common_init` first, then sniff/inject/fetch/poll/provision/github/rogue/fw_analyze). |
| `ota_inject_message()` fails unless MQTT already connected | `ota_inject.c` | **Open** | Manual inject API only calls `ota_common_mqtt_publish`. Needs an active MQTT session (inject / sniff / client / rogue). Does **not** explicitly require inject mode. |
| `ota_rogue_broker` is an MQTT client to the real broker, not a rogue server | `ota_rogue_broker.c` | **Open** | Connects/subscribes to `real_broker`; can republish modified payloads. Does not listen on `rogue_port` or MITM device traffic. UI copy overstates capability. |
| Promiscuous sniff on encrypted WiFi | sniffer design | **Open (by design)** | Only cleartext HTTP/DNS/POST bodies are visible. HTTPS / WPA-encrypted L3 payloads are not decrypted. |

---

## BLE

| Issue | Where | Status | Notes |
|-------|-------|--------|-------|
| Name ADV builder wrote past 31-byte limit | `ble_spoof.c` | **Fixed** | Name capped at 26 bytes (Flags + AD overhead). |
| Hex encode OOB when value length is 128 | `ble_takeover.c` | **Fixed** | Cap at 127 bytes before writing into 256-byte hex buffers. |
| `auto_enable_notifies()` blocked NimBLE host (`vTaskDelay` in GATT cb) | `ble_takeover.c` | **Fixed** | CCCD enable runs in takeover task after discovery completes. |
| `ble_gap_connect` used peer addr type as own | `ble_gatt_probe.c` | **Fixed** | First arg is own addr type (`RANDOM` when rotating, else inferred). |
| Random-static bits set on wrong byte (`val[0]`) | `ble_gatt_probe` / `ble_deauth` | **Fixed** | Use NimBLE MSB: `val[5] = (val[5] & 0x3F) or 0xC0`. |
| Rotate MAC then connect as public | deauth / takeover / probe | **Fixed** | Use `BLE_OWN_ADDR_RANDOM` when `rotate_own_mac` is set. |
| Re-init drained sync sem / flagged init before sync | `ble_common.c` | **Fixed** | Already-init returns immediately; flag set only after sync succeeds. |
| `vTaskDelay` in GAP `ENC_CHANGE` callback | `ble_passkey.c` | **Fixed** | Terminate without delaying in host callback. |
| L2CAP disconnect wait skipped → false next connect | `ble_l2cap_flood.c` | **Fixed** | Always take disconnect sem after terminate. |
| Mutex/sem recreated every `*_init()` | takeover / probe / deauth / passkey | **Fixed** | Create only if `NULL`. |
| Scan results race without lock | `attack_bt_spam.c` | **Fixed** | `scan_mutex` around fill / JSON build; results in PSRAM. |
| Large static BSS (notif log, GATT tables, scan results) | takeover / probe / spam | **Fixed** | Moved to PSRAM via `heap_psram_*`. |
| CCCD assumed as `val_handle + 1` | takeover / gatt_probe | **Open** | Works often; fails when descriptors reorder. Needs `ble_gattc_disc_all_dscs` + UUID `0x2902`. |
| Encrypted BLE traffic not decryptable from sniff alone | design | **Open (by design)** | Same class of limit as WiFi L3 crypto. |

---

## WiFi

| Issue | Where | Status | Notes |
|-------|-------|--------|-------|
| HCCAPX M3 never copied ANonce if M1 missed | `hccapx_serializer.c` | **Fixed** | Check `message_ap == 0` before assigning `message_ap = 3`. |
| HCCAPX init left stale handshake state | `hccapx_serializer_init` | **Fixed** | Full reset of buffer + SM counters. |
| Handshake PCAP download always empty | `attack_handshake.c` | **Fixed** | Wired to `pcap_serializer_get_size/buffer()`. |
| New attack could start while one was running | `main/attack.c` | **Fixed** | Reject if `attack_status.state == RUNNING`. |
| `attack_alloc_result_content` leaked prior buffer | `main/attack.c` | **Fixed** | Free old content before allocate. |
| Deauth timer held raw scan `ap_record` pointer | `attack_method.c` | **Fixed** | Copy into owned `deauth_targets[]`. |
| Deauth period ignored (always 100 ms) | `attack_method_broadcast` | **Fixed** | Uses `period_sec * 1e6` (min 100 ms). |
| Sniffer stop left RX callback installed | `sniffer.c` | **Fixed** | `esp_wifi_set_promiscuous_rx_cb(NULL)` on stop. |
| Disassoc detection unreachable | `attack_deauth_detector.c` | **Fixed** | Accept subtype `0xC0` or `0xA0`. |
| Probe path only on DATA sniffer events | `frame_analyzer.c` | **Fixed** | MGMT handler for `SEARCH_PROBE`. |
| PMKID IE walk off-by-one / unsafe | `frame_analyzer_parser.c` | **Fixed** | Bounds-checked walk; malloc checked. |
| Evil twin DNS answer could overflow `tx_buf` | `attack_eviltwin.c` | **Fixed** | Clamp QNAME parse + refuse if answer would overflow. |
| Beacon builder trusted unbounded `ssid_length` | `wsl_bypasser.c` | **Fixed** | Cap at 32 / buffer size. |
| `esp_timer_delete` from timeout callback | handshake / pmkid / dos / beacon | **Fixed** | Defer delete via orphan handle when called from CB. |
| Large AP scan / beacon spam tables in internal DRAM | `ap_scanner` / `attack_beacon_spam` | **Fixed** | Allocated with `heap_psram_*`. |
| Probe attack hijacks global promiscuous CB | `attack_probe.c` | **Open** | Replaces sniffer CB; concurrent handshake/PMKID sniffing breaks. Prefer routing via `SNIFFER_EVENTS`. |
| Handshake success = any N EAPOL frames | `attack_handshake.c` | **Open** | Duplicate/retransmit of one message can count as complete; prefer valid `hccapx_serializer_get()`. |
| Evil twin verify tears down AP mid-portal | `attack_eviltwin.c` | **Open** | STA verify path can drop captive-portal clients. |
| Promiscuous sniff on encrypted WiFi | sniffer design | **Open (by design)** | Cleartext L2/L3 only; no WPA/HTTPS decrypt. |

---

## Open follow-ups

### OTA
1. **Rogue broker MITM** — real MQTT listener on `rogue_port` plus traffic redirection (ARP/DNS) if true device MITM is required.
2. **Manual inject without session** — optionally connect WiFi+MQTT inside `ota_inject_message` / inject API when credentials are supplied.
3. **Encrypted capture** — document-only unless a MITM TLS proxy or PTK capture path is added.

### BLE
1. **CCCD discovery** — discover descriptors and match UUID `0x2902` instead of `val_handle + 1`.
2. **Encrypted BLE** — design limit without pairing/key material.

### WiFi
1. **Shared promiscuous path** — route probe (and detector) through `sniffer` / `SNIFFER_EVENTS` so modules do not overwrite each other’s RX CB.
2. **Handshake completion criteria** — require a valid HCCAPX message pair, not raw EAPOL frame count.
3. **Evil twin verify** — verify off-path (or after portal stop) so APSTA portal stays up.
4. **Encrypted capture** — same design limit as OTA/BLE cleartext-only sniff.

### ESP-NOW
1. **Encrypted ESP-NOW payloads** — monitor/capture stores opaque bodies when peers use PMK encryption; no key recovery path.
2. **Soft-AP disconnect during channel lock** — fixed-channel ESP-NOW pauses the management AP; dashboard clients must reconnect after stop.
