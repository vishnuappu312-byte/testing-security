# Project overview — Omega Solutions

Full overview of the **testing-security** firmware: what it is, how it boots, features by domain, memory/PSRAM design, APIs, and limits.

Related docs: [README.md](README.md) · [KNOWN_ISSUES.md](KNOWN_ISSUES.md) · [MEMORY.md](MEMORY.md)

---

## 1. What this project is

**Omega Solutions** is an ESP-IDF firmware for **ESP32-S3** that turns the device into a local wireless security lab appliance:

- Starts a **management soft-AP**
- Serves a **cookie-auth web dashboard** at `http://192.168.4.1`
- Exposes HTTP APIs for **WiFi**, **BLE (NimBLE)**, **OTA intercept**, and **mesh** tooling

Default dashboard login: `omega` / `solutions123` (change for shared labs).

**Authorized / educational use only.** See the legal disclaimer in `README.md`.

| Item | Value |
|------|--------|
| Target SoC | ESP32-S3 (`CONFIG_IDF_TARGET=esp32s3`) |
| Framework | ESP-IDF v4.4.x |
| Radio | WiFi + BLE (NimBLE) |
| UI | Embedded HTML/JS in `web_ui.h` + `webserver.c` |
| License | MIT |

---

## 2. Boot flow (`main/main.c`)

```text
NVS init
  → heap_psram_init()          (log internal vs PSRAM free)
  → default event loop
  → wifictl_mgmt_ap_start()    (management AP)
  → scanner_init()
  → WiFi attack inits
  → BLE attack inits
  → OTA module inits (ota_common first)
  → Mesh module inits
  → start_web_server()
  → boot summary log
```

Only one major attack path should run at a time where radios conflict (promiscuous sniff vs STA connect vs BLE GAP). The central WiFi attack wrapper rejects a new request if `attack_status.state == RUNNING`.

---

## 3. Architecture

```text
┌─────────────────────────────────────────────────────────┐
│  Browser  →  soft-AP 192.168.4.1  →  HTTP server         │
│              web_ui.h + webserver.c (JSON APIs)          │
└─────────────┬───────────────┬───────────────┬───────────┘
              │               │               │
     ┌────────▼──────┐ ┌──────▼──────┐ ┌──────▼──────┐
     │  wifi/        │ │  bt/        │ │  ota/       │
     │  attacks +    │ │  NimBLE     │ │  modular    │
     │  sniffer +    │ │  modules    │ │  runners    │
     │  serializers  │ │             │ │  + common   │
     └───────────────┘ └─────────────┘ └─────────────┘
              │
     ┌────────▼──────┐     ┌──────────────────┐
     │  mesh/        │     │  utils/          │
     │  scan/spoof/  │     │  heap_psram      │
     │  MITM/DoS/…   │     │  helpers         │
     └───────────────┘     └──────────────────┘
```

### Directory map

| Path | Role |
|------|------|
| `main/main.c` | `app_main`, module wiring |
| `main/webserver.c` / `web_ui.h` | Dashboard + all `/api/*` routes |
| `main/main/attack.c` | Central WiFi attack request / timeout / status |
| `main/wifi/` | Controller, scanner, sniffer, frame analyzer, WiFi attacks |
| `main/bt/` | Shared `ble_common` + BLE attack modules |
| `main/ota/` | Shared `ota_common` + OTA mode modules |
| `main/mesh/` | Mesh scan + attack modules |
| `main/utils/` | PSRAM heap helpers, management helper, password verifier |
| `sdkconfig.defaults` | S3 PSRAM + WiFi/NimBLE memory defaults |

---

## 4. Features by domain

### 4.1 Web / control plane

- Login / logout / dashboard pages
- Cookie session auth
- Management AP get/set/reset APIs
- Aggregate status and **stop all**
- Per-module start / stop / status JSON endpoints

### 4.2 WiFi

| Feature | Description |
|---------|-------------|
| AP scan | Nearby APs (up to `CONFIG_SCAN_MAX_AP`, default 64) stored in PSRAM |
| Deauth | Timed deauth via raw 802.11 TX (`wsl_bypasser`) |
| Beacon spam | Up to 100 fake APs; modes: common / garbage / rick-roll / security |
| DoS | Broadcast deauth, rogue AP, combine, super-clone |
| Handshake | Promiscuous EAPOL capture → PCAP + HCCAPX |
| PMKID | Capture PMKID, hashcat-oriented hash string |
| Probe sniffer | Ghost APs from probe requests |
| Evil twin | Captive portal + password list APIs |
| Deauth detector | Tracks deauth **and** disassoc bursts |
| Sniffer | Promiscuous RX → `SNIFFER_EVENTS` (DATA / MGMT / CTRL) |
| Frame analyzer | EAPOL / PMKID / probe event posts for attacks |

Raw TX relies on `wsl_bypasser` + linker `-Wl,-zmuldefs` to override the IDF sanity check.

### 4.3 BLE (NimBLE)

Shared stack: `ble_common_init()` (idempotent sync).

| Feature | Description |
|---------|-------------|
| BLE spam | Rotating ADV (Apple / Samsung / Fast Pair style profiles) |
| BLE scan | Device discovery (results buffered in PSRAM) |
| Spoof / clone | Name rotation or clone from ADV profile |
| Connect flood | Repeated connection pressure |
| L2CAP flood | Connect + L2CAP signaling burst + terminate |
| GATT probe | Discover services/chars; optional read/write/subscribe |
| BLE deauth | Multi-phase disconnect pressure (+ optional WiFi RF jam phase) |
| Passkey | Pairing / passkey observation path |
| Takeover | Connect, discover GATT, notify enable, read/write, notif log |

**Constraint:** NimBLE allows essentially one GAP procedure at a time — stop other BLE modules before starting a new one.

### 4.4 OTA (modular)

All modes share `ota_common` (claim mutex, WiFi/MQTT helpers, capture stores, PSRAM JSON/firmware buffers).

| Module | Role |
|--------|------|
| `ota_mqtt_sniff` | Mode 0: MQTT + optional promiscuous DNS/HTTP; Mode 1: MQTT subscribe only |
| `ota_inject` | Publish spoofed OTA MQTT messages (needs live MQTT session) |
| `ota_fetch` | HTTP firmware download (optional STA creds on download API) |
| `ota_poll_sniff` | DNS/HTTP OTA URL discovery |
| `ota_provision` | Cleartext provision credential capture |
| `ota_github` | GitHub URL parse / repo / upload helpers |
| `ota_rogue_broker` | Client to real broker + optional republish (**not** a listening MITM broker yet) |
| `ota_fw_analyze` | Secret / string scan of downloaded firmware |

Mutual exclusion: `ota_common_try_claim()` / `ota_common_release()` so only one OTA runner owns the radio/MQTT path at a time.

### 4.5 Mesh

| Module | Role |
|--------|------|
| Node scanner | Nearby AP grouping + soft-AP subnet / host probe |
| Node spoof | MAC clone + traffic capture |
| Packet inject | 802.11 frame TX templates |
| MITM | ARP poison + capture |
| DoS | Child/parent deauth, mesh action, auth/probe/beacon style methods |
| Eavesdrop | Promiscuous mesh capture |
| Replay | Live / cycle frame replay |
| Wormhole | Capture + tunnel / re-TX |
| L2 deauth | Mesh link teardown |
| Route poison | Path disruption modes |

---

## 5. Memory & PSRAM

### 5.1 Why PSRAM

The dashboard, OTA JSON, firmware download (up to **512 KB**), AP scan table, beacon pool, and BLE GATT/scan stores do not fit comfortably in internal DRAM alone. The project targets **ESP32-S3 with octal PSRAM** (e.g. WROOM-1 N8R8).

### 5.2 Allocator (`utils/heap_psram.*`)

- Prefer `MALLOC_CAP_SPIRAM`
- Fall back to internal DRAM if PSRAM alloc fails
- `heap_psram_init()` logs free internal / PSRAM / total at boot

### 5.3 `sdkconfig.defaults` highlights

| Setting | Purpose |
|---------|---------|
| `CONFIG_SPIRAM=y`, octal, 80 MHz | Enable PSRAM |
| `CONFIG_SPIRAM_USE_MALLOC=y` | Allow SPIRAM in general malloc path |
| `CONFIG_SPIRAM_MALLOC_ALWAYSINTERNAL=4096` | Keep small allocs internal |
| `CONFIG_SPIRAM_MALLOC_RESERVE_INTERNAL=49152` | Reserve internal DRAM |
| `CONFIG_BT_NIMBLE_MEM_ALLOC_MODE_EXTERNAL=y` | NimBLE host buffers in PSRAM |
| Reduced WiFi static RX/TX counts | Leave room for concurrent modules |
| `CONFIG_ESP_MAIN_TASK_STACK_SIZE=8192` | Larger main stack |

### 5.4 What is allocated in PSRAM (examples)

| Consumer | Approx content |
|----------|----------------|
| OTA common | JSON slots (1–16 KB), HTTP recv 4 KB, GitHub API 4 KB, firmware buffer up to 512 KB |
| AP scanner | Full `wifictl_ap_records_t` (~64 × `wifi_ap_record_t`) |
| Beacon spam | Pool of up to 100 fake APs |
| BLE spam scan | Up to 50 scan entries |
| BLE takeover | Services, characteristics, notif ring, JSON buffers (~6 KB + 4 KB) |
| BLE GATT probe | Per-cycle service/char discovery tables |

### 5.5 OTA capture limits (by design, small fixed rings)

| Cap | Value |
|-----|-------|
| Captured MQTT msgs | 4 |
| Captured URLs | 4 |
| DNS / HTTP sniff entries | 4 each |
| Firmware download max | 512 KB |
| Prov creds / FW secrets / MITM msgs | 4 each |

---

## 6. HTTP API surface (high level)

Registered in `webserver.c` (non-exhaustive):

**Core:** `/`, `/login`, `/dashboard`, `/logout`, `/api/scan`, `/api/status`, `/api/stop`, `/api/stop/all`, `/api/mgmt-ap`

**WiFi:** `/api/attack`, `/api/beacon/*`, `/api/dos/*`, `/api/handshake/*` (+ `/pcap`), `/api/pmkid/*`, `/api/probe/*`, `/api/eviltwin/*`, `/api/deauth-detect/*`

**BLE:** `/api/ble/scan`, `/api/ble/status`, `/api/ble/spam|spoof|connect|l2cap|gatt|deauth|passkey|takeover/*`

**Mesh:** `/api/mesh/scan`, `/api/mesh/sniff`, `/api/mesh/remote-scan`, `/api/spoof/*`, `/api/mesh/inject|mitm|dos|eavesdrop|replay|wormhole|l2-deauth|route-poison/*` (as registered)

**OTA:** `/api/ota/...` routes for start/stop/status, download, GitHub, inject, provision, analyze, etc.

All JSON responses are intended for the embedded dashboard; many modules also expose `*_get_status_json()` helpers.

---

## 7. Runtime constraints & design limits

| Topic | Behavior |
|-------|----------|
| Encrypted WiFi / HTTPS sniff | Cleartext L2/L3 only — no WPA/TLS decrypt |
| OTA inject | Needs an already-connected MQTT session |
| OTA “rogue broker” | Client to real broker; does not listen on `rogue_port` |
| BLE CCCD | Often assumed `val_handle + 1` (may fail with odd descriptor layouts) |
| Probe vs sniffer | Probe can install its own promiscuous CB (can conflict with handshake/PMKID sniff) |
| Concurrent WiFi attacks | Central wrapper blocks overlapping `RUNNING` state |
| Concurrent BLE | Avoid overlapping GAP users |

See **[KNOWN_ISSUES.md](KNOWN_ISSUES.md)** for fixed vs still-open items.

---

## 8. Build & flash (short)

```bash
idf.py set-target esp32s3
idf.py build
idf.py -p PORT flash monitor
```

Root `CMakeLists.txt` adds `-Wl,-zmuldefs` for raw 802.11 TX override.

---

## 9. Quick inventory

| Area | Module count (approx) | Notes |
|------|----------------------:|-------|
| WiFi attack / support | ~15 source files under `wifi/` + wrappers | Sniffer + serializers included |
| BLE | 10 modules + `ble_common` | NimBLE |
| OTA | 8 modes + `ota_common` | Claim-based runners |
| Mesh | 10+ modules | Scan + attacks |
| Web | 1 large server + UI header | Dozens of `/api` routes |
| Utils | PSRAM + helpers | Boot-critical for memory |

---

## 10. Suggested reading order

1. This file (`overview.md`) — map of the system  
2. `README.md` — setup / flash / access  
3. `MEMORY.md` — flash / DRAM / IRAM / PSRAM headroom  
4. `main/main.c` — what initializes at boot  
5. `main/webserver.c` — API entry points  
6. Domain folders (`wifi/`, `bt/`, `ota/`, `mesh/`) — implementation  
7. `KNOWN_ISSUES.md` — known gaps before relying on a feature  

---

*Generated from the current tree (2026-07-16). Update this file when modules or memory policy change.*
