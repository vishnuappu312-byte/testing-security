# Omega Solutions — ESP32-S3 Security Testing Suite

[![Platform](https://img.shields.io/badge/platform-ESP32--S3-red)](https://www.espressif.com/en/products/socs/esp32-s3)
[![ESP-IDF](https://img.shields.io/badge/ESP--IDF-v4.4.x-blue)](https://docs.espressif.com/projects/esp-idf/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

Professional wireless security testing firmware for **ESP32-S3** (PSRAM recommended): WiFi, BLE, OTA intercept, and mesh tooling behind a local web dashboard.

---

## Important legal disclaimer

**This tool is for educational and authorized security testing only.**

- Only use on networks and devices you **own** or have **written permission** to test
- Unauthorized use may violate local and national law
- The authors assume **no liability** for misuse or damage
- Always obtain proper authorization before any assessment

By using this software, you agree that you are solely responsible for your actions.

---

## Features

### Web dashboard
- Cookie-based login (default: `omega` / `solutions123` — change for any shared/lab use)
- WiFi scan, attack controls, live status/logs
- Serves on the management soft-AP at `http://192.168.4.1`

### WiFi
| Module | Description |
|--------|-------------|
| Deauth | Timed deauthentication |
| Beacon spam | Common / garbage / rick-roll / troll pools |
| DoS | Broadcast, rogue AP, combine, super-clone |
| Handshake | EAPOL capture → PCAP / HCCAPX |
| PMKID | PMKID capture (hashcat-oriented output) |
| Probe sniffer | Ghost APs from probe requests |
| Evil twin | Captive portal credential capture |
| Deauth detector | Incoming deauth/disassoc monitoring |

### BLE (NimBLE)
| Module | Description |
|--------|-------------|
| BLE spam | Rotating fake advertising (Apple / Samsung / Fast Pair style) |
| BLE scan | Discover nearby devices |
| BLE spoof / clone | Name rotation and ADV clone |
| Connect / L2CAP flood | Connection and signaling pressure |
| GATT probe | Enumerate + optional read/write/subscribe |
| BLE deauth | Multi-phase disconnect pressure |
| Passkey capture | Pairing/passkey observation path |
| Takeover | Connect, discover GATT, notify/read/write |

### OTA (modular)
Shared helpers in `ota_common`; modes:

| Module | Description |
|--------|-------------|
| MQTT sniff / client | Passiveive capture or broker subscribe (+ optional DNS/HTTP sniff) |
| Inject | Spoof OTA MQTT publishes (needs active MQTT session) |
| Fetch | Download firmware over HTTP (optional WiFi creds on download API) |
| Poll sniff | DNS/HTTP OTA URL discovery |
| Provision | Credential capture from cleartext provision traffic |
| GitHub | Repo access / firmware upload helpers |
| Rogue broker | Client-side subscribe + optional republish (not a listening MITM broker yet) |
| Firmware analyze | Secret / string scan of downloaded firmware |

### Mesh
| Module | Description |
|--------|-------------|
| Node scanner | Nearby AP + soft-AP subnet discovery |
| Node spoof | MAC clone + traffic capture |
| Packet inject | 802.11 TX templates |
| MITM | ARP poison + capture |
| DoS | Child/parent deauth, mesh action, auth/probe/beacon |
| Eavesdrop / replay / wormhole | Promiscuous capture, replay, tunnel/re-TX |
| L2 deauth / route poison | Link teardown and path disruption |

### Memory
- Large buffers (OTA JSON, AP scan table, beacon pool, BLE GATT/scan stores) prefer **PSRAM** via `heap_psram_*`
- See `sdkconfig.defaults` for ESP32-S3 octal PSRAM + NimBLE external alloc defaults
- Flash / DRAM / IRAM / remaining storage: **[MEMORY.md](MEMORY.md)**

Known limitations and remaining work: **[KNOWN_ISSUES.md](KNOWN_ISSUES.md)**.

---

## Hardware

| Item | Recommendation |
|------|----------------|
| SoC | **ESP32-S3** (project target in `sdkconfig`) |
| Flash | ≥ 4 MB |
| PSRAM | Strongly recommended (e.g. WROOM-1 N8R8 / octal PSRAM) |
| Power | USB 5V |

Classic ESP32 (no S3 / no PSRAM) is not the supported target for this tree.

---

## Software

- **ESP-IDF** (project developed against the **v4.4.x** line)
- Python 3.8+, CMake 3.5+, Ninja
- `idf.py` on `PATH` after exporting IDF

Example (adjust paths for your machine):

```bash
git clone -b v4.4.7 --recursive https://github.com/espressif/esp-idf.git
cd esp-idf && ./install.sh && . ./export.sh
```

---

## Build & flash

```bash
cd testing-security
idf.py set-target esp32s3   # once
idf.py build
idf.py -p /dev/ttyUSB0 flash monitor   # macOS often /dev/cu.usbserial-*
```

Useful:

```bash
idf.py menuconfig
idf.py fullclean
idf.py erase-flash
```

Link note: `CMakeLists.txt` appends `-Wl,-zmuldefs` so `wsl_bypasser` can override the 802.11 TX sanity check for raw frames.

---

## Web interface

1. Flash and boot the device  
2. Join the management AP (SSID printed in boot log)  
3. Open **http://192.168.4.1**  
4. Login: **omega** / **solutions123**

Boot log also lists enabled WiFi / BLE / OTA / mesh modules.

---

## Project structure

```text
testing-security/
├── CMakeLists.txt
├── sdkconfig / sdkconfig.defaults   # ESP32-S3 + PSRAM defaults
├── KNOWN_ISSUES.md
├── MEMORY.md
├── LICENSE
├── README.md
└── main/
    ├── main.c                 # app_main: NVS, AP, module inits, web server
    ├── webserver.c / web_ui.h # HTTP API + dashboard
    ├── wifi/                  # WiFi attacks, sniffer, serializers, controller
    ├── bt/                    # NimBLE attacks + ble_common
    ├── ota/                   # Modular OTA intercept / fetch / analyze
    ├── mesh/                  # Mesh scanner + attack modules
    ├── utils/                 # heap_psram, helpers, verifiers
    └── main/                  # Central attack wrapper (attack.c/h)
```

---

## Troubleshooting

| Symptom | What to check |
|---------|----------------|
| Build fails on target | `idf.py set-target esp32s3`; use IDF 4.4.x |
| Low heap / crashes under web+BLE+OTA | Board has PSRAM; `CONFIG_SPIRAM=y` from `sdkconfig.defaults` |
| Raw deauth/beacon TX fails | Confirm `-zmuldefs` link option and `wsl_bypasser` override |
| BLE connect/scan flaky | Only one GAP procedure at a time; stop other BLE modules |
| OTA inject does nothing | Need an active MQTT session (see KNOWN_ISSUES) |
| Encrypted WiFi/HTTPS “empty” sniff | By design — cleartext only unless you add MITM/TLS tooling |

Serial:

```bash
idf.py -p PORT monitor
```

---

## Credits

Built on ESP-IDF, NimBLE, and community WiFi/BLE research tooling. Project branding: **Omega Solutions**.

---

## License

MIT — see [LICENSE](LICENSE).
