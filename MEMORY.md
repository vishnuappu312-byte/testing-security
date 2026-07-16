# Memory & storage usage

Snapshot from the last local build of **testing-security** (ESP32-S3, 8 MB flash).  
Rebuild after large code changes and re-check with `idf.py size` / boot logs for live heap.

Related: [overview.md](overview.md) · [README.md](README.md) · [partitions.csv](partitions.csv) · [sdkconfig.defaults](sdkconfig.defaults)

---

## Summary

| Resource | Used / reserved | Remaining / notes |
|----------|-----------------|-------------------|
| Flash chip | 8 MB configured | ~3.94 MB not assigned in partition table |
| App (`factory` 3 MB) | ~1.54 MB image | **~1.46 MB free** (~49% of factory left) |
| SPIFFS | 1 MB partition | Mostly empty until files are written |
| Static DRAM (`.data` + `.bss`) | ~152.5 KiB | Runtime heap = leftover internal SRAM |
| Static IRAM | ~92 KiB | Vectors + hot code |
| PSRAM (typical N8R8 = 8 MB) | Runtime only | OTA / scan / BLE large buffers; see boot log |

---

## Flash layout

Configured: `CONFIG_ESPTOOLPY_FLASHSIZE=8MB`  
Custom table: `partitions.csv`

| Name | Type | Offset | Size | Role |
|------|------|--------|------|------|
| `nvs` | data/nvs | `0x9000` | 24 KB | NVS keys |
| `phy_init` | data/phy | `0xf000` | 4 KB | PHY calibration |
| `factory` | app/factory | `0x10000` | **3 MB** | Main firmware |
| `spiffs` | data/spiffs | `0x310000` | **1 MB** | Optional FS |

Partition layout ends at about **`0x410000` (~4.06 MB)**.  
On an 8 MB chip that leaves **~3.94 MB** flash **unallocated** (available if you extend partitions later).

### Last measured app image

| Artifact | Size |
|----------|------|
| `build/testing-security.bin` | **1,613,136 bytes (~1,575 KiB / ~1.54 MB)** |
| `build/bootloader/bootloader.bin` | ~21 KB |
| `build/partition_table/partition-table.bin` | 3 KB |

**Factory free space** = `3 MB − app.bin` ≈ **1,532,592 bytes (~1,497 KiB / ~1.46 MB)**  
→ about **48.7%** of the factory slot still free.

---

## Internal RAM (static ELF sections)

From `xtensa-esp32s3-elf-size -A` on `build/testing-security.elf`:

| Section | Size | Notes |
|---------|------|-------|
| `.dram0.data` | ~19 KiB | Initialized data |
| `.dram0.bss` | ~134 KiB | Zeroed BSS |
| **DRAM static total** | **~152.5 KiB** | `.data` + `.bss` |
| `.iram0.vectors` + `.iram0.text` | **~92 KiB** | IRAM |
| `.flash.text` | ~941 KiB | Code in flash |
| `.flash.rodata` (+ appdesc) | ~523 KiB | Const data in flash |

Runtime **internal heap** is whatever remains after static DRAM, task stacks, WiFi/BT DMA buffers, etc. It is **not** the same as flash free space.

At boot, `heap_psram_init()` logs:

```text
Heap at boot — internal: … B, PSRAM: … B, total: … B
```

Use that (or `heap_caps_get_free_size`) for **live** free DRAM / PSRAM.

---

## PSRAM (external)

- Enabled in `sdkconfig.defaults` (octal SPIRAM, 80 MHz, NimBLE external alloc).
- Typical board: **ESP32-S3 with 8 MB PSRAM** (e.g. WROOM-1 N8R8).
- Not part of the flash image; size/free only exist at runtime.

### Large consumers (prefer PSRAM via `heap_psram_*`)

| Consumer | Approx content |
|----------|----------------|
| OTA common | JSON scratch (1–16 KB slots), HTTP 4 KB, GitHub API 4 KB, firmware buffer **up to 512 KB** |
| AP scanner | Full scan table (`CONFIG_SCAN_MAX_AP`, default 64 records) |
| Beacon spam | Pool up to 100 fake APs |
| BLE spam scan | Up to 50 scan entries |
| BLE takeover | Services / chars / notif log + JSON buffers |
| BLE GATT probe | Discovery tables |

If PSRAM is missing, allocators fall back to internal DRAM (higher risk of OOM under web + BLE + OTA).

---

## How to refresh these numbers

```bash
cd testing-security
idf.py build

# Image / DRAM / IRAM breakdown (needs IDF Python env):
idf.py size
idf.py size-components   # optional

# Or toolchain:
xtensa-esp32s3-elf-size -A build/testing-security.elf
```

On device after boot, check serial for `heap_psram` free internal / PSRAM lines.

---

## Headroom guidance

| Goal | Current headroom |
|------|------------------|
| Grow firmware without changing partitions | **~1.46 MB** in `factory` |
| Store files on device | **~1 MB** SPIFFS |
| Add another app / OTA app slot / bigger SPIFFS | Use the **~3.9 MB** unallocated flash (edit `partitions.csv`) |
| Grow large runtime buffers | Prefer **PSRAM**, keep internal DRAM for stacks/DMA |

---

*Last measured against local `build/` app binary ~1.54 MB. Update this file after significant feature or partition changes.*
