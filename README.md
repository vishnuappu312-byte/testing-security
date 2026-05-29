# Omega Solutions - ESP32 Advanced Security Testing Suite

[![ESP-IDF](https://img.shields.io/badge/ESP--IDF-v4.4.7-blue)](https://docs.espressif.com/projects/esp-idf/en/v4.4.7/)
[![Platform](https://img.shields.io/badge/platform-ESP32-red)](https://www.espressif.com/en/products/socs/esp32)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

<div align="center">
  <img src="https://img.shields.io/badge/Omega-Solutions-orange?style=for-the-badge&logo=wifi&logoColor=white">
  <br>
  <strong>Professional Security Testing Platform for ESP32</strong>
</div>

---

## ⚠️ IMPORTANT LEGAL DISCLAIMER

> **THIS TOOL IS FOR EDUCATIONAL AND AUTHORIZED SECURITY TESTING ONLY!**
>
> - Only use on networks you OWN or have WRITTEN PERMISSION to test
> - Unauthorized use of this tool may violate local, state, and federal laws
> - The author assumes NO liability for misuse or damage caused by this tool
> - Always obtain proper authorization before conducting any security assessment
>
> **By using this software, you agree that you are solely responsible for your actions.**

---

## 📋 Table of Contents

- [Features](#-features)
- [Hardware Requirements](#-hardware-requirements)
- [Software Requirements](#-software-requirements)
- [Installation & Setup](#-installation--setup)
- [Web Interface Access](#-web-interface-access)
- [Available Attacks](#-available-attacks)
- [Project Structure](#-project-structure)
- [Building & Flashing](#-building--flashing)
- [Troubleshooting](#-troubleshooting)
- [Credits](#-credits)
- [License](#-license)

---

## 🚀 Features

### 🔐 Authentication
- **Secure Web Login** - Username/password protected interface
- **Session Management** - Cookie-based authentication
- **Default Credentials**:
  - Username: `omega`
  - Password: `solutions123`
  - *Change these in production!*

### 📡 Network Scanner
- Scan nearby WiFi networks (up to 30 APs)
- Display SSID, BSSID, Channel, RSSI, Security type
- Select target networks with one click

### ⚡ Attack Modules

| Attack | Description | Status |
|--------|-------------|--------|
| **Deauth Attack** | Deauthentication frames to disconnect clients | ✅ Active |
| **Beacon Spam** | 4 modes: Common, Garbage, Rick Roll, Security | ✅ Active |
| **DoS Attack** | Broadcast, Rogue AP, Combine All, Super Clone | ✅ Active |
| **Handshake Capture** | EAPOL frame capture for WPA/WPA2 | ✅ Active |
| **PMKID Attack** | PMKID capture for WPA3 | ✅ Active |
| **Probe Sniffer** | Ghost AP creation from probe requests | ✅ Active |
| **Evil Twin** | Captive portal password capture | ✅ Active |

### 🎨 UI Features
- **Dark/Light Mode** - Automatic theme switching
- **Real-time Log Terminal** - Live attack monitoring
- **Attack Timer** - Custom duration (1-999 minutes)
- **Threat Detection** - Monitors incoming deauth attacks
- **Responsive Design** - Works on mobile and desktop

---

## 🛠️ Hardware Requirements

| Component | Specification |
|-----------|---------------|
| **Microcontroller** | ESP32 (any variant) |
| **Flash Size** | Minimum 4MB |
| **USB Cable** | Data-capable cable |
| **Power** | USB 5V or battery |

### Recommended ESP32 Boards
- ESP32-WROOM-32
- ESP32-DevKitC
- NodeMCU-32S
- Lolin32

---

## 💻 Software Requirements

### Development Environment
- **ESP-IDF v4.4.7** (Required - specific version!)
- Python 3.11+
- CMake 3.5+
- Ninja build system

### Install ESP-IDF v4.4.7 at Your Location

```bash
# Navigate to your ESP directory
cd /Users/vishnu/esp

# Clone ESP-IDF v4.4.7
git clone -b v4.4.7 --recursive https://github.com/espressif/esp-idf.git esp-idf-v4.4.7

# Install tools
cd esp-idf-v4.4.7
./install.sh

# Set up environment (add this to your ~/.zshrc for permanent use)
echo 'export IDF_PATH=/Users/vishnu/esp/esp-idf-v4.4.7' >> ~/.zshrc
echo 'source $IDF_PATH/export.sh' >> ~/.zshrc

# Or source manually each time
source /Users/vishnu/esp/esp-idf-v4.4.7/export.sh
