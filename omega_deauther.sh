#!/bin/bash

# Omega Solutions - ESP32 Deauther for ESP-IDF v4.4.7
# This script sets up v4.4.7 environment and provides easy commands

# Colors for better output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Fixed path for ESP-IDF v4.4.7
export IDF_PATH=/Users/vishnu/esp/esp-idf-v4.4.7

# Source v4.4.7 environment
echo -e "${CYAN}🔧 Setting up ESP-IDF v4.4.7 environment...${NC}"
source $IDF_PATH/export.sh 2>/dev/null

# Verify version
IDF_VERSION=$(idf.py --version 2>&1 | grep "ESP-IDF" | head -1)
echo -e "${GREEN}✓ $IDF_VERSION${NC}"

# Fix mbedtls CMake issue for v4.4.7
fix_cmake() {
    local CMAKE_FILE="$IDF_PATH/components/mbedtls/mbedtls/CMakeLists.txt"
    if [ -f "$CMAKE_FILE" ]; then
        if grep -q "cmake_minimum_required(VERSION 2.8.12)" "$CMAKE_FILE"; then
            echo -e "${YELLOW}🔧 Fixing mbedtls CMake for v4.4.7...${NC}"
            perl -pi -e 's/cmake_minimum_required\(VERSION 2\.8\.12\)/cmake_minimum_required(VERSION 3.5)/' "$CMAKE_FILE"
            echo -e "${GREEN}✓ CMake fix applied${NC}"
        fi
    fi
}

# Build the project for v4.4.7
build() {
    echo -e "${BLUE}🔨 Building Omega Deauther with ESP-IDF v4.4.7...${NC}"
    fix_cmake
    rm -rf build/
    export CMAKE_POLICY_VERSION_MINIMUM=3.5
    idf.py set-target esp32
    idf.py build
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Build successful!${NC}"
        echo -e "${CYAN}📦 Binary size: $(ls -lh build/testing-security.bin | awk '{print $5}')${NC}"
    else
        echo -e "${RED}✗ Build failed${NC}"
    fi
}

# Detect ESP32 serial port automatically
detect_port() {
    PORT=""
    # Try common ports on macOS
    for p in /dev/cu.usbserial-* /dev/cu.SLAB_USBtoUART /dev/cu.wchusbserial*; do
        if [ -e "$p" ]; then
            PORT="$p"
            break
        fi
    done
    
    if [ -z "$PORT" ]; then
        echo -e "${RED}❌ No ESP32 found! Check USB connection.${NC}"
        echo -e "${YELLOW}Available ports:${NC}"
        ls /dev/cu.* 2>/dev/null
        return 1
    fi
    echo "$PORT"
    return 0
}

# Flash the device
flash() {
    PORT=$(detect_port)
    if [ $? -ne 0 ]; then
        return 1
    fi
    
    echo -e "${BLUE}📡 Flashing to $PORT...${NC}"
    echo -e "${YELLOW}💡 Tip: Hold BOOT button if auto-detection fails${NC}"
    
    # Flash with v4.4.7 compatible settings
    idf.py -p $PORT -b 460800 flash
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✓ Flash successful!${NC}"
        echo -e "${CYAN}🔌 Device is ready at http://192.168.4.1${NC}"
    else
        echo -e "${YELLOW}🔄 Trying with lower baud rate...${NC}"
        idf.py -p $PORT -b 115200 flash
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✓ Flash successful!${NC}"
        else
            echo -e "${RED}✗ Flash failed${NC}"
        fi
    fi
}

# Monitor serial output
monitor() {
    PORT=$(detect_port)
    if [ $? -ne 0 ]; then
        return 1
    fi
    
    echo -e "${GREEN}📺 Monitoring $PORT...${NC}"
    echo -e "${YELLOW}Press Ctrl+] to exit monitor${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    idf.py -p $PORT monitor
}

# Clean build
clean() {
    echo -e "${YELLOW}🧹 Cleaning build files...${NC}"
    rm -rf build/ sdkconfig
    echo -e "${GREEN}✓ Clean complete${NC}"
}

# Full rebuild
rebuild() {
    clean
    build
}

# Build and flash in one go
build_flash() {
    build
    if [ $? -eq 0 ]; then
        flash
    fi
}

# Show device info
info() {
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${GREEN}🛡️  Omega Solutions - ESP32 Deauther${NC}"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}📌 ESP-IDF Version:${NC} v4.4.7"
    echo -e "${YELLOW}📌 Project Path:${NC} $PWD"
    
    PORT=$(detect_port 2>/dev/null)
    if [ $? -eq 0 ]; then
        echo -e "${YELLOW}📌 Serial Port:${NC} $PORT"
    else
        echo -e "${YELLOW}📌 Serial Port:${NC} Not connected"
    fi
    
    echo -e "${YELLOW}📌 Web Interface:${NC} http://192.168.4.1"
    echo -e "${YELLOW}📌 WiFi SSID:${NC} ESP32_Deauther"
    echo -e "${YELLOW}📌 WiFi Password:${NC} 12345678"
    echo -e "${CYAN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
}

# Show menu
menu() {
    clear
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║${GREEN}      🛡️  OMEGA SOLUTIONS - DEAUTHER v2.0  ${CYAN}║${NC}"
    echo -e "${CYAN}║${YELLOW}         ESP-IDF v4.4.7 | Security Device   ${CYAN}║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "${YELLOW}  📋 MAIN MENU${NC}"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -e "  ${CYAN}1${NC}) 🔨 Build Project"
    echo -e "  ${CYAN}2${NC}) 📡 Flash to ESP32"
    echo -e "  ${CYAN}3${NC}) 📺 Monitor Serial"
    echo -e "  ${CYAN}4${NC}) 🔄 Rebuild & Flash"
    echo -e "  ${CYAN}5${NC}) 🧹 Clean Build"
    echo -e "  ${CYAN}6${NC}) ℹ️  Device Info"
    echo -e "  ${CYAN}7${NC}) 🚪 Exit"
    echo -e "${GREEN}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"
    echo -n -e "${CYAN}➜ ${NC}Choose option: "
    read choice
    
    case $choice in
        1) build ;;
        2) flash ;;
        3) monitor ;;
        4) build_flash ;;
        5) clean ;;
        6) info ;;
        7) exit 0 ;;
        *) echo -e "${RED}Invalid option${NC}" ;;
    esac
    
    echo ""
    echo -e "${YELLOW}Press Enter to continue...${NC}"
    read
    menu
}

# Check if command line argument provided
if [ $# -eq 0 ]; then
    # Show interactive menu
    menu
else
    # Run command directly
    case $1 in
        build) build ;;
        flash) flash ;;
        monitor) monitor ;;
        clean) clean ;;
        rebuild) rebuild ;;
        build-flash) build_flash ;;
        info) info ;;
        fix) fix_cmake ;;
        *)
            echo -e "${CYAN}Omega Solutions - ESP32 Deauther (ESP-IDF v4.4.7)${NC}"
            echo ""
            echo "Usage: ./omega_deauther.sh [command]"
            echo ""
            echo "Commands:"
            echo "  build        - Build the project"
            echo "  flash        - Flash to ESP32"
            echo "  monitor      - Monitor serial output"
            echo "  clean        - Clean build files"
            echo "  rebuild      - Clean and rebuild"
            echo "  build-flash  - Build and flash"
            echo "  info         - Show device information"
            echo "  fix          - Fix CMake issue"
            echo ""
            echo "No command = Interactive menu"
            ;;
    esac
fi
