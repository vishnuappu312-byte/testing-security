#!/bin/bash

export IDF_PATH=/Users/vishnu/esp/esp-idf-v4.4.7
source $IDF_PATH/export.sh

cd /Users/vishnu/Desktop/personalcodes/vishnutr/testing-security

echo "========================================="
echo "Ready to flash ESP32"
echo "========================================="
echo ""
echo "1. Press and HOLD the BOOT button"
echo "2. Press and RELEASE the RESET button"
echo "3. RELEASE the BOOT button"
echo ""
read -p "Press ENTER to flash..."

idf.py -p /dev/cu.usbserial-0001 -b 115200 flash

echo ""
echo "Flash complete! Press RESET to run"
