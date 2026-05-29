#!/bin/bash

cd /Users/vishnu/Desktop/personalcodes/vishnutr/testing-security

# Source environment
export IDF_PATH=/Users/vishnu/esp/esp-idf-v4.4.7
source $IDF_PATH/export.sh

echo "========================================"
echo "Flashing Omega Solutions ESP32"
echo "========================================"
echo ""
echo "1. Hold BOOT button"
echo "2. Press RESET button"
echo "3. Release BOOT button"
echo ""
read -p "Press ENTER to flash..."

idf.py -p /dev/cu.usbserial-0001 -b 115200 flash

if [ $? -eq 0 ]; then
    echo ""
    echo "✅ Flash successful!"
    echo ""
    read -p "Press ENTER to start monitor..."
    idf.py -p /dev/cu.usbserial-0001 monitor
else
    echo "❌ Flash failed. Try again with lower baud rate."
    read -p "Press ENTER to try with 9600 baud..."
    idf.py -p /dev/cu.usbserial-0001 -b 9600 flash
fi
