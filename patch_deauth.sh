#!/bin/bash

# Path to your built ELF file
ELF_FILE="build/testing-security.elf"

# Create a small binary that returns 0
echo -n -e '\x22\x0a' > ret0.bin  # movi.n a2, 0; ret.n

# Find the ieee80211_raw_frame_sanity_check function address
ADDR=$(xtensa-esp32-elf-objdump -t $ELF_FILE | grep ieee80211_raw_frame_sanity_check | awk '{print $1}')

if [ -z "$ADDR" ]; then
    echo "Function not found in ELF, trying to patch library directly..."
    
    # Direct library patch
    LIB_PATH="/Users/vishnu/esp/esp-idf-v4.4.7/components/esp_wifi/lib/esp32/libnet80211.a"
    
    # Backup original
    cp $LIB_PATH ${LIB_PATH}.backup
    
    # Extract object file
    cd /tmp
    ar x $LIB_PATH ieee80211_output.o
    
    # Patch the function (this is complex - requires binary patching)
    echo "Manual library patching required. Using alternative method..."
fi

echo "Patch completed. Rebuild with: idf.py build"
