cmake_minimum_required(VERSION 3.5)
include($ENV{IDF_PATH}/tools/cmake/project.cmake)

# Allow ieee80211_raw_frame_sanity_check override in wsl_bypasser.c.
# Must be set before project(); ESP-IDF applies LINK_OPTIONS during the final elf link.
idf_build_set_property(LINK_OPTIONS "-Wl,-zmuldefs" APPEND)

project(testing-security)