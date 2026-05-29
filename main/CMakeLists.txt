idf_component_register(SRCS 
    "main.c"
    "web_server.c"
    "wifi_scanner.c"
    "attack_deauth.c"
    "attack_deauth_detector.c"
    "attack_beacon_spam.c"
    "wsl_bypasser.c"
    "attack_dos.c"
    "attack_handshake.c"
    "attack_pmkid.c"
    "attack_probe.c"
    "attack_eviltwin.c"
    "attack_method.c"
    "attack.c"
    "wifi_controller.c"
    "frame_analyzer.c"
    "pcap_serializer.c"
    "hccapx_serializer.c"
    INCLUDE_DIRS "."
)

set(COMPONENT_REQUIRES cjson esp_timer)