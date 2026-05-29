#ifndef PCAP_SERIALIZER_H
#define PCAP_SERIALIZER_H

#include <stdint.h>
#include <stddef.h>
void pcap_serializer_init(void);
void pcap_serializer_append_frame(const uint8_t *frame, size_t len, uint32_t timestamp);

#endif