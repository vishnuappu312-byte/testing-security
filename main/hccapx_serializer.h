#ifndef HCCAPX_SERIALIZER_H
#define HCCAPX_SERIALIZER_H

#include <stdint.h>

typedef struct {
    uint8_t data[256];
} data_frame_t;

void hccapx_serializer_init(const uint8_t *ssid, uint8_t ssid_len);
void hccapx_serializer_add_frame(data_frame_t *frame);

#endif