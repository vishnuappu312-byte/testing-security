/*
 * heap_psram.h — allocate large buffers from ESP32-S3 PSRAM when available.
 */

#ifndef HEAP_PSRAM_H
#define HEAP_PSRAM_H

#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>

void  heap_psram_init(void);
bool  heap_psram_available(void);
size_t heap_psram_free_bytes(void);
size_t heap_internal_free_bytes(void);

void *heap_psram_malloc(size_t size);
void *heap_psram_calloc(size_t count, size_t size);
void  heap_psram_free(void *ptr);

#endif /* HEAP_PSRAM_H */
