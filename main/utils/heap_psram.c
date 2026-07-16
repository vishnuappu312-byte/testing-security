#include "heap_psram.h"

#include "esp_heap_caps.h"
#include "esp_log.h"
#include <stdlib.h>
#include <string.h>

static const char *TAG = "heap_psram";

void heap_psram_init(void)
{
    size_t internal = heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    size_t spiram   = heap_caps_get_free_size(MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    size_t total    = heap_caps_get_free_size(MALLOC_CAP_8BIT);

    ESP_LOGI(TAG, "Heap at boot — internal: %u B, PSRAM: %u B, total: %u B",
             (unsigned)internal, (unsigned)spiram, (unsigned)total);

#if CONFIG_ESP32S3_SPIRAM_SUPPORT
    if (spiram == 0) {
        ESP_LOGW(TAG, "PSRAM enabled in sdkconfig but no SPIRAM heap detected");
    }
#else
    ESP_LOGW(TAG, "PSRAM not enabled — large buffers use internal DRAM only");
#endif
}

bool heap_psram_available(void)
{
    return heap_caps_get_free_size(MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT) > 0;
}

size_t heap_psram_free_bytes(void)
{
    return heap_caps_get_free_size(MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
}

size_t heap_internal_free_bytes(void)
{
    return heap_caps_get_free_size(MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
}

void *heap_psram_malloc(size_t size)
{
    if (size == 0) {
        return NULL;
    }

    void *ptr = heap_caps_malloc(size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (ptr == NULL) {
        ptr = heap_caps_malloc(size, MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
    }
    if (ptr == NULL) {
        ESP_LOGE(TAG, "alloc %u bytes failed (internal free: %u, PSRAM free: %u)",
                 (unsigned)size,
                 (unsigned)heap_internal_free_bytes(),
                 (unsigned)heap_psram_free_bytes());
    }
    return ptr;
}

void *heap_psram_calloc(size_t count, size_t size)
{
    if (count == 0 || size == 0) {
        return NULL;
    }

    size_t total = count * size;
    void *ptr = heap_psram_malloc(total);
    if (ptr != NULL) {
        memset(ptr, 0, total);
    }
    return ptr;
}

void heap_psram_free(void *ptr)
{
    if (ptr != NULL) {
        heap_caps_free(ptr);
    }
}
