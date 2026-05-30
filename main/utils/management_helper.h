

#ifndef MANAGEMENT_HELPER_H
#define MANAGEMENT_HELPER_H

#ifdef __cplusplus
extern "C" {
    #endif

    char *load_html_from_spiffs(const char *path);
    void restore_management_system(void);

    #ifdef __cplusplus
}
#endif

#endif
