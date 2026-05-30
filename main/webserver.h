#ifndef WEB_SERVER_H
#define WEB_SERVER_H

#include "esp_event.h"

ESP_EVENT_DECLARE_BASE(WEBSERVER_EVENTS);

enum {
    WEBSERVER_EVENT_ATTACK_REQUEST,
    WEBSERVER_EVENT_ATTACK_RESET,
};

void start_web_server(void);
void webserver_stop(void);
void webserver_run(void);

#endif