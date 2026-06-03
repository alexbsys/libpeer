/**
 * Route libpeer LOG_* (utils.h) through ESP-IDF esp_log so esp_log_level_set("AGENT")
 * in app_main actually suppresses ICE keepalive spam on UART.
 */
#include "config.h"

#if LOG_REDIRECT

#include "esp_log.h"
#include "utils.h"

#include <stdarg.h>
#include <string.h>

static const char *TAG = "AGENT";

void peer_log(char *level_tag, const char *file_name, int line_number, const char *fmt, ...)
{
  (void)file_name;
  (void)line_number;

  esp_log_level_t level = ESP_LOG_INFO;
  if (level_tag && strcmp(level_tag, ERROR_TAG) == 0) {
    level = ESP_LOG_ERROR;
  } else if (level_tag && strcmp(level_tag, WARN_TAG) == 0) {
    level = ESP_LOG_WARN;
  } else if (level_tag && strcmp(level_tag, DEBUG_TAG) == 0) {
    level = ESP_LOG_DEBUG;
  }

  va_list ap;
  va_start(ap, fmt);
  esp_log_writev(level, TAG, fmt, ap);
  va_end(ap);
}

#endif /* LOG_REDIRECT */
