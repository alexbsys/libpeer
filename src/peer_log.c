/*
 * Default, platform-agnostic implementation of libpeer's log sink (peer_log()).
 *
 * Selection happens in ONE place (see peer_log.h for the rationale):
 *   - LOG_USE_CUSTOM=1 -> this file provides NOTHING; you implement peer_log()
 *                         yourself and route libpeer's logs anywhere you like.
 *                         libpeer makes no platform assumptions in that case.
 *   - ESP_PLATFORM     -> forward to ESP-IDF esp_log, so esp_log_level_set()
 *                         can throttle libpeer's chatter on the console. The tag
 *                         defaults to "AGENT" (override with PEER_LOG_ESP_TAG).
 *   - otherwise        -> plain printf to stdout (upstream libpeer behaviour).
 */
#include "peer_log.h"

#if !defined(LOG_USE_CUSTOM)

#include "utils.h"

#include <stdarg.h>
#include <string.h>

#if defined(ESP_PLATFORM)

#include "esp_log.h"

/* Keep the historical tag so existing esp_log_level_set("AGENT", ...) calls in
 * the host application still throttle libpeer's ICE/keepalive spam. */
#ifndef PEER_LOG_ESP_TAG
#define PEER_LOG_ESP_TAG "AGENT"
#endif

void peer_log(const char* level_tag, const char* file_name, int line_number,
              const char* fmt, ...) {
  (void)file_name;
  (void)line_number;

  esp_log_level_t level = ESP_LOG_INFO;
  if (level_tag) {
    if (strcmp(level_tag, ERROR_TAG) == 0) {
      level = ESP_LOG_ERROR;
    } else if (strcmp(level_tag, WARN_TAG) == 0) {
      level = ESP_LOG_WARN;
    } else if (strcmp(level_tag, DEBUG_TAG) == 0) {
      level = ESP_LOG_DEBUG;
    }
  }

  va_list ap;
  va_start(ap, fmt);
  esp_log_writev(level, PEER_LOG_ESP_TAG, fmt, ap);
  va_end(ap);
}

#else /* generic host (POSIX / bare printf) */

#include <stdio.h>

void peer_log(const char* level_tag, const char* file_name, int line_number,
              const char* fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  fprintf(stdout, "%s\t%s\t%d\t", level_tag ? level_tag : "", file_name, line_number);
  vfprintf(stdout, fmt, ap);
  fputc('\n', stdout);
  va_end(ap);
}

#endif /* ESP_PLATFORM */

#endif /* !LOG_USE_CUSTOM */
