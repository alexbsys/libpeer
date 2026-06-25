#ifndef PEER_LOG_H_
#define PEER_LOG_H_

/*
 * Platform-agnostic logging shim for libpeer.
 *
 * libpeer itself NEVER calls a platform logger directly. All logging funnels
 * through two things, both resolved in ONE place (this header + peer_log.c):
 *
 *   1. The leveled macros LOGE/LOGW/LOGI/LOGD (see utils.h) -> peer_log().
 *   2. The lock-free PEER_LOG_RAW() used on hot/hang paths.
 *
 * This keeps the rest of the library free of any platform #ifdefs and free of
 * any hard dependency on a specific OS/SDK (ESP-IDF, FreeRTOS, POSIX, ...).
 *
 * Choosing the backend (single switch):
 *   - Define LOG_USE_CUSTOM=1 and provide your OWN peer_log() implementation.
 *     This is the intended extension point: route libpeer's logs wherever you
 *     like, with zero changes to the library. libpeer ships no peer_log() in
 *     that case, so you are not tied to any platform at all.
 *   - Otherwise libpeer provides a default peer_log() (peer_log.c): on ESP-IDF
 *     (ESP_PLATFORM) it forwards to esp_log; on every other target it falls back
 *     to plain printf. The same auto-detection drives PEER_LOG_RAW() below.
 */

#include "config.h"

#ifdef __cplusplus
extern "C" {
#endif

/* Leveled log sink. @p level_tag is one of the *_TAG strings from utils.h.
 * Implemented in peer_log.c unless LOG_USE_CUSTOM is set, in which case YOU
 * implement it. */
void peer_log(const char* level_tag, const char* file_name, int line_number,
              const char* fmt, ...);

/*
 * Lock-free "raw" diagnostic print for hot/hang paths where the normal buffered
 * logger may be unavailable (e.g. a wedged stdout/console lock). It must not
 * take locks or allocate. Resolved per-platform here, in one spot:
 *   - ESP-IDF: esp_rom_printf() — writes straight to the ROM UART, lock-free.
 *   - other:   plain printf().
 * Override by defining PEER_LOG_RAW before including this header.
 */
#ifndef PEER_LOG_RAW
#if defined(ESP_PLATFORM)
extern int esp_rom_printf(const char* fmt, ...);
#define PEER_LOG_RAW(...) esp_rom_printf(__VA_ARGS__)
#else
#include <stdio.h>
#define PEER_LOG_RAW(...) printf(__VA_ARGS__)
#endif
#endif /* PEER_LOG_RAW */

#ifdef __cplusplus
}
#endif

#endif /* PEER_LOG_H_ */
