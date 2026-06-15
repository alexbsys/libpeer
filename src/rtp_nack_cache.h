#ifndef RTP_NACK_CACHE_H_

#define RTP_NACK_CACHE_H_



#include <stdint.h>



#include "config.h"



/* Plaintext RTP cache for Generic NACK (seq % N). Slots are heap-allocated in

 * peer_connection_create so the ~700 KiB ring does not live inside PeerConnection

 * internal RAM (512 static slots broke stable video on ESP32-P4). */

/* Default ring depth = how many of the most recent outbound RTP packets are
 * retained for NACK/RTX resend. Deeper = recovers older losses on lossy links,
 * at RTP_NACK_MAX_PKT bytes per slot of (PSRAM) RAM. Runtime-overridable via
 * rtp_nack_cache_set_default_ring_size() / rtp_nack_cache_resize(). */
#define RTP_NACK_RING_DEFAULT 512

/* Safety clamp for user-supplied sizes. 4096 * (CONFIG_MTU+128) ~= 5.7 MiB,
 * which lives in PSRAM. */
#define RTP_NACK_RING_MAX 4096

/* Backward-compat alias for the old compile-time name. */
#define RTP_NACK_RING RTP_NACK_RING_DEFAULT

#define RTP_NACK_MAX_PKT (CONFIG_MTU + 128)

/* Default cap on RTX resends per second; runtime-overridable (see setters). */
#define RTP_NACK_RESEND_PER_SEC_DEFAULT 500

/* Backward-compat alias. */
#define RTP_NACK_RESEND_PER_SEC RTP_NACK_RESEND_PER_SEC_DEFAULT



typedef int (*rtp_nack_send_fn)(void* user, const uint8_t* rtp_plain, int len);



typedef struct {

  uint16_t seq;

  int len;

  uint8_t data[RTP_NACK_MAX_PKT];

} rtp_nack_slot_t;



typedef struct rtp_nack_cache {

  rtp_nack_slot_t* slot;

  unsigned ring_size;

  uint32_t rl_window_start_ms;

  int rl_count;

  /** Per-second RTX resend cap (rate limit). 0 falls back to the default. */
  unsigned rl_max_per_sec;

  /** When set, Generic NACK will not resend RTP with seq before this value
   * (updated on each outgoing IDR access unit). */
  uint16_t resend_floor_seq;

  int discard_pre_idr;

} rtp_nack_cache_t;



void rtp_nack_cache_init(rtp_nack_cache_t* c);



void rtp_nack_cache_deinit(rtp_nack_cache_t* c);



void rtp_nack_cache_store(rtp_nack_cache_t* c, const uint8_t* rtp, int len);

void rtp_nack_cache_set_discard_pre_idr(rtp_nack_cache_t* c, int enable);

/** @p seq is the next RTP seq that will be used for a new IDR access unit. */
void rtp_nack_cache_set_resend_floor(rtp_nack_cache_t* c, uint16_t seq);

/* ---- Runtime-tunable capacity ----------------------------------------- */

/** Process-wide default ring depth (packets) applied by rtp_nack_cache_init()
 *  to caches created afterwards. Clamped to [1, RTP_NACK_RING_MAX]; 0 ignored. */
void rtp_nack_cache_set_default_ring_size(unsigned slots);
unsigned rtp_nack_cache_get_default_ring_size(void);

/** Reallocate an existing cache to @p slots packets (drops buffered history).
 *  0 -> use the current process default. Clamped to [1, RTP_NACK_RING_MAX].
 *  Returns 0 on success, -1 on allocation failure (cache left disabled). */
int rtp_nack_cache_resize(rtp_nack_cache_t* c, unsigned slots);

/** Process-wide default resend rate cap (packets/s) for new caches; 0 ignored. */
void rtp_nack_cache_set_default_resend_per_sec(unsigned per_sec);
unsigned rtp_nack_cache_get_default_resend_per_sec(void);

/** Per-cache resend rate cap (packets/s). 0 -> fall back to the default. */
void rtp_nack_cache_set_resend_per_sec(rtp_nack_cache_t* c, unsigned per_sec);

/**

 * Handle Generic NACK FCI (RFC 4585): list of (PID, BLP) pairs.

 * Invokes @p send for each cached RTP packet (plaintext) still in the ring.

 */

int rtp_nack_cache_process_fci(rtp_nack_cache_t* c, const uint8_t* fci, int fci_len, rtp_nack_send_fn send,

                                 void* user);



#endif /* RTP_NACK_CACHE_H_ */

