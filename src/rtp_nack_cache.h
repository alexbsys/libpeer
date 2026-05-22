#ifndef RTP_NACK_CACHE_H_

#define RTP_NACK_CACHE_H_



#include <stdint.h>



#include "config.h"



/* Plaintext RTP cache for Generic NACK (seq % N). Slots are heap-allocated in

 * peer_connection_create so the ~700 KiB ring does not live inside PeerConnection

 * internal RAM (512 static slots broke stable video on ESP32-P4). */

#define RTP_NACK_RING 512

#define RTP_NACK_MAX_PKT (CONFIG_MTU + 128)

#define RTP_NACK_RESEND_PER_SEC 500



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

/**

 * Handle Generic NACK FCI (RFC 4585): list of (PID, BLP) pairs.

 * Invokes @p send for each cached RTP packet (plaintext) still in the ring.

 */

int rtp_nack_cache_process_fci(rtp_nack_cache_t* c, const uint8_t* fci, int fci_len, rtp_nack_send_fn send,

                                 void* user);



#endif /* RTP_NACK_CACHE_H_ */

