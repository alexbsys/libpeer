#include "rtp_nack_cache.h"

#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

#if defined(ESP_PLATFORM)
#include "esp_heap_caps.h"
#endif

#include "ports.h"
#include "utils.h"

#define RTP_NACK_MAX_EXPAND 256

static uint16_t rtp_read_seq(const uint8_t* rtp) {
  return (uint16_t)(((uint16_t)rtp[2] << 8) | (uint16_t)rtp[3]);
}

static int rate_allow(rtp_nack_cache_t* c) {
  uint32_t now = ports_get_epoch_time();
  if (c->rl_window_start_ms == 0 || (uint32_t)(now - c->rl_window_start_ms) >= 1000u) {
    c->rl_window_start_ms = now;
    c->rl_count = 0;
  }
  if (c->rl_count >= RTP_NACK_RESEND_PER_SEC) {
    return 0;
  }
  c->rl_count++;
  return 1;
}

void rtp_nack_cache_init(rtp_nack_cache_t* c) {
  if (!c) {
    return;
  }
  memset(c, 0, sizeof(*c));
  c->ring_size = RTP_NACK_RING;
#if defined(ESP_PLATFORM)
  c->slot = (rtp_nack_slot_t*)heap_caps_calloc(c->ring_size, sizeof(rtp_nack_slot_t),
                                                MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
  if (!c->slot) {
    c->slot = (rtp_nack_slot_t*)calloc(c->ring_size, sizeof(rtp_nack_slot_t));
  }
#else
  c->slot = (rtp_nack_slot_t*)calloc(c->ring_size, sizeof(rtp_nack_slot_t));
#endif
  if (!c->slot) {
    LOGW("rtp_nack: alloc(%u slots) failed, NACK cache disabled", (unsigned)c->ring_size);
    c->ring_size = 0;
  }
}

void rtp_nack_cache_deinit(rtp_nack_cache_t* c) {
  if (!c) {
    return;
  }
  free(c->slot);
  c->slot = NULL;
  c->ring_size = 0;
}

void rtp_nack_cache_set_discard_pre_idr(rtp_nack_cache_t* c, int enable) {
  if (c) {
    c->discard_pre_idr = enable ? 1 : 0;
  }
}

void rtp_nack_cache_set_resend_floor(rtp_nack_cache_t* c, uint16_t seq) {
  if (c) {
    c->resend_floor_seq = seq;
  }
}

void rtp_nack_cache_store(rtp_nack_cache_t* c, const uint8_t* rtp, int len) {
  if (!c || !c->slot || c->ring_size == 0 || !rtp || len < 12 || len > RTP_NACK_MAX_PKT) {
    return;
  }
  uint16_t seq = rtp_read_seq(rtp);
  unsigned idx = (unsigned)seq % c->ring_size;
  c->slot[idx].seq = seq;
  c->slot[idx].len = len;
  memcpy(c->slot[idx].data, rtp, (size_t)len);
}

static const uint8_t* cache_get(rtp_nack_cache_t* c, uint16_t seq, int* out_len) {
  if (!c->slot || c->ring_size == 0) {
    return NULL;
  }
  unsigned idx = (unsigned)seq % c->ring_size;
  if (c->slot[idx].len <= 0 || c->slot[idx].seq != seq) {
    return NULL;
  }
  *out_len = c->slot[idx].len;
  return c->slot[idx].data;
}

/* RFC 3550-style comparison (handles seq wrap). */
static int rtp_seq_before(uint16_t a, uint16_t b) {
  return (int16_t)(a - b) < 0;
}

static int append_seq(uint16_t* out, int out_n, int out_cap, uint16_t s) {
  if (out_n >= out_cap) {
    return out_n;
  }
  for (int i = 0; i < out_n; i++) {
    if (out[i] == s) {
      return out_n;
    }
  }
  out[out_n] = s;
  return out_n + 1;
}

static void sort_seq_list(uint16_t* seqs, int n) {
  for (int i = 1; i < n; i++) {
    uint16_t v = seqs[i];
    int j = i - 1;
    while (j >= 0 && rtp_seq_before(v, seqs[j])) {
      seqs[j + 1] = seqs[j];
      j--;
    }
    seqs[j + 1] = v;
  }
}

static int expand_nack_fci(const uint8_t* fci, int fci_len, uint16_t* seq_out, int seq_out_cap) {
  int n = 0;
  for (int i = 0; i + 4 <= fci_len && n < seq_out_cap; i += 4) {
    uint16_t pid = ntohs(*(const uint16_t*)(fci + i));
    uint16_t blp = ntohs(*(const uint16_t*)(fci + i + 2));
    n = append_seq(seq_out, n, seq_out_cap, pid);
    for (int b = 0; b < 16 && n < seq_out_cap; b++) {
      if (blp & (1u << (15 - b))) {
        n = append_seq(seq_out, n, seq_out_cap, (uint16_t)(pid + 1u + (unsigned)b));
      }
    }
  }
  return n;
}

int rtp_nack_cache_process_fci(rtp_nack_cache_t* c, const uint8_t* fci, int fci_len, rtp_nack_send_fn send,
                               void* user) {
  if (!c || !send || !fci || fci_len < 4) {
    return 0;
  }

  uint16_t seqs[RTP_NACK_MAX_EXPAND];
  int nseq = expand_nack_fci(fci, fci_len, seqs, RTP_NACK_MAX_EXPAND);
  int sent = 0;

  if (nseq > 1) {
    sort_seq_list(seqs, nseq);
  }

  for (int i = 0; i < nseq; i++) {
    if (c->discard_pre_idr && rtp_seq_before(seqs[i], c->resend_floor_seq)) {
      continue;
    }
    int plen = 0;
    const uint8_t* p = cache_get(c, seqs[i], &plen);
    if (!p || plen <= 0) {
      continue;
    }
    if (!rate_allow(c)) {
      LOGD("rtp_nack: rate limit (%d/s), drop rest", RTP_NACK_RESEND_PER_SEC);
      break;
    }
    if (send(user, p, plen) >= 0) {
      sent++;
    }
  }
  return sent;
}
