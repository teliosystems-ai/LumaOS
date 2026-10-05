/* SPDX-License-Identifier: GPL-2.0-only
 * Linked into the pinned chrony integration fixture, not a public UTC API. */
#ifndef LUMA_UTC_PUBLISHER_H
#define LUMA_UTC_PUBLISHER_H
#include <stdint.h>
#include <time.h>
#define LU_FRAME_SIZE 232
typedef struct {
  uint64_t sequence, observed_ms;
  int64_t lower_ms, upper_ms;
  int available;
} LU_Source;
typedef struct {
  unsigned char policy[32], boot[16];
  uint64_t producer, clock, round;
  LU_Source sources[3];
  int disabled;
} LU_Publisher;
int LU_Init(LU_Publisher *, const unsigned char[32], const unsigned char[16], uint64_t);
void LU_Fence(LU_Publisher *);
void LU_Lose(LU_Publisher *, unsigned);
/* Called ONLY by the good-packet NTS hook. Arguments here are not auth proofs. */
int LU_Observe(LU_Publisher *, unsigned, int, const struct timespec *, double,
               double, double, const struct timespec *, double, uint64_t, uint64_t);
int LU_Frame(LU_Publisher *, uint64_t, uint64_t, int64_t, unsigned char[LU_FRAME_SIZE]);
#endif
