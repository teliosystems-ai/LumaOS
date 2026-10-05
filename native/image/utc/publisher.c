/* SPDX-License-Identifier: GPL-2.0-only */
#include "publisher.h"
#include <math.h>
#include <stddef.h>
#include <string.h>
#include <inttypes.h>
#include <stdarg.h>
#include <stdio.h>

static void put64(unsigned char *p, uint64_t n)
{
  unsigned i;
  for (i = 0; i < 8; i++) { p[i] = (unsigned char)n; n >>= 8; }
}

int LU_Init(LU_Publisher *p, const unsigned char policy[32],
            const unsigned char boot[16], uint64_t producer)
{
  unsigned char zero[32] = {0};
  memset(p, 0, sizeof(*p));
  if (!producer || !memcmp(policy, zero, 32) || !memcmp(boot, zero, 16)) {
    p->disabled = 1;
    return 0;
  }
  memcpy(p->policy, policy, 32);
  memcpy(p->boot, boot, 16);
  p->producer = producer;
  p->clock = 1;
  return 1;
}

static int append_json(unsigned char *out, size_t *used, const char *format, ...)
{
  int n;
  size_t remaining = LU_ENVELOPE_SIZE - *used;
  va_list arguments;
  va_start(arguments, format);
  n = vsnprintf((char *)out + *used, remaining, format, arguments);
  va_end(arguments);
  if (n < 0 || (size_t)n >= remaining) return 0;
  *used += (size_t)n;
  return 1;
}

int LU_Envelope(LU_Publisher *p, uint64_t boot_ms, uint64_t mono_ms, int64_t real_ms,
                uint32_t pid, uint32_t uid, unsigned char out[LU_ENVELOPE_SIZE], size_t *length)
{
  unsigned char legacy[LU_FRAME_SIZE];
  char policy[65], boot[33];
  static const char digits[] = "0123456789abcdef";
  size_t used = 4;
  unsigned i;
  *length = 0;
  memset(out, 0, LU_ENVELOPE_SIZE);
  if (!pid || pid > INT32_MAX || boot_ms > UINT64_MAX - 999 ||
      !LU_Frame(p, boot_ms, mono_ms, real_ms, legacy)) return 0;
  for (i = 0; i < 32; i++) {
    policy[2*i] = digits[p->policy[i] >> 4]; policy[2*i+1] = digits[p->policy[i] & 15];
  }
  policy[64] = 0;
  for (i = 0; i < 16; i++) {
    boot[2*i] = digits[p->boot[i] >> 4]; boot[2*i+1] = digits[p->boot[i] & 15];
  }
  boot[32] = 0;
  if (!append_json(out, &used,
      "{\"schema_version\":1,\"request_id\":\"utc-%s-%" PRIu64 "-%" PRIu64 "-%" PRIu64
      "\",\"caller\":{\"pid\":%" PRIu32 ",\"uid\":%" PRIu32 "},\"deadline\":%" PRIu64
      ",\"deadline_clock\":\"boottime\",\"method\":\"utc_measurements\",\"measurements\":{"
      "\"policy_sha256\":\"%s\",\"boot_id\":\"%s\",\"process_generation\":%" PRIu64
      ",\"source_clock_generation\":%" PRIu64 ",\"sequence\":%" PRIu64
      ",\"captured_boottime_ms\":%" PRIu64 ",\"captured_monotonic_ms\":%" PRIu64
      ",\"captured_realtime_ms\":%" PRId64 ",\"sources\":[",
      boot, p->producer, p->clock, p->round, pid, uid, boot_ms + 999,
      policy, boot, p->producer, p->clock, p->round, boot_ms, mono_ms, real_ms)) goto failed;
  for (i = 0; i < 3; i++) {
    const LU_Source *s = &p->sources[i];
    if (!append_json(out, &used,
        "%s{\"operator\":%u,\"available\":%s,\"sequence\":%" PRIu64
        ",\"observed_boottime_ms\":%" PRIu64 ",\"lower_ms\":%" PRId64 ",\"upper_ms\":%" PRId64 "}",
        i ? "," : "", i + 1, s->available ? "true" : "false",
        s->available ? s->sequence : 0, s->available ? s->observed_ms : 0,
        s->available ? s->lower_ms : 0, s->available ? s->upper_ms : 0)) goto failed;
  }
  if (!append_json(out, &used, "]}}")) goto failed;
  out[0] = (unsigned char)((used - 4) >> 24);
  out[1] = (unsigned char)((used - 4) >> 16);
  out[2] = (unsigned char)((used - 4) >> 8);
  out[3] = (unsigned char)(used - 4);
  *length = used;
  return 1;
failed:
  memset(out, 0, LU_ENVELOPE_SIZE);
  LU_Fence(p);
  return 0;
}

void LU_Fence(LU_Publisher *p)
{
  memset(p->sources, 0, sizeof(p->sources));
  if (p->clock == UINT64_MAX) p->disabled = 1;
  else p->clock++;
}

void LU_Lose(LU_Publisher *p, unsigned operator_id)
{
  if (operator_id >= 1 && operator_id <= 3)
    p->sources[operator_id - 1].available = 0;
}

static int valid_ts(const struct timespec *t)
{
  /* Explicit representable range: 1970..2100; no overflowing float-to-int cast. */
  return t && t->tv_sec >= 0 && t->tv_sec < 4102444800LL &&
         t->tv_nsec >= 0 && t->tv_nsec < 1000000000;
}

int LU_Observe(LU_Publisher *p, unsigned id, int normal_leap,
               const struct timespec *midpoint, double offset, double root_delay,
               double root_dispersion, const struct timespec *cooked,
               double cooked_error, uint64_t before_ms, uint64_t after_ms)
{
  long double age, centre, radius, low, high;
  LU_Source *s;
  if (id < 1 || id > 3) return 0;
  s = &p->sources[id - 1];
  s->available = 0; /* Invalid replacement must not retain a previous sample. */
  if (p->disabled || !normal_leap || !valid_ts(midpoint) || !valid_ts(cooked) ||
      !isfinite(offset) || !isfinite(root_delay) || !isfinite(root_dispersion) ||
      !isfinite(cooked_error) || fabsl(offset) > 86400.0L ||
      root_delay < 0 || root_delay > 10 || root_dispersion < 0 ||
      root_dispersion > 10 || cooked_error < 0 || cooked_error > 10 ||
      after_ms < before_ms || after_ms - before_ms > 20 ||
      s->sequence == UINT64_MAX || (s->sequence && after_ms <= s->observed_ms))
    return 0;
  age = (long double)cooked->tv_sec - midpoint->tv_sec +
        ((long double)cooked->tv_nsec - midpoint->tv_nsec) / 1000000000.0L;
  if (age < 0 || age > 5) return 0;
  /* NTP offset is remote minus local. Cooked time is only a coordinate:
   * the authenticated offset and complete root error supply the UTC claim.
   * Conditional on the approved TOTAL rate-error bound, including discipline.
   * Cooked read is bracketed by BOOTTIME. At the AFTER anchor, the unknown
   * capture position contributes [0, span/(1-rate)]. Add 2ms each side for
   * timestamp quantisation and floating-point rounding in this bounded range.
   * These error assumptions still require runtime/physical qualification. */
  centre = (long double)cooked->tv_sec + cooked->tv_nsec / 1000000000.0L + offset;
  radius = root_delay / 2.0L + root_dispersion + cooked_error + age * 100.0L / 999900.0L;
  low = floorl((centre - radius) * 1000.0L) - 2;
  high = ceill((centre + radius) * 1000.0L +
               (after_ms - before_ms) * 1000000.0L / 999900.0L) + 2;
  if (!isfinite(low) || !isfinite(high) || low < 0 || high > 4102444800000.0L || low > high)
    return 0;
  s->sequence++;
  s->observed_ms = after_ms;
  s->lower_ms = (int64_t)low;
  s->upper_ms = (int64_t)high;
  s->available = 1;
  return 1;
}

int LU_Frame(LU_Publisher *p, uint64_t boot_ms, uint64_t mono_ms, int64_t real_ms,
             unsigned char frame[LU_FRAME_SIZE])
{
  unsigned i;
  if (p->disabled || boot_ms < mono_ms || real_ms < 0 || p->round == UINT64_MAX)
    return 0;
  memset(frame, 0, LU_FRAME_SIZE);
  memcpy(frame, "LUMAUTC1", 8);
  memcpy(frame + 8, p->policy, 32);
  memcpy(frame + 40, p->boot, 16);
  put64(frame + 56, p->producer);
  put64(frame + 64, p->clock);
  put64(frame + 72, ++p->round);
  put64(frame + 80, boot_ms);
  put64(frame + 88, mono_ms);
  put64(frame + 96, (uint64_t)real_ms); /* Observation of host clock, NOT trusted UTC. */
  for (i = 0; i < 3; i++) {
    LU_Source *s = &p->sources[i];
    unsigned char *e = frame + 112 + 40 * i;
    e[0] = (unsigned char)(i + 1);
    /* ceil(age/(1-rate)) <= 180000, using division-safe bounded threshold.
     * Keep the original sample identity/anchor: a heartbeat NEVER re-ages it. */
    if (s->available && (boot_ms < s->observed_ms || boot_ms - s->observed_ms > 179982))
      s->available = 0;
    if (!s->available) continue;
    e[1] = 1;
    put64(e + 8, s->sequence);
    put64(e + 16, s->observed_ms);
    put64(e + 24, (uint64_t)s->lower_ms);
    put64(e + 32, (uint64_t)s->upper_ms);
  }
  return 1;
}
