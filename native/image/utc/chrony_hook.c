/* SPDX-License-Identifier: GPL-2.0-only
 * Pinned-source integration fixture. NOT installed or an authorizing service.
 * No chronyc/tracking/log scraper and no public unauthenticated time input. */
#include "config.h"
#include "sysincl.h"
#include "chrony_hook.h"
#include "publisher.h"
#include "luma_policy_digest.h" /* Generated from the fixed policy by prepare_chrony.py. */
#include "local.h"
#include "sched.h"
#include <sys/random.h>
#include <sys/un.h>

static LU_Publisher publisher;
static const void *owners[3];
static int sock = -1;
static SCH_TimeoutID heartbeat;
static uint64_t last_boot, last_mono;
static int have_clock;

static void fence(void) { LU_Fence(&publisher); }

static int read_ms(clockid_t clock, uint64_t *out)
{
  struct timespec t;
  if (clock_gettime(clock, &t) || t.tv_sec < 0 || t.tv_nsec < 0 ||
      t.tv_nsec >= 1000000000 || (uint64_t)t.tv_sec > UINT64_MAX / 1000 - 1)
    return 0;
  *out = (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
  return 1;
}

static int read_clocks(uint64_t *boot, uint64_t *mono, int64_t *real)
{
  uint64_t before, r;
  if (!read_ms(CLOCK_BOOTTIME, &before) || !read_ms(CLOCK_MONOTONIC, mono) ||
      !read_ms(CLOCK_REALTIME, &r) || !read_ms(CLOCK_BOOTTIME, boot) ||
      *boot < before || *boot - before > 2 || *boot < *mono || r > INT64_MAX)
    return 0;
  *real = (int64_t)r;
  /* Secondary suspend/jump detection, NOT proof that every suspend is noticed.
   * Protected resume notification remains an installation requirement. */
  if (have_clock) {
    uint64_t bd, md;
    if (*boot < last_boot || *mono < last_mono) return 0;
    bd = *boot - last_boot; md = *mono - last_mono;
    if ((bd > md ? bd - md : md - bd) > 2) fence();
  }
  last_boot = *boot; last_mono = *mono; have_clock = 1;
  return 1;
}

static void publish(void *unused)
{
  unsigned char frame[LU_FRAME_SIZE];
  struct sockaddr_un address;
  uint64_t boot, mono;
  int64_t real;
  (void)unused;
  heartbeat = 0;
  memset(&address, 0, sizeof(address));
  address.sun_family = AF_UNIX;
  strcpy(address.sun_path, "/run/luma-utc/measurements.sock");
  if (!read_clocks(&boot, &mono, &real) ||
      !LU_Frame(&publisher, boot, mono, real, frame)) {
    fence();
  } else if (sock < 0 || sendto(sock, frame, sizeof(frame), MSG_DONTWAIT | MSG_NOSIGNAL,
                              (struct sockaddr *)&address, sizeof(address)) != (ssize_t)sizeof(frame)) {
    /* A loss is never repaired by retransmitting an old apparently-fresh batch. */
    fence();
  }
  if (!publisher.disabled) heartbeat = SCH_AddTimeoutByDelay(0.5, publish, NULL);
}

static void clock_change(struct timespec *raw, struct timespec *cooked,
                         double dfreq, double doffset, LCL_ChangeType type, void *unused)
{
  (void)raw; (void)cooked; (void)dfreq; (void)doffset; (void)unused;
  if (type != LCL_ChangeAdjust) fence();
}

static void dispersion(double amount, void *unused)
{
  (void)amount; (void)unused;
  fence(); /* Existing samples must not retain an unaccounted clock error. */
}

void LUH_Initialise(void)
{
  FILE *f;
  char uuid[38];
  unsigned char boot[16];
  uint64_t generation = 0;
  unsigned i, j = 0, value;
  memset(&publisher, 0, sizeof(publisher)); publisher.disabled = 1;
  memset(owners, 0, sizeof(owners)); have_clock = 0;
  f = fopen("/proc/sys/kernel/random/boot_id", "re");
  if (!f) return;
  if (!fgets(uuid, sizeof(uuid), f)) { fclose(f); return; }
  fclose(f);
  if (strlen(uuid) != 37 || uuid[36] != '\n') return;
  for (i = 0; i < 36;) {
    if (i == 8 || i == 13 || i == 18 || i == 23) {
      if (uuid[i++] != '-') return;
    } else {
      if (j >= 16 || sscanf(uuid + i, "%2x", &value) != 1) return;
      boot[j++] = (unsigned char)value; i += 2;
    }
  }
  if (j != 16 || getrandom(&generation, sizeof(generation), 0) != (ssize_t)sizeof(generation) ||
      !LU_Init(&publisher, luma_policy_digest, boot, generation)) return;
  sock = socket(AF_UNIX, SOCK_DGRAM | SOCK_NONBLOCK | SOCK_CLOEXEC, 0);
  if (sock < 0) { publisher.disabled = 1; return; }
  LCL_AddParameterChangeHandler(clock_change, NULL);
  LCL_AddDispersionNotifyHandler(dispersion, NULL);
  heartbeat = SCH_AddTimeoutByDelay(0.5, publish, NULL);
}

void LUH_Finalise(void)
{
  if (heartbeat) SCH_RemoveTimeout(heartbeat);
  heartbeat = 0;
  if (sock >= 0) {
    LCL_RemoveParameterChangeHandler(clock_change, NULL);
    LCL_RemoveDispersionNotifyHandler(dispersion, NULL);
    close(sock); sock = -1;
  }
  publisher.disabled = 1;
  fence();
}

unsigned LUH_Register(const void *owner, const char *name, int strict_nts)
{
  static const char *names[3] = {"time.cloudflare.com", "nts.netnod.se", "ptbtime1.ptb.de"};
  unsigned i;
  if (publisher.disabled) return 0;
  for (i = 0; i < 3; i++) if (name && !strcmp(name, names[i])) break;
  if (!owner || i == 3 || !strict_nts || owners[i]) {
    fence(); publisher.disabled = 1; /* Dedicated closed source set, not pool aliases. */
    return 0;
  }
  owners[i] = owner;
  return i + 1;
}

void LUH_Destroy(const void *owner, unsigned id)
{
  if (id && id <= 3 && owners[id - 1] == owner) {
    owners[id - 1] = NULL;
    fence();
  }
}
void LUH_Lose(unsigned id) { LU_Lose(&publisher, id); }
void LUH_Leap(unsigned id, int normal_leap)
{
  if (id && !normal_leap) fence(); /* Authenticated leap ambiguity fences ALL sources. */
}

void LUH_Good(unsigned id, NTP_Sample *sample, int normal_leap)
{
  struct timespec cooked;
  double error;
  uint64_t before, after, mono;
  int64_t real;
  /* Sample.time is the cooked local midpoint. Capture BEFORE discipline applies
   * this sample. No wall-clock-only estimate, source regression or public report. */
  if (!id) return;
  if (!normal_leap) { fence(); return; }
  if (!read_clocks(&before, &mono, &real)) { fence(); return; }
  LCL_ReadCookedTime(&cooked, &error);
  if (!read_ms(CLOCK_BOOTTIME, &after)) { fence(); return; }
  LU_Observe(&publisher, id, normal_leap, &sample->time, sample->offset,
             sample->root_delay, sample->root_dispersion, &cooked, error, before, after);
}
