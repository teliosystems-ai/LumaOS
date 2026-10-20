/* SPDX-License-Identifier: MIT
 * One ordinary-user, explicitly requested, confined speech rendering worker.
 * Emits a complete bounded PCM WAV to its parent pipe, never opens audio output.
 */
#define _GNU_SOURCE
#include "tts_engine.h"
#include <errno.h>
#include <fcntl.h>
#include <linux/capability.h>
#include <linux/audit.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <stddef.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <unistd.h>

#define SEALS (F_SEAL_WRITE | F_SEAL_GROW | F_SEAL_SHRINK | F_SEAL_SEAL)
static int forbid_descendants(void) {
  /* Libraries may create ordinary threads, never a separate process that
   * could outlive the PIDFD-owned worker. clone3 falls back to checked clone.
   * This profile and installed binary are amd64 only. */
  struct sock_filter rules[] = {
    BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, arch)),
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, AUDIT_ARCH_X86_64, 1, 0),
    BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
    BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, nr)),
    BPF_JUMP(BPF_JMP|BPF_JGE|BPF_K, 0x40000000, 0, 1),
    BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, SYS_clone3, 0, 1),
    BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ERRNO|ENOSYS),
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, SYS_fork, 4, 0),
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, SYS_vfork, 3, 0),
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, SYS_execve, 2, 0),
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, SYS_execveat, 1, 0),
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, SYS_clone, 1, 4),
    BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ERRNO|EPERM),
    BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, args[0])),
    BPF_JUMP(BPF_JMP|BPF_JSET|BPF_K, 0x00010000, 1, 0),
    BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ERRNO|EPERM),
    BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
  };
  struct sock_fprog program = {.len = sizeof(rules)/sizeof(rules[0]), .filter = rules};
  return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program);
}
static int refuse(void) {
  static const char text[] = "luma-speech-render: refused or incomplete\n";
  if (write(2, text, sizeof(text)-1) != (ssize_t)(sizeof(text)-1)) return 1;
  return 1;
}
static int write_all(const void *data, size_t size) {
  const unsigned char *at = data;
  while (size) {
    ssize_t written = write(1, at, size);
    if (written < 0 && errno == EINTR) continue;
    if (written <= 0) return -1;
    at += written; size -= (size_t)written;
  }
  return 0;
}
static void little16(unsigned char *output, uint16_t value) {
  output[0] = (unsigned char)value; output[1] = (unsigned char)(value >> 8);
}
static void little32(unsigned char *output, uint32_t value) {
  for (unsigned i = 0; i < 4; i++) output[i] = (unsigned char)(value >> (8*i));
}
static int authority(void) {
  if (getuid() == 0 || getuid() != geteuid() || getgid() != getegid()) return -1;
  const char *owner = getenv("LUMA_SPEECH_PARENT");
  if (!owner || !*owner) return -1;
  for (const char *at = owner; *at; at++) if (*at < '0' || *at > '9') return -1;
  errno = 0; char *end = NULL; long parent = strtol(owner, &end, 10);
  if (errno || !end || *end || parent <= 1 || parent >= INT32_MAX || owner[0] == '0' || getppid() != parent) return -1;
  if (prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0) || getppid() != parent) return -1;
  int label = open("/proc/self/attr/current", O_RDONLY|O_CLOEXEC);
  if (label < 0) return -1;
  char actual[128] = {0}; ssize_t count = read(label, actual, sizeof(actual));
  if (close(label) || count != (ssize_t)strlen("luma-workspace-speech-render (enforce)\n") ||
      memcmp(actual, "luma-workspace-speech-render (enforce)\n", (size_t)count)) return -1;
  struct __user_cap_header_struct header = {.version = _LINUX_CAPABILITY_VERSION_3, .pid = 0};
  struct __user_cap_data_struct caps[2] = {{0}, {0}};
  if (syscall(SYS_capget, &header, caps) || caps[0].effective || caps[0].permitted || caps[0].inheritable ||
      caps[1].effective || caps[1].permitted || caps[1].inheritable || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
      prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1) return -1;
  for (int capability = 0; capability < 64; capability++) {
    int value = prctl(PR_CAP_AMBIENT, PR_CAP_AMBIENT_IS_SET, capability, 0, 0);
    if (value > 0 || (value < 0 && errno != EINVAL)) return -1;
  }
  struct rlimit memory = {128*1024*1024, 128*1024*1024}, cpu = {2, 2}, files = {32, 32}, zero = {0, 0};
  if (setrlimit(RLIMIT_AS, &memory) || setrlimit(RLIMIT_CPU, &cpu) || setrlimit(RLIMIT_NOFILE, &files) ||
      setrlimit(RLIMIT_CORE, &zero) || setrlimit(RLIMIT_FSIZE, &zero) || setrlimit(RLIMIT_MEMLOCK, &zero) ||
      clearenv() || getppid() != parent || forbid_descendants()) return -1;
  umask(0077);
  return 0;
}

int main(int argc, char **argv) {
  (void)argv;
  if (argc != 1 || authority()) return refuse();
  struct stat input, output;
  if (fstat(0, &input) || fstat(1, &output) || !S_ISREG(input.st_mode) || !S_ISFIFO(output.st_mode) ||
      input.st_size <= 0 || input.st_size > LUMA_TTS_TEXT_MAX || fcntl(0, F_GET_SEALS) != SEALS) return refuse();
  char name[128]; ssize_t name_length = readlink("/proc/self/fd/0", name, sizeof(name));
  const char expected[] = "/memfd:luma-speech-text (deleted)";
  if (name_length != (ssize_t)(sizeof(expected)-1) || memcmp(name, expected, sizeof(expected)-1)) return refuse();
  unsigned char text[LUMA_TTS_TEXT_MAX + 1];
  ssize_t received = pread(0, text, sizeof(text), 0);
  if (received != input.st_size || close(0)) return refuse();
  const int16_t *samples = NULL; size_t count = 0;
  int result = luma_tts_render(text, (size_t)received, &samples, &count);
  volatile unsigned char *wipe = text;
  for (size_t i = 0; i < sizeof(text); i++) wipe[i] = 0;
  if (result != LUMA_TTS_OK || !samples || !count || count > LUMA_TTS_SAMPLES_MAX) {
    luma_tts_forget();
    if (result == LUMA_TTS_LIMIT) return 2;
    return refuse();
  }
  unsigned char header[44] = {0};
  memcpy(header, "RIFF", 4); little32(header+4, (uint32_t)(count*2+36)); memcpy(header+8, "WAVEfmt ", 8);
  little32(header+16, 16); little16(header+20, 1); little16(header+22, 1);
  little32(header+24, LUMA_TTS_RATE); little32(header+28, LUMA_TTS_RATE*2); little16(header+32, 2); little16(header+34, 16);
  memcpy(header+36, "data", 4); little32(header+40, (uint32_t)(count*2));
  int failed = write_all(header, sizeof(header));
  for (size_t offset = 0; !failed && offset < count;) {
    unsigned char encoded[8192];
    size_t portion = count - offset < 4096 ? count - offset : 4096;
    for (size_t index = 0; index < portion; index++) little16(encoded + index*2, (uint16_t)samples[offset + index]);
    failed = write_all(encoded, portion*2); offset += portion;
  }
  luma_tts_forget();
  return failed ? refuse() : 0;
}
