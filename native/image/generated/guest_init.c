/* SPDX-License-Identifier: MIT
 * Fixed PID1 for the KVM-only generated-ELF appliance. No host filesystem,
 * disk, network or credential is presented to this guest. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/prctl.h>
#include <sys/reboot.h>
#include <sys/resource.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef OUTPUT_MAX
#define OUTPUT_MAX 32768
#endif
#ifndef WALL_MS
#define WALL_MS 3000
#endif
static unsigned char output[2][OUTPUT_MAX];
static size_t lengths[2];

static void halt_failure(void) {
  if (write(1, "LUMA_GENERATED_FAILURE_V1\n", 26) != 26) _exit(111);
  (void)reboot(RB_POWER_OFF);
  _exit(111);
}
static uint64_t milliseconds(void) {
  struct timespec value;
  if (clock_gettime(CLOCK_MONOTONIC, &value) || value.tv_sec < 0) halt_failure();
  return (uint64_t)value.tv_sec * 1000 + (uint64_t)value.tv_nsec / 1000000;
}
#define ALLOW(call) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_##call, 0, 1), BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW)
static int filter(void) {
  struct sock_filter rules[] = {
    BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, arch)),
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, AUDIT_ARCH_X86_64, 1, 0),
    BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
    BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, nr)),
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_read, 0, 4),
    BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, args[0])),
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 0, 0, 1),
    BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
    BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_write, 0, 5),
    BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, args[0])),
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 1, 1, 0),
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 2, 0, 1),
    BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
    BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_execveat, 0, 7),
    BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, args[0])),
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, 3, 0, 4),
    BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, args[4])),
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, AT_EMPTY_PATH, 0, 2),
    BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
    BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
    BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_prctl, 0, 5),
    BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, args[0])),
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, PR_GET_NO_NEW_PRIVS, 2, 0),
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, PR_CAPBSET_READ, 1, 0),
    BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
    BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW),
    ALLOW(exit), ALLOW(exit_group), ALLOW(brk), ALLOW(mmap), ALLOW(mprotect),
    ALLOW(munmap), ALLOW(mremap), ALLOW(madvise), ALLOW(arch_prctl),
    ALLOW(set_tid_address), ALLOW(set_robust_list), ALLOW(rseq), ALLOW(futex),
    ALLOW(getrandom), ALLOW(clock_gettime), ALLOW(getpid), ALLOW(gettid),
    ALLOW(nanosleep), ALLOW(clock_nanosleep),
    ALLOW(getuid), ALLOW(geteuid), ALLOW(getgid), ALLOW(getegid), ALLOW(getgroups), ALLOW(capget),
    ALLOW(rt_sigaction), ALLOW(rt_sigprocmask), ALLOW(rt_sigreturn),
    ALLOW(sigaltstack), ALLOW(uname), ALLOW(prlimit64), ALLOW(fstat), ALLOW(newfstatat),
    /* Static libc resolves its own executable during initialization. This is
     * a read-only query in the private initramfs, not a filesystem open. */
    ALLOW(readlink), ALLOW(readlinkat),
    ALLOW(lseek), ALLOW(close), ALLOW(sched_yield),
    BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS)
  };
  struct sock_fprog program = {.len = (unsigned short)(sizeof(rules)/sizeof(rules[0])), .filter = rules};
  return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program);
}
static void child(int pipes[2][2], int executable, int input) {
  struct __user_cap_header_struct header = {.version = _LINUX_CAPABILITY_VERSION_3, .pid = 0};
  struct __user_cap_data_struct caps[2] = {{0}, {0}};
  struct rlimit address = {32*1024*1024, 32*1024*1024};
  struct rlimit cpu = {1, 1}, descriptors = {4, 4}, core = {0, 0};
  /* Duplicate above the inherited pipe range first, avoiding fd3 aliasing. */
  int held = fcntl(executable, F_DUPFD_CLOEXEC, 32);
  if (held < 0 || dup2(input, 0) != 0 || dup2(pipes[0][1], 1) != 1 ||
      dup2(pipes[1][1], 2) != 2 || dup2(held, 3) != 3) _exit(112);
  for (int fd = 4; fd < 64; fd++) (void)close(fd);
  if (fcntl(3, F_SETFD, FD_CLOEXEC)) _exit(115);
  for (int capability = 0; capability < 64; capability++) {
    int present = prctl(PR_CAPBSET_READ, capability, 0, 0, 0);
    if ((present < 0 && errno != EINVAL) || (present > 0 && prctl(PR_CAPBSET_DROP, capability, 0, 0, 0))) _exit(116);
  }
  if (setrlimit(RLIMIT_AS, &address) || setrlimit(RLIMIT_CPU, &cpu) ||
      setrlimit(RLIMIT_NOFILE, &descriptors) || setrlimit(RLIMIT_CORE, &core) ||
      setgroups(0, NULL) || setgid(1000) || setuid(1000) ||
      syscall(SYS_capset, &header, caps) || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
      syscall(SYS_capget, &header, caps) || caps[0].effective || caps[0].permitted || caps[0].inheritable ||
      caps[1].effective || caps[1].permitted || caps[1].inheritable || filter()) _exit(113);
  char *argv[] = {(char *)"generated-task", NULL};
  char *environment[] = {(char *)"LANG=C", NULL};
  (void)syscall(SYS_execveat, 3, "", argv, environment, AT_EMPTY_PATH);
  _exit(114);
}
static void hexadecimal(size_t stream) {
  static const char alphabet[] = "0123456789abcdef";
  for (size_t index = 0; index < lengths[stream]; index++) {
    putchar(alphabet[output[stream][index] >> 4]);
    putchar(alphabet[output[stream][index] & 15]);
  }
}
int main(void) {
  if (getpid() != 1 || getuid() != 0) halt_failure();
  int console = open("/dev/console", O_WRONLY|O_CLOEXEC);
  if (console < 0 || dup2(console, 1) != 1 || dup2(console, 2) != 2) halt_failure();
  if (console > 2) close(console);
  int executable = open("/task", O_RDONLY|O_CLOEXEC);
  int input = open("/input", O_RDONLY|O_CLOEXEC);
  int pipes[2][2];
  if (executable < 0 || input < 0 || pipe2(pipes[0], O_CLOEXEC) || pipe2(pipes[1], O_CLOEXEC)) halt_failure();
  pid_t pid = fork();
  if (pid < 0) halt_failure();
  if (!pid) child(pipes, executable, input);
  close(executable); close(input);
  close(pipes[0][1]); close(pipes[1][1]);
  for (int index = 0; index < 2; index++) {
    int flags = fcntl(pipes[index][0], F_GETFL);
    if (flags < 0 || fcntl(pipes[index][0], F_SETFL, flags|O_NONBLOCK)) halt_failure();
  }
  uint64_t started = milliseconds();
  int status = 0, finished = 0, ended[2] = {0, 0}, killed = 0, overflowed = 0;
  while (!finished || !ended[0] || !ended[1]) {
    if (!finished && !killed && milliseconds() - started >= WALL_MS) {
      if (kill(pid, SIGKILL)) halt_failure();
      killed = 1;
    }
    struct pollfd descriptors[2] = {{pipes[0][0], POLLIN|POLLHUP, 0}, {pipes[1][0], POLLIN|POLLHUP, 0}};
    if (poll(descriptors, 2, 10) < 0 && errno != EINTR) halt_failure();
    for (int index = 0; index < 2; index++) {
      unsigned char buffer[4096];
      ssize_t size;
      while ((size = read(pipes[index][0], buffer, sizeof(buffer))) > 0) {
        size_t remaining = OUTPUT_MAX - lengths[index];
        size_t copied = (size_t)size < remaining ? (size_t)size : remaining;
        for (size_t byte = 0; byte < copied; byte++) output[index][lengths[index]++] = buffer[byte];
        if (copied != (size_t)size) {
          overflowed = 1;
          if (!killed) {
            if (!finished && kill(pid, SIGKILL)) halt_failure();
            killed = 2;
          }
        }
      }
      if (!size) ended[index] = 1;
      else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) halt_failure();
    }
    if (!finished) {
      pid_t observed = waitpid(pid, &status, WNOHANG);
      if (observed < 0) halt_failure();
      if (observed == pid) finished = 1;
    }
  }
  close(pipes[0][0]); close(pipes[1][0]);
  if (!WIFEXITED(status) && !WIFSIGNALED(status)) halt_failure();
#ifndef REPORT_LIMITS
  /* A reaped/exiting leader can leave buffered bytes. V1 has no output-limit
   * status: never describe a clipped buffer as a complete successful exit. */
  if (overflowed && WIFEXITED(status)) halt_failure();
#endif
  const char *execution_status = WIFEXITED(status) ? "exit" : "signal";
#ifdef REPORT_LIMITS
  if (killed == 1) execution_status = "timeout";
  if (overflowed) execution_status = "output_limit";
#endif
  printf("\nLUMA_GENERATED_RESULT_V1 {\"execution_status\":\"%s\",\"execution_value\":%d,\"stdout_hex\":\"",
         execution_status, WIFEXITED(status) ? WEXITSTATUS(status) : WTERMSIG(status));
  hexadecimal(0); printf("\",\"stderr_hex\":\""); hexadecimal(1); printf("\"}\n");
  if (fflush(stdout)) halt_failure();
  (void)reboot(RB_POWER_OFF);
  _exit(0);
}
