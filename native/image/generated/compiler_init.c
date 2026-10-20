/* SPDX-License-Identifier: MIT
 * Fixed compiler-only PID1. User source is compiled here, never on the host.
 * No block device, network interface, host mount or secret enters this guest.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <linux/audit.h>
#include <linux/capability.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <libtcc.h>
#include <poll.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/reboot.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define STREAM_MAX 2048
#define ELF_MAX 32768
#ifdef LUMA_COMPILER_DIAGNOSTIC
#define COMPILER_DENY SECCOMP_RET_TRAP
static void denied(int number, siginfo_t *information, void *context) {
  (void)number; (void)context;
  char output[48];
  int length = snprintf(output, sizeof(output), "compiler syscall denied: %d\n", information->si_syscall);
  if (length > 0 && length < (int)sizeof(output) && write(2, output, (size_t)length) != length) _exit(118);
  _exit(117);
}
#else
#define COMPILER_DENY SECCOMP_RET_KILL_PROCESS
#endif
static unsigned char outputs[2][STREAM_MAX], executable[ELF_MAX];
static size_t lengths[2], executable_length;
static void fail(void) {
  if (write(1, "LUMA_COMPILER_FAILURE_V1\n", 25) != 25) _exit(111);
  (void)reboot(RB_POWER_OFF); _exit(111);
}
static uint64_t milliseconds(void) {
  struct timespec now;
  if (clock_gettime(CLOCK_MONOTONIC, &now) || now.tv_sec < 0) fail();
  return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
}
#define ALLOW(call) BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, __NR_##call, 0, 1), BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_ALLOW)
static int compiler_filter(void) {
  struct sock_filter rules[] = {
    BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, arch)),
    BPF_JUMP(BPF_JMP|BPF_JEQ|BPF_K, AUDIT_ARCH_X86_64, 1, 0),
    BPF_STMT(BPF_RET|BPF_K, SECCOMP_RET_KILL_PROCESS),
    BPF_STMT(BPF_LD|BPF_W|BPF_ABS, offsetof(struct seccomp_data, nr)),
    /* Compiler file access is confined to this disposable initramfs. All
     * image/source files are root-owned and non-writable; only /work is writable.
     * No socket, clone/fork, mount, ptrace, ioctl or further exec is allowed. */
    ALLOW(read), ALLOW(write), ALLOW(openat), ALLOW(close), ALLOW(lseek),
    ALLOW(fstat), ALLOW(newfstatat), ALLOW(access), ALLOW(readlink), ALLOW(readlinkat), ALLOW(unlink),
    ALLOW(brk), ALLOW(mmap), ALLOW(mprotect), ALLOW(munmap), ALLOW(mremap),
    ALLOW(madvise), ALLOW(arch_prctl), ALLOW(set_tid_address), ALLOW(set_robust_list),
    ALLOW(rseq), ALLOW(futex), ALLOW(getrandom), ALLOW(prlimit64), ALLOW(fcntl),
    ALLOW(rt_sigaction), ALLOW(rt_sigprocmask), ALLOW(rt_sigreturn), ALLOW(sigaltstack),
    ALLOW(getuid), ALLOW(geteuid), ALLOW(getgid), ALLOW(getegid), ALLOW(getpid),
    ALLOW(gettid), ALLOW(clock_gettime), ALLOW(uname), ALLOW(exit), ALLOW(exit_group),
    BPF_STMT(BPF_RET|BPF_K, COMPILER_DENY)
  };
  struct sock_fprog program = {.len = (unsigned short)(sizeof(rules)/sizeof(rules[0])), .filter = rules};
  return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &program);
}
static void compile(int pipes[2][2]) {
  if (dup2(pipes[0][1], 1) != 1 || dup2(pipes[1][1], 2) != 2) _exit(112);
  close(0);
  for (int fd = 3; fd < 64; fd++) close(fd);
  for (int cap = 0; cap < 64; cap++) {
    int present = prctl(PR_CAPBSET_READ, cap, 0, 0, 0);
    if ((present < 0 && errno != EINVAL) || (present > 0 && prctl(PR_CAPBSET_DROP, cap, 0, 0, 0))) _exit(114);
  }
  struct rlimit address = {48*1024*1024, 48*1024*1024}, cpu = {2, 2};
  struct rlimit files = {ELF_MAX, ELF_MAX}, descriptors = {32, 32}, core = {0, 0};
  struct __user_cap_header_struct header = {.version = _LINUX_CAPABILITY_VERSION_3, .pid = 0};
  struct __user_cap_data_struct caps[2] = {{0}, {0}};
#ifdef LUMA_COMPILER_DIAGNOSTIC
  struct sigaction action = {.sa_sigaction = denied, .sa_flags = SA_SIGINFO};
  if (sigemptyset(&action.sa_mask) || sigaction(SIGSYS, &action, NULL)) _exit(119);
#endif
  if (setrlimit(RLIMIT_AS, &address) || setrlimit(RLIMIT_CPU, &cpu) ||
      setrlimit(RLIMIT_FSIZE, &files) || setrlimit(RLIMIT_NOFILE, &descriptors) ||
      setrlimit(RLIMIT_CORE, &core) || setgroups(0, NULL) || setgid(1000) || setuid(1000) ||
      syscall(SYS_capset, &header, caps) || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) ||
      syscall(SYS_capget, &header, caps) || caps[0].effective || caps[0].permitted || caps[0].inheritable ||
      caps[1].effective || caps[1].permitted || caps[1].inheritable ||
      getuid() != 1000 || geteuid() != 1000 || getgid() != 1000 || getegid() != 1000 ||
      getgroups(0, NULL) != 0 || prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1) _exit(115);
  for (int cap = 0; cap < 64; cap++) {
    int present = prctl(PR_CAPBSET_READ, cap, 0, 0, 0);
    if (present > 0 || (present < 0 && errno != EINVAL)) _exit(115);
  }
  if (compiler_filter()) _exit(115);
  TCCState *state = tcc_new();
  if (!state) _exit(116);
  tcc_set_lib_path(state, "/compiler");
  tcc_set_options(state, "-nostdinc -nostdlib -static -Werror -Wunsupported");
  if (tcc_add_include_path(state, "/include") || tcc_set_output_type(state, TCC_OUTPUT_EXE) ||
      tcc_add_file(state, "/runtime.c") || tcc_add_file(state, "/source.c") ||
      tcc_output_file(state, "/work/task")) { tcc_delete(state); _exit(1); }
  tcc_delete(state); _exit(0);
}
static void hexadecimal(const unsigned char *data, size_t length) {
  static const char alphabet[] = "0123456789abcdef";
  for (size_t i = 0; i < length; i++) {
    putchar(alphabet[data[i] >> 4]); putchar(alphabet[data[i] & 15]);
  }
}
int main(void) {
  if (getpid() != 1 || getuid() != 0) fail();
  int console = open("/dev/console", O_WRONLY|O_CLOEXEC);
  if (console < 0 || dup2(console, 1) != 1 || dup2(console, 2) != 2) fail();
  if (console > 2) close(console);
  if (mount("tmpfs", "/work", "tmpfs", MS_NODEV|MS_NOSUID, "size=2097152,mode=0700,uid=1000,gid=1000")) fail();
  int pipes[2][2];
  if (pipe2(pipes[0], O_CLOEXEC) || pipe2(pipes[1], O_CLOEXEC)) fail();
  pid_t pid = fork();
  if (pid < 0) fail();
  if (!pid) compile(pipes);
  close(pipes[0][1]); close(pipes[1][1]);
  for (int i = 0; i < 2; i++) {
    int flags = fcntl(pipes[i][0], F_GETFL);
    if (flags < 0 || fcntl(pipes[i][0], F_SETFL, flags|O_NONBLOCK)) fail();
  }
  uint64_t started = milliseconds();
  int status = 0, finished = 0, ended[2] = {0, 0}, reason = 0;
  while (!finished || !ended[0] || !ended[1]) {
    if (!finished && !reason && milliseconds() - started >= 5000) {
      if (kill(pid, SIGKILL)) fail();
      reason = 1;
    }
    struct pollfd fds[2] = {{pipes[0][0], POLLIN|POLLHUP, 0}, {pipes[1][0], POLLIN|POLLHUP, 0}};
    if (poll(fds, 2, 10) < 0 && errno != EINTR) fail();
    for (int i = 0; i < 2; i++) {
      unsigned char block[512]; ssize_t count;
      while ((count = read(pipes[i][0], block, sizeof(block))) > 0) {
        size_t available = STREAM_MAX - lengths[i];
        size_t copied = (size_t)count < available ? (size_t)count : available;
        for (size_t b = 0; b < copied; b++) outputs[i][lengths[i]++] = block[b];
        if (copied != (size_t)count && !reason) {
          reason = 2;
          if (!finished && kill(pid, SIGKILL)) fail();
        }
      }
      if (!count) ended[i] = 1;
      else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) fail();
    }
    if (!finished) {
      pid_t observed = waitpid(pid, &status, WNOHANG);
      if (observed < 0) fail();
      if (observed == pid) finished = 1;
    }
  }
  close(pipes[0][0]); close(pipes[1][0]);
  if (!WIFEXITED(status) && !WIFSIGNALED(status)) fail();
  if (!reason && WIFEXITED(status) && !WEXITSTATUS(status)) {
    int fd = open("/work/task", O_RDONLY|O_NOFOLLOW|O_CLOEXEC);
    struct stat info;
    if (fd < 0 || fstat(fd, &info) || !S_ISREG(info.st_mode) || info.st_nlink != 1 ||
        info.st_size < 64 || info.st_size > ELF_MAX) fail();
    ssize_t count;
    while ((count = read(fd, executable + executable_length, ELF_MAX - executable_length)) > 0) executable_length += (size_t)count;
    if (count < 0 || executable_length != (size_t)info.st_size || close(fd)) fail();
  }
  const char *result = reason == 1 ? "timeout" : reason == 2 ? "output_limit" : WIFEXITED(status) ? "exit" : "signal";
  printf("\nLUMA_COMPILER_RESULT_V1 {\"status\":\"%s\",\"value\":%d,\"stdout_hex\":\"", result,
         WIFEXITED(status) ? WEXITSTATUS(status) : WTERMSIG(status));
  hexadecimal(outputs[0], lengths[0]); printf("\",\"stderr_hex\":\"");
  hexadecimal(outputs[1], lengths[1]); printf("\",\"executable_hex\":\"");
  hexadecimal(executable, executable_length); printf("\"}\n");
  if (fflush(stdout)) fail();
  (void)reboot(RB_POWER_OFF); _exit(0);
}
