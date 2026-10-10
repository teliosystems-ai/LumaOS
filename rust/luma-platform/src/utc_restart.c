/* Fixed supervised UTC lifecycle transition. No caller action, unit or secret.
 * Only the immutable luma-admin executable can create the kernel-authenticated
 * connection consumed here, after its typed current PAM/custody transaction. */
#define _GNU_SOURCE
#include <sys/socket.h>
#include <sys/resource.h>
#include <sys/prctl.h>
#include <sys/time.h>
#include <poll.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#ifndef SO_PEERPIDFD
#define SO_PEERPIDFD 77
#endif

static int exact(int fd, void *buffer, size_t size)
{
  unsigned char *bytes = buffer;
  while (size) {
    ssize_t count = read(fd, bytes, size);
    if (count <= 0) return 0;
    bytes += count;
    size -= (size_t)count;
  }
  return 1;
}
static int label(int fd)
{
  char value[128];
  socklen_t length = sizeof(value);
  if (getsockopt(fd, SOL_SOCKET, SO_PEERSEC, value, &length) ||
      !length || length > sizeof(value)) return 0;
  if (value[length - 1] == '\0') --length;
  return length == sizeof("luma-admin (enforce)") - 1 &&
         !memcmp(value, "luma-admin (enforce)", length);
}
int main(int argc, char **argv)
{
  static const char prefix[] = "{\"operation\":\"restart-fixed-utc\",\"reviewed_sha256\":\"";
  unsigned char header[4], request[sizeof(prefix) - 1 + 64 + 2], byte;
  struct ucred peer;
  socklen_t length = sizeof(peer);
  struct timeval timeout = {.tv_sec = 2, .tv_usec = 0};
  struct rlimit core = {.rlim_cur = 0, .rlim_max = 0};
  char self[128];
  int profile, pin = -1;
  uint32_t size;
  struct pollfd alive;
  (void)argv;
  if (argc != 1 || geteuid() || getegid() || setrlimit(RLIMIT_CORE, &core) ||
      prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)) goto refuse;
  profile = open("/proc/self/attr/current", O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (profile < 0) goto refuse;
  ssize_t count = read(profile, self, sizeof(self));
  close(profile);
  if (count != (ssize_t)(sizeof("luma-utc-restart (enforce)\n") - 1) ||
      memcmp(self, "luma-utc-restart (enforce)\n", (size_t)count)) goto refuse;
  if (getsockopt(3, SOL_SOCKET, SO_PEERCRED, &peer, &length) ||
      length != sizeof(peer) || peer.uid || peer.gid || peer.pid <= 0 || !label(3)) goto refuse;
  length = sizeof(pin);
  if (getsockopt(3, SOL_SOCKET, SO_PEERPIDFD, &pin, &length) ||
      length != sizeof(pin) || pin < 0) goto refuse;
  alive = (struct pollfd){.fd = pin, .events = POLLIN, .revents = 0};
  if (poll(&alive, 1, 0) != 0 ||
      setsockopt(3, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) ||
      !exact(3, header, sizeof(header))) goto refuse;
  size = ((uint32_t)header[0] << 24) | ((uint32_t)header[1] << 16) |
         ((uint32_t)header[2] << 8) | header[3];
  if (size != sizeof(request) || !exact(3, request, sizeof(request)) ||
      read(3, &byte, 1) != 0 || memcmp(request, prefix, sizeof(prefix) - 1) ||
      memcmp(request + sizeof(request) - 2, "\"}", 2)) goto refuse;
  int nonzero = 0;
  for (size_t i = sizeof(prefix) - 1; i < sizeof(prefix) - 1 + 64; ++i) {
    if (!((request[i] >= '0' && request[i] <= '9') ||
          (request[i] >= 'a' && request[i] <= 'f'))) goto refuse;
    nonzero |= request[i] != '0';
  }
  if (!nonzero || !label(3) || poll(&alive, 1, 0) != 0) goto refuse;
  close(pin);
  close(3);
  char *const command[] = {"/usr/bin/systemctl", "--no-ask-password", "restart",
      "luma-utc-keeper.service", "luma-utc-producer.path", NULL};
  char *const environment[] = {"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C", "LC_ALL=C", NULL};
  execve(command[0], command, environment);
refuse:
  if (pin >= 0) close(pin);
  fputs("UTC supervised restart refused or uncertain; inspect without automatic retry\n", stderr);
  return 78;
}
