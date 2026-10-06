/* Disposable owned leaf only: tiny weights, numeric UIDs 988/989, no model/runtime
 * authority. Check the exec thread's PDEATHSIG, not a Rust test-harness thread.
 * Test-only environment/paths never enter the production native supervisor. */
#define _GNU_SOURCE
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <unistd.h>

static int descriptor(const char *name) {
    const char *value = getenv(name);
    char *end = NULL;
    if (!value || !*value) return -1;
    long fd = strtol(value, &end, 10);
    if (!end || *end || fd < 3 || fd > INT_MAX) return -1;
    int flags = fcntl((int)fd, F_GETFD);
    return flags >= 0 && !(flags & FD_CLOEXEC) ? (int)fd : -1;
}

int main(int argc, char **argv) {
    static const char weights[] = "private tiny validation weight fixture";
    int signal = 0;
    if (argc != 2) return 2;
    int acquisition_hold = !strcmp(argv[1], "acquisition-hold");
    int acquisition = !strcmp(argv[1], "acquisition-success") || acquisition_hold;
    if (!acquisition && strcmp(argv[1], "leaf-hold") && strcmp(argv[1], "leaf-success") && strcmp(argv[1], "leaf-failure")) return 2;
    uid_t uid = acquisition ? 988 : 989;
    if (geteuid() != uid || getegid() != uid || getgroups(0, NULL) != 0) return 3;
    if (prctl(PR_GET_PDEATHSIG, &signal, 0, 0, 0) || signal != SIGKILL) return 4;
    if (acquisition) {
        static const char output[] = "confined acquisition fixture";
        struct rlimit limit;
        struct stat metadata;
        if (prctl(PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0) != 1 ||
            getrlimit(RLIMIT_FSIZE, &limit) || limit.rlim_cur != 128 || limit.rlim_max != 128 ||
            fstat(STDOUT_FILENO, &metadata) || !S_ISREG(metadata.st_mode) || metadata.st_uid != 0 ||
            metadata.st_nlink != 1 || (metadata.st_mode & 07777) != 0600 ||
            flock(STDOUT_FILENO, LOCK_EX | LOCK_NB)) return 12;
        if (write(STDOUT_FILENO, output, sizeof(output) - 1) != (ssize_t)(sizeof(output) - 1)) return 13;
        if (acquisition_hold) sleep(15);
        return 0;
    }
    int weight = descriptor("LUMA_VALIDATION_LEAF_WEIGHT_FD");
    int runtime = descriptor("LUMA_VALIDATION_LEAF_RUNTIME_FD");
    if (weight < 0 || runtime < 0) return 5;
    char bytes[sizeof(weights)];
    if (pread(weight, bytes, sizeof(bytes), 0) != (ssize_t)(sizeof(weights) - 1) ||
        memcmp(bytes, weights, sizeof(weights) - 1)) return 6;
    struct stat metadata;
    if (fstat(runtime, &metadata) || !S_ISREG(metadata.st_mode) || metadata.st_uid != 0 ||
        metadata.st_nlink != 1 || metadata.st_size != 0 || (metadata.st_mode & 07777) != 0644) return 8;
    const char *root = getenv("LUMA_VALIDATION_TEST_ROOT");
    char path[1024], pid[32];
    if (!root) return 9;
    int length = snprintf(path, sizeof(path), "%s/worker-fixture/leaf.ready", root);
    if (length < 0 || (size_t)length >= sizeof(path)) return 9;
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return 10;
    int count = snprintf(pid, sizeof(pid), "%ld\n", (long)getpid());
    if (count <= 0 || (size_t)count >= sizeof(pid) || write(fd, pid, (size_t)count) != count || fsync(fd) || close(fd)) return 11;
    if (!strcmp(argv[1], "leaf-hold")) sleep(15);
    return !strcmp(argv[1], "leaf-failure") ? 7 : 0;
}
