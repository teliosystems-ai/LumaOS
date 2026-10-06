/* Disposable CLI fixture only; never packaged or loaded by production code. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <string.h>
#include <sys/types.h>

static int forward_open(const char *symbol, const char *path, int flags, mode_t mode)
{
    int (*next)(const char *, int, ...) = dlsym(RTLD_NEXT, symbol);
    if (next == NULL) {
        errno = ENOSYS;
        return -1;
    }
    if (strcmp(path, "/proc/cmdline") == 0)
        path = "/repo/native/tests/resource_history_cmdline.txt";
    return next(path, flags, mode);
}

int open(const char *path, int flags, ...)
{
    mode_t mode = 0;
    if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }
    return forward_open("open", path, flags, mode);
}

int open64(const char *path, int flags, ...)
{
    mode_t mode = 0;
    if ((flags & O_CREAT) || (flags & O_TMPFILE) == O_TMPFILE) {
        va_list args;
        va_start(args, flags);
        mode = va_arg(args, mode_t);
        va_end(args);
    }
    return forward_open("open64", path, flags, mode);
}
