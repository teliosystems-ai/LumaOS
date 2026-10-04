/* Disposable fixture only; no fault selector is linked into the product. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int renameat2(int source_fd, const char *source, int target_fd,
              const char *target, unsigned int flags) {
    int (*next)(int, const char *, int, const char *, unsigned int) =
        dlsym(RTLD_NEXT, "renameat2");
    const char *fault = getenv("LUMA_TPM_TEST_PUBLICATION_FAULT");
    int publication = strstr(source, "/pending-enrollment") != NULL &&
                      strstr(target, "/pending-admin") != NULL;
    if (publication && fault && strcmp(fault, "lost-before-rename") == 0) _exit(94);
    int result = next(source_fd, source, target_fd, target, flags);
    if (result == 0 && publication && fault && strcmp(fault, "lost-after-rename") == 0) _exit(95);
    return result;
}
