/* Test-only abrupt native process exits. No fault switch enters the runtime. */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int sqlite3_exec(void *db, const char *sql,
    int (*callback)(void *, int, char **, char **), void *context, char **error) {
    int (*next)(void *, const char *, int (*)(void *, int, char **, char **), void *, char **) =
        dlsym(RTLD_NEXT, "sqlite3_exec");
    const char *fault = getenv("LUMA_ARTIFACT_TEST_FAULT");
    int commit = strcmp(sql, "COMMIT;") == 0;
    if (commit && fault && strcmp(fault, "before-commit") == 0) _exit(86);
    int result = next(db, sql, callback, context, error);
    if (commit && result == 0 && fault && strcmp(fault, "after-commit") == 0) _exit(87);
    return result;
}

int renameat2(int source_fd, const char *source, int target_fd, const char *target, unsigned int flags) {
    int (*next)(int, const char *, int, const char *, unsigned int) = dlsym(RTLD_NEXT, "renameat2");
    int result = next(source_fd, source, target_fd, target, flags);
    const char *fault = getenv("LUMA_ARTIFACT_TEST_FAULT");
    if (result == 0 && strlen(target) == 64 && fault && strcmp(fault, "after-object") == 0) _exit(88);
    return result;
}
