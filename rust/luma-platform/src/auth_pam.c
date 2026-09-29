/* Fixed local-account authentication helper, never setuid. No session,
 * password changes, roles or caller-selected PAM service. Secret only on stdin.
 */
#define _GNU_SOURCE
#include <security/pam_appl.h>
#include <pwd.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>

struct input { const char *password; unsigned prompts; };
static int converse(int count, const struct pam_message **messages,
                    struct pam_response **response, void *data) {
    struct input *input = data;
    if (count < 1 || count > 8) return PAM_CONV_ERR;
    struct pam_response *result = calloc((size_t)count, sizeof(*result));
    if (!result) return PAM_BUF_ERR;
    for (int i = 0; i < count; i++) {
        if (!messages[i]) goto denied;
        switch (messages[i]->msg_style) {
        case PAM_PROMPT_ECHO_OFF:
            if (++input->prompts != 1) goto denied;
            result[i].resp = strdup(input->password);
            if (!result[i].resp) goto denied;
            break;
        case PAM_TEXT_INFO:
        case PAM_ERROR_MSG:
            break;
        default:
            goto denied;
        }
    }
    *response = result; /* PAM owns successful conversation responses. */
    return PAM_SUCCESS;
denied:
    for (int i = 0; i < count; i++) {
        if (result[i].resp) explicit_bzero(result[i].resp, strlen(result[i].resp));
        free(result[i].resp);
    }
    free(result);
    return PAM_CONV_ERR;
}

static int human(const char *name, uint32_t *uid) {
    size_t len = strlen(name);
    if (len < 1 || len > 32 || name[0] < 'a' || name[0] > 'z') return 0;
    for (size_t i = 0; i < len; i++)
        if (!((name[i] >= 'a' && name[i] <= 'z') ||
              (name[i] >= '0' && name[i] <= '9') || name[i] == '_' || name[i] == '-')) return 0;
    struct passwd account, *found = NULL;
    char buffer[16384];
    if (getpwnam_r(name, &account, buffer, sizeof(buffer), &found) || !found ||
        strcmp(found->pw_name, name) || found->pw_uid < 1000 || found->pw_uid >= 65534 ||
        (strcmp(found->pw_shell, "/bin/bash") && strcmp(found->pw_shell, "/bin/sh"))) return 0;
    *uid = found->pw_uid;
    return 1;
}

int main(int argc, char **argv) {
    struct rlimit core = {0, 0};
    if (argc != 2 || geteuid() != 0 || setrlimit(RLIMIT_CORE, &core) ||
        prctl(PR_SET_DUMPABLE, 0, 0, 0, 0)) return 1;
    uint32_t before = 0, after = 0;
    if (!human(argv[1], &before)) return 1;
    char password[1025] = {0};
    if (mlock(password, sizeof(password))) return 1;
    size_t used = 0;
    while (used < sizeof(password)) {
        ssize_t n = read(STDIN_FILENO, password + used, sizeof(password) - used);
        if (n <= 0) break;
        used += (size_t)n;
    }
    int status = PAM_AUTH_ERR;
    pam_handle_t *handle = NULL;
    size_t length = strnlen(password, sizeof(password));
    if (used != sizeof(password) || length == 0 || length > 1024) goto done;
    for (size_t i = length; i < sizeof(password); i++) if (password[i] != 0) goto done;
    struct input input = {.password = password, .prompts = 0};
    struct pam_conv conversation = {.conv = converse, .appdata_ptr = &input};
    status = pam_start("luma-admin", argv[1], &conversation, &handle);
    if (!status) status = pam_authenticate(handle, PAM_SILENT | PAM_DISALLOW_NULL_AUTHTOK);
    if (!status && input.prompts != 1) status = PAM_AUTH_ERR;
    if (!status) status = pam_acct_mgmt(handle, PAM_SILENT);
    const void *user = NULL;
    if (!status) status = pam_get_item(handle, PAM_USER, &user);
    if (!status && (!user || strcmp(user, argv[1]) || !human(argv[1], &after) || before != after))
        status = PAM_AUTH_ERR;
done:
    if (handle) {
        int ended = pam_end(handle, status);
        if (ended) status = ended;
    }
    explicit_bzero(password, sizeof(password));
    munlock(password, sizeof(password));
    if (status != PAM_SUCCESS) return 1;
    unsigned char encoded[4] = {before >> 24, before >> 16, before >> 8, before};
    return write(STDOUT_FILENO, encoded, sizeof(encoded)) == sizeof(encoded) ? 0 : 1;
}
