#define _GNU_SOURCE
/* Nonprivileged fixed GUI entry. This named AppArmor domain grants userns
 * for WebKit's inherited bubblewrap sandbox, never product/PAM authority.
 * Kernel label formatting: Linux v6.8 security/apparmor/{label,policy}.c.
 */
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pwd.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statfs.h>
#include <sys/types.h>
#include <unistd.h>

#define LAUNCHER "/usr/libexec/luma-os/luma-workspace-launch"
#define SCRIPT "/usr/libexec/luma-os/workspace_app.py"
#define LABEL "luma-workspace (unconfined)\n"

static bool identities(uid_t real, uid_t effective, uid_t saved,
                       gid_t group, gid_t effective_group, gid_t saved_group)
{
    return real >= 1000 && real < 65534 && real == effective && real == saved
        && group != 0 && group == effective_group && group == saved_group;
}

static bool exact_label(const char *data, size_t size)
{
    return size == sizeof(LABEL) - 1 && memcmp(data, LABEL, size) == 0;
}

static bool display_name(const char *value)
{
    if (value == NULL || strncmp(value, "wayland-", 8) != 0)
        return false;
    size_t size = strlen(value);
    if (size < 9 || size > 16)
        return false;
    for (size_t i = 8; i < size; ++i)
        if (value[i] < '0' || value[i] > '9')
            return false;
    return true;
}

static bool safe_text(const char *value, size_t maximum)
{
    if (value == NULL || value[0] == '\0' || strlen(value) > maximum)
        return false;
    for (const unsigned char *p = (const unsigned char *)value; *p; ++p)
        if (*p < 32 || *p == 127)
            return false;
    return true;
}

static bool actual_label(void)
{
    int fd = open("/proc/self/attr/current", O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (fd < 0)
        return false;
    struct statfs filesystem;
    bool valid = fstatfs(fd, &filesystem) == 0 && filesystem.f_type == 0x9fa0;
    char value[128];
    size_t used = 0;
    while (valid && used < sizeof(value)) {
        ssize_t count = read(fd, value + used, sizeof(value) - used);
        if (count < 0 && errno == EINTR)
            continue;
        if (count < 0) {
            valid = false;
            break;
        }
        if (count == 0)
            break;
        used += (size_t)count;
    }
    close(fd);
    return valid && exact_label(value, used);
}

static bool actual_image_entry(void)
{
    char value[PATH_MAX + 1];
    ssize_t size = readlink("/proc/self/exe", value, PATH_MAX);
    if (size <= 0 || size >= PATH_MAX)
        return false;
    value[size] = '\0';
    if (strcmp(value, LAUNCHER) != 0)
        return false;
    struct stat executable;
    return stat("/proc/self/exe", &executable) == 0 && S_ISREG(executable.st_mode)
        && executable.st_uid == 0 && executable.st_nlink == 1
        && (executable.st_mode & 07777) == 0755;
}

static bool injection_absent(void)
{
    static const char *const forbidden[] = {
        "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "LD_DEBUG", "LD_PROFILE",
        "LD_ORIGIN_PATH", "GTK_MODULES", "GTK_PATH", "GI_TYPELIB_PATH",
        "GIO_EXTRA_MODULES", "GIO_MODULE_DIR", "GCONV_PATH", "PYTHONHOME",
        "PYTHONPATH", "PYTHONSTARTUP", "PYTHONINSPECT",
        "WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS"
    };
    for (size_t i = 0; i < sizeof(forbidden) / sizeof(forbidden[0]); ++i) {
        const char *value = getenv(forbidden[i]);
        if (value != NULL && value[0] != '\0')
            return false;
    }
    return true;
}

static bool owned_socket(int directory, const char *name, uid_t owner)
{
    struct stat member;
    return fstatat(directory, name, &member, AT_SYMLINK_NOFOLLOW) == 0
        && S_ISSOCK(member.st_mode) && member.st_uid == owner;
}

static bool desktop_runtime(const char *runtime, const char *display, uid_t owner)
{
    char expected[64];
    int length = snprintf(expected, sizeof(expected), "/run/user/%lu", (unsigned long)owner);
    const char *type = getenv("XDG_SESSION_TYPE");
    if (length <= 0 || (size_t)length >= sizeof(expected) || runtime == NULL
        || strcmp(runtime, expected) != 0 || !display_name(display)
        || type == NULL || strcmp(type, "wayland") != 0)
        return false;
    char resolved[PATH_MAX];
    if (realpath(runtime, resolved) == NULL || strcmp(resolved, expected) != 0)
        return false;
    int fd = open(runtime, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return false;
    struct stat held, named;
    bool valid = fstat(fd, &held) == 0 && lstat(runtime, &named) == 0
        && S_ISDIR(held.st_mode) && held.st_uid == owner
        && (held.st_mode & 07777) == 0700
        && held.st_dev == named.st_dev && held.st_ino == named.st_ino
        && owned_socket(fd, display, owner) && owned_socket(fd, "bus", owner);
    close(fd);
    return valid;
}

static int refuse(void)
{
    fputs("Luma workspace refused: fixed ordinary-user Wayland launcher, exact loaded AppArmor profile and protected image entry are required. No sandbox bypass or authority fallback.\n", stderr);
    return 1;
}

int main(int argc, char **argv)
{
    (void)argv;
    uid_t real, effective, saved;
    gid_t group, effective_group, saved_group;
    if (argc != 1 || getresuid(&real, &effective, &saved) != 0
        || getresgid(&group, &effective_group, &saved_group) != 0
        || !identities(real, effective, saved, group, effective_group, saved_group)
        || !injection_absent() || !actual_label() || !actual_image_entry())
        return refuse();

    const char *runtime_input = getenv("XDG_RUNTIME_DIR");
    const char *display_input = getenv("WAYLAND_DISPLAY");
    if (!desktop_runtime(runtime_input, display_input, real))
        return refuse();
    char runtime[64], display[17], bus[96];
    if (snprintf(runtime, sizeof(runtime), "%s", runtime_input) >= (int)sizeof(runtime)
        || snprintf(display, sizeof(display), "%s", display_input) >= (int)sizeof(display)
        || snprintf(bus, sizeof(bus), "unix:path=%s/bus", runtime) >= (int)sizeof(bus))
        return refuse();

    char password_buffer[16384];
    struct passwd account, *found = NULL;
    if (getpwuid_r(real, &account, password_buffer, sizeof(password_buffer), &found) != 0
        || found == NULL || found->pw_uid != real || found->pw_gid != group
        || !safe_text(found->pw_name, 32) || !safe_text(found->pw_dir, PATH_MAX - 1)
        || found->pw_dir[0] != '/')
        return refuse();
    if (clearenv() != 0
        || setenv("PATH", "/usr/bin:/bin", 1) != 0
        || setenv("LANG", "C.UTF-8", 1) != 0 || setenv("LC_ALL", "C.UTF-8", 1) != 0
        || setenv("GDK_BACKEND", "wayland", 1) != 0
        || setenv("XDG_SESSION_TYPE", "wayland", 1) != 0
        || setenv("XDG_SESSION_DESKTOP", "luma", 1) != 0
        || setenv("XDG_CURRENT_DESKTOP", "GNOME", 1) != 0
        || setenv("XDG_DATA_DIRS", "/usr/share", 1) != 0
        || setenv("XDG_CONFIG_DIRS", "/etc/xdg", 1) != 0
        || setenv("XDG_RUNTIME_DIR", runtime, 1) != 0
        || setenv("WAYLAND_DISPLAY", display, 1) != 0
        || setenv("DBUS_SESSION_BUS_ADDRESS", bus, 1) != 0
        || setenv("HOME", found->pw_dir, 1) != 0
        || setenv("USER", found->pw_name, 1) != 0
        || setenv("LOGNAME", found->pw_name, 1) != 0 || chdir("/") != 0)
        return refuse();
    umask(0077);
    if (close_range(3, ~0U, 0) != 0)
        return refuse();
    char *const command[] = { "/usr/bin/python3", "-I", SCRIPT, NULL };
    extern char **environ;
    execve(command[0], command, environ);
    return refuse();
}
