/* Pure protocol helpers and negative real entry only; never loads AppArmor,
 * changes credentials, creates a namespace, or starts GTK/Python.
 */
#define main workspace_product_main
#include "../image/workspace_launcher.c"
#undef main

#define CHECK(condition) do { ++checks; if (!(condition)) { \
    fprintf(stderr, "launcher fixture assertion %u failed\n", checks); return 1; \
} } while (0)

int main(void)
{
    unsigned checks = 0;
    CHECK(identities(1000, 1000, 1000, 1000, 1000, 1000));
    CHECK(identities(65533, 65533, 65533, 100, 100, 100));
    CHECK(!identities(0, 0, 0, 0, 0, 0));
    CHECK(!identities(999, 999, 999, 1000, 1000, 1000));
    CHECK(!identities(65534, 65534, 65534, 1000, 1000, 1000));
    CHECK(!identities(1000, 0, 1000, 1000, 1000, 1000));
    CHECK(!identities(1000, 1000, 0, 1000, 1000, 1000));
    CHECK(!identities(1000, 1000, 1000, 1000, 0, 1000));
    CHECK(!identities(1000, 1000, 1000, 1000, 1000, 0));
    CHECK(!identities(1000, 1000, 1000, 0, 0, 0));
    CHECK(exact_label(LABEL, sizeof(LABEL) - 1));
    CHECK(!exact_label(LABEL, sizeof(LABEL)));
    const char *const bad_labels[] = { "unconfined\n", "luma-workspace\n",
        "luma-workspace (enforce)\n", "luma-workspace (complain)\n",
        "luma-workspace//&unprivileged_userns (mixed)\n",
        "other (unconfined)\n", "luma-workspace (unconfined)", "" };
    for (size_t i = 0; i < sizeof(bad_labels) / sizeof(bad_labels[0]); ++i)
        CHECK(!exact_label(bad_labels[i], strlen(bad_labels[i])));
    CHECK(display_name("wayland-0"));
    CHECK(display_name("wayland-10"));
    const char *const bad_displays[] = { "", "/run/user/1000/wayland-0", "../wayland-0",
        "wayland-", "wayland-x", "wayland-1/other", "wayland-999999999", "wayland-1\n" };
    for (size_t i = 0; i < sizeof(bad_displays) / sizeof(bad_displays[0]); ++i)
        CHECK(!display_name(bad_displays[i]));
    CHECK(!display_name(NULL));
    CHECK(safe_text("/home/user", PATH_MAX - 1));
    CHECK(!safe_text("/home/user\n", PATH_MAX - 1));
    CHECK(!safe_text("long", 3));
    CHECK(!safe_text(NULL, 32));
    CHECK(clearenv() == 0);
    CHECK(injection_absent());
    const char *const injected[] = { "LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT",
        "GTK_MODULES", "GTK_PATH", "GI_TYPELIB_PATH", "GIO_EXTRA_MODULES", "GCONV_PATH",
        "PYTHONHOME", "PYTHONPATH", "WEBKIT_DISABLE_SANDBOX_THIS_IS_DANGEROUS" };
    for (size_t i = 0; i < sizeof(injected) / sizeof(injected[0]); ++i) {
        CHECK(setenv(injected[i], "inert-fixture-not-loaded", 1) == 0);
        CHECK(!injection_absent());
        CHECK(unsetenv(injected[i]) == 0);
    }
    CHECK(!desktop_runtime("/tmp", "wayland-0", 1000));
    CHECK(!desktop_runtime("/run/user/1001", "wayland-0", 1000));
    CHECK(!actual_image_entry());
    char *const wrong_args[] = { "fixture", "unwanted", NULL };
    CHECK(workspace_product_main(2, (char **)wrong_args) == 1);
    printf("{\"assertions\":%u,\"actual_c_helpers\":true,\"profile_loaded\":false,\"gui_started\":false,\"namespace_created\":false}\n", checks);
    return 0;
}
