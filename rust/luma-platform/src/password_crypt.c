/* Distribution libxcrypt adapter; no cryptographic algorithm is implemented here. */
#define _GNU_SOURCE
#include <crypt.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

size_t luma_password_context_size(void) { return sizeof(struct crypt_data); }

int luma_password_hash(const char *password, const uint8_t *entropy,
                       void *context, size_t context_len,
                       char *output, size_t output_len) {
    if (!password || !entropy || !context || context_len != sizeof(struct crypt_data)
        || !output || output_len < CRYPT_OUTPUT_SIZE) return -1;
    struct crypt_data *data = context;
    char salt[CRYPT_GENSALT_OUTPUT_SIZE];
    memset(data, 0, sizeof(*data));
    if (!crypt_gensalt_rn("$y$", 0, (const char *)entropy, 32, salt, sizeof(salt))) return -2;
    char *result = crypt_r(password, salt, data);
    if (!result || strncmp(result, "$y$", 3) || strlen(result) >= output_len) return -3;
    memcpy(output, result, strlen(result) + 1);
    /* The Rust mapping owner also wipes the complete context on every exit. */
    volatile unsigned char *wipe = (volatile unsigned char *)data;
    for (size_t i = 0; i < sizeof(*data); i++) wipe[i] = 0;
    return 0;
}

int luma_password_verify(const char *password, const char *hash,
                         void *context, size_t context_len) {
    if (!password || !hash || !context || context_len != sizeof(struct crypt_data)
        || strncmp(hash, "$y$", 3)) return -1;
    struct crypt_data *data = context;
    memset(data, 0, sizeof(*data));
    char *result = crypt_r(password, hash, data);
    if (!result || strncmp(result, "$y$", 3)) return -2;
    size_t length = strlen(hash);
    unsigned int different = strlen(result) != length;
    for (size_t i = 0; i < length && i < CRYPT_OUTPUT_SIZE; i++)
        different |= (unsigned char)hash[i] ^ (unsigned char)result[i];
    volatile unsigned char *wipe = (volatile unsigned char *)data;
    for (size_t i = 0; i < sizeof(*data); i++) wipe[i] = 0;
    return different ? 1 : 0;
}
