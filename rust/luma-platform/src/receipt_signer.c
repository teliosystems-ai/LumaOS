/* Fixed-purpose content-backup receipt crypto. This helper supplies no custody,
 * enrollment, grants or restore permission. The composition root must establish
 * those separately. Private seeds travel only through an anonymous locked memfd.
 */
#define _GNU_SOURCE
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/vfs.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <openssl/core_names.h>
#include <openssl/x509v3.h>

#define MAX_MESSAGE 65536U
#define MEMORY (64U * 1024U * 1024U)
static const unsigned char domain[] = "luma-content-backup-custody-receipt-v1";
static const unsigned char spki_prefix[12] = {
    0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00
};

static int transfer(int writing, unsigned char *data, size_t length)
{
    while (length) {
        ssize_t count = writing ? send(0, data, length, MSG_NOSIGNAL) : read(0, data, length);
        if (count < 0 && errno == EINTR) continue;
        if (count <= 0) return 0;
        data += (size_t)count;
        length -= (size_t)count;
    }
    return 1;
}

static uint32_t integer(const unsigned char *value)
{
    return ((uint32_t)value[0] << 24) | ((uint32_t)value[1] << 16)
        | ((uint32_t)value[2] << 8) | value[3];
}

static int private_descriptor(void)
{
    struct stat info;
    struct statfs volume;
    return fstat(3, &info) == 0 && S_ISREG(info.st_mode) && info.st_nlink == 0
        && info.st_uid == geteuid() && info.st_size == 32
        && fstatfs(3, &volume) == 0 && volume.f_type == 0x01021994
        && fcntl(3, F_GET_SEALS) >= 0;
}

static int digest(OSSL_LIB_CTX *library, const unsigned char *data, size_t size,
                  const unsigned char expected[32])
{
    unsigned char hash[32];
    size_t length = sizeof(hash);
    return EVP_Q_digest(library, "SHA256", "provider=default", data, size, hash, &length) == 1
        && length == sizeof(hash) && CRYPTO_memcmp(hash, expected, sizeof(hash)) == 0;
}

static X509 *recipient(OSSL_LIB_CTX *library, const unsigned char *der, size_t size,
                       const unsigned char pins[64])
{
    X509 *cert = NULL;
    EVP_PKEY *key = NULL;
    EVP_PKEY_CTX *check = NULL;
    BIGNUM *exponent = NULL;
    ASN1_BIT_STRING *usage = NULL;
    unsigned char *canonical = NULL, *spki = NULL;
    const unsigned char *cursor = der;
    int length, critical = -1, ok = 0;
    if (!size || size > 8192 || !digest(library, der, size, pins)) goto done;
    cert = X509_new_ex(library, "provider=default");
    if (!cert || !d2i_X509(&cert, &cursor, (long)size) || cursor != der + size) goto done;
    length = i2d_X509(cert, &canonical);
    if (length <= 0 || (size_t)length != size || CRYPTO_memcmp(der, canonical, size)) goto done;
    key = X509_get_pubkey(cert);
    if (!key || !EVP_PKEY_is_a(key, "RSA") || EVP_PKEY_get_bits(key) < 3072
        || EVP_PKEY_get_bits(key) > 8192
        || EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_E, &exponent) != 1
        || !BN_is_word(exponent, 65537)) goto done;
    check = EVP_PKEY_CTX_new_from_pkey(library, key, "provider=default");
    if (!check || EVP_PKEY_public_check(check) != 1) goto done;
    const ASN1_OCTET_STRING *identifier = X509_get0_subject_key_id(cert);
    int position = X509_get_ext_by_NID(cert, NID_subject_key_identifier, -1);
    if (!identifier || ASN1_STRING_length(identifier) < 20 || ASN1_STRING_length(identifier) > 32
        || position < 0 || X509_get_ext_by_NID(cert, NID_subject_key_identifier, position) >= 0) goto done;
    usage = X509_get_ext_d2i(cert, NID_key_usage, &critical, NULL);
    if (!usage || critical < 0 || ASN1_BIT_STRING_get_bit(usage, 0)
        || !ASN1_BIT_STRING_get_bit(usage, 2)) goto done;
    length = i2d_PUBKEY(key, &spki);
    if (length <= 0 || !digest(library, spki, (size_t)length, pins + 32)) goto done;
    ok = 1;
done:
    OPENSSL_free(canonical);
    OPENSSL_free(spki);
    BN_free(exponent);
    ASN1_BIT_STRING_free(usage);
    EVP_PKEY_CTX_free(check);
    EVP_PKEY_free(key);
    if (!ok) { X509_free(cert); cert = NULL; }
    return cert;
}

static int recipients(OSSL_LIB_CTX *library, const unsigned char *data, size_t size)
{
    if (size < 136) return 0;
    uint32_t owner_size = integer(data), admin_size = integer(data + 4);
    if (!owner_size || owner_size > 8192 || !admin_size || admin_size > 8192
        || size != 136U + owner_size + admin_size) return 0;
    X509 *owner = recipient(library, data + 136, owner_size, data + 8);
    X509 *admin = recipient(library, data + 136 + owner_size, admin_size, data + 72);
    EVP_PKEY *a = owner ? X509_get_pubkey(owner) : NULL;
    EVP_PKEY *b = admin ? X509_get_pubkey(admin) : NULL;
    BIGNUM *an = NULL, *bn = NULL, *gcd = BN_new();
    BN_CTX *context = BN_CTX_new();
    int ok = a && b && gcd && context && EVP_PKEY_eq(a, b) == 0
        && ASN1_OCTET_STRING_cmp(X509_get0_subject_key_id(owner), X509_get0_subject_key_id(admin)) != 0
        && EVP_PKEY_get_bn_param(a, OSSL_PKEY_PARAM_RSA_N, &an) == 1
        && EVP_PKEY_get_bn_param(b, OSSL_PKEY_PARAM_RSA_N, &bn) == 1
        && BN_gcd(gcd, an, bn, context) == 1 && BN_is_one(gcd);
    BN_free(an); BN_free(bn); BN_free(gcd); BN_CTX_free(context);
    EVP_PKEY_free(a); EVP_PKEY_free(b); X509_free(owner); X509_free(admin);
    return ok;
}

int main(int argc, char **argv)
{
    (void)argv;
    struct rlimit memory = {MEMORY, MEMORY}, core = {0, 0}, cpu = {10, 10};
    int socket_type = 0;
    socklen_t socket_size = sizeof(socket_type);
    /* Never read seed material before the entire helper address space is locked.
     * A missing locked-memory allowance is a refusal, not a pageable fallback. */
    if (argc != 1 || close_range(4, ~0U, 0) || setrlimit(RLIMIT_AS, &memory) || setrlimit(RLIMIT_CORE, &core)
        || setrlimit(RLIMIT_CPU, &cpu) || prctl(PR_SET_DUMPABLE, 0)
        || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
        || getsockopt(0, SOL_SOCKET, SO_TYPE, &socket_type, &socket_size)
        || socket_size != sizeof(socket_type) || socket_type != SOCK_STREAM)
        return 1;
    alarm(15);
    unsigned char header[32], seed[32] = {0}, public_key[44] = {0}, signature[64] = {0};
    unsigned char *message = NULL;
    EVP_PKEY *key = NULL;
    EVP_MD_CTX *operation = NULL;
    OSSL_LIB_CTX *library = NULL;
    OSSL_PROVIDER *provider = NULL;
    int ok = 0;
    uint32_t length = 0;
    if (!transfer(0, header, sizeof(header))
        || memcmp(header, "LUMARECEIPT01!!\n", 16)) goto cleanup;
    for (size_t i = 17; i < 24; i++) if (header[i]) goto cleanup;
    unsigned char mode = header[16];
    length = integer(header + 24);
    uint32_t public_length = integer(header + 28);
    if (mode < 1 || mode > 5 || length > MAX_MESSAGE
        || ((mode <= 2) && (length || public_length))
        || ((mode == 3) && public_length)
        || ((mode == 4) && public_length != sizeof(public_key))
        || ((mode == 5) && (public_length || length < 136))) goto cleanup;
    /* Verification handles public bytes only and can run without any private
     * memory allowance. All operations touching a seed must lock first. */
    if (mode <= 3 && mlockall(MCL_CURRENT | MCL_FUTURE)) goto cleanup;
    if (mode >= 3) {
        if (length <= sizeof(domain) || length > MAX_MESSAGE) goto cleanup;
        message = OPENSSL_malloc(length);
        if (!message || !transfer(0, message, length)
            || (mode <= 4 && memcmp(message, domain, sizeof(domain)))) goto cleanup;
    }
    library = OSSL_LIB_CTX_new();
    provider = library ? OSSL_PROVIDER_load(library, "default") : NULL;
    if (!provider) goto cleanup;
    if (mode >= 4 && close(3) != 0 && errno != EBADF) goto cleanup;
    if (mode == 5) {
        unsigned char verified = 1;
        ok = recipients(library, message, length) && transfer(1, &verified, 1);
        goto cleanup;
    }
    if (mode <= 3) {
        if (!private_descriptor()) goto cleanup;
        if (mode == 1) {
            if (RAND_priv_bytes_ex(library, seed, sizeof(seed), 256) != 1
                || pwrite(3, seed, sizeof(seed), 0) != (ssize_t)sizeof(seed)) goto cleanup;
        } else if (pread(3, seed, sizeof(seed), 0) != (ssize_t)sizeof(seed)) goto cleanup;
        key = EVP_PKEY_new_raw_private_key_ex(library, "ED25519", "provider=default", seed, sizeof(seed));
    } else {
        if (!transfer(0, public_key, sizeof(public_key))
            || memcmp(public_key, spki_prefix, sizeof(spki_prefix))
            || !transfer(0, signature, sizeof(signature))) goto cleanup;
        key = EVP_PKEY_new_raw_public_key_ex(library, "ED25519", "provider=default",
                                           public_key + sizeof(spki_prefix), 32);
    }
    if (!key) goto cleanup;
    if (mode <= 2) {
        memcpy(public_key, spki_prefix, sizeof(spki_prefix));
        size_t size = 32;
        if (EVP_PKEY_get_raw_public_key(key, public_key + sizeof(spki_prefix), &size) != 1
            || size != 32) goto cleanup;
        ok = transfer(1, public_key, sizeof(public_key));
    } else {
        operation = EVP_MD_CTX_new();
        if (!operation) goto cleanup;
        if (mode == 3) {
            size_t size = sizeof(signature);
            if (EVP_DigestSignInit_ex(operation, NULL, NULL, library, "provider=default", key, NULL) != 1
                || EVP_DigestSign(operation, signature, &size, message, length) != 1
                || size != sizeof(signature)) goto cleanup;
            ok = transfer(1, signature, sizeof(signature));
        } else {
            unsigned char verified = 1;
            if (EVP_DigestVerifyInit_ex(operation, NULL, NULL, library, "provider=default", key, NULL) != 1
                || EVP_DigestVerify(operation, signature, sizeof(signature), message, length) != 1)
                goto cleanup;
            ok = transfer(1, &verified, 1);
        }
    }
cleanup:
    OPENSSL_cleanse(seed, sizeof(seed));
    OPENSSL_cleanse(signature, sizeof(signature));
    EVP_MD_CTX_free(operation);
    EVP_PKEY_free(key);
    if (message) OPENSSL_clear_free(message, length);
    OSSL_PROVIDER_unload(provider);
    OSSL_LIB_CTX_free(library);
    return ok ? 0 : 1;
}
