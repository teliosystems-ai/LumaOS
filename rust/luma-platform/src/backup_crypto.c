/* Fixed, isolated CMS backup helper. No paths, credentials, or algorithms in argv.
 * The parent supplies independently governed certificate/key pins and mediates
 * every protocol checkpoint. This program does not grant export/restore rights.
 */
#define _GNU_SOURCE
#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/cms.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/provider.h>
#include <openssl/rsa.h>
#include <openssl/x509v3.h>
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#define CHUNK 32768U
#define CERT_LIMIT 8192U
#define KEY_LIMIT 16384U
#define DATA_LIMIT (20U + 256U * 1024U + 64U * 1024U * 1024U)
#define CMS_LIMIT (DATA_LIMIT + 65536U)
#define CHILD_MEMORY (512U * 1024U * 1024U)
#define CHECK 1U
#define INPUT 2U
#define OUTPUT_BEGIN 3U
#define OUTPUT 4U
#define FINISHED 5U
#define ACK 0xa7U

static OSSL_LIB_CTX *library;
static const char *properties = "provider=default";

static int transfer(int writing, unsigned char *p, size_t size)
{
    while (size != 0) {
        ssize_t n = writing ? send(0, p, size, MSG_NOSIGNAL) : read(0, p, size);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return 0;
        p += (size_t)n;
        size -= (size_t)n;
    }
    return 1;
}

static uint64_t integer(const unsigned char *p, size_t size)
{
    uint64_t result = 0;
    while (size-- != 0)
        result = (result << 8) | *p++;
    return result;
}

static int event(unsigned char kind, uint64_t value)
{
    unsigned char message[9], ack;
    size_t i;
    message[0] = kind;
    for (i = 0; i < 8; i++)
        message[8 - i] = (unsigned char)(value >> (8 * i));
    return transfer(1, message, sizeof(message))
        && transfer(0, &ack, 1) && ack == ACK;
}

static int check(void)
{
    return event(CHECK, 0);
}

static long bio_check(BIO *bio, int operation, const char *argument,
                      size_t length, int integer_argument, long long_argument,
                      int result, size_t *processed)
{
    int action = operation & ~BIO_CB_RETURN;
    (void)bio;
    (void)argument;
    (void)length;
    (void)integer_argument;
    (void)long_argument;
    (void)processed;
    if ((operation & BIO_CB_RETURN) == 0
        && (action == BIO_CB_READ || action == BIO_CB_WRITE)
        && !check())
        return 0;
    return result;
}

static int digest(const unsigned char *data, size_t length,
                   unsigned char output[32])
{
    size_t actual = 0;
    return EVP_Q_digest(library, "SHA256", properties, data, length,
                        output, &actual) == 1 && actual == 32;
}

/* Only definite, minimally encoded DER TLVs of this closed profile are read.
 * OpenSSL performs the full CMS/algorithm decoding. The walk makes the content
 * cipher, nonce/tag sizes, attributes, and embedded-data shape non-negotiable.
 */
typedef struct { const unsigned char *p; size_t left; } view;

static int take(view *input, unsigned char wanted, view *contents)
{
    const unsigned char *start = input->p, *next;
    size_t header = 2, length, count, i;
    long decoded;
    int tag, cls, flags;
    if (input->left < 2 || start[0] != wanted || (wanted & 31) == 31)
        return 0;
    if ((start[1] & 128) == 0) {
        length = start[1];
    } else {
        count = start[1] & 127;
        if (count == 0 || count > sizeof(size_t)
            || count > input->left - 2 || start[2] == 0)
            return 0;
        length = 0;
        for (i = 0; i < count; i++) {
            if (length > SIZE_MAX >> 8)
                return 0;
            length = (length << 8) | start[2 + i];
        }
        if (length < 128)
            return 0;
        header += count;
    }
    if (header > input->left || length > input->left - header
        || input->left > LONG_MAX)
        return 0;
    next = start;
    flags = ASN1_get_object(&next, &decoded, &tag, &cls, (long)input->left);
    if ((flags & (0x80 | 1)) != 0 || decoded < 0
        || (size_t)decoded != length || next != start + header
        || tag != (wanted & 31) || cls != (wanted & 0xc0)
        || (flags & V_ASN1_CONSTRUCTED) != (wanted & V_ASN1_CONSTRUCTED))
        return 0;
    contents->p = next;
    contents->left = length;
    input->p += header + length;
    input->left -= header + length;
    return 1;
}

static int oid(view *input, int expected)
{
    const unsigned char *start = input->p, *next = start;
    size_t before = input->left;
    view contents;
    ASN1_OBJECT *object;
    int ok;
    if (!take(input, 6, &contents))
        return 0;
    object = d2i_ASN1_OBJECT(NULL, &next, (long)(before - input->left));
    ok = object != NULL && next == input->p && OBJ_obj2nid(object) == expected;
    ASN1_OBJECT_free(object);
    return ok;
}

static int small_integer(view *input, unsigned char expected)
{
    view contents;
    return take(input, 2, &contents) && contents.left == 1
        && contents.p[0] == expected;
}

static int closed_content_profile(const unsigned char *der, size_t size,
                                   size_t *encrypted_size)
{
    view whole = {der, size}, ci, explicit_content, auth, recipients, recipient;
    view identifier, key_algorithm, wrapped;
    view encrypted, algorithm, parameters, nonce, bytes, mac;
    size_t count = 0;
    if (!take(&whole, 0x30, &ci) || whole.left != 0
        || !oid(&ci, NID_id_smime_ct_authEnvelopedData)
        || !take(&ci, 0xa0, &explicit_content) || ci.left != 0
        || !take(&explicit_content, 0x30, &auth) || explicit_content.left != 0
        || !small_integer(&auth, 0)
        || !take(&auth, 0x31, &recipients))
        return 0;
    while (recipients.left != 0) {
        if (++count > 2 || !take(&recipients, 0x30, &recipient)
            || !small_integer(&recipient, 2)
            || !take(&recipient, 0x80, &identifier)
            || identifier.left < 20 || identifier.left > 32
            || !take(&recipient, 0x30, &key_algorithm)
            || key_algorithm.left == 0 || key_algorithm.left > 256
            || !take(&recipient, 4, &wrapped)
            || wrapped.left < 384 || wrapped.left > 1024 || recipient.left != 0)
            return 0;
    }
    if (count != 2 || !take(&auth, 0x30, &encrypted)
        || !oid(&encrypted, NID_pkcs7_data)
        || !take(&encrypted, 0x30, &algorithm)
        || !oid(&algorithm, NID_aes_256_gcm)
        || !take(&algorithm, 0x30, &parameters) || algorithm.left != 0
        || !take(&parameters, 4, &nonce) || nonce.left != 12
        || !small_integer(&parameters, 16) || parameters.left != 0
        || !take(&encrypted, 0x80, &bytes) || encrypted.left != 0
        || bytes.left == 0 || bytes.left > DATA_LIMIT
        || !take(&auth, 4, &mac) || mac.left != 16 || auth.left != 0)
        return 0;
    *encrypted_size = bytes.left;
    return 1;
}

static int algorithm_is(const X509_ALGOR *algorithm, int nid)
{
    const ASN1_OBJECT *object;
    int type;
    const void *parameter;
    if (algorithm == NULL)
        return 0;
    X509_ALGOR_get0(&object, &type, &parameter, algorithm);
    (void)parameter;
    return OBJ_obj2nid(object) == nid
        && (type == V_ASN1_UNDEF || type == V_ASN1_NULL);
}

static int oaep_profile(X509_ALGOR *algorithm)
{
    const ASN1_OBJECT *object;
    const void *parameter;
    const ASN1_STRING *encoded;
    const unsigned char *p, *end;
    RSA_OAEP_PARAMS *oaep = NULL;
    X509_ALGOR *mask_hash = NULL;
    unsigned char *canonical = NULL;
    int type, n, ok = 0;
    X509_ALGOR_get0(&object, &type, &parameter, algorithm);
    if (OBJ_obj2nid(object) != NID_rsaesOaep || type != V_ASN1_SEQUENCE)
        return 0;
    encoded = parameter;
    if (ASN1_STRING_length(encoded) <= 0 || ASN1_STRING_length(encoded) > 256)
        return 0;
    p = ASN1_STRING_get0_data(encoded);
    end = p + ASN1_STRING_length(encoded);
    oaep = d2i_RSA_OAEP_PARAMS(NULL, &p, ASN1_STRING_length(encoded));
    if (oaep == NULL || p != end
        || !algorithm_is(oaep->hashFunc, NID_sha256)
        || oaep->maskGenFunc == NULL || oaep->pSourceFunc != NULL)
        goto done;
    n = i2d_RSA_OAEP_PARAMS(oaep, &canonical);
    if (n <= 0 || n != ASN1_STRING_length(encoded)
        || CRYPTO_memcmp(canonical, ASN1_STRING_get0_data(encoded), (size_t)n) != 0)
        goto done;
    OPENSSL_free(canonical);
    canonical = NULL;
    X509_ALGOR_get0(&object, &type, &parameter, oaep->maskGenFunc);
    if (OBJ_obj2nid(object) != NID_mgf1 || type != V_ASN1_SEQUENCE)
        goto done;
    encoded = parameter;
    if (ASN1_STRING_length(encoded) <= 0 || ASN1_STRING_length(encoded) > 64)
        goto done;
    p = ASN1_STRING_get0_data(encoded);
    end = p + ASN1_STRING_length(encoded);
    mask_hash = d2i_X509_ALGOR(NULL, &p, ASN1_STRING_length(encoded));
    if (mask_hash == NULL || p != end || !algorithm_is(mask_hash, NID_sha256))
        goto done;
    n = i2d_X509_ALGOR(mask_hash, &canonical);
    ok = n > 0 && n == ASN1_STRING_length(encoded)
        && CRYPTO_memcmp(canonical, ASN1_STRING_get0_data(encoded), (size_t)n) == 0;
done:
    OPENSSL_free(canonical);
    X509_ALGOR_free(mask_hash);
    RSA_OAEP_PARAMS_free(oaep);
    return ok;
}

static X509 *certificate(const unsigned char *der, size_t size,
                          const unsigned char expected_cert[32],
                          const unsigned char expected_spki[32])
{
    const unsigned char *p = der;
    unsigned char hash[32], *canonical = NULL, *public_der = NULL;
    X509 *cert = NULL;
    EVP_PKEY *public_key = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    BIGNUM *exponent = NULL;
    const ASN1_OCTET_STRING *identifier;
    int n = 0, ok = 0;
    if (size == 0 || size > CERT_LIMIT || !digest(der, size, hash)
        || CRYPTO_memcmp(hash, expected_cert, 32) != 0)
        goto done;
    cert = X509_new_ex(library, properties);
    if (cert == NULL || d2i_X509(&cert, &p, (long)size) == NULL || p != der + size)
        goto done;
    n = i2d_X509(cert, &canonical);
    if (n <= 0 || (size_t)n != size || CRYPTO_memcmp(canonical, der, size) != 0)
        goto done;
    public_key = X509_get_pubkey(cert);
    if (public_key == NULL || !EVP_PKEY_is_a(public_key, "RSA")
        || EVP_PKEY_get_bits(public_key) < 3072
        || EVP_PKEY_get_bits(public_key) > 8192
        || !EVP_PKEY_get_bn_param(public_key, OSSL_PKEY_PARAM_RSA_E, &exponent)
        || !BN_is_word(exponent, 65537))
        goto done;
    ctx = EVP_PKEY_CTX_new_from_pkey(library, public_key, properties);
    if (ctx == NULL || EVP_PKEY_public_check(ctx) != 1)
        goto done;
    identifier = X509_get0_subject_key_id(cert);
    if (identifier == NULL || ASN1_STRING_length(identifier) < 20
        || ASN1_STRING_length(identifier) > 32)
        goto done;
    n = i2d_PUBKEY(public_key, &public_der);
    if (n <= 0 || !digest(public_der, (size_t)n, hash)
        || CRYPTO_memcmp(hash, expected_spki, 32) != 0)
        goto done;
    ok = 1;
done:
    OPENSSL_free(canonical);
    OPENSSL_free(public_der);
    BN_free(exponent);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(public_key);
    if (!ok) {
        X509_free(cert);
        cert = NULL;
    }
    return cert;
}

static int independent(X509 *owner, X509 *admin)
{
    EVP_PKEY *a = X509_get_pubkey(owner), *b = X509_get_pubkey(admin);
    BIGNUM *an = NULL, *bn = NULL, *gcd = BN_new();
    BN_CTX *ctx = BN_CTX_new();
    const ASN1_OCTET_STRING *ai = X509_get0_subject_key_id(owner);
    const ASN1_OCTET_STRING *bi = X509_get0_subject_key_id(admin);
    int ok = a != NULL && b != NULL && gcd != NULL && ctx != NULL
        && EVP_PKEY_eq(a, b) == 0 && ASN1_OCTET_STRING_cmp(ai, bi) != 0
        && EVP_PKEY_get_bn_param(a, OSSL_PKEY_PARAM_RSA_N, &an) == 1
        && EVP_PKEY_get_bn_param(b, OSSL_PKEY_PARAM_RSA_N, &bn) == 1
        && BN_gcd(gcd, an, bn, ctx) == 1 && BN_is_one(gcd);
    BN_free(an);
    BN_free(bn);
    BN_free(gcd);
    BN_CTX_free(ctx);
    EVP_PKEY_free(a);
    EVP_PKEY_free(b);
    return ok;
}

static int recipients_profile(CMS_ContentInfo *cms, X509 *certs[2])
{
    STACK_OF(CMS_RecipientInfo) *recipients = CMS_get0_RecipientInfos(cms);
    unsigned int seen = 0;
    int i, slot;
    if (OBJ_obj2nid(CMS_get0_type(cms)) != NID_id_smime_ct_authEnvelopedData
        || recipients == NULL || sk_CMS_RecipientInfo_num(recipients) != 2)
        return 0;
    for (i = 0; i < 2; i++) {
        CMS_RecipientInfo *ri = sk_CMS_RecipientInfo_value(recipients, i);
        ASN1_OCTET_STRING *identifier = NULL;
        X509_NAME *issuer = NULL;
        ASN1_INTEGER *serial = NULL;
        X509_ALGOR *algorithm = NULL;
        if (CMS_RecipientInfo_type(ri) != CMS_RECIPINFO_TRANS
            || CMS_RecipientInfo_ktri_get0_signer_id(ri, &identifier,
                                                    &issuer, &serial) != 1
            || identifier == NULL || issuer != NULL || serial != NULL
            || CMS_RecipientInfo_ktri_get0_algs(ri, NULL, NULL, &algorithm) != 1
            || algorithm == NULL || !oaep_profile(algorithm))
            return 0;
        slot = CMS_RecipientInfo_ktri_cert_cmp(ri, certs[0]) == 0 ? 0 : 1;
        if (CMS_RecipientInfo_ktri_cert_cmp(ri, certs[slot]) != 0
            || (seen & (1U << slot)) != 0)
            return 0;
        seen |= 1U << slot;
    }
    return seen == 3;
}

static int canonical_cms(CMS_ContentInfo *cms, const unsigned char *der,
                          size_t length)
{
    unsigned char *canonical = NULL;
    int n;
    int ok;
    if (!check())
        return 0;
    n = i2d_CMS_ContentInfo(cms, NULL);
    if (n <= 0 || (size_t)n != length || (size_t)n > CMS_LIMIT)
        return 0;
    canonical = OPENSSL_malloc((size_t)n);
    if (canonical == NULL)
        return 0;
    {
        unsigned char *cursor = canonical;
        ok = i2d_CMS_ContentInfo(cms, &cursor) == n
            && cursor == canonical + n
            && CRYPTO_memcmp(canonical, der, length) == 0 && check();
    }
    OPENSSL_free(canonical);
    return ok;
}

static CMS_ContentInfo *encrypt_data(const unsigned char *input, size_t size,
                                     X509 *certs[2])
{
    CMS_ContentInfo *cms = NULL;
    EVP_CIPHER *cipher = NULL;
    BIO *source = NULL;
    int i, ok = 0;
    if (!check())
        goto done;
    cipher = EVP_CIPHER_fetch(library, "AES-256-GCM", properties);
    if (cipher == NULL)
        goto done;
    cms = CMS_encrypt_ex(NULL, NULL, cipher, CMS_PARTIAL | CMS_BINARY,
                         library, properties);
    if (cms == NULL)
        goto done;
    for (i = 0; i < 2; i++) {
        CMS_RecipientInfo *ri;
        EVP_PKEY_CTX *ctx;
        if (!check())
            goto done;
        ri = CMS_add1_recipient_cert(cms, certs[i], CMS_USE_KEYID | CMS_KEY_PARAM);
        ctx = ri == NULL ? NULL : CMS_RecipientInfo_get0_pkey_ctx(ri);
        if (ctx == NULL || EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING) <= 0
            || EVP_PKEY_CTX_set_rsa_oaep_md_name(ctx, "SHA256", properties) <= 0
            || EVP_PKEY_CTX_set_rsa_mgf1_md_name(ctx, "SHA256", properties) <= 0)
            goto done;
    }
    source = BIO_new_mem_buf(input, (int)size);
    if (source == NULL)
        goto done;
    BIO_set_callback_ex(source, bio_check);
    if (!check() || CMS_final(cms, source, NULL, CMS_BINARY) != 1
        || !check() || !recipients_profile(cms, certs))
        goto done;
    ok = 1;
done:
    BIO_free(source);
    EVP_CIPHER_free(cipher);
    if (!ok) {
        CMS_ContentInfo_free(cms);
        cms = NULL;
    }
    return cms;
}

static EVP_PKEY *private_key(size_t length, X509 *selected)
{
    unsigned char *der = NULL, *canonical = NULL;
    const unsigned char *p;
    PKCS8_PRIV_KEY_INFO *info = NULL;
    EVP_PKEY *key = NULL, *public_key = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    struct stat st;
    size_t offset = 0;
    int n = 0, ok = 0;
    if (length == 0 || length > KEY_LIMIT || fstat(3, &st) != 0
        || !S_ISREG(st.st_mode) || st.st_size != (off_t)length || !check())
        goto done;
    der = OPENSSL_malloc(length);
    if (der == NULL)
        goto done;
    while (offset < length) {
        ssize_t count = pread(3, der + offset, length - offset, (off_t)offset);
        if (count < 0 && errno == EINTR)
            continue;
        if (count <= 0)
            goto done;
        offset += (size_t)count;
    }
    p = der;
    info = d2i_PKCS8_PRIV_KEY_INFO(NULL, &p, (long)length);
    if (info == NULL || p != der + length)
        goto done;
    n = i2d_PKCS8_PRIV_KEY_INFO(info, &canonical);
    if (n <= 0 || (size_t)n != length || CRYPTO_memcmp(canonical, der, length) != 0)
        goto done;
    key = EVP_PKCS82PKEY_ex(info, library, properties);
    public_key = X509_get_pubkey(selected);
    if (key == NULL || public_key == NULL || EVP_PKEY_eq(key, public_key) != 1
        || !check())
        goto done;
    ctx = EVP_PKEY_CTX_new_from_pkey(library, key, properties);
    if (ctx == NULL || EVP_PKEY_private_check(ctx) != 1 || !check())
        goto done;
    ok = 1;
done:
    OPENSSL_clear_free(der, length);
    OPENSSL_clear_free(canonical, canonical == NULL || n <= 0 ? 0 : (size_t)n);
    if (info != NULL) {
        const unsigned char *private_octets = NULL;
        int private_length = 0;
        if (PKCS8_pkey_get0(NULL, &private_octets, &private_length, NULL, info) == 1
            && private_length > 0)
            OPENSSL_cleanse((void *)private_octets, (size_t)private_length);
    }
    PKCS8_PRIV_KEY_INFO_free(info);
    EVP_PKEY_free(public_key);
    EVP_PKEY_CTX_free(ctx);
    if (!ok) {
        EVP_PKEY_free(key);
        key = NULL;
    }
    return key;
}

static int protect_process(void)
{
    struct rlimit core = {0, 0}, address, cpu = {120, 120};
    int kind;
    socklen_t size = sizeof(kind);
    if (getsockopt(0, SOL_SOCKET, SO_TYPE, &kind, &size) != 0
        || kind != SOCK_STREAM || getrlimit(RLIMIT_AS, &address) != 0)
        return 0;
    if (address.rlim_cur > CHILD_MEMORY)
        address.rlim_cur = CHILD_MEMORY;
    if (address.rlim_max > CHILD_MEMORY)
        address.rlim_max = CHILD_MEMORY;
    if (setrlimit(RLIMIT_AS, &address) != 0
        || setrlimit(RLIMIT_CORE, &core) != 0
        || setrlimit(RLIMIT_CPU, &cpu) != 0
        || prctl(PR_SET_DUMPABLE, 0) != 0
        || prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0
        || mlockall(MCL_CURRENT | MCL_FUTURE) != 0)
        return 0;
    alarm(1800);
    return 1;
}

int main(int argc, char **argv)
{
    static const unsigned char magic[16] = "LUMACMSBACKUP01\n";
    unsigned char header[200], hash[32];
    unsigned char *cert_der[2] = {NULL, NULL};
    unsigned char *input = NULL, *encoded = NULL;
    X509 *certs[2] = {NULL, NULL};
    OSSL_PROVIDER *provider = NULL;
    CMS_ContentInfo *cms = NULL;
    EVP_PKEY *key = NULL;
    BIO *plain = NULL;
    const unsigned char *cursor, *result = NULL;
    long plain_length = 0;
    size_t cert_size[2] = {0, 0}, input_size = 0, output_size = 0;
    size_t key_size, encrypted_size, offset, count;
    uint64_t wire_input_size;
    unsigned int mode, slot;
    int n, i, ok = 0;
    (void)argv;
    if (argc != 1 || !protect_process())
        goto done;
    /* Retain only the duplex socket and the optional anonymous private key.
     * stdout/stderr are /dev/null; no inherited directory or TPM descriptors.
     */
    if (close_range(4, UINT_MAX, 0) != 0)
        goto done;
    library = OSSL_LIB_CTX_new();
    if (library == NULL || (provider = OSSL_PROVIDER_load(library, "default")) == NULL
        || !transfer(0, header, sizeof(header))
        || CRYPTO_memcmp(header, magic, 16) != 0
        || header[18] != 0 || header[19] != 0)
        goto done;
    mode = header[16];
    slot = header[17];
    key_size = (size_t)integer(header + 20, 4);
    cert_size[0] = (size_t)integer(header + 24, 4);
    cert_size[1] = (size_t)integer(header + 28, 4);
    wire_input_size = integer(header + 32, 8);
    if ((mode != 1 && mode != 2) || (mode == 1 && (slot != 255 || key_size != 0))
        || (mode == 2 && (slot > 1 || key_size == 0 || key_size > KEY_LIMIT))
        || wire_input_size == 0 || wire_input_size > (mode == 1 ? DATA_LIMIT : CMS_LIMIT))
        goto done;
    input_size = (size_t)wire_input_size;
    if (mode == 1)
        close(3);
    for (i = 0; i < 2; i++) {
        if (cert_size[i] == 0 || cert_size[i] > CERT_LIMIT)
            goto done;
        cert_der[i] = OPENSSL_malloc(cert_size[i]);
        if (cert_der[i] == NULL || !transfer(0, cert_der[i], cert_size[i]))
            goto done;
    }
    for (i = 0; i < 2; i++) {
        if (!check())
            goto done;
        certs[i] = certificate(cert_der[i], cert_size[i], header + 72 + 64 * i,
                                header + 104 + 64 * i);
        if (certs[i] == NULL || !check())
            goto done;
    }
    if (!independent(certs[0], certs[1]) || !check())
        goto done;
    input = OPENSSL_malloc(input_size);
    if (input == NULL)
        goto done;
    for (offset = 0; offset < input_size; offset += count) {
        count = input_size - offset < CHUNK ? input_size - offset : CHUNK;
        if (!event(INPUT, count) || !transfer(0, input + offset, count))
            goto done;
    }
    if (!check() || !digest(input, input_size, hash)
        || CRYPTO_memcmp(hash, header + 40, 32) != 0 || !check())
        goto done;
    if (mode == 1) {
        cms = encrypt_data(input, input_size, certs);
        if (cms == NULL || !check())
            goto done;
        n = i2d_CMS_ContentInfo(cms, NULL);
        if (n <= 0 || (size_t)n > CMS_LIMIT)
            goto done;
        encoded = OPENSSL_malloc((size_t)n);
        if (encoded == NULL)
            goto done;
        {
            unsigned char *destination = encoded;
            if (i2d_CMS_ContentInfo(cms, &destination) != n || destination != encoded + n)
                goto done;
        }
        if (!closed_content_profile(encoded, (size_t)n, &encrypted_size)
            || encrypted_size != input_size || !check())
            goto done;
        result = encoded;
        output_size = (size_t)n;
    } else {
        if (!closed_content_profile(input, input_size, &encrypted_size) || !check())
            goto done;
        cursor = input;
        cms = CMS_ContentInfo_new_ex(library, properties);
        if (cms == NULL || d2i_CMS_ContentInfo(&cms, &cursor, (long)input_size) == NULL
            || cursor != input + input_size || !recipients_profile(cms, certs)
            || !canonical_cms(cms, input, input_size)
            || (key = private_key(key_size, certs[slot])) == NULL)
            goto done;
        plain = BIO_new(BIO_s_mem());
        if (plain == NULL)
            goto done;
        BIO_set_callback_ex(plain, bio_check);
        if (!check() || CMS_decrypt(cms, key, certs[slot], NULL, plain, CMS_BINARY) != 1
            || !check())
            goto done;
        plain_length = BIO_get_mem_data(plain, &result);
        if (plain_length <= 0 || (size_t)plain_length != encrypted_size)
            goto done;
        output_size = (size_t)plain_length;
    }
    if (!event(OUTPUT_BEGIN, output_size))
        goto done;
    for (offset = 0; offset < output_size; offset += count) {
        count = output_size - offset < CHUNK ? output_size - offset : CHUNK;
        if (!event(OUTPUT, count)
            || !transfer(1, (unsigned char *)result + offset, count))
            goto done;
    }
    if (!event(FINISHED, output_size))
        goto done;
    ok = 1;
done:
    if (plain != NULL) {
        char *sensitive = NULL;
        long length = BIO_get_mem_data(plain, &sensitive);
        if (length > 0)
            OPENSSL_cleanse(sensitive, (size_t)length);
    }
    BIO_free(plain);
    EVP_PKEY_free(key);
    CMS_ContentInfo_free(cms);
    OPENSSL_clear_free(input, input_size);
    OPENSSL_free(encoded);
    for (i = 0; i < 2; i++) {
        X509_free(certs[i]);
        OPENSSL_free(cert_der[i]);
    }
    OPENSSL_cleanse(header, sizeof(header));
    OPENSSL_cleanse(hash, sizeof(hash));
    OSSL_PROVIDER_unload(provider);
    OSSL_LIB_CTX_free(library);
    ERR_clear_error();
    return ok ? 0 : 1;
}
