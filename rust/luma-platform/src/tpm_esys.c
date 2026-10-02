/* Fixed-width adapter to the packaged TPM2-TSS ESAPI, not a policy engine.
 * No shell, file credentials or global-handle flushing. The fixed provisioning
 * boundary uses existing owner authorization; it never changes any hierarchy.
 * Caller owns the context exclusively. Every authorization uses an HMAC
 * session, never ESYS_TR_PASSWORD. Provisioning encrypts the new NV auth value.
 */
#define _DEFAULT_SOURCE
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/sha.h>
#include <tss2/tss2_esys.h>
#include <tss2/tss2_mu.h>
#include <tss2/tss2_tctildr.h>

struct luma_tpm {
    TSS2_TCTI_CONTEXT *tcti;
    ESYS_CONTEXT *esys;
    ESYS_TR nv;
    ESYS_TR session;
};

void luma_tpm_close(struct luma_tpm *ctx) {
    if (!ctx) return;
    if (ctx->esys) {
        if (ctx->session != ESYS_TR_NONE) Esys_FlushContext(ctx->esys, ctx->session);
        if (ctx->nv != ESYS_TR_NONE) Esys_TR_Close(ctx->esys, &ctx->nv);
        Esys_Finalize(&ctx->esys);
    }
    if (ctx->tcti) Tss2_TctiLdr_Finalize(&ctx->tcti);
    explicit_bzero(ctx, sizeof(*ctx));
    free(ctx);
}

uint32_t luma_tpm_open(const char *transport, struct luma_tpm **result) {
    *result = NULL;
    struct luma_tpm *ctx = calloc(1, sizeof(*ctx));
    if (!ctx) return TSS2_ESYS_RC_MEMORY;
    ctx->nv = ctx->session = ESYS_TR_NONE;
    TSS2_RC rc = Tss2_TctiLdr_Initialize(transport, &ctx->tcti);
    if (!rc) rc = Esys_Initialize(&ctx->esys, ctx->tcti, NULL);
    if (!rc) rc = Esys_SetTimeout(ctx->esys, 5000);
    if (rc) { luma_tpm_close(ctx); return rc; }
    *result = ctx;
    return TSS2_RC_SUCCESS;
}

uint32_t luma_tpm_clock(struct luma_tpm *ctx, uint64_t *clock,
                       uint32_t *reset, uint32_t *restart, uint8_t *safe) {
    TPMS_TIME_INFO *info = NULL;
    TSS2_RC rc = Esys_ReadClock(ctx->esys, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &info);
    if (!rc) {
        *clock = info->clockInfo.clock;
        *reset = info->clockInfo.resetCount;
        *restart = info->clockInfo.restartCount;
        *safe = info->clockInfo.safe;
    }
    Esys_Free(info);
    return rc;
}

uint32_t luma_tpm_pcrs(struct luma_tpm *ctx, uint8_t output[64]) {
    TPML_PCR_SELECTION selection = { .count = 1, .pcrSelections = {
        { .hash = TPM2_ALG_SHA256, .sizeofSelect = 3, .pcrSelect = {0x80, 0x08, 0} }
    }};
    uint32_t counter;
    TPML_PCR_SELECTION *returned = NULL;
    TPML_DIGEST *values = NULL;
    TSS2_RC rc = Esys_PCR_Read(ctx->esys, ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
                             &selection, &counter, &returned, &values);
    if (!rc) {
        if (returned->count != 1 || returned->pcrSelections[0].hash != TPM2_ALG_SHA256 ||
            returned->pcrSelections[0].sizeofSelect != 3 ||
            memcmp(returned->pcrSelections[0].pcrSelect, selection.pcrSelections[0].pcrSelect, 3) ||
            values->count != 2 || values->digests[0].size != 32 || values->digests[1].size != 32)
            rc = TSS2_ESYS_RC_BAD_VALUE;
        else {
            memcpy(output, values->digests[0].buffer, 32);
            memcpy(output + 32, values->digests[1].buffer, 32);
        }
    }
    Esys_Free(returned); Esys_Free(values);
    return rc;
}

/* Read-only allocation check. Absence is not a reservation or permission to
 * provision; GetCapability errors must never be interpreted as an empty slot. */
uint32_t luma_tpm_index_exists(struct luma_tpm *ctx, uint32_t index, uint8_t *exists) {
    TPMS_CAPABILITY_DATA *data = NULL;
    TPMI_YES_NO more = 0;
    *exists = 1;
    TSS2_RC rc = Esys_GetCapability(ctx->esys, ESYS_TR_NONE, ESYS_TR_NONE,
        ESYS_TR_NONE, TPM2_CAP_HANDLES, index, 1, &more, &data);
    if (!rc) {
        if (!data || data->capability != TPM2_CAP_HANDLES ||
            data->data.handles.count > 1 ||
            (data->data.handles.count && data->data.handles.handle[0] < index) ||
            (!data->data.handles.count && more))
            rc = TSS2_ESYS_RC_BAD_VALUE;
        else *exists = data->data.handles.count && data->data.handles.handle[0] == index;
    }
    Esys_Free(data);
    return rc;
}

uint32_t luma_tpm_index(struct luma_tpm *ctx, uint32_t index, const uint8_t auth[32],
                       uint8_t name_out[34], uint32_t *attributes, uint16_t *size,
                       uint16_t *algorithm, uint16_t *policy_size) {
    if (ctx->nv != ESYS_TR_NONE) return TSS2_ESYS_RC_BAD_SEQUENCE;
    TSS2_RC rc = Esys_TR_FromTPMPublic(ctx->esys, index, ESYS_TR_NONE,
                                     ESYS_TR_NONE, ESYS_TR_NONE, &ctx->nv);
    TPM2B_NV_PUBLIC *public = NULL;
    TPM2B_NAME *name = NULL;
    if (!rc) rc = Esys_NV_ReadPublic(ctx->esys, ctx->nv, ESYS_TR_NONE,
                                    ESYS_TR_NONE, ESYS_TR_NONE, &public, &name);
    if (!rc) {
        if (name->size != 34) rc = TSS2_ESYS_RC_BAD_VALUE;
        else {
            memcpy(name_out, name->name, 34);
            *attributes = public->nvPublic.attributes;
            *size = public->nvPublic.dataSize;
            *algorithm = public->nvPublic.nameAlg;
            *policy_size = public->nvPublic.authPolicy.size;
        }
    }
    Esys_Free(public); Esys_Free(name);
    TPM2B_AUTH secret = {.size = 32};
    memcpy(secret.buffer, auth, 32);
    if (!rc) rc = Esys_TR_SetAuth(ctx->esys, ctx->nv, &secret);
    explicit_bzero(&secret, sizeof(secret));
    TPMT_SYM_DEF symmetric = {.algorithm = TPM2_ALG_NULL};
    if (!rc) rc = Esys_StartAuthSession(ctx->esys, ESYS_TR_NONE, ESYS_TR_NONE,
        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, NULL, TPM2_SE_HMAC,
        &symmetric, TPM2_ALG_SHA256, &ctx->session);
    if (!rc) rc = Esys_TRSess_SetAttributes(ctx->esys, ctx->session,
        TPMA_SESSION_CONTINUESESSION, TPMA_SESSION_CONTINUESESSION);
    return rc;
}

uint32_t luma_tpm_read(struct luma_tpm *ctx, uint8_t output[32]) {
    TPM2B_MAX_NV_BUFFER *value = NULL;
    TSS2_RC rc = Esys_NV_Read(ctx->esys, ctx->nv, ctx->nv, ctx->session,
                            ESYS_TR_NONE, ESYS_TR_NONE, 32, 0, &value);
    if (!rc) {
        if (value->size != 32) rc = TSS2_ESYS_RC_BAD_VALUE;
        else memcpy(output, value->buffer, 32);
    }
    Esys_Free(value);
    return rc;
}

uint32_t luma_tpm_extend(struct luma_tpm *ctx, const uint8_t digest[32]) {
    TPM2B_MAX_NV_BUFFER value = {.size = 32};
    memcpy(value.buffer, digest, 32);
    return Esys_NV_Extend(ctx->esys, ctx->nv, ctx->nv, ctx->session,
                         ESYS_TR_NONE, ESYS_TR_NONE, &value);
}

/* Caller must durably retain its sealed enrollment proposal before entry.
 * Any failure after DefineSpace may mean a persistent allocation exists.
 * There is intentionally NO rollback/undefine/clear/hierarchy-change path.
 * Owner auth belongs to the existing custodian, not Luma's NV authorization.
 */
uint32_t luma_tpm_provision_existing(struct luma_tpm *ctx,
    const uint8_t *owner, uint16_t owner_size, const uint8_t auth[32],
    const uint8_t genesis[32]) {
    if (!owner || !owner_size || owner_size > 64 || !auth || !genesis)
        return TSS2_ESYS_RC_BAD_VALUE;
    if (ctx->nv != ESYS_TR_NONE || ctx->session != ESYS_TR_NONE)
        return TSS2_ESYS_RC_BAD_SEQUENCE;
    const uint32_t index = 0x01804c41;
    uint8_t occupied = 1;
    TSS2_RC rc = luma_tpm_index_exists(ctx, index, &occupied);
    if (rc) return rc;
    if (occupied) return TSS2_ESYS_RC_BAD_VALUE;

    ESYS_TR initial = ESYS_TR_NONE, salt_key = ESYS_TR_NONE;
    ESYS_TR session = ESYS_TR_NONE, nv = ESYS_TR_NONE;
    TPMT_SYM_DEF plain = {.algorithm = TPM2_ALG_NULL};
    TPMT_SYM_DEF encrypted = {.algorithm = TPM2_ALG_AES,
        .keyBits = {.aes = 128}, .mode = {.aes = TPM2_ALG_CFB}};
    TPM2B_AUTH owner_auth = {.size = owner_size}, nv_auth = {.size = 32};
    memcpy(owner_auth.buffer, owner, owner_size);
    memcpy(nv_auth.buffer, auth, 32);

    /* This first HMAC session authorizes only an empty-auth NULL-hierarchy
     * transient key. No owner/NV secret is used until the salted session. */
    rc = Esys_StartAuthSession(ctx->esys, ESYS_TR_NONE, ESYS_TR_NONE,
        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, NULL, TPM2_SE_HMAC,
        &plain, TPM2_ALG_SHA256, &initial);
    if (!rc) rc = Esys_TRSess_SetAttributes(ctx->esys, initial,
        TPMA_SESSION_CONTINUESESSION, TPMA_SESSION_CONTINUESESSION);
    TPM2B_SENSITIVE_CREATE sensitive = {0};
    TPM2B_PUBLIC template = {.publicArea = {
        .type = TPM2_ALG_RSA, .nameAlg = TPM2_ALG_SHA256,
        .objectAttributes = TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
            TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_USERWITHAUTH |
            TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_DECRYPT,
        .parameters = {.rsaDetail = {
            .symmetric = {.algorithm = TPM2_ALG_AES, .keyBits = {.aes = 128},
                          .mode = {.aes = TPM2_ALG_CFB}},
            .scheme = {.scheme = TPM2_ALG_NULL}, .keyBits = 2048, .exponent = 0}}
    }};
    TPM2B_DATA outside = {0};
    TPML_PCR_SELECTION pcrs = {0};
    if (!rc) rc = Esys_CreatePrimary(ctx->esys, ESYS_TR_RH_NULL, initial,
        ESYS_TR_NONE, ESYS_TR_NONE, &sensitive, &template, &outside, &pcrs,
        &salt_key, NULL, NULL, NULL, NULL);
    if (initial != ESYS_TR_NONE) {
        TSS2_RC cleanup = Esys_FlushContext(ctx->esys, initial);
        if (!rc) rc = cleanup;
        initial = ESYS_TR_NONE;
    }
    if (!rc) rc = Esys_StartAuthSession(ctx->esys, salt_key, ESYS_TR_NONE,
        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, NULL, TPM2_SE_HMAC,
        &encrypted, TPM2_ALG_SHA256, &session);
    if (!rc) rc = Esys_TRSess_SetAttributes(ctx->esys, session,
        TPMA_SESSION_CONTINUESESSION | TPMA_SESSION_DECRYPT,
        TPMA_SESSION_CONTINUESESSION | TPMA_SESSION_DECRYPT | TPMA_SESSION_ENCRYPT);
    if (!rc) rc = Esys_TR_SetAuth(ctx->esys, ESYS_TR_RH_OWNER, &owner_auth);
    TPM2B_NV_PUBLIC public = {.nvPublic = {.nvIndex = index,
        .nameAlg = TPM2_ALG_SHA256, .attributes = 0x02040044, .dataSize = 32}};
    if (!rc) rc = Esys_NV_DefineSpace(ctx->esys, ESYS_TR_RH_OWNER, session,
        ESYS_TR_NONE, ESYS_TR_NONE, &nv_auth, &public, &nv);
    /* The same unbound salted session uses this entity's independent auth for
     * the genesis extend. All dispatches remain one-shot at this boundary. */
    if (!rc) rc = Esys_TR_SetAuth(ctx->esys, nv, &nv_auth);
    TPM2B_MAX_NV_BUFFER digest = {.size = 32};
    memcpy(digest.buffer, genesis, 32);
    if (!rc) rc = Esys_NV_Extend(ctx->esys, nv, nv, session,
        ESYS_TR_NONE, ESYS_TR_NONE, &digest);

    /* Only locally created transient/session handles are flushed. Closing an
     * ESYS NV handle does not delete its persistent allocation. */
    if (nv != ESYS_TR_NONE) {
        TSS2_RC cleanup = Esys_TR_Close(ctx->esys, &nv);
        if (!rc) rc = cleanup;
    }
    if (session != ESYS_TR_NONE) {
        TSS2_RC cleanup = Esys_FlushContext(ctx->esys, session);
        if (!rc) rc = cleanup;
    }
    if (salt_key != ESYS_TR_NONE) {
        TSS2_RC cleanup = Esys_FlushContext(ctx->esys, salt_key);
        if (!rc) rc = cleanup;
    }
    TPM2B_AUTH empty = {0};
    TSS2_RC cleanup = Esys_TR_SetAuth(ctx->esys, ESYS_TR_RH_OWNER, &empty);
    if (!rc) rc = cleanup;
    explicit_bzero(&owner_auth, sizeof(owner_auth));
    explicit_bzero(&nv_auth, sizeof(nv_auth));
    return rc;
}

/* Reserved storage parent for a future owner-compatible credential backend.
 * Caller must durably fence this persistent allocation before entry. A lost
 * EvictControl reply may still mean the handle was written: never retry it or
 * evict/overwrite an occupied handle. This function changes no hierarchy auth.
 */
uint32_t luma_tpm_provision_parent_existing(struct luma_tpm *ctx,
    const uint8_t *owner, uint16_t owner_size, uint8_t name_out[34]) {
    if (!ctx || !owner || !owner_size || owner_size > 64 || !name_out)
        return TSS2_ESYS_RC_BAD_VALUE;
    if (ctx->nv != ESYS_TR_NONE || ctx->session != ESYS_TR_NONE)
        return TSS2_ESYS_RC_BAD_SEQUENCE;
    const uint32_t handle = 0x81004c41;
    uint8_t occupied = 1;
    TSS2_RC rc = luma_tpm_index_exists(ctx, handle, &occupied);
    if (rc) return rc;
    if (occupied) return TSS2_ESYS_RC_BAD_VALUE;

    ESYS_TR initial = ESYS_TR_NONE, salt_key = ESYS_TR_NONE;
    ESYS_TR session = ESYS_TR_NONE, primary = ESYS_TR_NONE;
    ESYS_TR persistent = ESYS_TR_NONE;
    TPM2B_AUTH owner_auth = {.size = owner_size};
    memcpy(owner_auth.buffer, owner, owner_size);
    TPMT_SYM_DEF plain = {.algorithm = TPM2_ALG_NULL};
    TPMT_SYM_DEF encrypted = {.algorithm = TPM2_ALG_AES,
        .keyBits = {.aes = 128}, .mode = {.aes = TPM2_ALG_CFB}};
    TPM2B_SENSITIVE_CREATE sensitive = {0};
    TPM2B_PUBLIC template = {.publicArea = {
        .type = TPM2_ALG_RSA, .nameAlg = TPM2_ALG_SHA256,
        .objectAttributes = TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
            TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_USERWITHAUTH |
            TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_DECRYPT,
        .parameters = {.rsaDetail = {
            .symmetric = {.algorithm = TPM2_ALG_AES, .keyBits = {.aes = 128},
                          .mode = {.aes = TPM2_ALG_CFB}},
            .scheme = {.scheme = TPM2_ALG_NULL}, .keyBits = 2048, .exponent = 0}}
    }};
    TPM2B_DATA outside = {0};
    TPML_PCR_SELECTION pcrs = {0};

    /* Create only a temporary NULL-hierarchy salt key. It carries no owner
     * authorization; all owner commands run through the salted AES session. */
    rc = Esys_StartAuthSession(ctx->esys, ESYS_TR_NONE, ESYS_TR_NONE,
        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, NULL, TPM2_SE_HMAC,
        &plain, TPM2_ALG_SHA256, &initial);
    if (!rc) rc = Esys_TRSess_SetAttributes(ctx->esys, initial,
        TPMA_SESSION_CONTINUESESSION, TPMA_SESSION_CONTINUESESSION);
    if (!rc) rc = Esys_CreatePrimary(ctx->esys, ESYS_TR_RH_NULL, initial,
        ESYS_TR_NONE, ESYS_TR_NONE, &sensitive, &template, &outside, &pcrs,
        &salt_key, NULL, NULL, NULL, NULL);
    if (initial != ESYS_TR_NONE) {
        TSS2_RC cleanup = Esys_FlushContext(ctx->esys, initial);
        if (!rc) rc = cleanup;
        initial = ESYS_TR_NONE;
    }
    if (!rc) rc = Esys_StartAuthSession(ctx->esys, salt_key, ESYS_TR_NONE,
        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, NULL, TPM2_SE_HMAC,
        &encrypted, TPM2_ALG_SHA256, &session);
    if (!rc) rc = Esys_TRSess_SetAttributes(ctx->esys, session,
        TPMA_SESSION_CONTINUESESSION | TPMA_SESSION_DECRYPT,
        TPMA_SESSION_CONTINUESESSION | TPMA_SESSION_DECRYPT | TPMA_SESSION_ENCRYPT);
    if (!rc) rc = Esys_TR_SetAuth(ctx->esys, ESYS_TR_RH_OWNER, &owner_auth);
    if (!rc) rc = Esys_CreatePrimary(ctx->esys, ESYS_TR_RH_OWNER, session,
        ESYS_TR_NONE, ESYS_TR_NONE, &sensitive, &template, &outside, &pcrs,
        &primary, NULL, NULL, NULL, NULL);
    if (!rc) rc = Esys_EvictControl(ctx->esys, ESYS_TR_RH_OWNER, primary,
        session, ESYS_TR_NONE, ESYS_TR_NONE, handle, &persistent);
    if (!rc) {
        TPM2B_PUBLIC *public = NULL;
        TPM2B_NAME *name = NULL;
        TPM2B_NAME *qualified = NULL;
        rc = Esys_ReadPublic(ctx->esys, persistent, ESYS_TR_NONE,
            ESYS_TR_NONE, ESYS_TR_NONE, &public, &name, &qualified);
        if (!rc) {
            if (!name || name->size != 34 || !public ||
                public->publicArea.type != TPM2_ALG_RSA ||
                public->publicArea.nameAlg != TPM2_ALG_SHA256 ||
                public->publicArea.parameters.rsaDetail.keyBits != 2048 ||
                public->publicArea.parameters.rsaDetail.symmetric.algorithm != TPM2_ALG_AES ||
                public->publicArea.parameters.rsaDetail.symmetric.keyBits.aes != 128 ||
                public->publicArea.parameters.rsaDetail.symmetric.mode.aes != TPM2_ALG_CFB ||
                public->publicArea.parameters.rsaDetail.scheme.scheme != TPM2_ALG_NULL ||
                public->publicArea.authPolicy.size != 0 ||
                public->publicArea.unique.rsa.size != 256 ||
                public->publicArea.objectAttributes != template.publicArea.objectAttributes)
                rc = TSS2_ESYS_RC_BAD_VALUE;
            else memcpy(name_out, name->name, 34);
        }
        Esys_Free(public); Esys_Free(name); Esys_Free(qualified);
    }

    if (persistent != ESYS_TR_NONE) {
        TSS2_RC cleanup = Esys_TR_Close(ctx->esys, &persistent);
        if (!rc) rc = cleanup;
    }
    if (primary != ESYS_TR_NONE) {
        TSS2_RC cleanup = Esys_FlushContext(ctx->esys, primary);
        if (!rc) rc = cleanup;
    }
    if (session != ESYS_TR_NONE) {
        TSS2_RC cleanup = Esys_FlushContext(ctx->esys, session);
        if (!rc) rc = cleanup;
    }
    if (salt_key != ESYS_TR_NONE) {
        TSS2_RC cleanup = Esys_FlushContext(ctx->esys, salt_key);
        if (!rc) rc = cleanup;
    }
    TPM2B_AUTH empty = {0};
    TSS2_RC cleanup = Esys_TR_SetAuth(ctx->esys, ESYS_TR_RH_OWNER, &empty);
    if (!rc) rc = cleanup;
    explicit_bzero(&owner_auth, sizeof(owner_auth));
    return rc;
}

/* Credential operations are restricted to the parent reserved by enrollment.
 * The Name is supplied from a durable enrollment record, not from the handle
 * itself. A replaced or malformed persistent object is never used. */
static TSS2_RC credential_parent(struct luma_tpm *ctx,
    const uint8_t expected_name[34], ESYS_TR *parent) {
    *parent = ESYS_TR_NONE;
    TSS2_RC rc = Esys_TR_FromTPMPublic(ctx->esys, 0x81004c41,
        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, parent);
    TPM2B_PUBLIC *public = NULL;
    TPM2B_NAME *name = NULL, *qualified = NULL;
    if (!rc) rc = Esys_ReadPublic(ctx->esys, *parent, ESYS_TR_NONE,
        ESYS_TR_NONE, ESYS_TR_NONE, &public, &name, &qualified);
    if (!rc && (!public || !name || name->size != 34 ||
        CRYPTO_memcmp(name->name, expected_name, 34) ||
        public->publicArea.type != TPM2_ALG_RSA ||
        public->publicArea.nameAlg != TPM2_ALG_SHA256 ||
        public->publicArea.objectAttributes !=
            (TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
             TPMA_OBJECT_SENSITIVEDATAORIGIN | TPMA_OBJECT_USERWITHAUTH |
             TPMA_OBJECT_RESTRICTED | TPMA_OBJECT_DECRYPT) ||
        public->publicArea.authPolicy.size != 0 ||
        public->publicArea.parameters.rsaDetail.symmetric.algorithm != TPM2_ALG_AES ||
        public->publicArea.parameters.rsaDetail.symmetric.keyBits.aes != 128 ||
        public->publicArea.parameters.rsaDetail.symmetric.mode.aes != TPM2_ALG_CFB ||
        public->publicArea.parameters.rsaDetail.scheme.scheme != TPM2_ALG_NULL ||
        public->publicArea.parameters.rsaDetail.keyBits != 2048 ||
        public->publicArea.unique.rsa.size != 256))
        rc = TSS2_ESYS_RC_BAD_VALUE;
    Esys_Free(public); Esys_Free(name); Esys_Free(qualified);
    return rc;
}

uint32_t luma_tpm_credential_parent_matches(struct luma_tpm *ctx,
    const uint8_t expected_name[34]) {
    ESYS_TR parent = ESYS_TR_NONE;
    TSS2_RC rc = credential_parent(ctx, expected_name, &parent);
    if (parent != ESYS_TR_NONE) {
        TSS2_RC cleanup = Esys_TR_Close(ctx->esys, &parent);
        if (!rc) rc = cleanup;
    }
    return rc;
}

/* Import exactly an RSA-2048/e65537 PEM verifier; never a private signer.
 * Both sealing and unsealing derive the PolicyAuthorize key Name from this
 * independently pinned public key. */
static TSS2_RC credential_signer(struct luma_tpm *ctx,
    const uint8_t *pem, uint16_t pem_size, ESYS_TR *signer,
    TPM2B_NAME *key_name) {
    *signer = ESYS_TR_NONE;
    if (!pem || !pem_size || pem_size > 4096)
        return TSS2_ESYS_RC_BAD_VALUE;
    BIO *bio = BIO_new_mem_buf(pem, pem_size);
    EVP_PKEY *key = bio ? PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL) : NULL;
    BIGNUM *n = NULL, *e = NULL;
    TSS2_RC rc = TSS2_ESYS_RC_BAD_VALUE;
    TPM2B_PUBLIC public = {.publicArea = {
        .type = TPM2_ALG_RSA, .nameAlg = TPM2_ALG_SHA256,
        .objectAttributes = TPMA_OBJECT_SIGN_ENCRYPT,
        .parameters = {.rsaDetail = {
            .symmetric = {.algorithm = TPM2_ALG_NULL},
            .scheme = {.scheme = TPM2_ALG_NULL},
            .keyBits = 2048, .exponent = 65537}},
        .unique = {.rsa = {.size = 256}}
    }};
    if (!key || EVP_PKEY_base_id(key) != EVP_PKEY_RSA ||
        EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_N, &n) != 1 ||
        EVP_PKEY_get_bn_param(key, OSSL_PKEY_PARAM_RSA_E, &e) != 1 ||
        BN_num_bits(n) != 2048 || BN_get_word(e) != 65537 ||
        BN_bn2binpad(n, public.publicArea.unique.rsa.buffer, 256) != 256)
        goto cleanup;
    rc = Esys_LoadExternal(ctx->esys, ESYS_TR_NONE, ESYS_TR_NONE,
        ESYS_TR_NONE, NULL, &public, ESYS_TR_RH_OWNER, signer);
    if (!rc) {
        TPM2B_NAME *name = NULL;
        rc = Esys_TR_GetName(ctx->esys, *signer, &name);
        if (!rc) {
            if (!name || name->size != 34) rc = TSS2_ESYS_RC_BAD_VALUE;
            else memcpy(key_name, name, sizeof(*key_name));
        }
        Esys_Free(name);
    }
cleanup:
    BN_clear_free(n); BN_clear_free(e);
    EVP_PKEY_free(key); BIO_free(bio);
    explicit_bzero(&public, sizeof(public));
    return rc;
}

static TPML_PCR_SELECTION credential_pcr(uint8_t index) {
    TPML_PCR_SELECTION selection = {.count = 1, .pcrSelections = {
        {.hash = TPM2_ALG_SHA256, .sizeofSelect = 3}
    }};
    selection.pcrSelections[0].pcrSelect[index / 8] = (uint8_t)(1u << (index % 8));
    return selection;
}

static TSS2_RC credential_session(struct luma_tpm *ctx, ESYS_TR parent,
    TPM2_SE session_type, ESYS_TR *session) {
    TPMT_SYM_DEF symmetric = {.algorithm = TPM2_ALG_AES,
        .keyBits = {.aes = 128}, .mode = {.aes = TPM2_ALG_CFB}};
    *session = ESYS_TR_NONE;
    TSS2_RC rc = Esys_StartAuthSession(ctx->esys, parent, ESYS_TR_NONE,
        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, NULL, session_type,
        &symmetric, TPM2_ALG_SHA256, session);
    if (!rc) rc = Esys_TRSess_SetAttributes(ctx->esys, *session,
        TPMA_SESSION_CONTINUESESSION, TPMA_SESSION_CONTINUESESSION);
    return rc;
}

uint32_t luma_tpm_credential_fingerprint(const uint8_t *pem,
    uint16_t pem_size, uint8_t fingerprint[32]) {
    if (!pem || !pem_size || pem_size > 4096 || !fingerprint)
        return TSS2_ESYS_RC_BAD_VALUE;
    BIO *bio = BIO_new_mem_buf(pem, pem_size);
    EVP_PKEY *key = bio ? PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL) : NULL;
    TSS2_RC rc = TSS2_ESYS_RC_BAD_VALUE;
    unsigned char *der = NULL;
    size_t der_size = 0;
    if (key && EVP_PKEY_base_id(key) == EVP_PKEY_RSA &&
        EVP_PKEY_bits(key) == 2048) {
        int size = i2d_PublicKey(key, NULL);
        if (size > 0 && size <= 4096) {
            der_size = (size_t)size;
            der = OPENSSL_malloc(der_size);
            if (der) {
                unsigned char *cursor = der;
                if (i2d_PublicKey(key, &cursor) == size &&
                    SHA256(der, (size_t)size, fingerprint))
                    rc = TSS2_RC_SUCCESS;
            }
        }
    }
    if (der) OPENSSL_clear_free(der, der_size);
    EVP_PKEY_free(key); BIO_free(bio);
    return rc;
}

uint32_t luma_tpm_current_policy11(struct luma_tpm *ctx,
    uint8_t digest_out[32]) {
    if (!ctx || !digest_out) return TSS2_ESYS_RC_BAD_VALUE;
    ESYS_TR trial = ESYS_TR_NONE;
    TPM2B_DIGEST empty = {0};
    TPML_PCR_SELECTION pcr11 = credential_pcr(11);
    TPM2B_DIGEST *digest = NULL;
    TSS2_RC rc = credential_session(ctx, ESYS_TR_NONE, TPM2_SE_TRIAL, &trial);
    if (!rc) rc = Esys_PolicyPCR(ctx->esys, trial, ESYS_TR_NONE,
        ESYS_TR_NONE, ESYS_TR_NONE, &empty, &pcr11);
    if (!rc) rc = Esys_PolicyGetDigest(ctx->esys, trial,
        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &digest);
    if (!rc) {
        if (!digest || digest->size != 32) rc = TSS2_ESYS_RC_BAD_VALUE;
        else memcpy(digest_out, digest->buffer, 32);
    }
    Esys_Free(digest);
    if (trial != ESYS_TR_NONE) {
        TSS2_RC cleanup = Esys_FlushContext(ctx->esys, trial);
        if (!rc) rc = cleanup;
    }
    return rc;
}

/* Read-only boot-policy admission before any persistent allocation. The same
 * signature and policy are checked again by credential_unseal after allocation.
 */
uint32_t luma_tpm_verify_policy11(struct luma_tpm *ctx,
    const uint8_t *pem, uint16_t pem_size, const uint8_t policy[32],
    const uint8_t signature[256]) {
    if (!ctx || !pem || !policy || !signature)
        return TSS2_ESYS_RC_BAD_VALUE;
    uint8_t current[32] = {0};
    TSS2_RC rc = luma_tpm_current_policy11(ctx, current);
    if (!rc && CRYPTO_memcmp(current, policy, 32))
        rc = TSS2_ESYS_RC_BAD_VALUE;
    ESYS_TR signer = ESYS_TR_NONE;
    TPM2B_NAME name = {0};
    if (!rc) rc = credential_signer(ctx, pem, pem_size, &signer, &name);
    TPM2B_DIGEST message = {.size = 32};
    SHA256(policy, 32, message.buffer);
    TPMT_SIGNATURE signed_policy = {.sigAlg = TPM2_ALG_RSASSA,
        .signature = {.rsassa = {.hash = TPM2_ALG_SHA256,
            .sig = {.size = 256}}}};
    memcpy(signed_policy.signature.rsassa.sig.buffer, signature, 256);
    TPMT_TK_VERIFIED *ticket = NULL;
    if (!rc) rc = Esys_VerifySignature(ctx->esys, signer,
        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
        &message, &signed_policy, &ticket);
    Esys_Free(ticket);
    if (signer != ESYS_TR_NONE) {
        TSS2_RC cleanup = Esys_FlushContext(ctx->esys, signer);
        if (!rc) rc = cleanup;
    }
    explicit_bzero(&message, sizeof(message));
    explicit_bzero(&signed_policy, sizeof(signed_policy));
    return rc;
}

/* A fixed signed-PCR11 authorization followed by current PCR7. The trial
 * digest is attached to a policy-only child, so password auth cannot bypass it.
 * The caller owns the returned encrypted TPM2B blobs. */
uint32_t luma_tpm_credential_seal(struct luma_tpm *ctx,
    const uint8_t parent_name[34], const uint8_t *pem, uint16_t pem_size,
    const uint8_t secret[32], uint8_t *public_out, size_t public_capacity,
    size_t *public_size, uint8_t *private_out, size_t private_capacity,
    size_t *private_size) {
    if (!ctx || !parent_name || !pem || !secret || !public_out || !private_out ||
        !public_size || !private_size || public_capacity < 512 ||
        private_capacity < 512)
        return TSS2_ESYS_RC_BAD_VALUE;
    *public_size = *private_size = 0;
    ESYS_TR parent = ESYS_TR_NONE, signer = ESYS_TR_NONE;
    ESYS_TR trial = ESYS_TR_NONE, hmac = ESYS_TR_NONE;
    TPM2B_NAME key_name = {0};
    TPM2B_DIGEST *policy = NULL;
    TPM2B_PRIVATE *private_blob = NULL;
    TPM2B_PUBLIC *public_blob = NULL;
    TPM2B_SENSITIVE_CREATE sensitive = {0};
    TSS2_RC rc = credential_parent(ctx, parent_name, &parent);
    if (!rc) rc = credential_signer(ctx, pem, pem_size, &signer, &key_name);
    if (!rc) rc = credential_session(ctx, ESYS_TR_NONE, TPM2_SE_TRIAL, &trial);
    TPM2B_DIGEST approved = {0};
    TPM2B_NONCE policy_ref = {0};
    TPMT_TK_VERIFIED ticket = {.tag = TPM2_ST_VERIFIED,
        .hierarchy = TPM2_RH_NULL};
    if (!rc) rc = Esys_PolicyAuthorize(ctx->esys, trial, ESYS_TR_NONE,
        ESYS_TR_NONE, ESYS_TR_NONE, &approved, &policy_ref, &key_name, &ticket);
    TPML_PCR_SELECTION pcr7 = credential_pcr(7);
    if (!rc) rc = Esys_PolicyPCR(ctx->esys, trial, ESYS_TR_NONE,
        ESYS_TR_NONE, ESYS_TR_NONE, &approved, &pcr7);
    if (!rc) rc = Esys_PolicyGetDigest(ctx->esys, trial, ESYS_TR_NONE,
        ESYS_TR_NONE, ESYS_TR_NONE, &policy);
    if (!rc && (!policy || policy->size != 32)) rc = TSS2_ESYS_RC_BAD_VALUE;
    if (trial != ESYS_TR_NONE) {
        TSS2_RC cleanup = Esys_FlushContext(ctx->esys, trial);
        if (!rc) rc = cleanup;
        trial = ESYS_TR_NONE;
    }
    if (signer != ESYS_TR_NONE) {
        TSS2_RC cleanup = Esys_FlushContext(ctx->esys, signer);
        if (!rc) rc = cleanup;
        signer = ESYS_TR_NONE;
    }
    TPM2B_PUBLIC child_public = {.publicArea = {
        .type = TPM2_ALG_KEYEDHASH, .nameAlg = TPM2_ALG_SHA256,
        .objectAttributes = TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
            TPMA_OBJECT_ADMINWITHPOLICY,
        .parameters = {.keyedHashDetail = {.scheme = {.scheme = TPM2_ALG_NULL}}}
    }};
    if (!rc) {
        child_public.publicArea.authPolicy.size = 32;
        memcpy(child_public.publicArea.authPolicy.buffer, policy->buffer, 32);
        rc = credential_session(ctx, parent, TPM2_SE_HMAC, &hmac);
    }
    if (!rc) rc = Esys_TRSess_SetAttributes(ctx->esys, hmac,
        TPMA_SESSION_CONTINUESESSION | TPMA_SESSION_DECRYPT,
        TPMA_SESSION_CONTINUESESSION | TPMA_SESSION_DECRYPT | TPMA_SESSION_ENCRYPT);
    if (!rc && mlock(&sensitive, sizeof(sensitive))) rc = TSS2_ESYS_RC_BAD_VALUE;
    else if (!rc) {
        sensitive.sensitive.data.size = 32;
        memcpy(sensitive.sensitive.data.buffer, secret, 32);
        TPM2B_DATA outside = {0};
        TPML_PCR_SELECTION empty_pcrs = {0};
        rc = Esys_Create(ctx->esys, parent, hmac, ESYS_TR_NONE, ESYS_TR_NONE,
            &sensitive, &child_public, &outside, &empty_pcrs,
            &private_blob, &public_blob, NULL, NULL, NULL);
        explicit_bzero(&sensitive, sizeof(sensitive));
        munlock(&sensitive, sizeof(sensitive));
    }
    if (!rc) {
        size_t public_offset = 0, private_offset = 0;
        rc = Tss2_MU_TPM2B_PUBLIC_Marshal(public_blob, public_out,
            public_capacity, &public_offset);
        if (!rc) rc = Tss2_MU_TPM2B_PRIVATE_Marshal(private_blob, private_out,
            private_capacity, &private_offset);
        if (!rc) {
            *public_size = public_offset;
            *private_size = private_offset;
        }
    }
    if (hmac != ESYS_TR_NONE) {
        TSS2_RC cleanup = Esys_FlushContext(ctx->esys, hmac);
        if (!rc) rc = cleanup;
    }
    if (parent != ESYS_TR_NONE) {
        TSS2_RC cleanup = Esys_TR_Close(ctx->esys, &parent);
        if (!rc) rc = cleanup;
    }
    Esys_Free(policy); Esys_Free(private_blob); Esys_Free(public_blob);
    explicit_bzero(&sensitive, sizeof(sensitive));
    explicit_bzero(&child_public, sizeof(child_public));
    if (rc) *public_size = *private_size = 0;
    return rc;
}

/* Runtime unlock has no owner authorization. The policy session is salted by
 * the persistent parent and encrypts the Unseal response on the TPM transport.
 * The signed approvedPolicy must equal the current SHA-256 PCR11 policy digest.
 */
uint32_t luma_tpm_credential_unseal(struct luma_tpm *ctx,
    const uint8_t parent_name[34], const uint8_t *pem, uint16_t pem_size,
    const uint8_t *public_blob, size_t public_size,
    const uint8_t *private_blob, size_t private_size,
    const uint8_t approved_policy[32], const uint8_t *signature,
    uint16_t signature_size, uint8_t secret_out[32]) {
    if (!ctx || !parent_name || !pem || !public_blob || !private_blob ||
        !approved_policy || !signature || !secret_out ||
        !public_size || public_size > 4096 || !private_size ||
        private_size > 4096 || signature_size != 256)
        return TSS2_ESYS_RC_BAD_VALUE;
    memset(secret_out, 0, 32);
    ESYS_TR parent = ESYS_TR_NONE, signer = ESYS_TR_NONE;
    ESYS_TR hmac = ESYS_TR_NONE, policy_session = ESYS_TR_NONE;
    ESYS_TR child = ESYS_TR_NONE;
    TPM2B_NAME key_name = {0};
    TPM2B_PUBLIC child_public = {0};
    TPM2B_PRIVATE child_private = {0};
    size_t offset = 0;
    TSS2_RC rc = Tss2_MU_TPM2B_PUBLIC_Unmarshal(public_blob, public_size,
        &offset, &child_public);
    if (!rc && offset != public_size) rc = TSS2_ESYS_RC_BAD_VALUE;
    offset = 0;
    if (!rc) rc = Tss2_MU_TPM2B_PRIVATE_Unmarshal(private_blob, private_size,
        &offset, &child_private);
    if (!rc && offset != private_size) rc = TSS2_ESYS_RC_BAD_VALUE;
    if (!rc && (child_public.publicArea.type != TPM2_ALG_KEYEDHASH ||
        child_public.publicArea.nameAlg != TPM2_ALG_SHA256 ||
        child_public.publicArea.objectAttributes !=
            (TPMA_OBJECT_FIXEDTPM | TPMA_OBJECT_FIXEDPARENT |
             TPMA_OBJECT_ADMINWITHPOLICY) ||
        child_public.publicArea.authPolicy.size != 32 ||
        child_public.publicArea.parameters.keyedHashDetail.scheme.scheme != TPM2_ALG_NULL))
        rc = TSS2_ESYS_RC_BAD_VALUE;
    if (!rc) rc = credential_parent(ctx, parent_name, &parent);
    if (!rc) rc = credential_signer(ctx, pem, pem_size, &signer, &key_name);
    TPM2B_DIGEST message = {.size = 32};
    SHA256(approved_policy, 32, message.buffer);
    TPMT_SIGNATURE signed_policy = {.sigAlg = TPM2_ALG_RSASSA,
        .signature = {.rsassa = {.hash = TPM2_ALG_SHA256,
            .sig = {.size = 256}}}};
    memcpy(signed_policy.signature.rsassa.sig.buffer, signature, 256);
    TPMT_TK_VERIFIED *ticket = NULL;
    if (!rc) rc = Esys_VerifySignature(ctx->esys, signer, ESYS_TR_NONE,
        ESYS_TR_NONE, ESYS_TR_NONE, &message, &signed_policy, &ticket);
    if (signer != ESYS_TR_NONE) {
        TSS2_RC cleanup = Esys_FlushContext(ctx->esys, signer);
        if (!rc) rc = cleanup;
        signer = ESYS_TR_NONE;
    }
    if (!rc) rc = credential_session(ctx, parent, TPM2_SE_HMAC, &hmac);
    if (!rc) rc = Esys_Load(ctx->esys, parent, hmac,
        ESYS_TR_NONE, ESYS_TR_NONE, &child_private, &child_public, &child);
    if (hmac != ESYS_TR_NONE) {
        TSS2_RC cleanup = Esys_FlushContext(ctx->esys, hmac);
        if (!rc) rc = cleanup;
        hmac = ESYS_TR_NONE;
    }
    if (!rc) rc = credential_session(ctx, parent, TPM2_SE_POLICY, &policy_session);
    TPML_PCR_SELECTION pcr11 = credential_pcr(11);
    TPM2B_DIGEST empty = {0};
    if (!rc) rc = Esys_PolicyPCR(ctx->esys, policy_session, ESYS_TR_NONE,
        ESYS_TR_NONE, ESYS_TR_NONE, &empty, &pcr11);
    TPM2B_DIGEST *actual = NULL;
    if (!rc) rc = Esys_PolicyGetDigest(ctx->esys, policy_session,
        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &actual);
    if (!rc && (!actual || actual->size != 32 ||
        CRYPTO_memcmp(actual->buffer, approved_policy, 32)))
        rc = TSS2_ESYS_RC_BAD_VALUE;
    TPM2B_DIGEST approved = {.size = 32};
    memcpy(approved.buffer, approved_policy, 32);
    TPM2B_NONCE policy_ref = {0};
    if (!rc) rc = Esys_PolicyAuthorize(ctx->esys, policy_session,
        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE,
        &approved, &policy_ref, &key_name, ticket);
    TPML_PCR_SELECTION pcr7 = credential_pcr(7);
    if (!rc) rc = Esys_PolicyPCR(ctx->esys, policy_session,
        ESYS_TR_NONE, ESYS_TR_NONE, ESYS_TR_NONE, &empty, &pcr7);
    if (!rc) rc = Esys_TRSess_SetAttributes(ctx->esys, policy_session,
        TPMA_SESSION_CONTINUESESSION | TPMA_SESSION_ENCRYPT,
        TPMA_SESSION_CONTINUESESSION | TPMA_SESSION_ENCRYPT | TPMA_SESSION_DECRYPT);
    TPM2B_SENSITIVE_DATA *unsealed = NULL;
    if (!rc) rc = Esys_Unseal(ctx->esys, child, policy_session,
        ESYS_TR_NONE, ESYS_TR_NONE, &unsealed);
    if (!rc) {
        if (!unsealed || unsealed->size != 32) rc = TSS2_ESYS_RC_BAD_VALUE;
        else memcpy(secret_out, unsealed->buffer, 32);
    }
    if (unsealed) {
        explicit_bzero(unsealed, sizeof(*unsealed));
        Esys_Free(unsealed);
    }
    Esys_Free(actual); Esys_Free(ticket);
    if (policy_session != ESYS_TR_NONE) {
        TSS2_RC cleanup = Esys_FlushContext(ctx->esys, policy_session);
        if (!rc) rc = cleanup;
    }
    if (child != ESYS_TR_NONE) {
        TSS2_RC cleanup = Esys_FlushContext(ctx->esys, child);
        if (!rc) rc = cleanup;
    }
    if (parent != ESYS_TR_NONE) {
        TSS2_RC cleanup = Esys_TR_Close(ctx->esys, &parent);
        if (!rc) rc = cleanup;
    }
    explicit_bzero(&child_private, sizeof(child_private));
    explicit_bzero(&message, sizeof(message));
    explicit_bzero(&signed_policy, sizeof(signed_policy));
    if (rc) memset(secret_out, 0, 32);
    return rc;
}
