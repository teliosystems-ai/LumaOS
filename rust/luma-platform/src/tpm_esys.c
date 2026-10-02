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
#include <tss2/tss2_esys.h>
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
