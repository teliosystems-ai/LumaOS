/* Fixed-width adapter to the packaged TPM2-TSS ESAPI, not a policy engine.
 * No shell, file credentials, global-handle flushing or TPM provisioning.
 * Caller owns the context exclusively. Every authorization uses an HMAC
 * session, never ESYS_TR_PASSWORD; only public digests cross the TPM bus.
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
