/* CC0 license applied, see LICENCE.md */

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/params.h>

/*********************************************************************
 *
 *  Error handling
 *
 *****/

/*
 * libcrypto gives providers the tools to create error routines similar
 * to the ones defined in <openssl/err.h>
 */
static OSSL_FUNC_core_new_error_fn *c_new_error = NULL;
static OSSL_FUNC_core_set_error_debug_fn *c_set_error_debug = NULL;
static OSSL_FUNC_core_vset_error_fn *c_vset_error = NULL;

static void vigenere_err(OSSL_CORE_HANDLE *core, uint32_t reason,
                         const char *fmt, ...)
{
    va_list ap;

    va_start(ap, fmt);
    c_new_error(core);
    c_vset_error(core, reason, fmt, ap);
    va_end(ap);
}

static void vigenere_err_set_debug(OSSL_CORE_HANDLE *core, const char *file,
                                   int line, const char *func)
{
    c_set_error_debug(core, file, line, func);
}

/* The error reasons used here */
#define VIGENERE_NO_KEYLEN_SET          1
#define VIGENERE_ONGOING_OPERATION      2
static const OSSL_ITEM reason_strings[] = {
    { VIGENERE_NO_KEYLEN_SET, "no key length has been set" },
    { VIGENERE_ONGOING_OPERATION, "an operation is underway" },
    { 0, NULL }
};

/*********************************************************************
 *
 *  The implementation itself
 *
 *****/

/*
 * Forward declarations to ensure we get signatures right.  All the
 * OSSL_FUNC_* types come from <openssl/core_dispatch.h>
 */
static OSSL_FUNC_provider_query_operation_fn vigenere_operation;
static OSSL_FUNC_cipher_newctx_fn vigenere_newctx;
static OSSL_FUNC_cipher_encrypt_init_fn vigenere_encrypt_init;
static OSSL_FUNC_cipher_decrypt_init_fn vigenere_decrypt_init;
static OSSL_FUNC_cipher_update_fn vigenere_update;
static OSSL_FUNC_cipher_final_fn vigenere_final;
static OSSL_FUNC_cipher_dupctx_fn vigenere_dupctx;
static OSSL_FUNC_cipher_freectx_fn vigenere_freectx;
static OSSL_FUNC_cipher_get_params_fn vigenere_get_params;
static OSSL_FUNC_cipher_gettable_params_fn vigenere_gettable_params;
static OSSL_FUNC_cipher_set_ctx_params_fn vigenere_set_ctx_params;
static OSSL_FUNC_cipher_get_ctx_params_fn vigenere_get_ctx_params;
static OSSL_FUNC_cipher_settable_ctx_params_fn vigenere_settable_ctx_params;
static OSSL_FUNC_cipher_gettable_ctx_params_fn vigenere_gettable_ctx_params;

/*
 * The context used throughout all these functions.
 */
struct vigenere_ctx_st {
    void *prov;
    size_t keyl;                /* The configured length of the key */

    unsigned char *key;         /* A copy of the key */
    size_t keypos;              /* The current position in the key */
    int enc;                    /* 0 = decrypt, 1 = encrypt */
    int ongoing;                /* 1 = operation has started */
};

static void *vigenere_newctx(void *vprovctx)
{
    struct vigenere_ctx_st *ctx = malloc(sizeof(*ctx));

    if (ctx != NULL) {
        memset(ctx, 0, sizeof(*ctx));
        ctx->prov = vprovctx;
    }
    return ctx;
}

static void vigenere_cleanctx(void *vctx)
{
    struct vigenere_ctx_st *ctx = vctx;

    if (ctx == NULL)
        return;
    free(ctx->key);
    ctx->key = NULL;
    ctx->keypos = 0;
    ctx->enc = 0;
    ctx->ongoing = 0;
}

static void *vigenere_dupctx(void *vctx)
{
    struct vigenere_ctx_st *src = vctx;
    struct vigenere_ctx_st *dst = NULL;

    dst = vigenere_newctx(NULL);
    if (dst == NULL)
        return NULL;

    dst->prov = src->prov;
    dst->keyl = src->keyl;

    if (src->key != NULL) {
        if ((dst->key = malloc(src->keyl)) == NULL) {
            vigenere_freectx(dst);
            return NULL;
        }
        memcpy(dst->key, src->key, src->keyl);
    }

    dst->keypos = src->keypos;
    dst->enc = src->enc;
    dst->ongoing = src->ongoing;

    return dst;
}

static void vigenere_freectx(void *vctx)
{
    struct vigenere_ctx_st *ctx = vctx;

    vigenere_cleanctx(ctx);
    free(ctx);
}

static int vigenere_encrypt_init(void *vctx,
                                 const unsigned char *key,
                                 size_t keyl,
                                 const unsigned char *iv_unused,
                                 size_t ivl_unused)
{
    struct vigenere_ctx_st *ctx = vctx;

    if (keyl == (size_t)-1) {
        vigenere_err(ctx->prov, VIGENERE_NO_KEYLEN_SET, NULL);
        vigenere_err_set_debug(ctx->prov, __FILE__, __LINE__, __func__);
        return 0;
    }
    vigenere_cleanctx(ctx);
    ctx->key = malloc(keyl);
    memcpy(ctx->key, key, keyl);
    ctx->keyl = keyl;
    ctx->keypos = 0;
    ctx->ongoing = 0;
    return 1;
}

static int vigenere_decrypt_init(void *vctx,
                                 const unsigned char *key,
                                 size_t keyl,
                                 const unsigned char *iv_unused,
                                 size_t ivl_unused)
{
    struct vigenere_ctx_st *ctx = vctx;
    size_t i;

    if (keyl == (size_t)-1) {
        vigenere_err(ctx->prov, VIGENERE_NO_KEYLEN_SET, NULL);
        vigenere_err_set_debug(ctx->prov, __FILE__, __LINE__, __func__);
        return 0;
    }
    vigenere_cleanctx(ctx);
    ctx->key = malloc(keyl);
    for (i = 0; i < keyl; i++)
        ctx->key[i] = 256 - key[i];
    ctx->keyl = keyl;
    ctx->keypos = 0;
    ctx->ongoing = 0;
    return 1;
}

static int vigenere_update(void *vctx,
                           unsigned char *out, size_t *outl, size_t outsz,
                           const unsigned char *in, size_t inl)
{
    struct vigenere_ctx_st *ctx = vctx;

    assert(outsz >= inl);
    assert(out != NULL);
    assert(outl != NULL);
    if (outsz < inl || out == NULL)
        return 0;

    ctx->ongoing = 1;
    *outl = 0;
    for (; inl-- > 0; (*outl)++) {
        *out++ = (*in++ + ctx->key[ctx->keypos++]) % 256;
        if (ctx->keypos >= ctx->keyl)
            ctx->keypos = 0;
    }

    return 1;
}

static int vigenere_final(void *vctx,
                          unsigned char *out, size_t *outl, size_t outsz)
{
    struct vigenere_ctx_st *ctx = vctx;

    *outl = 0;
    ctx->ongoing = 0;

    return 1;
}

/* Parameters that libcrypto can get from this implementation */
static const OSSL_PARAM *vigenere_gettable_params(void *provctx)
{
    static const OSSL_PARAM table[] = {
        OSSL_PARAM_size_t("blocksize", NULL),
        OSSL_PARAM_END
    };

    return table;
}

static int vigenere_get_params(OSSL_PARAM params[])
{
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, "blocksize")) != NULL)
        if (!OSSL_PARAM_set_size_t(p, 1))
            return 0;
    return 1;
}

static const OSSL_PARAM *vigenere_gettable_ctx_params(void *provctx)
{
    static const OSSL_PARAM table[] = {
        OSSL_PARAM_size_t("keylen", NULL),
        OSSL_PARAM_END
    };

    return table;
}

static int vigenere_get_ctx_params(void *vctx, OSSL_PARAM params[])
{
    struct vigenere_ctx_st *ctx = vctx;
    OSSL_PARAM *p;

    if (ctx->keyl > 0
        && (p = OSSL_PARAM_locate(params, "keylen")) != NULL
        && !OSSL_PARAM_set_size_t(p, ctx->keyl))
        return 0;
    return 1;
}

/* Parameters that libcrypto can send to this implementation */
static const OSSL_PARAM *vigenere_settable_ctx_params(void *provctx)
{
    static const OSSL_PARAM table[] = {
        OSSL_PARAM_size_t("keylen", NULL),
        OSSL_PARAM_END
    };

    return table;
}

static int vigenere_set_ctx_params(void *vctx, const OSSL_PARAM params[])
{
    struct vigenere_ctx_st *ctx = vctx;
    const OSSL_PARAM *p;

    if (ctx->ongoing) {
        vigenere_err(ctx->prov, VIGENERE_ONGOING_OPERATION, NULL);
        vigenere_err_set_debug(ctx->prov, __FILE__, __LINE__, __func__);
        return 0;
    }

    if ((p = OSSL_PARAM_locate_const(params, "keylen")) != NULL
        && !OSSL_PARAM_get_size_t(p, &ctx->keyl))
        return 0;
    return 1;
}


/*********************************************************************
 *
 *  Setup
 *
 *****/

typedef void (*funcptr_t)(void);

/* The Vigenere dispatch table */
static const OSSL_DISPATCH vigenere_functions[] = {
    { OSSL_FUNC_CIPHER_NEWCTX, (funcptr_t)vigenere_newctx },
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (funcptr_t)vigenere_encrypt_init },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (funcptr_t)vigenere_decrypt_init },
    { OSSL_FUNC_CIPHER_UPDATE, (funcptr_t)vigenere_update },
    { OSSL_FUNC_CIPHER_FINAL, (funcptr_t)vigenere_final },
    { OSSL_FUNC_CIPHER_DUPCTX, (funcptr_t)vigenere_dupctx },
    { OSSL_FUNC_CIPHER_FREECTX, (funcptr_t)vigenere_freectx },
    { OSSL_FUNC_CIPHER_GET_PARAMS, (funcptr_t)vigenere_get_params },
    { OSSL_FUNC_CIPHER_GETTABLE_PARAMS, (funcptr_t)vigenere_gettable_params },
    { OSSL_FUNC_CIPHER_GET_CTX_PARAMS, (funcptr_t)vigenere_get_ctx_params },
    { OSSL_FUNC_CIPHER_GETTABLE_CTX_PARAMS,
      (funcptr_t)vigenere_gettable_ctx_params },
    { OSSL_FUNC_CIPHER_SET_CTX_PARAMS, (funcptr_t)vigenere_set_ctx_params },
    { OSSL_FUNC_CIPHER_SETTABLE_CTX_PARAMS,
      (funcptr_t)vigenere_settable_ctx_params },
    { 0, NULL }
};

/* The table of ciphers this provider offers */
static const OSSL_ALGORITHM vigenere_ciphers[] = {
    { "vigenere", NULL, vigenere_functions },
    { NULL , NULL, NULL }
};

/* The function that returns the appropriate algorithm table per operation */
static const OSSL_ALGORITHM *vigenere_operation(void *vprovctx,
                                                int operation_id,
                                                int *no_cache)
{
    *no_cache = 0;
    switch (operation_id) {
    case OSSL_OP_CIPHER:
        return vigenere_ciphers;
    }
    return NULL;
}

static const OSSL_ITEM *vigenere_get_reason_strings(void *provctx)
{
    return reason_strings;
}

/* The base dispatch table */
static const OSSL_DISPATCH provider_functions[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (funcptr_t)vigenere_operation },
    { OSSL_FUNC_PROVIDER_GET_REASON_STRINGS,
      (funcptr_t)vigenere_get_reason_strings },
    { 0, NULL }
};

int OSSL_provider_init(const OSSL_CORE_HANDLE *core,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **vprovctx)
{
    for (; in->function_id != 0; in++)
        switch (in->function_id) {
        case OSSL_FUNC_CORE_NEW_ERROR:
            c_new_error = OSSL_FUNC_core_new_error(in);
            break;
        case OSSL_FUNC_CORE_SET_ERROR_DEBUG:
            c_set_error_debug = OSSL_FUNC_core_set_error_debug(in);
            break;
        case OSSL_FUNC_CORE_VSET_ERROR:
            c_vset_error = OSSL_FUNC_core_vset_error(in);
            break;
        }

    *out = provider_functions;

    /*
     * This provider has no need of its own context, so it simply passes
     * the core handle, which will get passed back to diverse functions
     * and must be present for our error macro to work right.
     */
    *vprovctx = (void *)core;
    return 1;
}
