/* CC0 license applied, see LICENCE.md */

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <openssl/core.h>
#include <openssl/core_dispatch.h>
#include <openssl/params.h>

#include "prov/err.h"

/*********************************************************************
 *
 *  Errors
 *
 *****/

/* The error reasons used here */
#define VIGENERE_NO_KEYLEN_SET          1
#define VIGENERE_ONGOING_OPERATION      2
#define VIGENERE_INCORRECT_KEYLEN       3
static const OSSL_ITEM reason_strings[] = {
    { VIGENERE_NO_KEYLEN_SET, "no key length has been set" },
    { VIGENERE_ONGOING_OPERATION, "an operation is underway" },
    { VIGENERE_INCORRECT_KEYLEN, "incorrect key length" },
    { 0, NULL }
};

/*********************************************************************
 *
 *  Provider context
 *
 *****/

struct provider_ctx_st {
    const OSSL_CORE_HANDLE *core_handle;
    struct proverr_functions_st *proverr_handle;
};

static void provider_ctx_free(struct provider_ctx_st *ctx)
{
    if (ctx != NULL)
        proverr_free_handle(ctx->proverr_handle);
    free(ctx);
}

static struct provider_ctx_st *provider_ctx_new(const OSSL_CORE_HANDLE *core,
                                                const OSSL_DISPATCH *in)
{
    struct provider_ctx_st *ctx;

    if ((ctx = malloc(sizeof(*ctx))) != NULL
        && (ctx->proverr_handle = proverr_new_handle(core, in)) != NULL) {
        ctx->core_handle = core;
    } else {
        provider_ctx_free(ctx);
        ctx = NULL;
    }
    return ctx;
}

/*********************************************************************
 *
 *  The implementation itself
 *
 *****/

/*
 * Forward declarations to ensure we get signatures right.  All the
 * OSSL_FUNC_* types come from <openssl/core_dispatch.h>
 */
static OSSL_FUNC_provider_query_operation_fn vigenere_prov_operation;
static OSSL_FUNC_provider_get_params_fn vigenere_prov_get_params;
static OSSL_FUNC_provider_get_reason_strings_fn vigenere_prov_get_reason_strings;

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
    struct provider_ctx_st *provctx;

#define DEFAULT_KEYLENGTH 16    /* amount of bytes == 128 bits */
    size_t keyl;                /* The configured length of the key */

    unsigned char *key;         /* A copy of the key */
    size_t keypos;              /* The current position in the key */
    int enc;                    /* 0 = decrypt, 1 = encrypt */
    int ongoing;                /* 1 = operation has started */
};
#define ERR_HANDLE(ctx) ((ctx)->provctx->proverr_handle)

static void *vigenere_newctx(void *vprovctx)
{
    struct vigenere_ctx_st *ctx = malloc(sizeof(*ctx));

    if (ctx != NULL) {
        memset(ctx, 0, sizeof(*ctx));
        ctx->provctx = vprovctx;
        ctx->keyl = DEFAULT_KEYLENGTH;
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

    if (src == NULL
        || (dst = vigenere_newctx(NULL)) == NULL)

    dst->provctx->proverr_handle =
        proverr_dup_handle(src->provctx->proverr_handle);
    dst->provctx = src->provctx;
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

    ctx->provctx = NULL;
    vigenere_cleanctx(ctx);
    free(ctx);
}

static int vigenere_encrypt_init(void *vctx,
                                 const unsigned char *key,
                                 size_t keyl,
                                 const unsigned char *iv_unused,
                                 size_t ivl_unused,
                                 const OSSL_PARAM params[])
{
    struct vigenere_ctx_st *ctx = vctx;

    if (keyl == (size_t)-1) {
        ERR_raise(ERR_HANDLE(ctx), VIGENERE_NO_KEYLEN_SET);
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
                                 size_t ivl_unused,
                                 const OSSL_PARAM params[])
{
    struct vigenere_ctx_st *ctx = vctx;
    size_t i;

    if (keyl == (size_t)-1) {
        ERR_raise(ERR_HANDLE(ctx), VIGENERE_NO_KEYLEN_SET);
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

static const OSSL_PARAM *vigenere_gettable_ctx_params(void *cctx, void *provctx)
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
static const OSSL_PARAM *vigenere_settable_ctx_params(void *cctx, void *provctx)
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
        ERR_raise(ERR_HANDLE(ctx), VIGENERE_ONGOING_OPERATION);
        return 0;
    }

    if ((p = OSSL_PARAM_locate_const(params, "keylen")) != NULL) {
        size_t keyl = 0;

        if (!OSSL_PARAM_get_size_t(p, &keyl))
            return 0;
        ctx->keyl = keyl;
    }
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
    { "vigenere:1.3.6.1.4.1.5168.4711.22087.1", NULL, vigenere_functions },
    { NULL , NULL, NULL }
};

/* The function that returns the appropriate algorithm table per operation */
static const OSSL_ALGORITHM *vigenere_prov_operation(void *vprovctx,
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

static const OSSL_ITEM *vigenere_prov_get_reason_strings(void *provctx)
{
    return reason_strings;
}

static int vigenere_prov_get_params(void *provctx, OSSL_PARAM *params)
{
    OSSL_PARAM *p;

    if ((p = OSSL_PARAM_locate(params, "version")) != NULL
        && !OSSL_PARAM_set_utf8_ptr(p, VERSION))
        return 0;
    if ((p = OSSL_PARAM_locate(params, "buildinfo")) != NULL
        && BUILDTYPE[0] != '\0'
        && !OSSL_PARAM_set_utf8_ptr(p, BUILDTYPE))
        return 0;
    return 1;
}

/* The function that tears down this provider */
static void vigenere_prov_teardown(void *vprovctx)
{
    provider_ctx_free(vprovctx);
}

/* The base dispatch table */
static const OSSL_DISPATCH provider_functions[] = {
    { OSSL_FUNC_PROVIDER_TEARDOWN, (funcptr_t)vigenere_prov_teardown },
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (funcptr_t)vigenere_prov_operation },
    { OSSL_FUNC_PROVIDER_GET_REASON_STRINGS,
      (funcptr_t)vigenere_prov_get_reason_strings },
    { OSSL_FUNC_PROVIDER_GET_PARAMS,
      (funcptr_t)vigenere_prov_get_params },
    { 0, NULL }
};

int OSSL_provider_init(const OSSL_CORE_HANDLE *core,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **vprovctx)
{
    if ((*vprovctx = provider_ctx_new(core, in)) == NULL)
        return 0;
    *out = provider_functions;
    return 1;
}
