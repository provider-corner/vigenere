/* CC0 license applied, see LICENCE.md */

#include <stdlib.h>
#include <string.h>
#include <assert.h>

#include <openssl/core.h>
#include <openssl/core_numbers.h>
#include <openssl/params.h>

typedef void (*funcptr_t)(void);

struct vigenere_ctx_st {
    unsigned char *key;
    size_t keyl;
    size_t keypos;
    int enc;
};

/* Forward declarations to ensure we get signatures right */
static OSSL_provider_query_operation_fn vigenere_operation;
static OSSL_OP_cipher_newctx_fn vigenere_newctx;
static OSSL_OP_cipher_encrypt_init_fn vigenere_encrypt_init;
static OSSL_OP_cipher_decrypt_init_fn vigenere_decrypt_init;
static OSSL_OP_cipher_update_fn vigenere_update;
static OSSL_OP_cipher_final_fn vigenere_final;
static OSSL_OP_cipher_dupctx_fn vigenere_dupctx;
static OSSL_OP_cipher_freectx_fn vigenere_freectx;

static void *vigenere_newctx(void *vprovctx)
{
    struct vigenere_ctx_st *ctx = malloc(sizeof(*ctx));

    if (ctx != NULL)
        memset(ctx, 0, sizeof(*ctx));
    return ctx;
}

static void vigenere_cleanctx(void *vctx)
{
  struct vigenere_ctx_st *ctx = vctx;

  if (ctx == NULL)
    return;
  free(ctx->key);
  memset(ctx, '\0', sizeof(*ctx));
}

static void *vigenere_dupctx(void *vctx)
{
    struct vigenere_ctx_st *src = vctx;
    struct vigenere_ctx_st *dst = NULL;

    dst = vigenere_newctx(NULL);
    if (dst == NULL)
      return NULL;
    if (src->keyl > 0) {
      if ((dst->key = malloc(src->keyl)) == NULL) {
        vigenere_freectx(dst);
        return NULL;
      }
      memcpy(dst->key, src->key, src->keyl);
      dst->keyl = src->keyl;
    }
    dst->keypos = src->keypos;
    dst->enc = src->enc;

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

    vigenere_cleanctx(ctx);
    if (keyl == (size_t)-1)
      /* Because that's what test_vigenere.c gives */
      keyl = 16;
    ctx->key = malloc(keyl);
    memcpy(ctx->key, key, keyl);
    ctx->keyl = keyl;
    ctx->keypos = 0;
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

    vigenere_cleanctx(ctx);
    if (keyl == (size_t)-1)
      /* Because that's what test_vigenere.c gives */
      keyl = 16;
    ctx->key = malloc(keyl);
    for (i = 0; i < keyl; i++)
        ctx->key[i] = 256 - key[i];
    ctx->keyl = keyl;
    ctx->keypos = 0;
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
    *outl = 0;
    return 1;
}

static int vigenere_get_params(OSSL_PARAM params[])
{
  OSSL_PARAM *p;

  if ((p = OSSL_PARAM_locate(params, "blocksize")) != NULL)
    if (!OSSL_PARAM_set_size_t(p, 1))
      return 0;
  return 1;
}

static const OSSL_DISPATCH vigenere_functions[] = {
    { OSSL_FUNC_CIPHER_NEWCTX, (funcptr_t)vigenere_newctx },
    { OSSL_FUNC_CIPHER_ENCRYPT_INIT, (funcptr_t)vigenere_encrypt_init },
    { OSSL_FUNC_CIPHER_DECRYPT_INIT, (funcptr_t)vigenere_decrypt_init },
    { OSSL_FUNC_CIPHER_UPDATE, (funcptr_t)vigenere_update },
    { OSSL_FUNC_CIPHER_FINAL, (funcptr_t)vigenere_final },
    { OSSL_FUNC_CIPHER_DUPCTX, (funcptr_t)vigenere_dupctx },
    { OSSL_FUNC_CIPHER_FREECTX, (funcptr_t)vigenere_freectx },
    { OSSL_FUNC_CIPHER_GET_PARAMS, (funcptr_t)vigenere_get_params },
    { 0, NULL }
};

static const OSSL_ALGORITHM vigenere_ciphers[] =
  { { "vigenere", NULL, vigenere_functions },
    { NULL , NULL, NULL } };

static const OSSL_ALGORITHM *vigenere_operation(void *vprovctx,
                                                int operation_id,
                                                const int *no_cache)
{
    switch (operation_id) {
    case OSSL_OP_CIPHER:
        return vigenere_ciphers;
    }
    return NULL;
}

static const OSSL_DISPATCH provider_functions[] = {
    { OSSL_FUNC_PROVIDER_QUERY_OPERATION, (funcptr_t)vigenere_operation },
    { 0, NULL }
};

int OSSL_provider_init(const OSSL_PROVIDER *provider,
                       const OSSL_DISPATCH *in,
                       const OSSL_DISPATCH **out,
                       void **vprovctx)
{
    *out = provider_functions;
    return 1;
}
