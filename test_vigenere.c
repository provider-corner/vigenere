/* CC0 license applied, see LICENCE.md */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/core.h>
#include <openssl/provider.h>

#define T(e)                                    \
  if (!(e)) {                                   \
    ERR_print_errors_fp(stderr);                \
    OPENSSL_die(#e, __FILE__, __LINE__);        \
  }
#define cRED    "\033[1;31m"
#define cDRED   "\033[0;31m"
#define cGREEN  "\033[1;32m"
#define cDGREEN "\033[0;32m"
#define cBLUE   "\033[1;34m"
#define cDBLUE  "\033[0;34m"
#define cNORM   "\033[m"
#define TEST_ASSERT(e)                                  \
  {                                                     \
    if (!(test = (e)))                                  \
      printf(cRED "  Test FAILED" cNORM "\n");          \
    else                                                \
      printf(cGREEN "  Test passed" cNORM "\n");        \
  }

static void hexdump(const void *ptr, size_t len)
{
    const unsigned char *p = ptr;
    size_t i, j;

    for (i = 0; i < len; i += j) {
        for (j = 0; j < 16 && i + j < len; j++)
            printf("%s%02x", j? "" : " ", p[i + j]);
    }
    printf("\n");
}

static const unsigned char plaintext[] = "Ceasar's trove of junk";
static const unsigned char key[] =
  { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    'Z', 'W', 'T', 'Q', 'N', 'K', 'H', 'B' };
static unsigned char ciphertext[sizeof(plaintext)];
static unsigned char plaintext2[sizeof(plaintext)];

int main()
{
  OPENSSL_CTX *libctx = NULL;
  EVP_CIPHER *c = NULL;
  EVP_CIPHER_CTX *ctx = NULL;
  int outl = 0, outlf = 0;
  int outl2 = 0, outl2f = 0;
  OSSL_PROVIDER *prov = NULL;
  int test = 0;

  printf(cBLUE "Trying to load vigenere provider" cNORM "\n");
  T((c = EVP_CIPHER_fetch(libctx, "vigenere", NULL)) == NULL);
  T((prov = OSSL_PROVIDER_load(libctx, "vigenere")) != NULL);
  T((c = EVP_CIPHER_fetch(libctx, "vigenere", NULL)) != NULL);
  T((ctx = EVP_CIPHER_CTX_new()) != NULL);
  EVP_CIPHER_free(c);         /* ctx holds on to the cipher */
  /* Test encryption */
  printf(cBLUE "Testing init without a key" cNORM "\n");
  T(EVP_CipherInit(ctx, c, NULL, NULL, 1));
  printf(cBLUE "Testing setting key length to %lu" cNORM "\n", sizeof(key));
  T(EVP_CIPHER_CTX_set_key_length(ctx, sizeof(key)) > 0);
  printf(cBLUE "Testing encryption" cNORM "\n");
  T(EVP_CipherInit(ctx, NULL, key, NULL, 1));
  T(EVP_CipherUpdate(ctx, ciphertext, &outl, plaintext, sizeof(plaintext)));
  T(EVP_CipherFinal(ctx, ciphertext + outl, &outlf));
  /* Test decryption */
  printf(cBLUE "Testing decryption" cNORM "\n");
  T(EVP_CipherInit(ctx, NULL, key, NULL, 0));
  T(EVP_CipherUpdate(ctx, plaintext2, &outl2, ciphertext, outl));
  T(EVP_CipherFinal(ctx, plaintext2 + outl2, &outl2f));

  printf("Plaintext[%lu]  = ", sizeof(plaintext));
  hexdump(plaintext, sizeof(plaintext));
  printf("Key[%lu]        = ", sizeof(key));
  hexdump(key, sizeof(key));
  printf("Ciphertext[%d] = ", outl + outlf);
  hexdump(ciphertext, outl + outlf);
  printf("Plaintext2[%d] = ", outl2 + outl2f);
  hexdump(plaintext2, outl2 + outl2f);

  EVP_CIPHER_CTX_free(ctx);
  OSSL_PROVIDER_unload(prov);

  TEST_ASSERT(sizeof(plaintext) == outl2 + outl2f
              && memcmp(plaintext, plaintext2, sizeof(plaintext)) == 0);

  /* Exit code 0 == success */
  return !test;
}
