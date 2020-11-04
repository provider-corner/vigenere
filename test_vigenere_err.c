/* CC0 license applied, see LICENCE.md */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/core.h>
#include <openssl/provider.h>

#include "test_common.h"

static const unsigned char plaintext[] = "Ceasar's trove of junk";
static const unsigned char key[] =
  { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    'Z', 'W', 'T', 'Q', 'N', 'K', 'H', 'B' };
static unsigned char ciphertext[sizeof(plaintext)];
static unsigned char plaintext2[sizeof(plaintext)];

int main()
{
  OSSL_LIB_CTX *libctx = NULL;
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
  printf(cBLUE "Testing setting key length to %zu" cNORM "\n", sizeof(key));
  T(EVP_CIPHER_CTX_set_key_length(ctx, sizeof(key)) > 0);
  printf(cBLUE "Testing encryption" cNORM "\n");
  T(EVP_CipherInit(ctx, NULL, key, NULL, 1));
  T(EVP_CipherUpdate(ctx, ciphertext, &outl, plaintext, sizeof(plaintext)));
  printf(cBLUE "Testing setting key length to %zu during ongoing operation fails" cNORM "\n",
         sizeof(key));
  TF(EVP_CIPHER_CTX_set_key_length(ctx, sizeof(key) - 1) <= 0);

  EVP_CIPHER_CTX_free(ctx);
  OSSL_PROVIDER_unload(prov);

  /* If the last EVP_CIPHER_CTX_set_key_length() succeeded, we aborted */
  TEST_ASSERT(1);

  /* Exit code 0 == success */
  return !test;
}
