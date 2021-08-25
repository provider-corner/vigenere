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
  printf(cBLUE "Testing setting key length to %zu (measured in bytes)" cNORM "\n",
         sizeof(key));
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

  printf("Plaintext[%zu]  = ", sizeof(plaintext));
  hexdump(plaintext, sizeof(plaintext));
  printf("Key[%zu]        = ", sizeof(key));
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
