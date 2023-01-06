# Vigenère cipher provider

The Vigenère provider only contains one algorithm, which is an
adaptation of the well known Vigenère cipher, covering the whole range
of byte values, not just alphabetic characters.

This cipher, as well as its history, is described in the
[Vigenère_cipher wikipedia page]

## Algorithm Names

The following names can be used with [EVP_CIPHER_fetch(3)]

-   vigenere
-   1.3.6.1.4.1.5168.4711.22087.1

## Properties

The following property can be used to distinguish this particular
implementation of the Vigenère cipher when fetching it with
[EVP_CIPHER_fetch(3)]:

-   x.author=@levitte

## Parameters

### Provider parameters

These parameters can be retrieved using [OSSL_PROVIDER_get_params(3)]:

-   "version" \<UTF8 string\>

    The version number of the provider.

-   "buildinfo" \<UTF8 string\>

    The build type as specified by [cmake].

-   "author" \<UTF8 string\>

    An identifier for the author of this provider.

### Vigenère cipher parameters

#### Algorithm parameters

These parameters can be retrieved using [EVP_CIPHER_gettable_params(3)] and
[EVP_CIPHER_get_params(3)]:

-   "blocksize" \<unsigned integer\>

    The block size of this cipher (it will always be 1).
    
    The OpenSSL call [EVP_CIPHER_block_size(3)] uses this parameter
    implicitly.

-   "keylen" \<unsigned integer\>

    The standard key length for this cipher, expressed in number of bytes.
    It's usually 16 (i.e. 128 bits), but may be changed with the environment
    variable `VIGENERE_KEYLEN`, further described below.

    The OpenSSL call [EVP_CIPHER_key_length(3)] uses this parameter
    implicitly.

#### Cipher context parameters

This parameters can be retrieved using [EVP_CIPHER_CTX_gettable_params(3)],
[EVP_CIPHER_CTX_get_params(3)], [EVP_CIPHER_CTX_settable_params(3)], and
[EVP_CIPHER_CTX_set_params(3)]:

-   "keylen" \<unsigned integer\>

    The key length used in the given cipher context, expressed in number of
    bytes.  It defaults to the standard key length as described above, but
    may be changed to the user's preference.

    The OpenSSL calls [EVP_CIPHER_CTX_set_key_length(3)] and
    [EVP_CIPHER_CTX_key_length(3)] use this parameter implicitly.

## Environment

-   `VIGENERE_KEYLEN`

    This environment variable can be set to an arbitrary key length,
    expressed in bytes.  The number syntax is implied by strtoul(3),
    which means that a number starting with "0x" will be understood as a
    hexadecimal number, and a number starting with "0" will be understood as
    an octal number.

    This allows the user of `openssl enc` to specify the desired key length,
    which is otherwise not supported by that command.

## Example command line usage

These examples all assume that `vigenere.so` / `vigenere.dll` is located in
the current directory.

-   Listing the provider itself:

    ``` console
    $ openssl list -provider-path . -provider vigenere -providers
    Providers:
      vigenere
        version: 1.2
    ```

-   Listing the algorithm:

    ``` console
    $ openssl list -provider-path . -provider vigenere \
        -cipher-algorithms -verbose
    ...
    Provided:
      { 1.3.6.1.4.1.5168.4711.22087.1, vigenere } @ vigenere
        description: undefined
        retrievable algorithm parameters:
          blocksize: unsigned integer (max 8 bytes large)
          keylen: unsigned integer (max 8 bytes large)
        retrievable operation parameters:
          keylen: unsigned integer (max 8 bytes large)
        settable operation parameters:
          keylen: unsigned integer (max 8 bytes large)
    ```

-   Encryption with the standard key length (128 bits, i.e. 16 bytes):

    ``` console
    $ echo "The quick brown fox jumps over the lazy dog" \
      | openssl enc -provider-path . -provider vigenere \
            -e -vigenere \
            -K 00112233445566778899AABBCCDDEEFF \
            -a
    VHmHU7XKz9rzuQwtO1RcH2aAmlOuytPn+7kZMTFPDnNodkKfpc/fl+wIEcU=
    ```

-   Encryption with the non-standard key length (256 bits, i.e. 32 bytes):

    ``` console
    $ echo "The quick brown fox jumps over the lazy dog" \
      | VIGENERE_KEYLEN=32 openssl enc -provider-path . -provider vigenere \
          -e -vigenere \
          -K 00112233445566778899AABBCCDDEEFF0123456789ABCDEF0123456789ABCDEF \
          -a
    VHmHU7XKz9rzuQwtO1RcH2eSvYfzIDpfdEO03e4d7WNodkKfpc/fl+wIEcU=
    ```

# Disclaimer

This provider is a very small demonstration of fairly minimum requirements
for a cipher in an OpenSSL 3.0 provider module.

*The cipher that it provides is a toy and should not be used in a real
situation*.

<!-- Links -->

[Vigenère_cipher wikipedia page]:
    <https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher>
[EVP_CIPHER_fetch(3)]:
    <https://www.openssl.org/docs/man3.0/man3/EVP_CIPHER_fetch.html>
[OSSL_PROVIDER_get_params(3)]:
    <https://www.openssl.org/docs/man3.0/man3/OSSL_PROVIDER_get_params.html>
[cmake]:
    <https://cmake.org/cmake/help/latest/variable/CMAKE_BUILD_TYPE.html>
[EVP_CIPHER_gettable_params(3)]:
    <https://www.openssl.org/docs/man3.0/man3/EVP_CIPHER_gettable_params.html>
[EVP_CIPHER_get_params(3)]:
    <https://www.openssl.org/docs/man3.0/man3/EVP_CIPHER_get_params.html>
[EVP_CIPHER_block_size(3)]:
    <https://www.openssl.org/docs/man3.0/man3/EVP_CIPHER_block_size.html>
[EVP_CIPHER_key_length(3)]:
    <https://www.openssl.org/docs/man3.0/man3/EVP_CIPHER_key_length.html>
[EVP_CIPHER_CTX_gettable_params(3)]:
    <https://www.openssl.org/docs/man3.0/man3/EVP_CIPHER_CTX_gettable_params.html>
[EVP_CIPHER_CTX_get_params(3)]:
    <https://www.openssl.org/docs/man3.0/man3/EVP_CIPHER_CTX_get_params.html>
[EVP_CIPHER_CTX_settable_params(3)]:
    <https://www.openssl.org/docs/man3.0/man3/EVP_CIPHER_CTX_settable_params.html>
[EVP_CIPHER_CTX_set_params(3)]:
    <https://www.openssl.org/docs/man3.0/man3/EVP_CIPHER_CTX_set_params.html>
[EVP_CIPHER_CTX_key_length(3)]:
    <https://www.openssl.org/docs/man3.0/man3/EVP_CIPHER_CTX_key_length.html>
[EVP_CIPHER_CTX_set_key_length(3)]:
    <https://www.openssl.org/docs/man3.0/man3/EVP_CIPHER_CTX_set_key_length.html>
