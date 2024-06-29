[![github actions ci badge]][github actions ci]
[![github actions windows ci badge]][github actions windows ci]

![CC0](http://i.creativecommons.org/p/zero/1.0/88x15.png)

Vigenère cipher provider
========================

This is a very small demonstration that shows the minimum required
things for a cipher in an OpenSSL 3.0 provider module.

This provider implements an extended version of the well known
Vigenère cipher, covering the whole range of byte values, not just
alphabetic characters.
For a description of this cipher, as well as its history, see
[https://en.wikipedia.org/wiki/Vigenère_cipher](https://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher)

It goes without saying that at this day and age, this cipher should
not be used in a real situation, but the implementation can be used as
a template for other cipher providers to start from.
If you want to use this for real, go back to the 16th century :wink:

Documentation
-------------

Detailed user documentation can be found in [vigenere.md](vigenere.md).

Setup source code directory
---------------------------

To complete the source repository, all git submodules must be up to date
too.  The first time, they need to be initialized too, as follows:

    git submodule update --init

The next time, `--init` can be skipped.

Building
--------

Building this provider requires [cmake](https://cmake.org) and a
building toolchain that it supports.

Simple configuration, for a system installation of OpenSSL 3:

    cmake -S . -B _build

If you have OpenSSL 3 installed somewhere else, do the following
instead, with `{path}` replaced with the directory of an OpenSSL 3
*installation*:

    cmake -DCMAKE_PREFIX_PATH={path} -S . -B _build

To build, do this:

    cmake --build _build

The result is `_build/vigenere.so` or `_build/Debug/vigenere.dll`.

Using
-----

OpenSSL provides a number of ways to specify where a module can be
found:

- Command line options for relevant `openssl` subcommands.
  Specifically, `-provider-path` and `-provider` options should be
  combined to add another path to look for provider modules, and the
  name of a provider to be loaded.

  ``` console
  $ echo "The quick brown fox jumps over the lazy dog" \
    | openssl enc -provider-path _build -provider vigenere \
                  -e -vigenere -K 0123456789ABCDEF0123456789ABCDEF \
    | od -tx1
  0000000 55 8b aa 87 fa 20 36 52 6c 43 a7 d9 f8 22 3b 0f
  0000020 67 92 bd 87 f3 20 3a 5f 74 43 b4 dd ee 1d ed 63
  0000040 69 88 65 d3 ea 25 46 0f 65 92 ac 71
  0000054
  ```

  Ref: [openssl(1)](https://www.openssl.org/docs/man3.0/man1/openssl.html#Provider-Options)

- The environment variable `OPENSSL_MODULES`, which works for any
  program that links OpenSSL's libcrypto.

  ``` console
  $ export OPENSSL_MODULES=_build
  $ echo "The quick brown fox jumps over the lazy dog" \
    | openssl enc -provider vigenere -e -vigenere -K 0123456789ABCDEF0123456789ABCDEF \
    | od -tx1
  0000000 55 8b aa 87 fa 20 36 52 6c 43 a7 d9 f8 22 3b 0f
  0000020 67 92 bd 87 f3 20 3a 5f 74 43 b4 dd ee 1d ed 63
  0000040 69 88 65 d3 ea 25 46 0f 65 92 ac 71
  0000054
  ```

  Ref: [openssl-env(7)](https://www.openssl.org/docs/man3.0/man7/openssl-env.html#OPENSSL_MODULES)

- Programmatically, if you want to do in your program what
  `-provider-path` does in `openssl` subcommands.

  Ref: [OSSL\_PROVIDER(3)](https://www.openssl.org/docs/man3.0/man3/OSSL_PROVIDER.html)

<!-- Logos and Badges -->

[github actions ci badge]:
    <https://github.com/provider-corner/vigenere/workflows/Linux%20%26%20MacOS%20GitHub%20CI/badge.svg>
    "GitHub Actions CI Status"

[github actions ci]:
    <https://github.com/provider-corner/vigenere/actions?query=workflow%3A%22Linux%20%26%20MacOS%20GitHub+CI%22>
    "GitHub Actions CI"

[github actions windows ci badge]:
    <https://github.com/provider-corner/vigenere/workflows/Windows%20GitHub%20CI/badge.svg>
    "GitHub Actions CI Status"

[github actions windows ci]:
    <https://github.com/provider-corner/vigenere/actions?query=workflow%3A%22Windows+GitHub+CI%22>
    "GitHub Actions CI"

