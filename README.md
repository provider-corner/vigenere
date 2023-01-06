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

