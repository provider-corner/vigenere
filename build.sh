#!/bin/bash
gcc test_vigenere.c test_common.c -L/home/dev/git/openssl/ -lcrypto
gcc -shared -o vigenere.so vigenere.c