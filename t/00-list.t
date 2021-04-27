use strict;
use warnings;
use Test2::V0;

plan(1);

like(`openssl list -provider vigenere -cipher-algorithms`,
     qr/vigenere \} \@ vigenere\n/,
     'vigenere is listed');
