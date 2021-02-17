use strict;
use warnings;
use Test2::V0;

plan(1);

my $testname = "01-cipher";
my $count;

subtest('plain vigenere', \&cipher_test,
        -cleartext => "The quick brown fox jumps over the lazy dog\n",
        -ciphertext => '54686520717569636b2062726f776e20666f78206a756d7073206f76657220746865206c617a7920646f670a',
        -key => '0123456789ABCDEF' x 2);
# If OpenSSL would allow a -keylength option, we could set the key to
# -key => '0123456789ABCDEF' x 4

sub cipher_test {
    my %opts = @_;

    plan (4);

    my $keylength = length($opts{-key} // 0) / 2 * 8;
    # Currently, OpenSSL doesn't support a key length argument,
    # so we zero it here to avoid adding that argument.
    $keylength = 0;
    my $keylength_arg = $keylength ? " -keylength $keylength" : "";

    my $cleartextfile = "$testname-count.txt";
    open my $fclear, '>', $cleartextfile;
    print $fclear $opts{-cleartext};
    close $fclear;

    my $enccmd =
        "openssl enc -provider vigenere -e -vigenere$keylength_arg -K $opts{-key} -in $cleartextfile";
    my $enctext = `$enccmd`;
    is($?, 0,                                     "encrypting with '$enccmd'");
    is(unpack('H*',$enctext), $opts{-ciphertext}, "encryption result");

    my $ciphertextfile = "$testname-count.dat";
    open my $fcipher, '>', $ciphertextfile;
    print $fcipher $enctext;
    close $fcipher;

    my $deccmd =
        "openssl enc -provider vigenere -d -vigenere$keylength_arg -K $opts{-key} -in $ciphertextfile";
    my $dectext = `$deccmd`;
    is($?, 0,                                     "decrypting with '$enccmd'");
    is($dectext, $opts{-cleartext}, "decryption result");
}
