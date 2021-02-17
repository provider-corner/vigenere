use strict;
use warnings;
use Test2::V0;

plan(1);

my $testname = "01-cipher";
my $count;

subtest('plain vigenere', \&cipher_test,
        -cleartext => "The quick brown fox jumps over the lazy dog\n",
        -ciphertext => '558baa87fa2036526c43a7d9f8223b0f6792bd87f3203a5f7443b4ddee1ded63698865d3ea25460f6592ac71',
        -key => '0123456789ABCDEF' x 4);

sub cipher_test {
    my %opts = @_;

    plan (4);

    my $keylength = length($opts{-key} // 0) / 2 * 8;
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
        "openssl enc -provider vigenere -d -vigenere -keylength $keylength -K $opts{-key} -in $ciphertextfile";
    my $dectext = `$deccmd`;
    is($?, 0,                                     "decrypting with '$enccmd'");
    is($dectext, $opts{-cleartext}, "decryption result");
}
