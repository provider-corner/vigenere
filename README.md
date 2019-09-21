![CC0](http://i.creativecommons.org/p/zero/1.0/88x15.png)

Vignère cipher provider
=======================

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

