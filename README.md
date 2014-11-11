kernel-aes
==========

Testing kernel AES encryption through crypto-dev (https://github.com/cryptodev-linux/cryptodev-linux).
Please install crypto-dev module.

Compiling
=========

$gcc aes.c -o aes

Running
=======

./aes aaaa 0123456789abcdef

Key 0123456789abcdef, Size 16
Got cbc(aes) with driver cbc(aes-generic)
Note: This is not an accelerated cipher
2f 5b ffffffec 15 37 ffffffd2 ffffff9d 42 fffffff2 ffffffbf ffffffac 0d ffffffe1 ffffffe3 ffffff9e 02 Key 0123456789abcdef, Size 16
Got cbc(aes) with driver cbc(aes-generic)
Note: This is not an accelerated cipher
61 61 61 61 7b 7b 7b 7b 7b 7b 7b 7b 7b 7b 7b 7b


Notes
=====

Because of CBC with need to do padding. The character for padding in this case is { (0x7b). 
Also the key should be at least 16 characters.

