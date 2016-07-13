# stego_01
"Secure" BMP Stenography Server and Client, with a twist!
About
- BMP Steganography Software
- Written by Anthony Garcia

Project goal was to have a piece of software that could hide information
securly within an image file, while also keeping the transfer of the
plaintext and ciphertext secure. This is my first attempt at creating any type
of steganography software.

- Encoding methodology
Plaintext is sent over SSL to the server -> 2048 bit RSA encoding is applied
  to the plaintext -> the ciphertext is split into 6 byte rows,
  XOR'd with a random byte, and used as RBG pixels within the bmp image.
Additional bytes are used to keep 8 byte padding consistent. -> steganography
image is sent over a secure socket (SSL) to client

- Decoding methodology
BMP image is sent over SSL to server -> 8 byte rows are taken from the
  image, XOR decoding takes place, the rows are placed in their original
order, and the first 6 bytes stripped (with the exception of the last row)
to obtain the RSA ciphertext -> RSA decryption occurs -> plaintext is sent
over SSL to client

Changelog

-v3.0
        . XOR and row jumble added.
        . Store ciphertext in color bytes and not padding.
        . Cleaned up unused variables and code logic.
-v2.0
        . SSL added for security.
-v1.0
        . Added threading.
        . Added filesize > BLOCK_SIZE support.
        . Resolved image size issue.
