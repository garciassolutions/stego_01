# stego_01
"Secure" BMP Stenography Server and Client, with a twist!
About
- BMP Steganography Software
- Written by Anthony Garcia
 
Project Goal

- To have a piece of software that could hide information securly within an image file, while also keeping the transfer of the
plaintext and ciphertext secure. This is my first attempt at creating any type of steganography software (ever), and using SSL protocol within C.

Encoding methodology
- The clients plaintext is sent over SSL to the server -> the server uses 2048 bit RSA encoding to encrypt the plaintext.
- The ciphertext is split into 6 byte rows and XOR'd with a random byte.
- These newly created rows are 'jumbled' and reordered "randomly".
- The ciphertext is then used as a RBG pixel within the bmp image. Additional bytes are used to keep 8 byte (For this BMP configuration.) alignment consistent.
- The RSA image is sent over a secure socket (SSL) to client.

Decoding methodology
- The clients ciphertext image is sent over SSL to server.
- 8 byte rows are taken from the image, XOR decoding takes place, the rows are 'unjumbled' and reordered.
- and the first 6 bytes stripped (with the exception of the last row) to obtain the RSA ciphertext -> RSA decryption occurs -> plaintext is sent
over SSL to client

- Changelog
v3.0<br />
. XOR and row jumble added.<br />
. Store ciphertext in color bytes and not padding.<br />
. Cleaned up unused variables and code logic. <br />
v2.0<br />
. SSL added for security.<br />
v1.0<br />
. Added threading.<br />
. Added filesize > BLOCK_SIZE support.<br />
. Resolved image size issue.<br />
