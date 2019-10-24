# crypto-tools
crypto tools written for practice

### padding oracle attack

This is the attack on PKCS#5 padding.

The padding oracle I used is a 1-block decryption oracle that takes in `"0x... 0x...."` as the input. The two blocks represent the `(iv, ciphertext)` tuple. The padding oracle returns a value indicating if the padding is valid.

### encryption oracle creator

Uses a decryption oracle to create an encryption oracle.
The decryption oracle returns the actual plaintext.
