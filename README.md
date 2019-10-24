# crypto-tools
crypto tools written for practice

### padding oracle attack

This is the attack on (PKCS#5 padding)[https://en.wikipedia.org/wiki/Padding_(cryptography)#PKCS#5_and_PKCS#7].

Notes on the input/ output format of the padding oracle:
- The padding oracle I used is a 1-block decryption oracle
- Input: `"0x... 0x...."`. The two blocks represent the `(iv, ciphertext)` tuple. 
- Output: "1" for valid padding, "0" for invalid padding.

### encryption oracle creator

Uses a decryption oracle to create an encryption oracle. 

The message can be multi-block.

### Remarks

Development was done in python2, which is going to be deprecated. The algorithm still works, though.
