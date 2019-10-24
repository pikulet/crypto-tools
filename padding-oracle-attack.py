'''
Padding Oracle Decrypter
'''

import sys
from oracle_python import pad_oracle

CORRECT_PADDING = str(1)
WRONG_PADDING = str(0)
BLOCK_SIZE = 8
EMPTY_BYTE = ("00").decode("hex")

def main():
    if len(sys.argv) != 3:
        print("Usage: python padding-orcale-attack.py c_0 c_1")
        sys.exit(-1)

    ct = sys.argv[1], sys.argv[2]
    pt = padding_oracle_decrypt(ct)
    print(pt)

########### HELPERS ###########
def h2b(hex_string):
    return hex_string[2:].decode("hex")

def b2h(byte_string):
    return "0x" + byte_string.encode("hex")

def get_byte(value):
    return ("0" + str(value)).decode("hex")

def xor(a, b):
    return chr( ord(a) ^ ord(b) )

def xor_multiple(a, b):
    res = "".join([ xor(a[i], b[i]) for i in range(len(a))])
    return res

########### MAIN ALGORITHM ###########
def get_byte_string(value, length):
    return get_byte(value) * length

def discover_padding_length(iv_bytes, c):
    # discover padding length
    for i in range(BLOCK_SIZE):
        new_iv = iv_bytes[:i] + xor( iv_bytes[i], chr(1) ) + iv_bytes[i+1:]
        valid_ct = pad_oracle(b2h(new_iv), c)
        if valid_ct == WRONG_PADDING:
            padding_length = BLOCK_SIZE - i
            return padding_length

def padding_oracle_decrypt(ct):
    iv = ct[0]
    c = ct[1]

    iv_bytes = h2b(iv)

    valid_ct = pad_oracle(iv, c)
    if valid_ct == WRONG_PADDING:
        print("Ciphertext is invalid. Please use a valid ciphertext.")

    padding_length = discover_padding_length(iv_bytes, c)
    discovered_bytes = get_byte_string(padding_length, padding_length) 

    for i in range(BLOCK_SIZE - padding_length):
        index = BLOCK_SIZE - padding_length - i - 1

        attempted_padding_length = i + padding_length + 1
        # 0x(b+1).... b times
        byte_string = get_byte_string(attempted_padding_length, 
                attempted_padding_length - 1)

        remaining_bytes = xor_multiple( discovered_bytes, \
                xor_multiple( iv_bytes[index+1:], byte_string ) )

        for j in range(2**8):
            new_iv = iv_bytes[:index] \
                    + xor( iv_bytes[index], chr(j) ) \
                    + remaining_bytes
                    
            valid_ct = pad_oracle(b2h(new_iv), c)
            if valid_ct == CORRECT_PADDING:
                message_byte = xor( chr(j), chr(attempted_padding_length) )
                discovered_bytes = message_byte + discovered_bytes
                break

    return "".join(discovered_bytes)[:8 - padding_length]

if __name__ == "__main__":
    main()
