'''
Encryption Oracle
'''

import sys
from oracle_python import dec_oracle

BLOCK_SIZE = 8
EMPTY_BLOCK = "0x" + "00"*BLOCK_SIZE

def main():
    if len(sys.argv) != 2:
        print("Usage: python encryption-oracle.py \"message\"")
        sys.exit(-1)

    message = sys.argv[1]
    ct = encryption_oracle(message)
    print(ct)

########## HELPERS ##########

def b2h(byte_string):
    return "0x" + byte_string.encode("hex")

def h2b(hex_string):
    return hex_string[2:].decode("hex")

def get_byte(value):
    return ("0" + str(value)).decode("hex")

def get_byte_string(value, length):
    return get_byte(value) * length

def xor(a, b):
    return chr( ord(a) ^ ord(b) )

def xor_multiple(a, b):
    res = "".join([ xor(a[i], b[i]) for i in range(len(a))])
    return res

########## MAIN ALGORITHEM ##########

def get_padded_message(m):
    blocks = [ m[i: i + BLOCK_SIZE] for i in range(0, len(m), BLOCK_SIZE) ]

    # last block
    last_block = blocks[-1]
    padding_length = BLOCK_SIZE - len(last_block)
    if padding_length == 0:
        padding_length = BLOCK_SIZE
        padding = get_byte_string(padding_length, padding_length)
        blocks.append(padding)

    padding = get_byte_string(padding_length, padding_length)
    blocks[-1] = last_block + padding

    return blocks

def decipher(m, ct):
    ct = b2h(ct)
    attempted_iv = h2b(EMPTY_BLOCK)

    decryption_result = dec_oracle(b2h(attempted_iv), ct)
    decryption_result_bytes = h2b(decryption_result)

    correct_iv_bytes = xor_multiple(decryption_result_bytes, m)

    return correct_iv_bytes

def encryption_oracle(pt):
    last_ct_bytes = h2b(EMPTY_BLOCK)

    blocked_message = get_padded_message(pt)

    ciphertext = list()
    ciphertext.append(last_ct_bytes)

    for i in range(len(blocked_message)):
        block_to_find = len(blocked_message) - 1 - i
        previous_ct = decipher(blocked_message[block_to_find], \
                ciphertext[0])
        ciphertext.insert(0, previous_ct)

    return " ".join([b2h(i) for i in ciphertext])

if __name__ == "__main__":
    main()
