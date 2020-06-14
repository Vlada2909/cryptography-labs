import Aes
from random import getrandbits
import sys

def cbc_encrypt(input_b, key):
    if len(input_b) % 16:
        sys.exit("Uncorrect length of message: {}.".format(len(input_b)))
    initial_block = getrandbits(16)
    res = initial_block
    prev_block = list(initial_block)
    blocks = []
    for i in range(0, len(input_b), 16):
        blocks.append(input_b[i:i + 16])
    for block in blocks:
        bl = []
        for x in prev_block:
            for y in block:
                bl.append(x^y)
        block = Aes.encrypt(bl, key)
        res += bytes(block)
        prev_block = block
    return res

def cbc_decrypt(cipher, key):
    if len(cipher) % 16:
        sys.exit("Uncorrect length of ciphertext: {}.".format(len(cipher)))
    res = b''
    blocks = []
    for i in range(0, len(cipher), 16):
        blocks.append(cipher[i: i + 16])
    for i in range(len(blocks) - 1, 0, -1):
        mi = Aes.decrypt(blocks[i], key)
        m = []
        for x in mi:
            for y in blocks[i-1]:
                m.append(x^y)
        res = bytes(m) + res
    return res

def ctr_encrypt(input_b, key):
    if len(input_b) % 16:
        sys.exit("Uncorrect length of message: {}.".format(len(input_b)))
    nonce = getrandbits(8)
    res = nonce
    blocks = []
    for i in range(0, len(input_b), 16):
        blocks.append(input_b[i: i + 16])
    for i in range(len(blocks)):
        block = blocks[i]
        hex_i = hex(i)[2:]
        count = nonce.hex() + '0' * (16 - len(hex_i)) + hex_i
        count = bytes.fromhex(count)
        r = Aes.encrypt(count, key)
        res += bytes([x ^ y for x, y in zip(r, block)])
    return res

def ctr_decrypt(c,key):
    if len(c) % 16 != 8:
        sys.exit("Uncorrect length of ciphertext: {}.".format(len(c)))
    nonce = c[:8]
    blocks = []
    for i in range(8, len(c), 16):
        blocks.append(c[i: i + 16])
    res = b''
    for i in range(len(blocks)):
        block = blocks[i]
        hex_i = hex(i)[2:]
        count = nonce.hex() + '0' * (16 - len(hex_i)) + hex_i
        count = bytes.fromhex(count)
        r = Aes.decrypt(count, key)
        res += bytes([x ^ y for x, y in zip(r, block)])
    return res