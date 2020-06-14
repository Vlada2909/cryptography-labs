#SHA-256 uses sequence of sixty-four constant 32-bit words

K = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]

# the initial hash value

H = [0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19]

def shift_right(x, n):
    """x is a w-bit word, n is an integer with 0 ≤ n < w
    (x)=x >> n.
    """
    if 0 <= n & n< 32:
        return x >> n


def rotate_right(x, n):
    """x is a w-bit word,n is an integer with 0 ≤ n < w
    (x) =(x >> n) ∨ (x << w - n).
    """
    if 0 <= n & n < 32:
        return  (x >> n)  | (x << (32 - n ))


def ch(x, y, z):
    """The x input chooses if the output is from y or z.
    Ch(x,y,z)=(x∧y)⊕(¬x∧z)
    """
    res = (x & y) ^ ((~x) & z)
    return res


def maj(x, y, z):
    """The result is set according to the majority of the 3 inputs.
    Maj(x, y,z) = (x ∧ y) ⊕ (x ∧ z) ⊕ ( y ∧ z)
    """
    res = (x & y) ^ (x & z) ^ (y & z)
    return res


def sigma0(x):
    # Rotr 2(x) ⊕ Rotr 13(x) ⊕ Rotr 22(x)
    return rotate_right(x, 2) ^ rotate_right(x, 13) ^ rotate_right(x, 22)



def sigma1(x):
    # Rotr 6(x) ⊕ Rotr 11(x) ⊕ Rotr 25(x)
    return rotate_right(x, 6) ^ rotate_right(x, 11) ^ rotate_right(x, 25)



def gamma0(x):
    # Rotr 7(x) ⊕ Rotr 18(x) ⊕ Shr 3(x)
    return rotate_right(x, 7) ^ rotate_right(x, 18) ^ shift_right(x, 3)


def gamma1(x):
    # Rotr 17(x) ⊕ Rotr 19(x) ⊕ Shr 10(x)
    return rotate_right(x, 17) ^ rotate_right(x, 19) ^ shift_right(x, 10)

# PREPROCESSING
# Preprocessing consists of 3 steps: padding the message,parsing the message into message block,setting initial hash values.

def padding(text):
    """
    The lenght of text is l bits.
    k is the smallest non-negative solution to the equation l+1+k = 448 (mod 512)
    Append '1' bit to the end of the text,followed by k zero bits.
    """
    l = 8*len(text)
    k = (448 - 1-l) % 512
    padding = '1' + '0'*k + bin(l)[2:].rjust(64, '0')
    res = text + bytes.fromhex(hex(int(padding, 2))[2:])
    return res


def parsing(text):
    w = []
    for i in range(0, 16):
        w.append(sum([text[4 * i + 0] << 24,text[4 * i + 1] << 16,text[4 * i + 2] << 8,text[4 * i + 3] << 0,]))
    return w


def encrypt(text):
    message = padding(text)
    for i in range(0, len(message), 64):
        w = parsing(message[i:i + 64])
        for i in range(16, 64):
            temp = gamma1(w[i - 2]) + w[i - 7] + gamma0(w[i - 15]) + w[i - 16]
            w.append(temp & 0xffffffff)
        a = H[0]
        b = H[1]
        c = H[2]
        d = H[3]
        e = H[4]
        f = H[5]
        g = H[6]
        h = H[7]
        for i in range(64):
            t1 = (h + sigma1(e) + ch(e, f, g) + K[i] + w[i]) & 0xffffffff
            t2 = (sigma0(a) + maj(a, b, c)) & 0xffffffff
            h = g
            g = f
            f = e
            e = (d + t1) & 0xffffffff
            d = c
            c = b
            b = a
            a = (t1 + t2) & 0xffffffff
        h0 = (a + H[0]) & 0xffffffff
        h1 = (b + H[1]) & 0xffffffff
        h2 = (c + H[2]) & 0xffffffff
        h3 = (d + H[3]) & 0xffffffff
        h4 = (e + H[4]) & 0xffffffff
        h5 = (f + H[5]) & 0xffffffff
        h6 = (g + H[6]) & 0xffffffff
        h7 = (h + H[7]) & 0xffffffff
    h1 = (h0).to_bytes(4, 'big') + (h1).to_bytes(4, 'big') + (h2).to_bytes(4, 'big') + (h3).to_bytes(4, 'big')
    h2 = (h4).to_bytes(4, 'big') + (h5).to_bytes(4, 'big') + (h6).to_bytes(4, 'big') + (h7).to_bytes(4, 'big')
    hash0 = h1 + h2
    hash = bytearray(hash0).hex()
    return hash

def hmac(text,key,blockSize = 64,outputSize = 32):
    if len(key) > blockSize:
        key = encrypt(key)
        key = key + (0).to_bytes(blockSize - outputSize, 'big')
    if len(key) < blockSize:
        key = key + (0).to_bytes(blockSize - len(key), 'big')
    o_key_pad = []
    i_key_pad = []
    for i in key:
        o_key_pad.append(i^ 0x5c)
        i_key_pad.append(i^0x36)
    one = encrypt(bytes(i_key_pad) + text)
    result = encrypt(bytes(o_key_pad) + bytes(one.encode('utf-8')))
    return result

def key_for_aes(key):
    return encrypt(key)[32:]

message = 'when the days are cold'
message= message.encode('utf-8')
print(encrypt(message))
key1 = bytes('night'.encode('utf-8'))
mess = bytes('it`s been so late'.encode('utf-8'))
print(hmac(mess,key1))
print(key_for_aes(message))

