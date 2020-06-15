from RSA import generate_keys
import SHA256
import sys
import os

hLen = 32

def rsa_encr(p,key):
    e = key[0]
    n = key[1]
    c = pow(p,e,n)
    return c

def rsa_dp(c,key):
    d = key[0]
    n = key[1]
    m = pow(c, d, n)
    return m

def xor(x,y):
    res = []
    for i in x:
        for j in y:
            res.append(i^j)
    return bytes(res)

def I2OSP(x,l):
    """
     I2OSP (Integer-to-Octet-String primitive)produces an octet string of a desired length from an integer;
     the string may be viewed as the base-256representation of the integer
    :param x: nonnegative integer to be converted
    :param l: ntended length of the resulting octet string
    :return: corresponding octet string of length l
    """
    res = bytes.fromhex(hex(x)[2:].rjust(l*2,'0'))
    return res

def OS2IP(x):
    # OS2IP (Octet-String-to-Integer primitive) is the inverse of I2OSP.
    res = 0
    l = len(x)
    for i in range(l):
        res += x[l - 1 - i] * 256 ** i
    return res

def MGF(z,l):
    """
    hasb : hash function (hLen denotes the length in octets of the hash function output)
    :param z: seed from which mask is generated, an octet string
    :param l: ntended length in octets of the mask, at most 2^32 hLen
    :return:  mask, an octet string of lengthl
    """
    if l > 2** 32 * hLen:
        sys.exit('Message too long')
    T = ''
    for i in range (int(l/256) - 1):
        C = I2OSP(i,4)
        T += SHA256.encrypt(z + C)
    mask = T[:l]
    return mask

def EME_OAEP_Encode(m):
    l = 128
    message_len = len(m)
    if message_len > l - 2*hLen -2:
        sys.exit('Message too long.')
    pHash = SHA256.encrypt(b'')
    ps = I2OSP(0, max(l - message_len - 2 * hLen - 2, 0))
    db = bytes(pHash.encode('utf-8')) + ps + b'\x01' + m
    seed = os.urandom(256)
    dbMask = MGF(seed, hLen)
    maskedDB = xor(db,dbMask)
    seedMask = MGF(maskedDB, hLen)
    maskedSeed = xor(seed,seedMask)
    EM = maskedSeed + maskedDB
    return EM

def EME_OAEP_Decode(en_m):
    l = 128
    if l < hLen + 1:
        sys.exit("Decoding error.")
    em = I2OSP(en_m, l)
    maskedSeed = em[1: hLen + 1]
    maskedDb = em[hLen + 1:]
    seedMask = MGF(maskedDb, hLen)
    seed = xor(maskedSeed,seedMask)
    dbMask = MGF(seed, l - hLen)
    DB = xor(maskedDb,dbMask)
    pHash = SHA256.encrypt(b'')
    lHash2 = DB[:hLen]
    if pHash != lHash2:
        sys.exit('Decoding error.')
    for i, el in enumerate(DB[hLen:],hLen):
        if el == 1:
            break
        m = DB[i+1:]
    return m


def RSA_OAEP_Enc(pub_k,m):

    #:param pub_k : recipient’s RSA public key
    #:param m :message to be encrypted, an octet string of length at mostk−2−2hLen,
    #wherekis the length in octets of the modulus n and hLen is the length in octets of the hash function output for EME-OAEP.
    #:param p : encoding parameters, an octet string that may be empty
    #:return: c ciphertext, an octet string of lengthk
    #k = 2 * hLen + 2
    EM = EME_OAEP_Encode(m)
    m = OS2IP(EM)
    c = rsa_encr(m,pub_k)
    C = I2OSP(c, k)
    return C

def RSA_OAEP_Decr(K,c):

    #:param K: recipient’s RSA private key
    #:param c: ciphertext to be decrypted, an octet string of length k, where k is the length in octets of the modulus n
    #:param p: encoding parameters, an octet string that may be empty
    #:return: M : message, an octet string of length at most k−2−2hLen, where hLen is the length in octets
    #of the hash function output for EME-OAEP
    c1 = OS2IP(c)
    m = rsa_dp(c1,K)
    EM = I2OSP(m, 128)
    M = EME_OAEP_Decode(EM)
    return M


k = int(input('Required modulus bit length:'))
text = 'when teh days are cold'.encode('utf-8')
public,private = generate_keys(k)
enc_message = RSA_OAEP_Enc(public,text)
print("Encrypted message is: ",enc_message)
decr_message = RSA_OAEP_Decr(private,enc_message)
print("Initial message is: ",decr_message)