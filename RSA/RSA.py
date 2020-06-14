import random
from math import gcd

def power(x,y,p):
    res = 1
    x = x % p
    while y > 0:
        if y & 1:
            res = (res * x) % p
        y = y >> 1
        x = (x * x) % p
    return res

def miller_rabin(d,n):
    a = 2 + random.randint(1, n - 4)
    x = power(a, d, n)
    if x == 1 or x == n - 1:
        return True
    while d != n - 1:
        x = (x * x) % n
        d *= 2

        if x == 1:
            return False
        if x == n - 1:
            return True
    return False


def is_prime(n):
    count = 4
    d = n - 1
    while d % 2 == 0:
        d //= 2
    for i in range(count):
        if miller_rabin(d, n) == False:
            return False
    return True


def mult_inverse(a,m):
    m0 = m
    y = 0
    x = 1
    if (m == 1):
        return 0
    while (a > 1):
        q = a // m
        t = m
        m = a % m
        a = t
        t = y
        y = x - q * y
        x = t
    if (x < 0):
        x = x + m0
    return x


def generate_keys(k):
    p = random.getrandbits(int(k/2))
    while is_prime(p) != True:
        p = random.getrandbits(int(k/2))
        is_prime(p)
    q = random.getrandbits(int(k-k/2))
    while (p == q) or (is_prime(q) == False):
        q = random.getrandbits(int(k-k/2))
        is_prime(q)
    phi = (p-1)*(q-1)
    N = p*q
    e = random.randint(1,phi)
    while gcd(e,phi) != 1:
        e = random.randint(1, phi)
    d = mult_inverse(e,phi)
    return ((e, N), (d, N))

def decryption(c,keys):
    d = keys[0]
    n = keys[1]
    text = [chr(pow(char, d, n)) for char in c]
    return "".join(text)

def encryption(p,keys):
    n = keys[1]
    e = keys[0]
    c = [pow(ord(char), e, n) for char in p]
    return c

k = int(input('Required modulus bit length:'))
ttext = 'When the days are cold'
public,private = generate_keys(k)
enc_message = encryption(ttext,public)
print("Encrypted message is: ", ''.join(map(lambda x: str(x), enc_message)))
decr_message = decryption(enc_message,private)
print("Initial message is: ",decr_message)