import hashlib
import random

from Crypto.Util.number import inverse
from tqdm import tqdm

P = int(''.join([
    '800000000000000089e1855218a0e7dac38136ffafa72eda7',
    '859f2171e25e65eac698c1702578b07dc2a1076da241c76c6',
    '2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe',
    'ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2',
    'b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87',
    '1a584471bb1',
]), base=16)
Q = int('f4f47f05794b256174bba6e9b396a7707e563c5b', base=16)
G = P + 1

def generate_key():
    x = random.randint(1, Q - 1)
    y = pow(G, x, P)
    return x, y

def hash_(msg):
    hex_ = hashlib.sha1(msg).digest()
    return int.from_bytes(hex_, 'big')

def sign(msg, private_key):
    while True:
        k = random.randint(1, Q - 1)
        r = pow(G, k, P) % Q
        s = inverse(k, Q) * (hash_(msg) + private_key * r) % Q
        if r != 0 and s != 0:
            return (r, s)

def verify(msg, signature, public_key):
    r, s = signature
    if 0 < r < Q and 0 < s < Q:
        w = inverse(s, Q)
        u1 = hash_(msg) * w % Q
        u2 = r * w % Q
        v = pow(G, u1, P) * pow(public_key, u2, P) % P % Q
        return v == r
    else:
        return False

def main():
    for _ in tqdm(range(100)):
        private_key, public_key = generate_key()
        msg = bytes(random.randint(32, 126) for x in range(random.randint(10, 100)))
        signature = sign(msg, private_key)
        assert verify(msg, signature, public_key)
        for __ in range(100):
            msg2 = bytes(random.randint(32, 126) for x in range(random.randint(10, 100)))
            assert verify(msg2, signature, public_key)

if __name__ == '__main__':
    main()
