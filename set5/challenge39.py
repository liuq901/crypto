import random

from Crypto.Util.number import getStrongPrime, inverse
from tqdm import tqdm

def encrypt(plaintext, public_key):
    e, n = public_key
    return pow(plaintext, e, n)

def decrypt(ciphertext, private_key):
    d, n = private_key
    return pow(ciphertext, d, n)

def main():
    for _ in tqdm(range(100)):
        p = getStrongPrime(512, e=3)
        q = getStrongPrime(512, e=3)
        n = p * q
        et = (p - 1) * (q - 1)
        e = 3
        d = inverse(e, et)
        public_key = (e, n)
        private_key = (d, n)
        msg = random.randint(0, 1 << 64)
        assert decrypt(encrypt(msg, public_key), private_key) == msg

if __name__ == '__main__':
    main()
