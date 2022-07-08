import random

from Crypto.Util.number import getStrongPrime, inverse
from tqdm import tqdm

def encrypt(plaintext, public_key):
    e, n = public_key
    return pow(plaintext, e, n)

def decrypt(ciphertext, private_key):
    d, n = private_key
    return pow(ciphertext, d, n)

def generate_key():
    p = getStrongPrime(512, e=3)
    q = getStrongPrime(512, e=3)
    n = p * q
    et = (p - 1) * (q - 1)
    e = 3
    d = inverse(e, et)
    public_key = (e, n)
    private_key = (d, n)
    return public_key, private_key

def pad(ciphertext, public_key):
    e, n = public_key
    s = random.randint(2, n - 1)
    fake_ciphertext = pow(s, e, n) * ciphertext % n
    return fake_ciphertext, s

def unpad(fake_plaintext, s, public_key):
    n = public_key[1]
    return fake_plaintext * inverse(s, n) % n

def main():
    for _ in tqdm(range(100)):
        plaintext = random.randint(0, 1 << 512)
        public_key, private_key = generate_key()
        ciphertext = encrypt(plaintext, public_key)
        assert decrypt(ciphertext, private_key) == plaintext
        fake_ciphertext, s = pad(ciphertext, public_key)
        assert fake_ciphertext != ciphertext
        fake_plaintext = decrypt(fake_ciphertext, private_key)
        assert unpad(fake_plaintext, s, public_key) == plaintext

if __name__ == '__main__':
    main()
