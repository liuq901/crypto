import base64
from decimal import Decimal, getcontext

from Crypto.Util.number import getStrongPrime, inverse
from tqdm import tqdm

TEXT = 'VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ=='

def rsa(msg, key):
    return pow(msg, key[0], key[1])

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

def parity(ciphertext, private_key):
    return rsa(ciphertext, private_key) & 1

def solve(ciphertext, public_key, private_key):
    e, n = public_key
    length = 1024
    l = Decimal(0)
    r = Decimal(n)
    step = pow(2, e, n)
    getcontext().prec = length
    for _ in tqdm(range(length)):
        mid = (l + r) / 2
        ciphertext = ciphertext * step % n
        if parity(ciphertext, private_key) == 1:
            l = mid
        else:
            r = mid
    return int(r)

def main():
    text = base64.b64decode(TEXT)
    plaintext = int.from_bytes(text, 'big')
    public_key, private_key = generate_key()
    ciphertext = rsa(plaintext, public_key)
    guess = solve(ciphertext, public_key, private_key)
    assert guess.to_bytes((guess.bit_length() + 7) // 8, 'big') == text

if __name__ == '__main__':
    main()
