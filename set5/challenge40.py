import functools
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

def solve(a, m):
    assert all(x[0] == 3 for x in m) and len(a) == len(m) == 3
    m = [x[1] for x in m]
    M = functools.reduce(lambda x, y: x * y, m, 1)
    result = 0
    for i in range(3):
        tmp = M // m[i]
        t = inverse(tmp, m[i])
        result += a[i] * t * tmp
    return result % M

def cube_root(x):
    l = 0
    r = x
    ans = None
    while l <= r:
        mid = (l + r) // 2
        if mid ** 3 <= x:
            l = mid + 1
            ans = mid
        else:
            r = mid - 1
    return ans

def main():
    for _ in tqdm(range(100)):
        msg = random.randint(0, 1 << 512)
        public_key = []
        private_key = []
        ciphertext = []
        for i in range(3):
            key = generate_key()
            public_key.append(key[0])
            private_key.append(key[1])
            ciphertext.append(encrypt(msg, public_key[-1]))
            assert decrypt(ciphertext[-1], private_key[-1]) == msg
        result = solve(ciphertext, public_key)
        plaintext = cube_root(result)
        assert plaintext == msg

if __name__ == '__main__':
    main()
