import random

from Crypto.Util.number import GCD, getPrime, inverse

MSG = b'kick it, CC'

def gen_prime(bits, e):
    while True:
        p = getPrime(bits)
        if GCD(p - 1, e) == 1:
            return p

def generate_key():
    p = gen_prime(384, e=3)
    q = gen_prime(384, e=3)
    n = p * q
    et = (p - 1) * (q - 1)
    e = 3
    d = inverse(e, et)
    public_key = (e, n)
    private_key = (d, n)
    return public_key, private_key

def rsa(msg, key):
    return pow(msg, key[0], key[1])

def pad(msg):
    length = 96
    padding_len = length - 3 - len(msg)
    assert padding_len >= 8
    padding_string = bytes(random.randint(1, 255) for _ in range(padding_len))
    plaintext = b'\x00\x02' + padding_string + b'\x00' + msg
    return int.from_bytes(plaintext, 'big')

def unpad(hex_):
    assert hex_[0] == 0 and hex_[1] == 2
    for i in range(2, len(hex_)):
        if hex_[i] == 0:
            return hex_[i + 1:]
    assert False

def verify(ciphertext, private_key):
    plaintext = rsa(ciphertext, private_key).to_bytes(96, 'big')
    return plaintext[0] == 0 and plaintext[1] == 2

def ceil(x, y):
    return (x + y - 1) // y

def merge(a):
    res = []
    a.sort()
    for l, r in a:
        if res and l <= res[-1][1] + 1:
            res[-1] = (res[-1][0], max(r, res[-1][1]))
        else:
            res.append((l, r))
    return res

def solve(ciphertext, public_key, private_key):
    e, n = public_key
    B = 2 ** (8 * (96 - 2))
    M_ = [(2 * B, 3 * B - 1)]
    first = True
    while True:
        if first:
            s = ceil(n, 3 * B)
            while True:
                if verify(ciphertext * pow(s, e, n) % n, private_key):
                    break
                s += 1
        elif len(M_) >= 2:
            s = s_ + 1
            while True:
                if verify(ciphertext * pow(s, e, n) % n, private_key):
                    break
                s += 1
        else:
            assert len(M_) == 1
            a, b = M_[0]
            r = 2 * ceil(b * s_ - 2 * B, n)
            s = ceil(2 * B + r * n, b)
            while True:
                if verify(ciphertext * pow(s, e, n) % n, private_key):
                    break
                s += 1
                if s > (3 * B + r * n) // a:
                    r += 1
                    s = ceil(2 * B + r * n, b)
        M = []
        for a, b in M_:
            lower = ceil(a * s - 3 * B + 1, n)
            upper = (b * s - 2 * B) // n
            for r in range(lower, upper + 1):
                begin = max(a, ceil(2 * B + r * n, s))
                end = min(b, (3 * B - 1 + r * n) // s)
                M.append((begin, end))
        M = merge(M)
        if len(M) == 1 and M[0][0] == M[0][1]:
            return M[0][0] % n
        s_, M_ = s, M
        first = False

def main():
    public_key, private_key = generate_key()
    ciphertext = rsa(pad(MSG), public_key)
    assert verify(ciphertext, private_key)
    result = solve(ciphertext, public_key, private_key)
    plaintext = unpad(result.to_bytes(96, 'big'))
    assert plaintext == MSG

if __name__ == '__main__':
    main()
