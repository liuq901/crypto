import hashlib
import random

def rotate(x, n):
    x &= 0xffffffff
    return x << n | x >> 32 - n

def sha1(plaintext):
    h0 = 0x67452301
    h1 = 0xefcdab89
    h2 = 0x98badcfe
    h3 = 0x10325476
    h4 = 0xc3d2e1f0
    length = len(plaintext)
    plaintext += bytes([1 << 7])
    padding = (120 - len(plaintext) % 64) % 64
    plaintext += b'\x00' * padding
    plaintext += (length * 8).to_bytes(8, 'big')
    assert len(plaintext) % 64 == 0
    for offset in range(0, len(plaintext), 64):
        chunk = plaintext[offset:offset + 64]
        w = [int.from_bytes(chunk[i:i + 4], 'big') for i in range(0, 64, 4)]
        for i in range(16, 80):
            w.append(rotate(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1))
        a, b, c, d, e = h0, h1, h2, h3, h4
        for i in range(80):
            if i < 20:
                f = b & c | ~b & d
                k = 0x5a827999
            elif i < 40:
                f = b ^ c ^ d
                k = 0x6ed9eba1
            elif i < 60:
                f = b & c | b & d | c & d
                k = 0x8f1bbcdc
            elif i < 80:
                f = b ^ c ^ d
                k = 0xca62c1d6
            else:
                assert False
            a, b, c, d, e = rotate(a, 5) + f + e + k + w[i], a, rotate(b, 30), c, d
        h0 = h0 + a & 0xffffffff
        h1 = h1 + b & 0xffffffff
        h2 = h2 + c & 0xffffffff
        h3 = h3 + d & 0xffffffff
        h4 = h4 + e & 0xffffffff
    return b''.join(x.to_bytes(4, 'big') for x in (h0, h1, h2, h3, h4))

def main():
    for _ in range(1000):
        key = b'EpicFail Unknown'
        msg = bytes(random.randint(32, 126) for x in range(random.randint(10, 100)))
        plaintext = key + msg
        assert hashlib.sha1(plaintext).digest() == sha1(plaintext)

if __name__ == '__main__':
    main()
