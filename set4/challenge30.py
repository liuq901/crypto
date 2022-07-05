import hashlib
import random

def rotate(x, n):
    x &= 0xffffffff
    return x << n | x >> 32 - n

def get_pad(length):
    padding = bytes([1 << 7])
    pad_len = (120 - (length + 1) % 64) % 64
    padding += b'\x00' * pad_len
    padding += (length * 8).to_bytes(8, 'little')
    assert (length + len(padding)) % 64 == 0
    return padding

def md4(plaintext, h0=0x67452301, h1=0xefcdab89, h2=0x98badcfe, h3=0x10325476, length=0):
    padding = get_pad(length + len(plaintext))
    plaintext += padding
    assert len(plaintext) % 64 == 0
    for offset in range(0, len(plaintext), 64):
        chunk = plaintext[offset:offset + 64]
        block = []
        for i in range(0, len(chunk), 4):
            block.append(chunk[i] | chunk[i + 1] << 8 | chunk[i + 2] << 16 | chunk[i + 3] << 24)
        a, b, c, d = h0, h1, h2, h3
        rotate_num = [3, 7, 11, 19]
        for i in range(4):
            for j in range(4):
                e = b & c | ~b & d
                a, b, c, d = d, rotate(a + e + block[i * 4 + j], rotate_num[j]), b, c
        rotate_num = [3, 5, 9, 13]
        for i in range(4):
            for j in range(4):
                e = b & c | b & d | c & d
                k = 0x5a827999
                a, b, c, d = d, rotate(a + e + block[i + j * 4] + k, rotate_num[j]), b, c
        rotate_num = [3, 9, 11, 15]
        idx = [0, 8, 4, 12, 2, 10, 6, 14, 1, 9, 5, 13, 3, 11, 7, 15]
        for i in range(4):
            for j in range(4):
                e = b ^ c ^ d
                k = 0x6ed9eba1
                a, b, c, d = d, rotate(a + e + block[idx[i * 4 + j]] + k, rotate_num[j]), b, c
        h0 = h0 + a & 0xffffffff
        h1 = h1 + b & 0xffffffff
        h2 = h2 + c & 0xffffffff
        h3 = h3 + d & 0xffffffff
    return b''.join(x.to_bytes(4, 'little') for x in (h0, h1, h2, h3))

def main():
    key = b'EpicFail Unknown'
    for _ in range(1000):
        msg = bytes(random.randint(32, 126) for x in range(random.randint(10, 100)))
        plaintext = key + msg
        assert hashlib.new('md4', plaintext).digest() == md4(plaintext)
    message = b'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'
    attack_message = b';admin=true'
    digest = md4(key + message)
    h0, h1, h2, h3 = [int.from_bytes(digest[i:i + 4], 'little') for i in range(0, len(digest), 4)]
    key_len = 0
    while True:
        glue_padding = get_pad(key_len + len(message))
        length = key_len + len(message) + len(glue_padding)
        secret = md4(key + message + glue_padding + attack_message)
        generated = md4(attack_message, h0, h1, h2, h3, length)
        if secret == generated:
            assert len(key) == key_len
            break
        key_len += 1

if __name__ == '__main__':
    main()
