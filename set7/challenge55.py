import hashlib
import random

def rotate(x, n):
    x &= 0xffffffff
    return x << n | x >> 32 - n

def rev_rotate(x, n):
    x &= 0xffffffff
    return x >> n | x << 32 - n

def f(a, b, c, d, block, rot):
    e = b & c | ~b & d
    return rotate(a + e + block, rot)

def rev_f(x, a, b, c, d, rot):
    e = b & c | ~b & d
    return rev_rotate(x, rot) - a - e & 0xffffffff

def g(a, b, c, d, block, rot):
    e = b & c | b & d | c & d
    return rotate(a + e + block + 0x5a827999, rot)

def rev_g(x, a, b, c, d, rot):
    e = b & c | b & d | c & d
    return rev_rotate(x, rot) - a - e - 0x5a827999 & 0xffffffff

def get(x, i):
    return x >> i - 1 & 1

def set_(x, *args):
    args = [(args[i], args[i + 1]) for i in range(0, len(args), 2)]
    for i, bit in args:
        x ^= (get(x, i) ^ bit) << i - 1
    return x

def byte2int(msg):
    x = []
    for i in range(0, len(msg), 4):
        x.append(msg[i] | msg[i + 1] << 8 | msg[i + 2] << 16 | msg[i + 3] << 24)
    return x

def int2byte(x):
    msg = []
    for i in range(len(x)):
        for delta in (0, 8, 16, 24):
            msg.append(x[i] >> delta & 0xff)
    return bytes(msg)

def md4(msg):
    x = byte2int(msg)
    a0, b0, c0, d0 = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
    a1 = f(a0, b0, c0, d0, x[0], 3)
    a1 = set_(a1, 7, get(b0, 7))
    x[0] = rev_f(a1, a0, b0, c0, d0, 3)
    d1 = f(d0, a1, b0, c0, x[1], 7)
    d1 = set_(d1, 7, 0, 8, get(a1, 8), 11, get(a1, 11))
    x[1] = rev_f(d1, d0, a1, b0, c0, 7)
    c1 = f(c0, d1, a1, b0, x[2], 11)
    c1 = set_(c1, 7, 1, 8, 1, 11, 0, 26, get(d1, 26))
    x[2] = rev_f(c1, c0, d1, a1, b0, 11)
    b1 = f(b0, c1, d1, a1, x[3], 19)
    b1 = set_(b1, 7, 1, 8, 0, 11, 0, 26, 0)
    x[3] = rev_f(b1, b0, c1, d1, a1, 19)
    a2 = f(a1, b1, c1, d1, x[4], 3)
    a2 = set_(a2, 8, 1, 11, 1, 26, 0, 14, get(b1, 14))
    x[4] = rev_f(a2, a1, b1, c1, d1, 3)
    d2 = f(d1, a2, b1, c1, x[5], 7)
    d2 = set_(d2, 14, 0, 19, get(a2, 19), 20, get(a2, 20), 21, get(a2, 21), 22, get(a2, 22), 26, 1)
    x[5] = rev_f(d2, d1, a2, b1, c1, 7)
    c2 = f(c1, d2, a2, b1, x[6], 11)
    c2 = set_(c2, 13, get(d2, 13), 14, 0, 15, get(d2, 15), 19, 0, 20, 0, 21, 1, 22, 0)
    x[6] = rev_f(c2, c1, d2, a2, b1, 11)
    b2 = f(b1, c2, d2, a2, x[7], 19)
    b2 = set_(b2, 13, 1, 14, 1, 15, 0, 17, get(c2, 17), 19, 0, 20, 0, 21, 0, 22, 0)
    x[7] = rev_f(b2, b1, c2, d2, a2, 19)
    a3 = f(a2, b2, c2, d2, x[8], 3)
    a3 = set_(a3, 13, 1, 14, 1, 15, 1, 17, 0, 19, 0, 20, 0, 21, 0, 23, get(b2, 23), 22, 1, 26, get(b2, 26))
    x[8] = rev_f(a3, a2, b2, c2, d2, 3)
    d3 = f(d2, a3, b2, c2, x[9], 7)
    d3 = set_(d3, 13, 1, 14, 1, 15, 1, 17, 0, 20, 0, 21, 1, 22, 1, 23, 0, 26, 1, 30, get(a3, 30))
    x[9] = rev_f(d3, d2, a3, b2, c2, 7)
    c3 = f(c2, d3, a3, b2, x[10], 11)
    c3 = set_(c3, 17, 1, 20, 0, 21, 0, 22, 0, 23, 0, 26, 0, 30, 1, 32, get(d3, 32))
    x[10] = rev_f(c3, c2, d3, a3, b2, 11)
    b3 = f(b2, c3, d3, a3, x[11], 19)
    b3 = set_(b3, 20, 0, 21, 1, 22, 1, 23, get(c3, 23), 26, 1, 30, 0, 32, 0)
    x[11] = rev_f(b3, b2, c3, d3, a3, 19)
    a4 = f(a3, b3, c3, d3, x[12], 3)
    a4 = set_(a4, 23, 0, 26, 0, 27, get(b3, 27), 29, get(b3, 29), 30, 1, 32, 0)
    x[12] = rev_f(a4, a3, b3, c3, d3, 3)
    d4 = f(d3, a4, b3, c3, x[13], 7)
    d4 = set_(d4, 23, 0, 26, 0, 27, 1, 29, 1, 30, 0, 32, 1)
    x[13] = rev_f(d4, d3, a4, b3, c3, 7)
    c4 = f(c3, d4, a4, b3, x[14], 11)
    c4 = set_(c4, 19, get(d4, 19), 23, 1, 26, 1, 27, 0, 29, 0, 30, 0)
    x[14] = rev_f(c4, c3, d4, a4, b3, 11)
    b4 = f(b3, c4, d4, a4, x[15], 19)
    b4 = set_(b4, 19, 0, 26, 1, 27, 1, 29, 1, 30, 0, 32, get(c4, 32))
    x[15] = rev_f(b4, b3, c4, d4, a4, 19)
    a5 = g(a4, b4, c4, d4, x[0], 3)
    a5 = set_(a5, 19, get(c4, 19), 26, 1, 27, 0, 29, 1, 32, 1)
    x[0] = rev_g(a5, a4, b4, c4, d4, 3)
    a1 = f(a0, b0, c0, d0, x[0], 3)
    x[1] = rev_f(d1, d0, a1, b0, c0, 7)
    x[2] = rev_f(c1, c0, d1, a1, b0, 11)
    x[3] = rev_f(b1, b0, c1, d1, a1, 19)
    x[4] = rev_f(a2, a1, b1, c1, d1, 3)
    d5 = g(d4, a5, b4, c4, x[4], 5)
    d5 = set_(d5, 29, get(b4, 29), 32, get(b4, 32))
    x[4] = rev_g(d5, d4, a5, b4, c4, 5)
    a2 = f(a1, b1, c1, d1, x[4], 3)
    x[5] = rev_f(d2, d1, a2, b1, c1, 7)
    x[6] = rev_f(c2, c1, d2, a2, b1, 11)
    x[7] = rev_f(b2, b1, c2, d2, a2, 19)
    x[8] = rev_f(a3, a2, b2, c2, d2, 3)
    return int2byte(x)

def delta(msg):
    x = byte2int(msg)
    x[1] = x[1] + 2 ** 31 & 0xffffffff
    x[2] = x[2] + 2 ** 31 - 2 ** 28 & 0xffffffff
    x[12] = x[12] - 2 ** 16 & 0xffffffff
    return int2byte(x)

def collide():
    while True:
        m = random.randbytes(64)
        m1 = md4(m)
        m2 = delta(m1)
        if hashlib.new('MD4', m1).digest() == hashlib.new('MD4', m2).digest():
            return m1, m2

def main():
    msg1, msg2 = collide()
    assert msg1 != msg2
    assert hashlib.new('MD4', msg1).digest() == hashlib.new('MD4', msg2).digest()

if __name__ == '__main__':
    main()
