import base64
from collections import Counter
import random

from Crypto.Cipher import ARC4
from tqdm import tqdm

COOKIE = 'QkUgU1VSRSBUTyBEUklOSyBZT1VSIE9WQUxUSU5F'

def oracle(request, cookie):
    key = random.randbytes(16)
    cipher = ARC4.new(key)
    return cipher.encrypt(request + cookie)

def guess(prefix_len, cookie, result):
    cnt = Counter()
    length = prefix_len + len(cookie)
    pos = []
    cnt = []
    bias = []
    for i in range(15, length, 16):
        pos.append(i)
        cnt.append(Counter())
    assert 1 <= len(pos) <= 2
    if len(pos) == 1:
        bias = [0xf0]
    else:
        bias = [0xf0, 0xe0]
    request = b'A' * prefix_len
    for _ in tqdm(range(2 ** 24)):
        tmp = oracle(request, cookie)
        for j in range(len(pos)):
            cnt[j][tmp[pos[j]]] += 1
    for i in range(len(result)):
        if result[i] is None and (i + prefix_len) % 16 == 15:
            for j in range(len(pos)):
                if pos[j] == i + prefix_len:
                    result[i] = cnt[j].most_common()[0][0] ^ bias[j]

def main():
    cookie = base64.b64decode(COOKIE)
    result = [None] * len(cookie)
    for i in range(16):
        guess(i, cookie, result)
    result = bytes(result)
    assert cookie == result

if __name__ == '__main__':
    main()
