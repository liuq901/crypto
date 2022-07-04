import random
import time

from tqdm import tqdm

class MT19937(object):
    def __init__(self, seed):
        self.mt = [None] * 624
        self.index = 0
        self.mt[0] = seed
        for i in range(1, 624):
            self.mt[i] = 0x6c078965 * (self.mt[i - 1] ^ self.mt[i - 1] >> 30) + i & 0xffffffff

    def extract_number(self):
        if self.index == 0:
            self.generate_numbers()
        y = self.mt[self.index]
        y ^= y >> 11
        y ^= y << 7 & 0x9d2c5680
        y ^= y << 15 & 0xefc60000
        y ^= y >> 18
        self.index = (self.index + 1) % 624
        return y

    def generate_numbers(self):
        for i in range(624):
            y = (self.mt[i] & 0x80000000) + (self.mt[(i + 1) % 624] & 0x7fffffff)
            self.mt[i] = self.mt[(i + 397) % 624] ^ y >> 1
            if y % 2 != 0:
                self.mt[i] ^= 0x9908b0df

def xor(x, y):
    length = min(len(x), len(y))
    return bytes(x[i] ^ y[i] for i in range(length))

def encrypt(plaintext, key):
    rand = MT19937(key)
    keystream = b''
    while len(keystream) < len(plaintext):
        keystream += rand.extract_number().to_bytes(4, 'little')
    return xor(keystream, plaintext)

def get_seed(ciphertext):
    decrypt = encrypt
    for key in range(1 << 16):
        if decrypt(ciphertext, key).endswith(b'A' * 14):
            return key
    assert False

def get_token():
    if random.randint(1, 2) == 1:
        return MT19937(int(time.time())).extract_number(), True
    else:
        return random.randint(0, 0xffffffff), False

def guess_token(token):
    now = int(time.time())
    for i in range(26):
        if MT19937(now - i).extract_number() == token:
            return True
    return False

def main():
    key = 19930131 & 0xfff
    plaintext = (''.join(chr(random.randint(32, 126)) for _ in range(random.randint(10, 100))) + 'A' * 14).encode()
    ciphertext = encrypt(plaintext, key)
    decrypt = encrypt
    assert plaintext == decrypt(ciphertext, key)
    assert get_seed(ciphertext) == key
    for _ in tqdm(range(1000)):
        token, from_time = get_token()
        assert guess_token(token) == from_time

if __name__ == '__main__':
    main()
