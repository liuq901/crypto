import random

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

def main():
    for i in range(100):
        seed = random.randint(0, 0xffffffff)
        x = MT19937(seed)
        y = MT19937(seed)
        for j in range(100):
            assert x.extract_number() == y.extract_number()

if __name__ == '__main__':
    main()
