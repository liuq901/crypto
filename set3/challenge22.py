import random
import time

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

def get_random():
    time.sleep(random.randint(40, 1000) / 100.0)
    seed = int(time.time())
    output = MT19937(seed).extract_number()
    time.sleep(random.randint(40, 1000) / 100.0)
    return seed, output

def get_seed(output):
    now = int(time.time())
    while MT19937(now).extract_number() != output:
        now -= 1
    return now

def main():
    seed, output = get_random()
    assert get_seed(output) == seed

if __name__ == '__main__':
    main()
