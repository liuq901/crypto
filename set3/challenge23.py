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

def get_bit(x, pos):
    return x >> pos & 1

def rshift_rev(y, delta):
    x = [None] * 32
    for i in range(31, -1, -1):
        if i + delta > 31:
            x[i] = get_bit(y, i)
        else:
            x[i] = get_bit(y, i) ^ x[i + delta]
    return sum(v << i for i, v in enumerate(x))

def lshift_rev(y, delta, magic):
    x = [None] * 32
    for i in range(32):
        if i - delta < 0:
            x[i] = get_bit(y, i) ^ get_bit(magic, i)
        else:
            x[i] = get_bit(y, i) ^ get_bit(magic, i) & x[i - delta]
    return sum(v << i for i, v in enumerate(x))

def reverse(y):
    y = rshift_rev(y, 18)
    y = lshift_rev(y, 15, 0xefc60000)
    y = lshift_rev(y, 7, 0x9d2c5680)
    y = rshift_rev(y, 11)
    return y

def main():
    seed = 19930131
    rand = MT19937(seed)
    number = [rand.extract_number() for _ in range(624)]
    state = [reverse(x) for x in number]
    hack_rand = MT19937(0)
    hack_rand.mt = state
    for _ in range(1000):
        assert rand.extract_number() == hack_rand.extract_number()

if __name__ == '__main__':
    main()
