import base64
import itertools

INPUT_FILE = '6.txt'

def bitcount(x):
    return bin(x).count('1')

def hamming(x, y):
    assert len(x) == len(y)
    return sum(bitcount(x[i] ^ y[i]) for i in range(len(x)))

def xor(hex_, num):
    return bytes([x ^ num for x in hex_])

def valid(hex_):
    return all(x == 10 or 32 <= x < 127 for x in hex_)

def score(string):
    return sum(string.count(x) for x in ('a', 'e', 'i', 'o', 'u'))

def solve(hex_):
    best = None
    choice = None
    for key in range(32, 127):
        tmp = xor(hex_, key)
        if valid(tmp):
            string = tmp.decode()
            if best is None or score(string) > score(best):
                best = string
                choice = key
    return choice

def main():
    with open(INPUT_FILE, 'r') as fin:
        input_ = ''.join(x.strip() for x in fin.readlines())
    input_ = base64.b64decode(input_)

    best = None
    key_len = None
    for length in range(2, 41):
        a = [input_[i * length:(i + 1) * length] for i in range(20)]
        diff = sum(hamming(x, y) for x, y in itertools.combinations(a, 2)) / length
        if best is None or diff < best:
            best = diff
            key_len = length

    key = []
    for i in range(key_len):
        tmp = input_[i::key_len]
        key.append(solve(tmp))
    print(''.join(chr(x ^ key[i % key_len]) for i, x in enumerate(input_)))
    print(f"Key: \"{''.join(chr(x) for x in key)}\"")

if __name__ == '__main__':
    main()
