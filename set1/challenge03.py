INPUT = '1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736'

def xor(hex_, num):
    return bytes([x ^ num for x in hex_])

def valid(hex_):
    return all(32 <= x < 127 for x in hex_)

def score(string):
    return sum(string.count(x) for x in ('a', 'e', 'i', 'o', 'u'))

def main():
    hex_ = bytes.fromhex(INPUT)
    best = None
    choice = None
    for key in range(32, 127):
        tmp = xor(hex_, key)
        if valid(tmp):
            string = tmp.decode()
            if best is None or score(string) > score(best):
                best = string
                choice = key

    print(best)
    print(f'Key: {chr(choice)}')

if __name__ == '__main__':
    main()
