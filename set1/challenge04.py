INPUT_FILE = '4.txt'

def xor(hex_, num):
    return bytes([x ^ num for x in hex_])

def valid(hex_):
    return all(x == 10 or 32 <= x < 127 for x in hex_)

def score(string):
    return sum(string.count(x) for x in ('a', 'e', 'i', 'o', 'u'))

def main():
    best = None
    choice = None
    origin = None
    with open(INPUT_FILE, 'r') as fin:
        for line in fin:
            line = line.strip()
            hex_ = bytes.fromhex(line)
            for key in range(32, 127):
                tmp = xor(hex_, key)
                if valid(tmp):
                    string = tmp.decode()
                    if best is None or score(string) > score(best):
                        best = string.strip()
                        choice = key
                        origin = line

    print(best)
    print(f'Key: {chr(choice)}')
    print(f'Origin: {origin}')

if __name__ == '__main__':
    main()
