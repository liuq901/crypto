INPUT = 'YELLOW SUBMARINE'
OUTPUT = 'YELLOW SUBMARINE\x04\x04\x04\x04'
PADDING = 20

def main():
    assert len(OUTPUT) == PADDING
    hex_ = INPUT.encode()
    padding = PADDING - len(hex_)
    hex_ += bytes([padding] * padding)
    string = hex_.decode()
    assert string == OUTPUT

if __name__ == '__main__':
    main()
