INPUT_FILE = '8.txt'

def main():
    with open(INPUT_FILE, 'r') as fin:
        for line in fin:
            line = line.strip()
            hex_ = bytes.fromhex(line)
            set_ = {hex_[i:i + 16] for i in range(0, len(hex_), 16)}
            if len(set_) != len(hex_) / 16:
                print(line)

if __name__ == '__main__':
    main()
