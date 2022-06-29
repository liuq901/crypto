INPUT1 = '1c0111001f010100061a024b53535009181c'
INPUT2 = '686974207468652062756c6c277320657965'
OUTPUT = '746865206b696420646f6e277420706c6179'

def main():
    x = int(INPUT1, base=16)
    y = int(INPUT2, base=16)
    z = x ^ y
    hex_ = hex(z)[2:]
    assert hex_ == OUTPUT

if __name__ == '__main__':
    main()
