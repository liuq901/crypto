import base64

INPUT = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
OUTPUT = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'

def main():
    hex_ = bytes.fromhex(INPUT)
    b64 = base64.b64encode(hex_)
    assert b64.decode() == OUTPUT

if __name__ == '__main__':
    main()
