import base64

from Crypto.Cipher import AES

INPUT_FILE = '10.txt'
KEY = 'YELLOW SUBMARINE'

def xor(x, y):
    assert len(x) == len(y)
    return bytes(x[i] ^ y[i] for i in range(len(x)))

def main():
    with open(INPUT_FILE, 'r') as fin:
        input_ = ''.join(x.strip() for x in fin.readlines())
    input_ = base64.b64decode(input_)
    cipher = AES.new(KEY.encode(), AES.MODE_ECB)
    prev = b'\x00' * 16
    result = []
    for i in range(0, len(input_), 16):
        chunk = input_[i:i + 16]
        result.append(xor(cipher.decrypt(chunk), prev))
        prev = chunk
    string = ''.join(x.decode() for x in result)
    print(string.strip())

if __name__ == '__main__':
    main()
