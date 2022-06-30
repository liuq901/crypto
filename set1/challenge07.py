import base64

from Crypto.Cipher import AES

INPUT_FILE = '7.txt'
KEY = 'YELLOW SUBMARINE'

def main():
    with open(INPUT_FILE, 'r') as fin:
        input_ = ''.join(x.strip() for x in fin.readlines())
    input_ = base64.b64decode(input_)
    cipher = AES.new(KEY.encode(), AES.MODE_ECB)
    string = cipher.decrypt(input_).decode()
    print(string.strip())

if __name__ == '__main__':
    main()
