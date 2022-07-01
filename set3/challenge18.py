import base64

from Crypto.Cipher import AES
from Crypto.Util import Counter

INPUT = 'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ=='

def main():
    ciphertext = base64.b64decode(INPUT)
    key = b'YELLOW SUBMARINE'
    counter = Counter.new(64, prefix=b'\x00' * 8, initial_value=0, little_endian=True)
    cipher = AES.new(key, AES.MODE_CTR, counter=counter)
    print(cipher.decrypt(ciphertext).decode())

if __name__ == '__main__':
    main()
