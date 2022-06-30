import random

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def random_bytes():
    return random.randbytes(random.randint(5, 10))

def encrypt_oracle(plaintext):
    plaintext = plaintext.encode()
    plaintext = random_bytes() + plaintext + random_bytes()
    plaintext = pad(plaintext, 16)
    key = random.randbytes(16)
    if random.randint(0, 1):
        mode = AES.MODE_ECB
        cipher = AES.new(key, mode)
    else:
        mode = AES.MODE_CBC
        iv = random.randbytes(16)
        cipher = AES.new(key, mode, iv)
    return cipher.encrypt(plaintext), mode

def detect_mode(ciphertext):
    set_ = {ciphertext[i:i + 16] for i in range(0, len(ciphertext), 16)}
    return AES.MODE_CBC if len(set_) == len(ciphertext) / 16 else AES.MODE_ECB

def main():
    plaintext = 'EpicFail' * 26
    for i in range(2600):
        ciphertext, mode = encrypt_oracle(plaintext)
        assert mode == detect_mode(ciphertext)

if __name__ == '__main__':
    main()
