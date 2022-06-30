import base64

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

INPUT = 'Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK'

def encrypt(input_):
    unknown = base64.b64decode(INPUT)
    key = b'EpicFail Unknown'
    plaintext = pad(input_ + unknown, 16)
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)

def detect_len():
    length = len(encrypt(b''))
    for i in range(1, 17):
        if len(encrypt(b'A' * i)) != length:
            return length - i
    assert False

def main():
    known = b''
    length = detect_len()
    choice = [10] + list(range(32, 127))
    while len(known) < length:
        prefix_len = 15 - len(known) % 16
        validate_len = (len(known) // 16 + 1) * 16
        ciphertext = encrypt(b'A' * prefix_len)
        for i in choice:
            possible = b'A' * prefix_len + known + bytes([i])
            tmp = encrypt(possible)
            if tmp[:validate_len] == ciphertext[:validate_len]:
                known += bytes([i])
                break
    assert known == base64.b64decode(INPUT)

if __name__ == '__main__':
    main()
