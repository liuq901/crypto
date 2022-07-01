import base64
import random

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

INPUT = [
    'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
    'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
    'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
    'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
    'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
    'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
    'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
    'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
    'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
    'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93',
]

def encrypt():
    input_ = random.choice(INPUT)
    plaintext = base64.b64decode(input_)
    key = b'EpicFail Unknown'
    iv = b'initialization V'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, 16))
    return ciphertext, iv

def decrypt(ciphertext, iv):
    key = b'EpicFail Unknown'
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plaintext = cipher.decrypt(ciphertext)
    try:
        unpad(plaintext, 16)
        return True
    except ValueError:
        return False

def xor(x, y):
    assert len(x) == len(y)
    return bytes(x[i] ^ y[i] for i in range(len(x)))

def main():
    ciphertext, iv = encrypt()
    plaintext = b''
    prev = iv
    for idx in range(0, len(ciphertext), 16):
        intermediate = [None] * 16
        for i in range(16):
            prefix = b'\x00' * (15 - i)
            suffix = b'' if i == 0 else bytes((i + 1) ^ x for x in intermediate[-i:])
            for j in range(256):
                hack_iv = prefix + bytes([j]) + suffix
                if decrypt(ciphertext[idx:idx + 16], hack_iv):
                    intermediate[15 - i] = (i + 1) ^ j
                    break
        plaintext += xor(prev, bytes(intermediate))
        prev = ciphertext[idx:idx + 16]
    plaintext = unpad(plaintext, 16)
    assert base64.b64encode(plaintext).decode() in INPUT

if __name__ == '__main__':
    main()
