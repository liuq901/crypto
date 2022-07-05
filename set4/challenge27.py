from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def encrypt(plaintext):
    key = b'EpicFail Unknown'
    cipher = AES.new(key, AES.MODE_CBC, iv=key)
    return cipher.encrypt(pad(plaintext, 16))

def decrypt(ciphertext):
    key = b'EpicFail Unknown'
    cipher = AES.new(key, AES.MODE_CBC, iv=key)
    plaintext = unpad(cipher.decrypt(ciphertext), 16)
    if all(32 <= x < 127 for x in plaintext):
        return None
    else:
        return plaintext

def xor(x, y):
    assert len(x) == len(y)
    return bytes(x[i] ^ y[i] for i in range(len(x)))

def main():
    plaintext = b'A' * 48
    ciphertext = encrypt(plaintext)
    ciphertext = ciphertext[:16] + b'\x00' * 16 + ciphertext
    result = decrypt(ciphertext)
    key = xor(result[:16], result[32:48])
    assert key == b'EpicFail Unknown'

if __name__ == '__main__':
    main()
