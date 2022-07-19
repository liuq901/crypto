from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

CODE = b"alert('MZA who was that?');\n"
HASH = '296b8d7cb78a243dda4d0a61d33bbdd1'
NEW_CODE = b"alert('Ayo, the Wu is back!');\n"

def hash_(msg):
    key = b'YELLOW SUBMARINE'
    iv = b'\x00' * 16
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(msg, 16))[-16:]

def xor(x, y):
    assert len(x) == len(y)
    return bytes(x[i] ^ y[i] for i in range(len(x)))

def main():
    signature = hash_(CODE)
    assert signature.hex() == HASH
    mac = hash_(NEW_CODE)
    new_code = pad(NEW_CODE, 16) + xor(mac, CODE[:16]) + CODE[16:]
    assert new_code.startswith(NEW_CODE)
    new_signature = hash_(new_code)
    assert new_signature.hex() == HASH

if __name__ == '__main__':
    main()
