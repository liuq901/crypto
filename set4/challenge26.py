from Crypto.Cipher import AES
from Crypto.Util import Counter

def encrypt(input_):
    input_ = input_.replace(';', '').replace('=', '')
    plaintext = f'comment1=cooking%20MCs;userdata={input_};comment2=%20like%20a%20pound%20of%20bacon'
    key = b'EpicFail Unknown'
    counter = Counter.new(64, prefix=b'\x00' * 8, initial_value=0, little_endian=True)
    cipher = AES.new(key, AES.MODE_CTR, counter=counter)
    return cipher.encrypt(plaintext.encode())

def admin(token):
    name, value = token.split('=')
    return name == 'admin' and value == 'true' 

def check(ciphertext):
    key = b'EpicFail Unknown'
    counter = Counter.new(64, prefix=b'\x00' * 8, initial_value=0, little_endian=True)
    cipher = AES.new(key, AES.MODE_CTR, counter=counter)
    plaintext = cipher.decrypt(ciphertext).decode(errors='ignore')
    return any(admin(x) for x in plaintext.split(';'))

def xor(x, y):
    assert len(x) == len(y)
    return bytes(x[i] ^ y[i] for i in range(len(x)))

def main():
    assert len('comment1=cooking%20MCs;userdata=') == 32
    ciphertext = encrypt('A' * 16)
    target = b'12345;admin=true'
    assert len(target) == 16
    chunk = xor(xor(ciphertext[32:48], b'A' * 16), target)
    ciphertext = ciphertext[:32] + chunk + ciphertext[48:]
    assert check(ciphertext) == True

if __name__ == '__main__':
    main()
