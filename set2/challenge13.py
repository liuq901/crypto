from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def profile_for(email):
    email = email.replace('&', '').replace('=', '')
    return f'email={email}&uid=26&role=user'

def encrypt(email):
    key = b'EpicFail Unknown'
    plaintext = profile_for(email).encode()
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(pad(plaintext, 16))

def parse(token):
    return token.split('=')

def decrypt(ciphertext):
    key = b'EpicFail Unknown'
    cipher = AES.new(key, AES.MODE_ECB)
    plaintext = unpad(cipher.decrypt(ciphertext), 16).decode()
    return dict(parse(x) for x in plaintext.split('&'))

def main():
    email = b'A' * (16 - len('email=')) + pad(b'admin', 16)
    ciphertext = encrypt(email.decode())
    admin = ciphertext[16:32]
    email = b'A' * (32 - len('email=&uid=26&role='))
    ciphertext = encrypt(email.decode())
    attack_text = ciphertext[:-16] + admin
    assert decrypt(attack_text)['role'] == 'admin'

if __name__ == '__main__':
    main()
