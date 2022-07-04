import base64

from Crypto.Cipher import AES
from Crypto.Util import Counter
from tqdm import tqdm

INPUT_FILE = '25.txt'

def encrypt(plaintext):
    key = b'EpicFail Unknown'
    counter = Counter.new(64, prefix=b'\x00' * 8, initial_value=0, little_endian=True)
    cipher = AES.new(key, AES.MODE_CTR, counter=counter)
    return cipher.encrypt(plaintext)

def decrypt(ciphertext):
    key = b'EpicFail Unknown'
    counter = Counter.new(64, prefix=b'\x00' * 8, initial_value=0, little_endian=True)
    cipher = AES.new(key, AES.MODE_CTR, counter=counter)
    return cipher.decrypt(ciphertext)

def edit(ciphertext, offset, token):
    plaintext = decrypt(ciphertext)
    plaintext = plaintext[:offset] + bytes([token]) + plaintext[offset + 1:]
    return encrypt(plaintext)

def main():
    with open(INPUT_FILE, 'r') as fin:
        plaintext = b''.join(base64.b64decode(x) for x in fin.readlines())
    ciphertext = encrypt(plaintext)
    guess = []
    for i in tqdm(range(len(ciphertext))):
        for j in range(256):
            tmp = edit(ciphertext, i, j)
            if tmp[i] == ciphertext[i]:
                guess.append(j)
                break
    guess = bytes(guess)
    assert guess == plaintext

if __name__ == '__main__':
    main()
