import base64

from Crypto.Cipher import AES
from Crypto.Util import Counter
from tqdm import tqdm

INPUT_FILE = '20.txt'

def encrypt(plaintext):
    key = b'EpicFail Unknown'
    counter = Counter.new(64, prefix=b'\x00' * 8 ,initial_value=0, little_endian=True)
    cipher = AES.new(key, AES.MODE_CTR, counter=counter)
    return cipher.encrypt(plaintext)

def xor(x, y):
    length = min(len(x), len(y))
    return bytes(x[i] ^ y[i] for i in range(length))

def valid(hex_):
    return all(32 <= x < 127 for x in hex_)

def get_prefix(list_):
    result = []
    for x in list_:
        for i in range(2, len(x) + 1):
            result.append(x[:i])
    return result

def score(string):
    unigram = {
        'a': 8.2, 'b': 1.5, 'c': 2.8, 'd': 4.3, 'e': 13, 'f': 2.2, 'g': 2.0,
        'h': 6.1, 'i': 7.0, 'j': 0.15, 'k': 0.77, 'l': 7.0, 'm': 2.4, 'n': 6.7,
        'o': 7.5, 'p': 1.9, 'q': 0.095, 'r': 6.0, 's': 6.3, 't': 9.1,
        'u': 2.8, 'v': 0.98, 'w': 2.4, 'x': 0.15, 'y': 2.0, 'z': 0.074,
    }
    bigram = {
        'th': 1.52, 'he': 1.28, 'in': 0.94, 'er': 0.94, 'an': 0.82, 're': 0.68, 'nd': 0.63,
        'at': 0.59, 'on': 0.57, 'nt': 0.56, 'ha': 0.56, 'es': 0.56, 'st': 0.55,
        'en': 0.55, 'ed': 0.53, 'to': 0.52, 'it': 0.50, 'ou': 0.50, 'ea': 0.47, 'hi': 0.46,
        'is': 0.46, 'or': 0.43, 'ti': 0.34, 'as': 0.33, 'te': 0.27, 'et': 0.19,
        'ng': 0.18, 'of': 0.16, 'al': 0.09, 'de': 0.09, 'se': 0.08, 'le': 0.08, 'sa': 0.06,
        'si': 0.05, 'ar': 0.04, 've': 0.04, 'ra': 0.04, 'ld': 0.02, 'ur': 0.02,
    }
    final_word = ['craziest', 'whole scenery']
    final_word = get_prefix(final_word)
    upper_penalty = abs(sum(x.isupper() for x in string) - 60)
    string = string.lower()
    unigram_score = sum(string.count(x) * y for x, y in unigram.items())
    bigram_score = sum(string.count(x) * y for x, y in bigram.items())
    punct_penalty = len(string) - sum(string.count(x) for x in list(unigram.keys()) + [' '])
    final_score = sum(string.count(x) for x in final_word)
    return unigram_score + bigram_score * 10 - punct_penalty * 10 - upper_penalty + final_score * 50

def main():
    groundtruth = []
    with open(INPUT_FILE, 'r') as fin:
        for line in fin:
            groundtruth.append(base64.b64decode(line.strip()))
    ciphertext = [encrypt(x) for x in groundtruth]
    max_len = max(len(x) for x in ciphertext)
    keystream = b''
    for i in tqdm(range(max_len)):
        best = None
        choice = None
        for j in range(256):
            tmp = keystream + bytes([j])
            string = b'$'.join(xor(tmp, x) for x in ciphertext)
            if not valid(string):
                continue
            string = string.decode()
            if best is None or score(string) > score(best):
                best = string
                choice = j
        keystream += bytes([choice])
    plaintext = [xor(keystream, x) for x in ciphertext]
    for x, y in zip(plaintext, groundtruth):
        assert x == y

if __name__ == '__main__':
    main()
