import base64

from Crypto.Cipher import AES
from Crypto.Util import Counter

INPUT = [
    'SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==',
    'Q29taW5nIHdpdGggdml2aWQgZmFjZXM=',
    'RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==',
    'RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=',
    'SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk',
    'T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==',
    'T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=',
    'UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==',
    'QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=',
    'T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl',
    'VG8gcGxlYXNlIGEgY29tcGFuaW9u',
    'QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==',
    'QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=',
    'QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==',
    'QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=',
    'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=',
    'VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==',
    'SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==',
    'SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==',
    'VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==',
    'V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==',
    'V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==',
    'U2hlIHJvZGUgdG8gaGFycmllcnM/',
    'VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=',
    'QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=',
    'VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=',
    'V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=',
    'SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==',
    'U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==',
    'U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=',
    'VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==',
    'QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu',
    'SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=',
    'VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs',
    'WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=',
    'SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0',
    'SW4gdGhlIGNhc3VhbCBjb21lZHk7',
    'SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=',
    'VHJhbnNmb3JtZWQgdXR0ZXJseTo=',
    'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=',
]

def encrypt(plaintext):
    key = b'EpicFail Unknown'
    counter = Counter.new(64, prefix=b'\x00' * 8, initial_value=0, little_endian=True)
    cipher = AES.new(key, AES.MODE_CTR, counter=counter)
    return cipher.encrypt(plaintext)

def xor(x, y):
    length = min(len(x), len(y))
    return bytes(x[i] ^ y[i] for i in range(length))

def valid(hex_):
    return all(32 <= x < 127 for x in hex_)

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
    final_word = ['hea', 'head', 'tur', 'turn', 'turn,']
    upper_penalty = abs(sum(x.isupper() for x in string) - 40)
    string = string.lower()
    unigram_score = sum(string.count(x) * y for x, y in unigram.items())
    bigram_score = sum(string.count(x) * y for x, y in bigram.items())
    punct_penalty = len(string) - sum(string.count(x) for x in list(unigram.keys()) + [' '])
    final_score = sum(string.count(x) for x in final_word)
    return unigram_score + bigram_score * 20 - punct_penalty * 10 + final_score * 50 - upper_penalty

def main():
    ciphertext = []
    for input_ in INPUT:
        plaintext = base64.b64decode(input_)
        ciphertext.append(encrypt(plaintext))
    max_len = max(len(x) for x in ciphertext)
    keystream = b''
    for i in range(max_len):
        best = None
        choice = None
        for j in range(256):
            tmp = keystream + bytes([j])
            string = b''.join(xor(tmp, x) for x in ciphertext)
            if not valid(string):
                continue
            string = string.decode()
            if best is None or score(string) > score(best):
                best = string
                choice = j
        keystream += bytes([choice])
    plaintext = [xor(keystream, x) for x in ciphertext]
    for x, y in zip(plaintext, INPUT):
        assert x == base64.b64decode(y)

if __name__ == '__main__':
    main()
