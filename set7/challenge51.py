import random
import string
import zlib

from Crypto.Cipher import AES
from Crypto.Util import Counter
from Crypto.Util.Padding import pad

SESSION_ID = 'TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE='
REQUEST = '\n'.join([
    'POST / HTTP/1.1',
    'Host: hapless.com',
    'Cookie: sessionid={session_id}',
    'Content-Length: {length}',
    '{content}',
])

def encrypt(plaintext, mode):
    key = random.randbytes(16)
    if mode == 'CTR':
        counter = Counter.new(64, prefix=random.randbytes(8), initial_value=0, little_endian=True)
        cipher = AES.new(key, AES.MODE_CTR, counter=counter)
    elif mode == 'CBC':
        iv = random.randbytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        plaintext = pad(plaintext, 16)
    else:
        assert False
    return cipher.encrypt(plaintext)

def oracle(msg, mode):
    request = REQUEST.format(session_id=SESSION_ID, length=len(msg), content=msg)
    plaintext = zlib.compress(request.encode())
    return len(encrypt(plaintext, mode))

def get_pad(s, mode):
    pad_char = '~!@#$%^&*()_{}[]<>?'
    length = oracle(s, mode)
    padding = ''
    for char in pad_char:
        padding += char
        if oracle(padding + s, mode) > length:
            return padding
    assert False

def guess(length, mode):
    base64_char = string.ascii_letters + string.digits + '+/='
    known = 'sessionid='
    for _ in range(length):
        best = None
        choice = None
        padding = get_pad((known + '`') * 2, mode)
        for char in base64_char:
            tmp = oracle(padding + (known + char) * 2, mode)
            if best is None or tmp < best:
                best = tmp
                choice = char
        known += choice
    return known[-length:]

def main():
    assert guess(len(SESSION_ID), mode='CTR') == SESSION_ID
    assert guess(len(SESSION_ID), mode='CBC') == SESSION_ID

if __name__ == '__main__':
    main()
