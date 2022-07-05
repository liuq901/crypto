import hashlib
import random
import time

def hash_(hex_):
    return hashlib.sha1(hex_).digest()

def xor(x, y):
    return bytes(x[i] ^ y[i] for i in range(len(x)))

def hmac(message):
    key = b'EpicFail Unknown'
    blocksize = 64
    if len(key) > blocksize:
        key = hash_(key)
    if len(key) < blocksize:
        key = key + b'\x00' * (blocksize - len(key))
    o_key_pad = xor(b'\x5c' * blocksize, key)
    i_key_pad = xor(b'\x36' * blocksize, key)
    return hash_(o_key_pad + hash_(i_key_pad + message))

def insecure_compare(secret, signature):
    assert len(secret) == len(signature)
    delay_time = 0.0
    result = True
    for i in range(len(secret)):
        delay_time += 0.05
        if secret[i] != signature[i]:
            result = False
            break
    return result, delay_time

def main():
    file_name = bytes(random.randint(32, 126) for _ in range(random.randint(10, 100)))
    secret = hmac(file_name)
    known = b''
    for idx in range(20):
        longest = None
        choice = None
        for i in range(256):
            guess = known + bytes([i]) + b'\x00' * (19 - idx)
            t = time.time()
            result, delay_time = insecure_compare(secret, guess)
            duration = time.time() - t + delay_time
            if idx < 19:
                if longest is None or duration > longest:
                    longest = duration
                    choice = i
            elif result:
                choice = i
        known += bytes([choice])
    assert insecure_compare(secret, known)[0]

if __name__ == '__main__':
    main()
