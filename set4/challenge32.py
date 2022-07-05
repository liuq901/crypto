import hashlib
import random
import time

from tqdm import tqdm

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
        delay_time += 0.001
        if secret[i] != signature[i]:
            result = False
            break
    return result, delay_time

def success(round_num):
    file_name = bytes(random.randint(32, 126) for _ in range(random.randint(10, 100)))
    secret = hmac(file_name)
    known = b''
    for idx in range(20):
        duration = [0.0] * 256
        for _ in range(round_num):
            for i in range(256):
                guess = known + bytes([i]) + b'\x00' * (19 - idx)
                t = time.time()
                result, delay_time = insecure_compare(secret, guess)
                duration[i] += time.time() - t + delay_time
                if result:
                    duration[i] += 100.0
        choice = 0
        for i in range(256):
            if duration[i] > duration[choice]:
                choice = i
        known += bytes([choice])
    return insecure_compare(secret, known)[0]

def main():
    assert not all(success(1) for _ in range(26))
    assert all(success(100) for _ in tqdm(range(26)))

if __name__ == '__main__':
    main()
