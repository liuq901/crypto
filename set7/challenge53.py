import random

from Crypto.Cipher import AES

def hash_(msg, state):
    length = len(state)
    assert len(msg) % 16 == 0
    for i in range(0, len(msg), 16):
        chunk = msg[i:i + 16]
        key = state + b'\x00' * (16 - length)
        cipher = AES.new(key, AES.MODE_ECB)
        state = cipher.encrypt(chunk)[:length]
    return state

def get_intermidiate(msg, k):
    intermidiate = {}
    state = b'\x00' * 2
    length = len(state)
    for i in range(0, len(msg), 16):
        chunk = msg[i:i + 16]
        key = state + b'\x00' * (16 - length)
        cipher = AES.new(key, AES.MODE_ECB)
        state = cipher.encrypt(chunk)[:length]
        idx = i // 16 + 1
        if idx >= k and idx != 2 ** k:
            intermidiate[state] = idx
    return intermidiate

def generate(k):
    state = b'\x00' * 2
    short = []
    long_ = []
    for i in range(k - 1, -1, -1):
        dummy = random.randbytes(16 * 2 ** i)
        value = hash_(dummy, state)
        result = {}
        while True:
            chunk = random.randbytes(16)
            result[hash_(chunk, state)] = chunk
            tmp = hash_(chunk, value)
            if tmp in result:
                state = tmp
                short.append(result[tmp])
                long_.append(dummy + chunk)
                break
    return state, short, long_

def construct(short, long_, idx):
    k = len(short)
    idx -= k
    prefix = b''
    for i in range(k):
        length = 2 ** (k - i - 1)
        if idx >= length:
            idx -= length
            prefix += long_[i]
        else:
            prefix += short[i]
    return prefix

def main():
    k = 16
    msg = random.randbytes(16 * 2 ** k)
    intermidiate = get_intermidiate(msg, k)
    while True:
        state, short, long_ = generate(k)
        if state in intermidiate:
            break
    idx = intermidiate[state]
    prefix = construct(short, long_, idx)
    preimage = prefix + msg[len(prefix):]
    assert msg != preimage
    assert len(msg) == len(preimage)
    assert msg[-1] == preimage[-1]
    assert hash_(msg, b'\x00' * 2) == hash_(preimage, b'\x00' * 2)

if __name__ == '__main__':
    main()
