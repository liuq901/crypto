import random

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def hash_(msg, state):
    length = len(state)
    msg = pad(msg, 16)
    for i in range(0, len(msg), 16):
        chunk = msg[i:i + 16]
        key = pad(state, 16)
        cipher = AES.new(key, AES.MODE_ECB)
        state = cipher.encrypt(chunk)[:length]
    return state

def find(state):
    result = {}
    while True:
        msg = random.randbytes(26)
        tmp = hash_(msg, state)
        if tmp in result:
            return msg, result[tmp]
        result[tmp] = msg

def generate(collision, weak):
    res = []
    msg1, msg2 = find(hash_(collision[0], weak))
    for msg in collision:
        res.append(pad(msg, 16) + msg1)
        res.append(pad(msg, 16) + msg2)
    return res

def solve(weak, strong):
    collision = list(find(weak))
    while True:
        assert all(hash_(collision[0], weak) == hash_(x, weak) for x in collision)
        result = {}
        for msg in collision:
            tmp = hash_(msg, strong)
            if tmp in result:
                return msg, result[tmp]
            result[tmp] = msg
        collision = generate(collision, weak)

def main():
    weak = b'\x00' * 2
    strong = b'\x00' * 4
    msg1, msg2 = solve(weak, strong)
    assert msg1 != msg2 and hash_(msg1, strong) == hash_(msg2, strong)

if __name__ == '__main__':
    main()
