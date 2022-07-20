import random

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def hash_(msg, state=b'\x00' * 2, no_pad=False):
    length = len(state)
    if no_pad:
        assert len(msg) % 16 == 0
    else:
        msg = pad(msg, 16)
    for i in range(0, len(msg), 16):
        chunk = msg[i:i + 16]
        key = pad(state, 16)
        cipher = AES.new(key, AES.MODE_ECB)
        state = cipher.encrypt(chunk)[:length]
    return state

def collide(state0, state1):
    result = {}
    while True:
        msg = random.randbytes(16)
        tmp0 = hash_(msg, state0, no_pad=True)
        tmp1 = hash_(msg, state1, no_pad=True)
        result[tmp0] = msg
        if tmp1 in result:
            return result[tmp1], msg, tmp1

def generate_tree(k):
    tree = [[]]
    for i in range(2 ** k):
        tree[0].append([random.randbytes(2), None])
    for i in range(k):
        tmp = []
        for j in range(0, len(tree[i]), 2):
            msg1, msg2, value = collide(tree[i][j][0], tree[i][j + 1][0])
            tree[i][j][1] = msg1
            tree[i][j + 1][1] = msg2
            tmp.append([value, None])
        tree.append(tmp)
    assert len(tree[-1]) == 1 and tree[-1][0][1] is None
    return tree

def generate_suffix(result, tree):
    value = {tree[0][i][0]: i for i in range(len(tree[0]))}
    cache = hash_(result, no_pad=True)
    while True:
        glue = random.randbytes(16)
        tmp = hash_(glue, cache, no_pad=True)
        if tmp in value:
            result += glue
            idx = value[tmp]
            break
    for i in range(0, len(tree) - 1):
        result += tree[i][idx][1]
        idx //= 2
    return result

def main():
    k = 8
    tree = generate_tree(k)
    prediction = hash_(b'', tree[-1][0][0])
    result = pad(random.randbytes(random.randint(10, 100)), 16)
    public = generate_suffix(result, tree)
    assert len(public) == len(result) + (k + 1) * 16
    assert hash_(public) == prediction

if __name__ == '__main__':
    main()
