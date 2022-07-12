import hashlib

from Crypto.Util.number import inverse

INPUT_FILE = '44.txt'
P = int(''.join([
    '800000000000000089e1855218a0e7dac38136ffafa72eda7',
    '859f2171e25e65eac698c1702578b07dc2a1076da241c76c6',
    '2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe',
    'ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2',
    'b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87',
    '1a584471bb1',
]), base=16)
Q = int('f4f47f05794b256174bba6e9b396a7707e563c5b', base=16)
G = int(''.join([
    '5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119',
    '458fef538b8fa4046c8db53039db620c094c9fa077ef389b5',
    '322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047',
    '0f5b64c36b625a097f1651fe775323556fe00b3608c887892',
    '878480e99041be601a62166ca6894bdd41a7054ec89f756ba',
    '9fc95302291',
]), base=16)
PUB_KEY = int(''.join([
    '2d026f4bf30195ede3a088da85e398ef869611d0f68f07',
    '13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8',
    '5519b1c23cc3ecdc6062650462e3063bd179c2a6581519',
    'f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430',
    'f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3',
    '2971c3de5084cce04a2e147821',
]), base=16)
PRIV_KEY_DIGEST = 'ca8f6f7c66fa362d40760d135b763eb8527d3d52'

def hash_(msg):
    hex_ = hashlib.sha1(msg).digest()
    return int.from_bytes(hex_, 'big')

def verify(msg, signature, public_key):
    r, s = signature
    if 0 < r < Q and 0 < s < Q:
        w = inverse(s, Q)
        u1 = hash_(msg) * w % Q
        u2 = r * w % Q
        v = pow(G, u1, P) * pow(public_key, u2, P) % P % Q
        return v == r
    else:
        return False

def guess(data1, data2):
    m1, (_, s1) = data1
    m2, (_, s2) = data2
    m1, m2 = hash_(m1), hash_(m2)
    return inverse(s1 - s2, Q) * (m1 - m2) % Q

def solve(signature, key, msg):
    r, s = signature
    return inverse(r, Q) * (s * key - hash_(msg)) % Q

def main():
    with open(INPUT_FILE, 'r') as fin:
        lines = fin.readlines()
    data = []
    for i in range(0, len(lines), 4):
        tmp = {}
        for j in range(4):
            line = lines[i + j].rstrip('\n')
            k, v = line.split(':', 1)
            tmp[k] = v.lstrip()
        signature = (int(tmp['r']), int(tmp['s']))
        assert hashlib.sha1(tmp['msg'].encode()).hexdigest().lstrip('0') == tmp['m']
        assert verify(tmp['msg'].encode(), signature, PUB_KEY)
        data.append([tmp['msg'].encode(), signature])
    ans = None
    for i in range(len(data)):
        for j in range(i + 1, len(data)):
            key = guess(data[i], data[j])
            private_key = solve(data[i][1], key, data[i][0])
            r = pow(G, key, P) % Q
            s = inverse(key, Q) * (hash_(data[i][0]) + private_key * r) % Q
            if (r, s) == data[i][1]:
                ans = private_key
                break
        if ans is not None:
            break
    assert hashlib.sha1(hex(ans)[2:].encode()).hexdigest() == PRIV_KEY_DIGEST

if __name__ == '__main__':
    main()
