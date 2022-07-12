import hashlib
import random

from Crypto.Util.number import inverse
from tqdm import tqdm

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
    '84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4',
    'abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004',
    'e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed',
    '1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b',
    'bb283e6633451e535c45513b2d33c99ea17',
]), base=16)
MSG = b'For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n'
MSG_DIGEST = 'd2d0714f014a9784047eaeccf956520045c45265'
SIGNATURE = (
    548099063082341131477253921760299949438196259240,
    857042759984254168557880549501802188789837994940,
)
PRIV_KEY_DIGEST = '0954edd5e0afe5542a4adf012611a91912a3ec16'

def generate_key():
    x = random.randint(1, Q - 1)
    y = pow(G, x, P)
    return x, y

def hash_(msg):
    hex_ = hashlib.sha1(msg).digest()
    return int.from_bytes(hex_, 'big')

def sign(msg, private_key):
    while True:
        k = random.randint(1, Q - 1)
        r = pow(G, k, P) % Q
        s = inverse(k, Q) * (hash_(msg) + private_key * r) % Q
        if r != 0 and s != 0:
            return (r, s), k

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

def solve(signature, key, msg):
    r, s = signature
    return inverse(r, Q) * (s * key - hash_(msg)) % Q

def main():
    for _ in tqdm(range(1000)):
        private_key, public_key = generate_key()
        msg = bytes(random.randint(32, 126) for x in range(random.randint(10, 100)))
        signature, key = sign(msg, private_key)
        assert verify(msg, signature, public_key)
        assert solve(signature, key, msg) == private_key
    assert hashlib.sha1(MSG).hexdigest() == MSG_DIGEST
    assert verify(MSG, SIGNATURE, PUB_KEY)
    for key in range(1 << 16):
        private_key = solve(SIGNATURE, key, MSG)
        r = pow(G, key, P) % Q
        s = inverse(key, Q) * (hash_(MSG) + private_key * r) % Q
        if (r, s) == SIGNATURE:
            break
    assert hashlib.sha1(hex(private_key)[2:].encode()).hexdigest() == PRIV_KEY_DIGEST

if __name__ == '__main__':
    main()
