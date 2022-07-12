import hashlib

from Crypto.Util.number import getStrongPrime, inverse

def rsa(msg, key):
    return pow(msg, key[0], key[1])

def generate_key():
    p = getStrongPrime(512, e=3)
    q = getStrongPrime(512, e=3)
    n = p * q
    et = (p - 1) * (q - 1)
    e = 3
    d = inverse(e, et)
    public_key = (e, n)
    private_key = (d, n)
    return public_key, private_key

def hash_(msg):
    return hashlib.sha1(msg.encode()).digest()

def pad(hex_):
    length = 128
    padding = length - 3 - len(hex_)
    return b'\x00\x01' + b'\xff' * padding + b'\x00' + hex_

def unpad(hex_):
    assert hex_[:2] == b'\x00\x01'
    idx = 2
    while idx < len(hex_) and hex_[idx] == 0xff:
        idx += 1
    assert hex_[idx] == 0x00
    return hex_[idx + 1:idx + 21]

def signature(msg, private_key):
    hash_ = hashlib.sha1(msg.encode()).digest()
    plaintext = int.from_bytes(pad(hash_), 'big')
    return rsa(plaintext, private_key)

def verify(digest, msg, public_key):
    key_len = 128
    plaintext = rsa(digest, public_key).to_bytes(key_len, 'big')
    try:
        digest = unpad(plaintext)
        return digest == hash_(msg)
    except Exception:
        return False

def cube_root(n):
    l = 1
    r = n
    ans = None
    while l <= r:
        mid = (l + r) // 2
        if mid ** 3 <= n:
            l = mid + 1
        else:
            ans = mid
            r = mid - 1
    return ans

def forge(msg):
    length = 128
    prefix = b'\x00\x01' + b'\xff' + b'\x00' + hash_(msg)
    forged = cube_root(int.from_bytes(prefix + b'\x00' * (length - len(prefix)), 'big'))
    return forged

def main():
    public_key, private_key = generate_key()
    msg = 'hi mom'
    digest = signature(msg, private_key)
    assert verify(digest, msg, public_key)
    fake_digest = forge(msg)
    assert fake_digest != digest and verify(fake_digest, msg, public_key)

if __name__ == '__main__':
    main()
