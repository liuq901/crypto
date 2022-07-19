import random

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

def sign(msg, use_iv):
    key = b'EpicFail Unknown'
    if use_iv:
        iv = random.randbytes(16)
    else:
        iv = b'\x00' * 16
    cipher = AES.new(key, AES.MODE_CBC, iv)
    mac = cipher.encrypt(pad(msg, 16))[-16:]
    if use_iv:
        result = msg + iv + mac
    else:
        result = msg + mac
    return result

def parse(data, use_iv):
    if use_iv:
        msg = data[:-32]
        iv = data[-32:-16]
        mac = data[-16:]
    else:
        msg = data[:-16]
        iv = b'\x00' * 16
        mac = data[-16:]
    return msg, iv, mac

def verify(data, use_iv):
    key = b'EpicFail Unknown'
    msg, iv, mac = parse(data, use_iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    server_mac = cipher.encrypt(pad(msg, 16))[-16:]
    return mac == server_mac

def xor(x, y):
    assert len(x) == len(y)
    return bytes(x[i] ^ y[i] for i in range(len(x)))

def hack(data, use_iv):
    msg, iv, mac = parse(data, use_iv)
    if use_iv:
        hacked_msg = b'from=ali&to=eve&amount=10000'
        hacked_iv = xor(xor(msg[:16], hacked_msg[:16]), iv)
        return hacked_msg + hacked_iv + mac
    else:
        valid_msg = b'from=eve&tx_list=eve:10000;eve:10000'
        valid_data = sign(valid_msg, use_iv=False)
        valid_mac = parse(valid_data, use_iv=False)[-1]
        return pad(msg, 16) + xor(mac, valid_msg[:16]) + valid_msg[16:] + valid_mac

def extract(msg, name):
    for token in msg.split(b'&'):
        name_, content = token.split(b'=', 1)
        if name == name_:
            return content
    return None

def hacked(data, use_iv):
    msg, _, _ = parse(data, use_iv)
    account = b'eve'
    if use_iv:
        return extract(msg, b'to') == account
    else:
        tx_list = extract(msg, b'tx_list')
        for token in tx_list.split(b';'):
            user = token.split(b':')[0]
            if user == account:
                return True
        return False

def main():
    msg = b'from=ali&to=bob&amount=10000'
    data = sign(msg, use_iv=True)
    assert verify(data, use_iv=True)
    hacked_data = hack(data, use_iv=True)
    assert parse(data, use_iv=True)[0] != parse(hacked_data, use_iv=True)[0]
    assert verify(hacked_data, use_iv=True)
    assert not hacked(data, use_iv=True)
    assert hacked(hacked_data, use_iv=True)
    msg = b'from=ali&tx_list=bob:10000;car:10000'
    data = sign(msg, use_iv=False)
    assert verify(data, use_iv=False)
    hacked_data = hack(data, use_iv=False)
    assert parse(data, use_iv=False)[0] != parse(hacked_data, use_iv=False)[0]
    assert verify(hacked_data, use_iv=False)
    assert not hacked(data, use_iv=False)
    assert hacked(hacked_data, use_iv=False)

if __name__ == '__main__':
    main()
