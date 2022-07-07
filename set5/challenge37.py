import hashlib
import random

from tqdm import tqdm

N = int(''.join([
    'ffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024',
    'e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd',
    '3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec',
    '6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f',
    '24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361',
    'c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552',
    'bb9ed529077096966d670c354e4abc9804f1746c08ca237327fff',
    'fffffffffffff',
]), base=16)
G = 2
K = 3

def sha256(string):
    return hashlib.sha256(string.encode()).hexdigest()

def init_server(server, password):
    salt = random.randint(10, 10000)
    xH = sha256(str(salt) + password)
    x = int(xH, base=16)
    v = pow(G, x, N)
    b = random.randint(0, N - 1)
    B = K * v + pow(G, b, N)
    server.update({'salt': salt, 'v': v, 'b': b, 'B': B})

def init_client(client, fake_public_key):
    client.update({'A': fake_public_key})

def send(sender, receiver, names):
    receiver.update({x: sender[x] for x in names})

def calc_u(A, B):
    uH = sha256(str(A) + str(B))
    return int(uH, base=16)

def calc_client(client):
    S = 0
    client['key'] = sha256(str(S))

def calc_server(server):
    A, B, b, v = [server[x] for x in ('A', 'B', 'b', 'v')]
    u = calc_u(A, B)
    S = pow(A * pow(v, u, N), b, N)
    server['key'] = sha256(str(S))

def hash_(plaintext):
    return hashlib.sha256(plaintext).digest()

def xor(x, y):
    assert len(x) == len(y)
    return bytes(x[i] ^ y[i] for i in range(len(x)))

def hmac_sha256(dict_):
    key = dict_['key'].encode()
    salt = dict_['salt']
    msg = salt.to_bytes((salt.bit_length() + 7) // 8, 'little')
    blocksize = 64
    if len(key) > blocksize:
        key = hash_(key)
    if len(key) < blocksize:
        key = key + b'\x00' * (blocksize - len(key))
    o_key_pad = xor(b'\x5c' * blocksize, key)
    i_key_pad = xor(b'\x36' * blocksize, key)
    return hash_(o_key_pad + hash_(i_key_pad + msg))

def main():
    for _ in tqdm(range(100)):
        password = bytes(random.randint(32, 126) for _ in range(random.randint(10, 100))).decode()
        fake_public_key = random.choice([0, N, N * 2])
        server = {}
        client = {}
        init_server(server, password)
        init_client(client, fake_public_key)
        send(client, server, ['A'])
        send(server, client, ['salt', 'B'])
        calc_client(client)
        calc_server(server)
        assert hmac_sha256(server) == hmac_sha256(client)

if __name__ == '__main__':
    main()
