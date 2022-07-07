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
    B = pow(G, b, N)
    u = random.randint(0, 65535)
    server.update({'salt': salt, 'v': v, 'b': b, 'B': B, 'u': u})

def init_client(client, password):
    a = random.randint(0, N - 1)
    A = pow(G, a, N)
    client.update({'a': a, 'A': A, 'password': password})

def init_attacker(attacker):
    salt = random.randint(10, 10000)
    b = random.randint(0, N - 1)
    B = pow(G, b, N)
    u = random.randint(0, 65535)
    attacker.update({'salt': salt, 'b': b, 'B': B, 'u': u})

def send(sender, receiver, names):
    receiver.update({x: sender[x] for x in names})

def calc_client(client):
    a, B, u, salt, password = [client[x] for x in ('a', 'B', 'u', 'salt', 'password')]
    x = int(sha256(str(salt) + password), base=16)
    S = pow(B, a + u * x, N)
    client['key'] = sha256(str(S))

def calc_server(server):
    A, b, v, u = [server[x] for x in ('A', 'b', 'v', 'u')]
    S = pow(A * pow(v, u, N), b, N)
    server['key'] = sha256(str(S))

def calc_attacker(attacker):
    A, b, u, salt, password = [attacker[x] for x in ('A', 'b', 'u', 'salt', 'password')]
    x = int(sha256(str(salt) + password), base=16)
    v = pow(G, x, N)
    S = pow(A * pow(v, u, N), b, N)
    attacker['key'] = sha256(str(S))

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
    dictionary = []
    for _ in range(10):
        dictionary.append(bytes(random.randint(32, 126) for _ in range(random.randint(10, 100))).decode())
    for _ in tqdm(range(100)):
        password = random.choice(dictionary)
        server = {}
        client = {}
        init_server(server, password)
        init_client(client, password)
        send(client, server, ['A'])
        send(server, client, ['salt', 'B', 'u'])
        calc_client(client)
        calc_server(server)
        assert hmac_sha256(server) == hmac_sha256(client)
        attacker = {}
        client = {}
        init_attacker(attacker)
        init_client(client, password)
        send(client, attacker, ['A'])
        send(attacker, client, ['salt', 'B', 'u'])
        calc_client(client)
        guess = None
        for candidate in dictionary:
            attacker['password'] = candidate
            calc_attacker(attacker)
            if hmac_sha256(client) == hmac_sha256(attacker):
                guess = candidate
                break
        assert guess == password

if __name__ == '__main__':
    main()
