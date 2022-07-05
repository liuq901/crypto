import random

from tqdm import tqdm

P = int(''.join([
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

def public_key():
    secret_num = random.randint(0, P - 1)
    public_key = pow(G, secret_num, P)
    return secret_num, public_key

def secret_key(secret_num, public_key):
    return pow(public_key, secret_num, P)

def main():
    for _ in tqdm(range(1000)):
        a, A = public_key()
        b, B = public_key()
        assert secret_key(a, B) == secret_key(b, A)

if __name__ == '__main__':
    main()
