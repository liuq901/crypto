import hashlib
import random

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

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

class Client(object):
    def __init__(self):
        self.private_key = random.randint(0, P - 1)
        self.public_key = pow(G, self.private_key, P)

    def get_key(self, public_key):
        secret = pow(public_key, self.private_key, P)
        key = hashlib.sha1(secret.to_bytes((secret.bit_length() + 7) // 8, 'little')).digest()[:16]
        return key

    def encrypt(self, msg, public_key):
        key = self.get_key(public_key)
        iv = random.randbytes(16)
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return cipher.encrypt(pad(msg, 16)) + iv

    def decrypt(self, msg, public_key):
        key = self.get_key(public_key)
        msg, iv = msg[:-16], msg[-16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(msg), 16)

def main():
    alice = Client()
    bob = Client()
    alice_msg = bytes(random.randint(32, 126) for _ in range(random.randint(10, 100)))
    alice_to_bob = alice.encrypt(alice_msg, bob.public_key)
    bob_msg = bob.decrypt(alice_to_bob, alice.public_key)
    bob_to_alice = bob.encrypt(bob_msg, alice.public_key)
    alice_msg2 = alice.decrypt(bob_to_alice, bob.public_key)
    assert alice_msg == bob_msg == alice_msg2
    eve = Client()
    eve.public_key = P
    alice_msg = bytes(random.randint(32, 126) for _ in range(random.randint(10, 100)))
    alice_to_eve = alice.encrypt(alice_msg, eve.public_key)
    eve_msg = eve.decrypt(alice_to_eve, 0)
    eve_to_bob = eve.encrypt(eve_msg, 0)
    bob_msg = bob.decrypt(eve_to_bob, eve.public_key)
    bob_to_eve = bob.encrypt(bob_msg, eve.public_key)
    eve_msg2 = eve.decrypt(bob_to_eve, 0)
    eve_to_alice = eve.encrypt(eve_msg2, 0)
    alice_msg2 = alice.decrypt(eve_to_alice, eve.public_key)
    assert alice_msg == eve_msg == bob_msg == eve_msg2 == alice_msg2

if __name__ == '__main__':
    main()
