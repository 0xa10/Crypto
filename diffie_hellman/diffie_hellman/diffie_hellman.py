import utils
import sha1
import random

NIST_PRIME = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
NIST_GENERATOR = 2

class DiffieHellmanException(Exception):
    pass

class DiffieHellman():
    def __init__(self, g, p):
        self._g = g
        self._p = p
        self._a = None
        self._response = None

    def make_secret(self):
        self._a = random.randint(0, 2**256) % self._p
        return pow(self._g, self._a, self._p)

    def get_response(self, response):
        self._response = response

    def session_key(self, hasher = lambda x : sha1.sha1(x).hexdigest()):
        if self._a is None or self._response is None:
            raise DiffieHellmanException("Missing party parameters")
        
        return hasher(hex(pow(self._response, self._a, self._p)).strip("0xL")).decode("hex")

def main():
    alice = DiffieHellman(5, 37)
    bob = DiffieHellman(5, 37)

    bob.get_response(alice.make_secret())
    alice.get_response(bob.make_secret())

    print "Alice's key:"
    print "%r" % (alice.session_key())
    print "Bob's key:"
    print "%r" % (bob.session_key())

    assert bob.session_key() == alice.session_key()

    alice = DiffieHellman(NIST_GENERATOR, NIST_PRIME)
    bob = DiffieHellman(NIST_GENERATOR, NIST_PRIME)

    bob.get_response(alice.make_secret())
    alice.get_response(bob.make_secret())

    print "Alice's new key:"
    print "%r" % (alice.session_key(),)
    print "Bob's new key:"
    print "%r" % (bob.session_key(),)

    assert bob.session_key() == alice.session_key()


    

if __name__ == "__main__":
    main()