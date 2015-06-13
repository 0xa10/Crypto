from diffie_hellman import DiffieHellman, NIST_GENERATOR, NIST_PRIME
import cbc
import sha1
import os
import time, random

def main():
    random.seed(time.time())
    # regular communication
    message = "This is a secret message".decode("base64")

    alice = DiffieHellman(NIST_GENERATOR, NIST_PRIME)
    bob = DiffieHellman(NIST_GENERATOR, NIST_PRIME)

    bob.get_response(alice.make_secret())
    alice.get_response(bob.make_secret())

    assert bob.session_key() == alice.session_key()

    # g = 1
    # 1^x = 1 mod p for any x
    message = "ZyA9IDEgc3V4=".decode("base64")

    alice = DiffieHellman(1, NIST_PRIME)
    bob = DiffieHellman(1, NIST_PRIME)

    bob.get_response(alice.make_secret())
    alice.get_response(bob.make_secret())

    assert bob.session_key() == alice.session_key()

    real_key = bob.session_key()
    bob_iv = os.urandom(16)
    alice_iv = os.urandom(16)
    alice_message = alice_iv + cbc.encrypt(alice.session_key()[:16], message, IV = alice_iv)
    relayed_msg = alice_message
    bob_message = bob_iv + cbc.encrypt(bob.session_key()[:16], cbc.decrypt(bob.session_key()[:16], relayed_msg)[16:], IV = bob_iv)

    injected_key = sha1.sha1(hex(1).strip("0xL")).hexdigest().decode("hex")

    print "g = 1:"
    print "Alice and Bob's secret message:"
    print "%r" % (cbc.decrypt(injected_key[:16], relayed_msg)[16:],)

    # g = p
    # p^x = 0 mod p for any x
    message = "ZyA9IHAgaXMgdXNlbGVzcw==".decode("base64")

    alice = DiffieHellman(NIST_PRIME, NIST_PRIME)
    bob = DiffieHellman(NIST_PRIME, NIST_PRIME)

    bob.get_response(alice.make_secret())
    alice.get_response(bob.make_secret())

    assert bob.session_key() == alice.session_key()

    real_key = bob.session_key()
    bob_iv = os.urandom(16)
    alice_iv = os.urandom(16)
    alice_message = alice_iv + cbc.encrypt(alice.session_key()[:16], message, IV = alice_iv)
    relayed_msg = alice_message
    bob_message = bob_iv + cbc.encrypt(bob.session_key()[:16], cbc.decrypt(bob.session_key()[:16], relayed_msg)[16:], IV = bob_iv)

    injected_key = sha1.sha1(hex(0).strip("0xL")).hexdigest().decode("hex")

    print "g = p:"
    print "Alice and Bob's secret message:"
    print "%r" % (cbc.decrypt(injected_key[:16], relayed_msg)[16:],)

    # g = p - 1
    # If the exponent is even the result will be 1, if odd, it will be (p-1)
    # for that reason, in any combination of results, the final session key will always be either 1 or p-1 (only if both a & b turned out odd thus g^a == g^b == p-1 == g^ab)
    message = "ZXZlbiBvciBvZGQ/".decode("base64")

    alice = DiffieHellman(NIST_PRIME-1 , NIST_PRIME)
    bob = DiffieHellman(NIST_PRIME-1, NIST_PRIME)

    alice_secret = alice.make_secret()
    bob_secret = bob.make_secret()
    bob.get_response(alice_secret)
    alice.get_response(bob_secret)

    assert bob.session_key() == alice.session_key()

    real_key = bob.session_key()
    bob_iv = os.urandom(16)
    alice_iv = os.urandom(16)
    alice_message = alice_iv + cbc.encrypt(alice.session_key()[:16], message, IV = alice_iv)
    relayed_msg = alice_message
    bob_message = bob_iv + cbc.encrypt(bob.session_key()[:16], cbc.decrypt(bob.session_key()[:16], relayed_msg)[16:], IV = bob_iv)

    if (alice_secret + bob_secret == 2*(NIST_PRIME-1)):
        # 25% chance of the session key being p-1
        injected_key = sha1.sha1(hex(NIST_PRIME-1).strip("0xL")).hexdigest().decode("hex")
    else:
        injected_key = sha1.sha1(hex(1).strip("0xL")).hexdigest().decode("hex")

    print "g = p-1:"
    print "Alice and Bob's secret message:"
    print "%r" % (cbc.decrypt(injected_key[:16], relayed_msg)[16:],)




if __name__ == "__main__":
    main()
