from diffie_hellman import DiffieHellman, NIST_GENERATOR, NIST_PRIME
import cbc
import sha1
import os
import time


def main():
    random.seed(time.time())
    # regular communication
    message = "This is a secret message".decode("base64")

    alice = DiffieHellman(NIST_GENERATOR, NIST_PRIME)
    bob = DiffieHellman(NIST_GENERATOR, NIST_PRIME)

    bob.get_response(alice.make_secret())
    alice.get_response(bob.make_secret())

    print "Alice's key:"
    print "%r" % (alice.session_key(),)
    print "Bob's key:"
    print "%r" % (bob.session_key(),)

    assert bob.session_key() == alice.session_key()

    bob_iv = os.urandom(16)
    alice_iv = os.urandom(16)

    alice_message = alice_iv + cbc.encrypt(alice.session_key()[:16], message, IV = alice_iv)
    bob_message = bob_iv + cbc.encrypt(bob.session_key()[:16], cbc.decrypt(bob.session_key()[:16], alice_message)[16:], IV = bob_iv)

    # mitm'd
    message = "Tm8gb25lIGNhbiByZWFkIHRoaXM=".decode("base64")

    alice = DiffieHellman(NIST_GENERATOR, NIST_PRIME)
    bob = DiffieHellman(NIST_GENERATOR, NIST_PRIME)

    mitm = DiffieHellman(NIST_GENERATOR, NIST_PRIME) 
    alice.make_secret()
    bob.make_secret()
    bob.get_response(NIST_PRIME)
    alice.get_response(NIST_PRIME)

    assert bob.session_key() == alice.session_key()

    real_key = bob.session_key()

    alice_message = alice_iv + cbc.encrypt(alice.session_key()[:16], message, IV = alice_iv)
    relayed_msg = alice_message
    bob_message = bob_iv + cbc.encrypt(bob.session_key()[:16], cbc.decrypt(bob.session_key()[:16], relayed_msg)[16:], IV = bob_iv)

    injected_key = sha1.sha1(hex(0).strip("0xL")).hexdigest().decode("hex")

    print "Alice and Bob's secret message:"
    print "%r" % (cbc.decrypt(injected_key[:16], relayed_msg)[16:],)




if __name__ == "__main__":
    main()

