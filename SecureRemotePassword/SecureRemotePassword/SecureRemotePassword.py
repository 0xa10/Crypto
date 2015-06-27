from sha1 import sha1
from mac import sha1_hmac
import os, random


class SingleSRPServer():
    def __init__(self, g, k, N):
        self._salt = None
        self._v = None
        self._g = g
        self._k = k
        self._N = N
        self._user = None
        self._A = None
        self._logged_in = False

    def _generate_salt(self):
        return os.urandom(random.randint(1,20))

    def register(self, user, password):
        self._user = user
        self._salt = self._generate_salt()
        # using sha1 instead of sha256 in spite of myself
        self._v = pow(self._g, sha1(self._salt + password).digest(), self._N)
        

    def initiate_login(self, user, A):
        if self._user != user:
            print "You must register first"
            return None, None

        self._A = A
        self._b = random.randint(0, 2**256) % self._N
        self._B = self._k * self._v + pow(self._g, self._b, self._N)
        self._u = sha1("%x%x" % (self._A, self._B)).digest()
        
        return self._salt, self._B

    def confirm_login(self, t):
        if self._A is None or self._B is None:
            print "Initiate login first"
            return None
        S = pow(self._A * pow(self._v, self._u, self._N), self._b, self._N)
        K = sha1(str(S)).hexdigest() 

        self._A = None
        self._b = None
        self._B = None

        if sha1_hmac(K).verify(self._salt, t):
            self._logged_in = True
            return True
        else:
            return False

    def whoami(self):
        if not self._logged_in:
            return "anonymous"
        else:
            return self._user
        

class SingleSRPClient():
    def __init__(self, server, g, k, N):
        self._g = g
        self._k = k
        self._N = N
        self._server = server

    def register(self, user, password):
        self._server.register(user, password)

    def _initiate_login(self, a, user):
        self._a = a
        self._A = pow(self._g, self._a, self._N)
        self._salt, self._B = self._server.initiate_login(user, self._A)

    def _complete_login(self, password):
        if self._salt is None or self._B is None:
            print "Complete initial login first"
            return False

        self._u = sha1("%x%x" % (self._A, self._B)).digest()
        x = sha1(self._salt + password).digest()
        S = pow(self._B - self._k * pow(self._g, x, self._N), self._a + self._u * x, self._N)

        K = sha1(str(S)).hexdigest()

        return self._server.confirm_login(sha1_hmac(K).tag(self._salt))

    def login(self, user, password):
       a = random.randint(0, 2**256) % self._N
       self._initiate_login(a, user)
       if self._complete_login(password):
           print "Login succesful, welcome %s" % (self._server.whoami()) 
       else:
           print "Login failed"



def main():
    NIST_PRIME = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff
    g = 2
    k = 3

    server = SingleSRPServer(g, k, NIST_PRIME)
    client = SingleSRPClient(server, g, k, NIST_PRIME)

    client.register("hello", "12345")
    client.login("hello", "1")
    client.login("hello", "123456")
    client.login("hello", "12345df6")
    client.login("helloa", "12345")

    client.login("hello", "12345")
    
    # test 1 - using A = 0

    server = SingleSRPServer(g, k, NIST_PRIME)
    client = SingleSRPClient(server, g, k, NIST_PRIME)

    client.register("root", os.urandom(32))
    print server.whoami()
    salt, B = server.initiate_login("root", 0)
    false_K = sha1(str(0)).hexdigest() 
    false_tag = sha1_hmac(false_K).tag(salt)
    server.confirm_login(false_tag)
    print server.whoami()

    # test 2 - using A = N

    server = SingleSRPServer(g, k, NIST_PRIME)
    client = SingleSRPClient(server, g, k, NIST_PRIME)

    client.register("admin", os.urandom(32))
    print server.whoami()
    salt, B = server.initiate_login("admin", NIST_PRIME)
    false_K = sha1(str(0)).hexdigest() 
    false_tag = sha1_hmac(false_K).tag(salt)
    server.confirm_login(false_tag)
    print server.whoami()

    # test 2 - using A = N * 2

    server = SingleSRPServer(g, k, NIST_PRIME)
    client = SingleSRPClient(server, g, k, NIST_PRIME)

    client.register("god", os.urandom(32))
    print server.whoami()
    salt, B = server.initiate_login("god", NIST_PRIME*2)
    false_K = sha1(str(0)).hexdigest() 
    false_tag = sha1_hmac(false_K).tag(salt)
    server.confirm_login(false_tag)
    print server.whoami()





if __name__ == "__main__":
    main()


