import utils
import falcon
from wsgiref import simple_server
from mac import sha1_hmac
import os, random, sys


key_min = 1
key_max = 30
key = os.urandom(random.randint(key_min, key_max)) 

timing = 50

def insecure_compare(a, b):
    from time import sleep, time
    global timing
    #start = time()
    for c1, c2 in zip(a,b):
        if c1 != c2:
            return False
        sleep(timing/1000.0)

    #print "Comparison took %f seconds" % (time() - start,)
    return True if len(a) == len(b) else False

class HMACTest:
    def __init__(self, key, slow = False):
        self._mac_engine = sha1_hmac(key)
        if slow:
            self._verify = insecure_compare
        else:
            self._verify = lambda x, y: x == y 

    def on_get(self, req, resp):
        if not req.get_param("file") or not req.get_param("signature"):
            raise falcon.HTTPBadRequest("Bad params", "You need to enter the file and signature params")
            

        tag = self._mac_engine.tag(req.get_param("file")).hexdigest().decode("hex")
        client_tag = req.get_param("signature").decode("hex")
        if len(client_tag) != 20:
            raise falcon.HTTPBadRequest("Bad params", "Bad HMAC length")
        from time import time
        
        if self._verify(tag, client_tag):
            resp.status = falcon.HTTP_200
        else:
            resp.status = falcon.HTTP_500

def main(argv):
    global key
    global timing
    slow = False
    if len(argv) > 3:
        key = argv[3]
        print "Using custom key"

    if len(argv) > 2:
        timing = int(argv[2])

    if len(argv) > 1 and argv[1] == "slow":
        slow = True
        print "Using slow comparison @ %d ms" % (timing,)

    app = falcon.API()
    app.add_route("/test", HMACTest(key, slow))
    
    print "Starting server on port 9000"
    httpd = simple_server.make_server(
        "127.0.0.1",
        9000,
        app)
    httpd.serve_forever()


if __name__ == "__main__":
    main(sys.argv)