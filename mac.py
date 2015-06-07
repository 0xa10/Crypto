import utils
from sha1 import sha1

class secret_prefix_mac():
    def __init__(self, key, hash_function):
        self._key = key
        self._hash_function = hash_function

    def tag(self, message):
        return self._hash_function(self._key + message)

    def verify(self, message, tag):
        return tag == self.tag(message)
    
    def verify_digest(self, message, digest):
        return digest == self.tag(message).hexdigest()

class hmac(secret_prefix_mac):
    def __init__(self, key, hash_function):
        self._key = key
        self._hash_function = hash_function
        self._block_size = 64 # hardcoded for MD5/SHA1

    def _hmac(self, message):
        key = self._key
        if (len(key) > self._block_size): 
            key = self._hash_function(key).hexdigest().decode("hex")
        else:
            key = key.ljust(self._block_size, "\x00")
        
        outer_pad = utils.xor(key, "\x5c" * self._block_size)
        inner_pad = utils.xor(key, "\x36" * self._block_size)

        return self._hash_function(outer_pad + self._hash_function(inner_pad + message).hexdigest().decode("hex"))

    def tag(self, message):
        return self._hmac(message)


class sha1_hmac(hmac):
    def __init__(self, key):
        hmac.__init__(self, key, sha1)