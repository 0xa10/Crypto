from utils import *
import struct

_CHAR_BIT_SIZE = 8

F = lambda x, y, z : (x & y) | (~x & z)
G = lambda x, y, z : (x & y) | (x & z) | (y & z)
H = lambda x, y, z : x ^ y ^ z
round1 = lambda a, b, c, d, X, k, s : leftrotate((a + F(b, c, d) + X[k]) & 0xFFFFFFFF, s)
round2 = lambda a, b, c, d, X, k, s : leftrotate((a + G(b, c, d) + X[k] + 0x5A827999) & 0xFFFFFFFF, s)
round3 = lambda a, b, c, d, X, k, s : leftrotate((a + H(b, c, d) + X[k] + 0x6ed9eba1) & 0xFFFFFFFF, s)

def invert_long_endianess(num):
    return struct.unpack(">L", struct.pack("<L", num))[0]

class md4():
    def __init__(self, message = None):
        self._a = 0x67452301
        self._b = 0xEFCDAB89
        self._c = 0x98BADCFE
        self._d = 0x10325476

        if message is not None:
            self._md4(message)

    def __eq__(self, other):
        return isinstance(other, self.__class__) and self.digest() == other.digest()


    def _md4(self, message, fake_length = None):
        # break message into 512-bit chunks
        padded_msg = md_pad(message, fake_length = fake_length, little_endian = True)
        blocks = blockify(padded_msg, 512/_CHAR_BIT_SIZE) # 64 bytes
        for block in blocks:
            X = struct.unpack("<" + "I"*16, block)

            a = self._a
            b = self._b
            c = self._c
            d = self._d

            # round 1
            a = round1(a,b,c,d, X, 0, 3)
            d = round1(d,a,b,c, X, 1, 7)
            c = round1(c,d,a,b, X, 2, 11)
            b = round1(b,c,d,a, X, 3, 19)

            a = round1(a,b,c,d, X, 4, 3)
            d = round1(d,a,b,c, X, 5, 7)
            c = round1(c,d,a,b, X, 6, 11) 
            b = round1(b,c,d,a, X, 7, 19)

            a = round1(a,b,c,d, X, 8, 3) 
            d = round1(d,a,b,c, X, 9, 7) 
            c = round1(c,d,a,b, X, 10, 11)
            b = round1(b,c,d,a, X, 11, 19)

            a = round1(a,b,c,d, X, 12, 3) 
            d = round1(d,a,b,c, X, 13, 7)  
            c = round1(c,d,a,b, X, 14, 11)  
            b = round1(b,c,d,a, X, 15, 19)

            # round 2
            a = round2(a,b,c,d, X, 0, 3)
            d = round2(d,a,b,c, X, 4, 5)
            c = round2(c,d,a,b, X, 8, 9) 
            b = round2(b,c,d,a, X, 12, 13)

            a = round2(a,b,c,d, X, 1, 3)
            d = round2(d,a,b,c, X, 5, 5)
            c = round2(c,d,a,b, X, 9, 9)
            b = round2(b,c,d,a, X, 13, 13)

            a = round2(a,b,c,d, X, 2, 3)
            d = round2(d,a,b,c, X, 6, 5) 
            c = round2(c,d,a,b, X, 10, 9) 
            b = round2(b,c,d,a, X, 14, 13)

            a = round2(a,b,c,d, X, 3, 3)
            d = round2(d,a,b,c, X, 7, 5) 
            c = round2(c,d,a,b, X, 11, 9) 
            b = round2(b,c,d,a, X, 15, 13)

            # round 3
            a = round3(a,b,c,d, X, 0, 3) 
            d = round3(d,a,b,c, X, 8, 9)
            c = round3(c,d,a,b, X, 4, 11) 
            b = round3(b,c,d,a, X, 12, 15)

            a = round3(a,b,c,d, X, 2, 3) 
            d = round3(d,a,b,c, X, 10, 9) 
            c = round3(c,d,a,b, X, 6, 11)
            b = round3(b,c,d,a, X, 14, 15)

            a = round3(a,b,c,d, X, 1, 3)
            d = round3(d,a,b,c, X, 9, 9) 
            c = round3(c,d,a,b, X, 5, 11)
            b = round3(b,c,d,a, X, 13, 15)

            a = round3(a,b,c,d, X, 3, 3)  
            d = round3(d,a,b,c, X, 11, 9) 
            c = round3(c,d,a,b, X, 7, 11)  
            b = round3(b,c,d,a, X, 15, 15)

            self._a = (self._a + a) & 0xFFFFFFFF
            self._b = (self._b + b) & 0xFFFFFFFF
            self._c = (self._c + c) & 0xFFFFFFFF
            self._d = (self._d + d) & 0xFFFFFFFF

    def digest(self):
        return (invert_long_endianess(self._a) << 96) | (invert_long_endianess(self._b) << 64) | (invert_long_endianess(self._c) << 32) | (invert_long_endianess(self._d))

    def hexdigest(self):
        return hex(self.digest())[2:-1].rjust(128/8*2, "0")

