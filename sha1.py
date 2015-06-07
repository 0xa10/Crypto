from utils import *
import struct


_CHAR_BIT_SIZE = 8

class sha1():
	def __init__(self, message = None):
		self._h0 = 0x67452301
		self._h1 = 0xEFCDAB89
		self._h2 = 0x98BADCFE
		self._h3 = 0x10325476
		self._h4 = 0xC3D2E1F0
		
		if message is not None:
			self._sha1(message)
	
	def __eq__(self, other):
		return isinstance(other, self.__class__) and self.digest() == other.digest()
			
	def _sha1(self, message, fake_length = None):
		# break message into 512-bit chunks
		blocks = blockify(md_pad(message, fake_length = fake_length), 512/_CHAR_BIT_SIZE) # 64 bytes
		for block in blocks:
			# break chunk into sixteen 32-bit big-endian words w[i], 0 <= i <= 15
			w = [0] * 80
			w[0:15] = struct.unpack(">" + "L"*16, block)
			
			for i in range(16, 80):
				w[i] = leftrotate(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1)
			
			a = self._h0
			b = self._h1
			c = self._h2
			d = self._h3
			e = self._h4
			
			for i in range(80):
				if (0 <= i < 20):
					f = (b & c) | ((~b) & d)
					k = 0x5A827999
				elif (20 <= i < 40):
					f = b ^ c ^ d
					k = 0x6ED9EBA1
				elif (40 <= i < 60):
					f = (b & c) | (b & d) | (c & d) 
					k = 0x8F1BBCDC
				elif (60 <= i < 80):
					f = b ^ c ^ d
					k = 0xCA62C1D6
				else:
					assert FALSE
				
				temp = (leftrotate(a, 5) + f + e + k + w[i]) & 0xffffffff
				e = d
				d = c
				c = leftrotate(b, 30)
				b = a
				a = temp
			
			self._h0 = (self._h0 + a) & 0xffffffff 
			self._h1 = (self._h1 + b) & 0xffffffff
			self._h2 = (self._h2 + c) & 0xffffffff
			self._h3 = (self._h3 + d) & 0xffffffff
			self._h4 = (self._h4 + e) & 0xffffffff
	
	def digest(self):
		return (self._h0 << 128) | (self._h1 << 96) | (self._h2 << 64) | (self._h3 << 32) | (self._h4)
	
	def hexdigest(self):
		return hex(self.digest())[2:-1].rjust(160/8*2, "0")


	
