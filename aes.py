from Crypto.Cipher import AES

class aes():
	def __init__(self, key):
		self._engine = AES.new(key, mode = AES.MODE_ECB)
		
	def encrypt(self, plaintext):
		return self._engine.encrypt(plaintext)
		 
	def decrypt(self, plaintext):
		return self._engine.decrypt(plaintext)