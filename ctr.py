import struct
import aes
from utils import *


def encrypt(key, plaintext, IV = "\x00"*16, cipher=aes.aes):
	nonce = IV[:8]
	counter = struct.unpack(">Q", IV[8:])[0]
	
	encrypter = cipher(key)
	
	ciphertext = ""
	
	for block in blockify(plaintext):
		keystream = encrypter.encrypt(nonce + struct.pack(">Q", counter))
		
		ciphertext += xor(block, keystream)
		
		counter += 1
	
	return ciphertext	
		
def decrypt(key, plaintext, IV = "\x00"*16, cipher=aes.aes):
	return encrypt(key, plaintext, IV, cipher)
	
	