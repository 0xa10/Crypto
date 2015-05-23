import aes
from utils import *
from pad import pad_pkcs7, unpad_pkcs7

class CbcError(Exception): 
	pass

def encrypt(key, plaintext, IV = "\x00"*16, cipher = aes.aes):
	encrypter = cipher(key)
	
	ciphertext = IV
	
	blocks = blockify(pad_pkcs7(plaintext))
	
	for block in blocks:
		ciphertext += encrypter.encrypt(xor(block, ciphertext[-len(IV):]))
	return ciphertext	
		
def decrypt(key, ciphertext, cipher = aes.aes):
	if len(ciphertext) % 16 != 0:
		raise CbcError("Invalid message length.")
	decrypter = cipher(key)
	
	plaintext = ""
	
	blocks = blockify(ciphertext)
	
	for prev_block, block in zip(blocks[:-1], blocks[1:]) :
		plaintext += xor(decrypter.decrypt(block), prev_block)
	return unpad_pkcs7(plaintext)	
	
	