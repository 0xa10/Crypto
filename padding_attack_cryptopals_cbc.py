from padding_attack import padding_attack
import pad
import cbc
import os
import sys
import random

plaintexts = ["MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
"MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
"MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
"MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
"MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
"MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
"MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
"MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
"MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
"MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93"]

random_key = os.urandom(16)

def get_ciphertext():
	return cbc.encrypt(random_key, random.choice(plaintexts).decode("base64"))

def oracle(ciphertext):
	try:
		cbc.decrypt(random_key, ciphertext)
		print "Good padding"
		return True
	except pad.PaddingError, e:
		print "Bad padding"
		return False


def main(argv):
	attacked_msg = get_ciphertext()
	recovered_msg, iterations = padding_attack(oracle, attacked_msg)

	print "Recovered message: \n\t%s" % (repr(recovered_msg), )
	print "Completed in %d iterations, %d avg iterations per character (length of message is %d)" % (iterations, iterations/(len(recovered_msg) - recovered_msg.count("?")), len(recovered_msg))
	
	
if __name__ == "__main__":
	main(sys.argv)
