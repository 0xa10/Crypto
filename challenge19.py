import ctr
from utils import *
import os
import random
from copy import copy

plaintexts = """SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==
Q29taW5nIHdpdGggdml2aWQgZmFjZXM=
RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==
RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=
SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk
T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=
UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=
T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl
VG8gcGxlYXNlIGEgY29tcGFuaW9u
QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==
QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=
QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==
QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=
QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=
VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==
SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==
SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==
VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==
V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==
V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==
U2hlIHJvZGUgdG8gaGFycmllcnM/
VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=
QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=
VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=
V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=
SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==
U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==
U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=
VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==
QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu
SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=
VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs
WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=
SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0
SW4gdGhlIGNhc3VhbCBjb21lZHk7
SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=
VHJhbnNmb3JtZWQgdXR0ZXJseTo=
QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=""".split()

random_key = os.urandom(16) 

def is_letter(c):
	return c in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	
def get_sorted_candidates(candidates):
	# sort by occurence of each element
	result = []
	for entry in set(candidates):
	    result.append((entry, candidates.count(entry)))
	result.sort(key = lambda x: -x[1])
	return result

def attempt_translation(test_cipher, ciphertexts):
	ciphertexts.remove(test_cipher)
	candidates = [["?"] for i in range(len(test_cipher))]
	
	# rely on the fact that anything xored with space is the opposite case of itself
	# A ^ 0x20 = a
	# z ^ 0x20 = Z
	# 
	# for each ciphertext we know is xored with the same keystream,
	# xor it with our target ciphertext, and extract each printable letter,
	# adding it to a list of candidates for that index
	for ct in ciphertexts:
		result = xor(test_cipher, ct)
		for i in range(len(result)):
			if is_letter(result[i]):
				candidates[i].append(result[i].lower())
			
	# sort the candidates at each index and combine the top candidates
	sorted_candidates = [get_sorted_candidates(candidate) for candidate in candidates]
	return "".join([candidate[0][0] for candidate in sorted_candidates])

def attempt_decrypt(ciphertext, partial_keystream):
	# decrypt with an incomplete keystream, replacing Nones in the keystream with
	# '?'s in the plaintext result
	keystream_nulled = [e if e is not None else "\x00" for e in partial_keystream]
	result = list(xor(ciphertext, "".join(keystream_nulled)))
	for i in range(len(result)):
		if partial_keystream[i] is None:
			result[i] = "?"
	
	return "".join(result)

def main():
	ciphertexts = [ctr.encrypt(random_key, i.decode("base64")) for i in plaintexts]
	
	# find what our target is
	keystream = [None] * max([len(ct) for ct in ciphertexts])
	print "Longest cipher len %d\n" % (len(keystream))	

	test_cipher = ciphertexts[4] # long and fruity
	result = attempt_translation(test_cipher, copy(ciphertexts))
	print result
	# ?ehaveopassedrwithiahnodsofnthidhi??
	# ? have passed with a nod of the head - good guess?

	keystream_candidate = xor(result, test_cipher)
	keystream[1:36] = xor(test_cipher[1:36], "? have passed with a nod of the head"[1:36])
	print "Missing %d values" % (keystream.count(None))
	print attempt_decrypt(test_cipher, keystream)
	
	print 
	test_cipher = ciphertexts[-2] # gives us first letter
	result = attempt_translation(test_cipher, copy(ciphertexts))
	print result
	# ?ransformediutterlyn
	# Transformed presumed, index 0
	
	keystream[0] = xor(test_cipher[0], "T"[0])
	print "Missing %d values" % (keystream.count(None))
	print attempt_decrypt(test_cipher, keystream)	
	
	# still missing two letters from the single longest phrase, cannot be recovered.
	# enough plaintext though to find Easter 1916 by William Butler Yeats
	print 
	test_cipher = ciphertexts[-3] # last two letters
	result = attempt_translation(test_cipher, copy(ciphertexts))
	print result
	# te, too, has been changed in his tur??
	# te, too, has been changed in his turn, - indices 36:38
	
	keystream[36:38] = xor(test_cipher[36:38], "te, too, has been changed in his turn,"[36:38])
	print "Missing %d values" % (keystream.count(None))
	print attempt_decrypt(test_cipher, keystream)	
	
	print 
	print "Done!\n"
	decrypted = [xor(ct, keystream) for ct in ciphertexts]
		
	for i in decrypted:
		print i
		

if __name__ == "__main__":
	main()