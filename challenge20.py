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
	
	# truncate to shortest length of ciphertext
	min_ct_len = len(min(ciphertexts, key=len))
	ciphertexts_truncated = [ct[:min_ct_len] for ct in ciphertexts]
	
	# transpose (index 0 will be concatenation of all ciphertexts @ index 0)
	transposed_cts = ["".join([ct[i] for ct in ciphertexts_truncated]) for i in range(min_ct_len)]	
	
	keystream = []
	for ct in transposed_cts:
		# create a list of all possible single byte xor outputs
		# take the one with the best score
		# use that for the keystream
		keystream += chr(max([(i, text_scorer(xor(ct, chr(i)*len(ct)))) for i in range(256)], key = lambda x: x[1])[0])
		# for claritys purpose, not in a one-liner
		#scores = [i, text_scorer(xor(ct, chr(i)*len(ct))) for i in range(256)]
		#best_score = max(scores, key = lambda x: x[1])
		#keystream += chr(best_score[0])
	
	keystream += [None] * (len(max(ciphertexts, key=len)) - min_ct_len) # unknown vals
	decrypted = [attempt_decrypt(ct, keystream) for ct in ciphertexts]
		
	for i in decrypted:
		print i

		

if __name__ == "__main__":
	main()