from utils import *
from collections import defaultdict
import pickle

p = 13407807929942597099574024998205846127479365820592393377723561443721764030073546976801874298166903427690031858186486050853753882811946569946433649006084171

g = 11717829880366207009516117596335367088558084999998952205599979459063929499736583746670572176471460312928594829675428279466566527115212748467589894601965568

h = 3239475104050450443565264378728065788649097520952449527834792452971981976143292558073856937958553180532878928001494706097394108577585732452307673444020333

B = 2**20

def calculate_final_x(x0, x1):
	return ((x0*B) + x1)

def main():
	# trying to solve h * (g**-x1) == (g**B)**x0 mod p
	
	results = defaultdict()
	
	# meet in the middle:
	# hash all results for h * inverse_mod(g**x1) mod p
	import time
	start = time.time()
	g_inverse = inverse_mod(g, p)
	result = h
	for x1 in range(B):
		results[result] = x1
		result = (result * g_inverse) % p 
			
	print "Finished generating hashtable, took %f seconds" % (time.time() - start, )
	#pickle.dump(results, file("ht%d" % time.time(),"wb")) # in case something goes wrong later
	#results = pickle.load(file(""))

	print "Starting x1 search"
	start = time.time()
	 
	# now do the other end
	base_value = pow(g, B, p)
	result = 1
	for x0 in range(B):
		if result in results: # should be fast enough
			x1 = results[result]
			match_found = True
			print "Found matching values:"
			print "\tx0: %d" % (x0,)  
			print "\tx1: %d" % (x1,)
			break
		result = (result * base_value) % p
	else:
		print "Found no matching values..."
		match_found = False

	print "Finished search, took %f seconds" % (time.time() - start, )
	
	if match_found:
		x = calculate_final_x(x0, x1)
		print "x: %d" % (x,)
		assert pow(g, x, p) == h

if __name__ == "__main__":
	main()