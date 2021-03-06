from utils import *
import sha1
from mac import secret_prefix_mac
import random
import os
import struct

key_min = 1
key_max = 30
key = os.urandom(random.randint(key_min, key_max)) 

def main():
	# create mac instance
	global key
	global key_min
	global key_max
	
		
	mac_gen = secret_prefix_mac(key, sha1.sha1)
	msg = """comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"""
	mac = mac_gen.tag(msg)
	wanted_extension = ";admin=true"
	
	assert mac_gen.verify(msg, mac)
	
	print "The mac for the msg: \n%s\nis:" % (repr(msg),)
	print "\t%s" % (mac.hexdigest(),)
	print "Trying to extend with %s" % (repr(wanted_extension),)
	print
	
	
	print "Starting search from key lengths %d to %d" % (key_min, key_max)
	for i in range(key_min, key_max+1):
		# for each possible key length
		# generate a valid padding block for the original msg, truncating it to remove the key
		padded = md_pad(("A"*i) + msg)[i:]
		 
		
		# create a new sha1 generator and splice in the original tag
		fake_tag = sha1.sha1()
		fake_tag._h0, fake_tag._h1, fake_tag._h2, fake_tag._h3, fake_tag._h4 = struct.unpack(">LLLLL", mac.hexdigest().decode("hex"))   
		
		# extend the hash by hasing the extension, with a fake length value in the padding
		# the fake length value should reflect the length of the original block (512 bits) 
		# plus the length of the extension (in bits)
		fake_length = (i + len(padded) + len(wanted_extension)) * 8
		fake_tag._sha1(wanted_extension, fake_length = fake_length)		
		
		# attempt to verify it 
		if mac_gen.verify(padded + wanted_extension, fake_tag):
			print "Success!" 
			print "Key length is %d, we succesfully verified the following msg:" % (i,)
			print repr(padded + wanted_extension)
			break
	else:
		print "Could not create a fake tag!"
		
	
if __name__ == "__main__":
	main()