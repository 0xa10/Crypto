import urllib2
import sys
from utils import *

TARGET = 'http://crypto-class.appspot.com/po?er='
#--------------------------------------------------------------
# padding oracle
#--------------------------------------------------------------
class PaddingOracle(object):
    def query(self, q):
        target = TARGET + urllib2.quote(q)    # Create query URL
        req = urllib2.Request(target)         # Send HTTP request to server
        try:
            f = urllib2.urlopen(req)          # Wait for response
        except urllib2.HTTPError, e:          
            print "We got: %d" % e.code       # Print response code
            if e.code == 404:
                return True # good padding
            return False # bad padding

# intuitively optimized order for text
# space, lower case, upper case, symbols and numbers in reverse, padding (in reverse) + rest
optimized_chars = [32,] + range(97, 123) + range(65, 97) + range(65, 33, -1) + range(16, 0, -1) + range(16, 32) + range(123, 256)
assert len(optimized_chars) == 256

def padding_attack(oracle, attacked_msg):
	recovered_msg = ""
	
	blocks = blockify(attacked_msg) 
	
	iterations = 0
	
	# start decoding each block, using the IV as the first test bed
	for prev_block, block in zip(blocks[:-1], blocks[1:]):
		decoded_block_text = ""
		pad_start = 1
		# special case for last block
		if block is blocks[-1]: 
			for pad_start in range(len(block), 0, -1):
				xored_block = "\xAA" * (len(block) - pad_start + 1)
				xored_block += prev_block[len(xored_block):]
				
				assert len(xored_block) == len(block)
				if (oracle(xored_block + block)):
					continue
				else:
					# found the padding length
					decoded_block_text = chr(pad_start) * pad_start
					pad_start += 1
					break
			else:
				print "Could not find the last blocks padding, aborting"
				pad_start = 1
						
		# start decoding from last char, count pad from 1 to 16 (including)
		for pad in range(pad_start,len(block)+1):
			# test all chars
			print "******************************** " + str(pad) +" *******************************"
			for c in optimized_chars:
				iterations += 1
				print repr(chr(c))
				# start by assembling the previous block 
				# truncate at the chars we already know, minus one for the currently abused index
				xored_block = prev_block[:(len(decoded_block_text)*-1) - 1] 
				
				# add the current char we're trying to discover
				xored_block += chr(ord(prev_block[(len(decoded_block_text)*-1) - 1]) ^ c ^ pad)
						
				# if we already know any chars, set up their padding correctly
				for decoded_char, cipher_char in zip(decoded_block_text,  prev_block[(len(decoded_block_text)*-1):]):
					xored_block += chr(ord(cipher_char) ^ ord(decoded_char) ^ pad)
						
				# and ship it out
				assert len(xored_block) ==  len(block)
				if (oracle(xored_block + block)):
					# found our char
					decoded_block_text = chr(c) + decoded_block_text
					print decoded_block_text
					break
			else:
				# didn't find shit
				print "Could not find the current char, aborting block"
				decoded_block_text = decoded_block_text.rjust(len(block), "?")
				break
				
					
		recovered_msg += decoded_block_text
		
	return recovered_msg, iterations

def main(argv):
	po = PaddingOracle()	
	attacked_msg = "f20bdba6ff29eed7b046d1df9fb7000058b1ffb4210a580f748b4ac714c001bd4a61044426fb515dad3f21f18aa577c0bdf302936266926ff37dbf7035d5eeb4".decode("hex")
	recovered_msg, iterations = padding_attack(lambda x: po.query(x.encode("hex")), attacked_msg)

	print "Recovered message: \n\t%s" % (repr(recovered_msg), )
	print "Completed in %d iterations, %d avg iterations per character (length of message is %d)" % (iterations, iterations/(len(recovered_msg) - recovered_msg.count("?")), len(recovered_msg))
	
	
if __name__ == "__main__":
	main(sys.argv)
