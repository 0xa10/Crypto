import struct

def gcd(a, b):
    """Calculate the Greatest Common Divisor of a and b.

    Unless b==0, the result will have the same sign as b (so that when
    b is divided by it, the result comes out positive).
    """
    while b:
        a, b = b, a%b
    return a
    
def egcd(a, b):
  if a == 0:
    return (b, 0, 1)
  else:
    g, y, x = egcd(b % a, a)
    return (g, x - (b // a) * y, y)

def inverse_mod(a, m):
  g, x, y = egcd(a, m)
  if g != 1:
    raise Exception('Modular inverse does not exist')
  else:
    return x % m

def power_mod(a, b, mod):
    # repeating square implementation, actually a bit slower than pythons default
    exponent = b
    accumulator = a
    result = 1
    i = 0
    while ((exponent >> i) > 0):
        if ((exponent >> i) & 1):
             result = (result * accumulator) % mod
        accumulator = (accumulator * accumulator) % mod 
        i += 1
    return result


def leftrotate(word, n, word_size=32):
	right_side = word >> (word_size-n) & (2**word_size) - 1
	left_side = word << (n) & (2**word_size) - 1
	
	return left_side | right_side
    
# Merkle Damgard compliant padding
def md_pad(message, _CHAR_BIT_SIZE = 8, fake_length = None, little_endian = False): 
    data = message
    #append the bit '1' to the message i.e. by adding 0x80 if characters are 8 bits. 
    message_length = 8*len(data)
    data += chr(1 << (_CHAR_BIT_SIZE - 1))
    
    # append 0 <= k < 512 bits '0', thus the resulting message length (in bits)
    data += "\x00" * ((((448 - ((message_length+8) % 512))) % 512) / _CHAR_BIT_SIZE)
    
    # append ml, in a 64-bit big-endian integer. So now the message length is a multiple of 512 bits.
    if fake_length is not None:
        data += struct.pack("%sQ" % ("<" if little_endian else ">",) , fake_length)
    else:
        data += struct.pack("%sQ" % ("<" if little_endian else ">",), message_length)
    
    assert (len(data)*8 % 512 == 0)
    
    return data
         
 
def blockify(data, size=16):
	return [data[i:i+size] for i in range(0, len(data), size)]
	
def xor(data, key):
	return "".join([chr(ord(i) ^ ord(j)) for i,j in zip(data, key)])
	
def binary(num):
	return "{0:b}".format(num).rjust(8,'0')
	
def text_scorer(data):
    from collections import defaultdict
    char_score = defaultdict(lambda : -1)
    
    char_score["a"] = 1.08167
    char_score["b"] = 1.01492
    char_score["c"] = 1.02782
    char_score["d"] = 1.04253
    char_score["e"] = 1.12702
    char_score["f"] = 1.02228
    char_score["g"] = 1.02015
    char_score["h"] = 1.06094
    char_score["i"] = 1.06966
    char_score["j"] = 1.00153
    char_score["k"] = 1.00772
    char_score["l"] = 1.04025
    char_score["m"] = 1.02406
    char_score["n"] = 1.06749
    char_score["o"] = 1.07507
    char_score["p"] = 1.01929
    char_score["q"] = 1.00095
    char_score["r"] = 1.05987
    char_score["s"] = 1.06327
    char_score["t"] = 1.09056
    char_score["u"] = 1.02758
    char_score["v"] = 1.00978
    char_score["w"] = 1.02360
    char_score["x"] = 1.00150
    char_score["y"] = 1.01974
    char_score["z"] = 1.00074
    char_score[" "] = 1
    char_score["."] = 1
    
    for key in char_score.copy():
        char_score[key.upper()] = char_score[key]
    
    score = 0
    for char in data:
        score += char_score[char]   
    return score / len(data)