import random

INT_SIZE = 32

def left(number, shift, mask):
	return number ^ ((number << shift) & mask)

def right(number, shift):
	return number ^ (number >> shift) 

def right_inverse(number, shift):
	result = number
	for i in range(shift, (INT_SIZE) + 1, shift):
		result = number ^ (result >> shift)

	return result

def left_inverse(number, shift, mask):
	result = number
	for i in range(shift, (INT_SIZE) + 1, shift):
		result = number ^ ((result << shift) & mask)

	return result


assert right_inverse(right(0xdeadbeef, 7), 7) == 0xdeadbeef
assert left_inverse(left(0xdeadbeef, 7, 0xbabecafe << 7), 7, 0xbabecafe << 7) == 0xdeadbeef

def untemper_mt19937(randnum):
	y = randnum
	
	y = right_inverse(y, 18)
	y = left_inverse(y, 15, 0xefc60000)
	y = left_inverse(y, 7, 0x9d2c5680)
	y = right_inverse(y, 11)
	
	return y
	
class mt19937():
	def __init__(self, seed = random.randint(0, 2**32)):
		self._state = [None] * 624
		self._index = 0
		self.seed(seed)
	
	def seed(self, seed):
		self._index = 0
		self._state[0] = seed
		for i in range(1, 624):
			self._state[i] = ((right(self._state[i-1], 30) * 0x6c078965) + i) & 0xFFFFFFFF 
	
	def random(self):
		if self._index == 0:
			self._generate_numbers()
			
		y = self._state[self._index]
		
		y = right(y, 11)
		y = left(y, 7, 0x9d2c5680)
		y = left(y, 15, 0xefc60000)
		y = right(y, 18)	
	
		self._index = (self._index + 1) % 624
		
		return y
	
	def _generate_numbers(self):
		for i in range(624):
			y = (self._state[i] & 0x80000000) + (self._state[(i+1) % 624] & 0x7fffffff)
			self._state[i] = self._state[(i+397) % 624] ^ (y >> 1)
			if (y % 2) != 0:
				self._state[i] ^= 0x9908b0df		
	
	
	def setstate(self, state, index):
		self._state = state
		self._index = index
	
	def getstate(self):
		return self._state, self._index
	
	
def clone_mt19937(samples):
	assert len(samples) == 624
	
	state = [None] * 624
	for sample, index in zip(samples, range(624)):
		state[index] = untemper_mt19937(sample)
		
	cloned = mt19937(0)
	cloned.setstate(state, 0)

	return cloned

	
def main():
	to_clone = mt19937()
	samples = [to_clone.random() for i in range(624)]
		
	cloned = clone_mt19937(samples)
	
	print "%x - %x" % (cloned.random(), to_clone.random())
	
	assert cloned.random() == to_clone.random()

if __name__ == "__main__":
	main()
	