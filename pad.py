class PaddingError(Exception):
    pass

def pad_pkcs7(data, blocklen=16):
	return data + chr(blocklen - (len(data) % blocklen)) * (blocklen - (len(data) % blocklen)) 
	
def unpad_pkcs7(data, blocklen=16):
	if not blocklen >= ord(data[-1]) >= 1:
		raise PaddingError("Invalid padding.")

	if data[-ord(data[-1]):].count(data[-1]) != ord(data[-1]):
		raise PaddingError("Invalid padding.")
	
	return data[:-ord(data[-1])]
	