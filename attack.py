from Crypto.Cipher import AES
import os, random, struct
import urllib2

BLOCK_SIZE = 16

# Function returns xor of two hex strings
def xor_hex_strings(a, b):
	new_a = a.decode("hex")
	new_b = b.decode("hex")
	return "".join([chr(ord(x)^ord(y)) for x,y in zip(new_a, new_b)]).encode("hex")

# Returns error when padding not valid
def get_status(u):
    req = urllib2.Request(u)
    try:
        f = urllib2.urlopen(req)
        return f.code
    except urllib2.HTTPError, e:
        return e.code

#Get hex representation of integer without "0x" prefix
def get_hex(x):
	res = hex(x)[2:]
	if(len(res) == 1):
		res = "0" + res
	return res

#Plaintext URL
url_orig = "http://cis556.cis.upenn.edu/hw3?"
#Ciphertext
url_c = "g%20q%89%C60%A7%C6%F44S%FD%5CW%D2%CBx%2C%14%2AEW%AD%05%D08ZM%C3%AF%F3/%BD%F3%8AN7%091%B4%40%DB%068%27%86%BAF%BB%1F%95/%85%0D%B8%E2d%EE%B2%98%DB%1AaxN%B3%3C%5D%1C%ACD%18%A3%AEW%14%F3%9B%24U%FE%0Ec%86V%CA%7C%A1%13%FA1%C7%F5%F6%C7z%E3%B1%BB%1B%CCu%C9%CAe%D0%13v%DBcFT"
# Encode as hex string
orig_hex = url_orig.encode("hex")

#Remove url decoding and encode as hex string
cipher_text = urllib2.unquote(url_c)
cipher_text = cipher_text.encode("hex")
ct_len = len(cipher_text)
# Number of ciphertext blocks
num_blocks = ct_len/32

# Store the ciphertext blocks
blocks = []
idx = 0
while(idx < len(cipher_text)):
	blocks.append(cipher_text[idx: idx + 32])
	idx = idx + 32

# Store the plaintext blocks
plain_text_blocks = []

# Iterate over each block
for n in range(num_blocks-1, 0, -1):
	# Initialize plaintext block as all zero string
	plain_text_n = ["00"]*16
	# Generate a random hex string
	c_rand = ''.join(chr(random.randint(0, 0xFF)) for i in range(BLOCK_SIZE)).encode("hex")

	# Iterate over each byte
	for b in range(30, -1, -2):
		print "Byte number: " + str(b)
		r_b = c_rand[b:b+2]
		# Keep modifying the bth byte of c_rand until you get a valid padding
		for byte in range(0,256):
			c_rand = c_rand[0:b] + xor_hex_strings(r_b, chr(byte).encode("hex")) + c_rand[b + 2:]
			mod_cipher = c_rand + blocks[n]
			query = url_orig + urllib2.quote(mod_cipher.decode("hex"))
			status = get_status(query)
			if(status != 500):
				print "Valid Padding"
				break

		# Get the bth plaintext byte
		plain_text_n[b/2] =  xor_hex_strings(xor_hex_strings(get_hex(16 - (b/2)), c_rand[b : b + 2]), blocks[n-1][b:b+2])

		# Modify the last 'a' bytes of c_rand such that the last 'a-1' bytes of decrypted ct are 'a'
		c_rand = [c_rand[i:i+2] for i in range(0, len(c_rand), 2)]
		for x in range(15, b/2 - 1, -1):
			c_rand[x] = xor_hex_strings(xor_hex_strings(get_hex(16 - (b/2) + 1), plain_text_n[x]), blocks[n-1][2*x :(2*x)+2])
		c_rand = "".join(c_rand)


	plain_text_n = "".join(plain_text_n)
	plain_text_blocks.insert(0, plain_text_n)

url = "".join(plain_text_blocks)
url = url.decode("hex")
#q = "687474703a2f2f6369733535362e6369732e7570656e6e2e6564752f6877332d77657374616e64746f6461796f6e7468656272696e6b6f66617265766f6c7574696f6e696e63727970746f6772617068792e7064660b0b0b0b0b0b0b0b0b0b0b"

print url








