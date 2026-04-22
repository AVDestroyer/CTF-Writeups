import os
os.environ["TERM"] = "xterm-256color"
from pwn import *
from tqdm import tqdm
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Taken from https://github.com/obafgkmdh/randcrack-linear
class NumericRand:
	def __init__(self, state):
		self.rng = self._numeric_random()
		self.state = [int(''.join(map(str, state[i*32:i*32+32])), 2) for i in range(624)]
	
	def _numeric_random(self):
		N = 624
		M = 397
		index = 0
		while 1:
			if index >= N:
				for kk in range(N):
					y = (self.state[kk]&0x80000000) | (self.state[(kk+1)%N]&0x7fffffff)
					self.state[kk] = (self.state[(kk+M)%N] ^^ (y >> 1) ^^ ((y & 1) * 0x9908b0df)) & 0xffffffff
				index = 0
			y = self.state[index]
			index += 1
			y ^^= (y >> 11) & 0xffffffff
			y ^^= (y << 7) & 0x9d2c5680
			y ^^= (y << 15) & 0xefc60000
			y ^^= (y >> 18) & 0xffffffff
			yield y & 0xffffffff
	
	def set_state(state):
		self.state = state[:624]
	
	def predictrand_uint32(self):
		return next(self.rng)

# Taken from https://github.com/obafgkmdh/randcrack-linear
class SymbolicRand:
	def __init__(self):
		self.rng = self._symbolic_random()
	
	def _ZERO(self): return zero_vector(GF(2), 32*624)
	def _AND(self, a, b): return [a[s] if ((b<<s) & 0x80000000) else self._ZERO() for s in range(32)]
	def _LSH(self, a, b): return a[b:] + [self._ZERO() for i in range(b)]
	def _RSH(self, a, b): return [self._ZERO() for i in range(b)] + a[:-b]
	def _XOR(self, *args): return [sum(i, self._ZERO()) for i in zip(*args)]
	def _XOR_in_place(self, a, b):
		for i in range(32): a[i] += b[i]
	def _MAGIC(self, a, b): return [a[31] if ((b<<s) & 0x80000000) else zero_vector(GF(2), 32*624) for s in range(32)]
	
	def _symbolic_random(self):
		N = 624
		M = 397
		mt = list(identity_matrix(GF(2), 32*N))
		index = 0
		while 1:
			if index >= N:
				for kk in range(N):
					y = mt[kk*32:][:1] + mt[(kk+1)%N*32:][1:32]
					mt[kk*32:(kk+1)*32] = self._XOR(mt[(kk+M)%N*32:][:32], self._RSH(y, 1), self._MAGIC(y, 0x9908b0df))
				index = 0
			y = mt[index*32:][:32]
			index += 1
			self._XOR_in_place(y, self._RSH(y, 11))
			self._XOR_in_place(y, self._AND(self._LSH(y, 7), 0x9d2c5680))
			self._XOR_in_place(y, self._AND(self._LSH(y, 15), 0xefc60000))
			self._XOR_in_place(y, self._RSH(y, 18))
			yield y
	
	def genrand_uint32(self):
		return next(self.rng)

K.<a> = GF(2^128)
V, from_V, to_V = K.vector_space()

def mul_matrix(x):
    return matrix(GF(2), [to_V(x * a^j) for j in range(128)]).transpose()

def from_int(n):
    return K([(n >> (127 - i)) & 1 for i in range(128)])

def to_int(el):
    v = to_V(el)
    return sum(int(v[i]) << (127 - i) for i in range(128))

def mul_matrix_from_int(n):
    return mul_matrix(from_int(n))

S = matrix(GF(2), [to_V(a^(2*j)) for j in range(128)]).transpose()
print(S)

MASK32 = (1 << 32) - 1
LOWER_MASK = MASK32 >> 1
UPPER_MASK = LOWER_MASK + 1

def convert_to_array(seed_int):
    n = seed_int
    out = []
    while n:
        num = n & MASK32
        out.append(num)
        n >>= 32
    return out

N = 624
M = 397
MATRIX_A = 0x9908b0df
state = [0] * 624

def init_genrand(s, mt_state = None):
    global state

    if mt_state is None:
        mt_state = state

    mt_state[0] = s
    for i in range(1, N):
        mt_state[i] = (1812433253 * (mt_state[i-1] ^ (mt_state[i-1] >> 30)) + i) & MASK32

def reverse_init_by_array(recovered_state, length):

    key = [0] * length

    initialized_state = [0] * 624
    init_genrand(19650218, initialized_state)
    # reverse last instruction
    recovered_state[0] = recovered_state[N-1]

    # reverse second loop. the base case is recovered_state[0] which is correct then we can inductively work back up
    i = 1
    for k in range(N-1, 0, -1):
        recovered_state[i] = (recovered_state[i] + i) & MASK32
        recovered_state[i] = (recovered_state[i] ^ (recovered_state[i-1] ^ (recovered_state[i-1] >> 30)) * 1566083941) & MASK32
        if i == N-1:
            # see comment below
            recovered_state[0] = recovered_state[i]
        i-=1
        if i == 0:
            # need previous value of state[0] which is only known from previous value of state[N-1] (this is set in the first loop!)
            i = N-1
    
    # reverse first loop. the first loop ends with i = 2. base case is recovered_state[0] and work inductively again. we only need to do `length` iterations.
    i = 2
    j = N % length
    counter = 0
    for k in range(N, 0, -1):
        j-=1
        if j < 0:
            j += length
        if i == 1:
            # reset state[0]. this is going to be state[0] created by init_genrand
            recovered_state[0] = initialized_state[0]
            i = N
        i-=1
        print(i)
        old_j_with_key = (recovered_state[i] - j) & MASK32
        # we know initialized_state[i] is the old value of state[i] UNLESS i = 1 at the start of the loop, in which case it was modified twice, skip this
        if k == N:
            # fix recovered_state[1] for the second modification
            continue
        old_j = (initialized_state[i] ^ ((recovered_state[i-1] ^ (recovered_state[i-1] >> 30)) * 1664525)) & MASK32
        key_j = (old_j_with_key - old_j) & MASK32
        recovered_state[i] = initialized_state[i]
        assert key[j] == 0 or key[j] == key_j, f"key: {key}, key at j: {bin(key[j])} j: {j}, key_j: {bin(key_j)}"
        key[j] = key_j

        counter += 1
        if counter == length:
            break
    
    return key

sym_rng = SymbolicRand()

def conn():
    if args.LOCAL:
        r = process(["python3", "many_tags.py"])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = process(["ncat", "--ssl", "manytags.opus4-7.b01le.rs", "8443"])

    return r

r = conn()

r.recvuntil(b'flag_nonce')
flag_nonce = bytes.fromhex(r.recvline().decode().strip().split()[-1])
flag_ciphertext = bytes.fromhex(r.recvline().decode().strip().split()[-1])
flag_tag = bytes.fromhex(r.recvline().decode().strip().split()[-1])

num_queries = 320

nonces = []
cts = []
tags = []

A_blocks = []
B_blocks = []
obs_blocks = []

for i in tqdm(range(num_queries)):
    r.sendlineafter(b'> ', b'1')
    nonce = bytes.fromhex(r.recvline().decode().strip().split()[-1])
    ciphertext = bytes.fromhex(r.recvline().decode().strip().split()[-1])
    tag = bytes.fromhex(r.recvline().decode().strip().split()[-1])
    r.recvline()
    nonces.append(nonce)
    cts.append(ciphertext)
    tags.append(tag)

r.close()

# model a twist by querying RNG 624 times
for _ in range(624):
	sym_rng.genrand_uint32()

# For each query, consume two words
for i in tqdm(range(num_queries)):

    A_i = mul_matrix_from_int(int.from_bytes(cts[i], "big")) * S + mul_matrix_from_int(0x80)
    A_i_lower = A_i[64:]                   # 64 x 128  (lower 64 bits of GHASH)

    word0 = sym_rng.genrand_uint32()  # list of 32 vectors in GF(2)^19968
    word1 = sym_rng.genrand_uint32()  # list of 32 vectors in GF(2)^19968
    
    # B_i is the 64x19968 matrix: rows are the symbolic bits of fault_words
    B_i = matrix(GF(2), word0 + word1)  # 64 rows, 19968 cols

    A_blocks.append(A_i_lower)
    B_blocks.append(B_i)
    tag_int = int.from_bytes(tags[i], "big")
    tag_lower = tag_int & ((1 << 64) - 1)
    obs_vec = vector(GF(2), [(tag_lower >> (63 - j)) & 1 for j in range(64)])
    obs_blocks.append(obs_vec)

big_A = block_matrix([[A] for A in A_blocks])   # (n*64) x 128
big_B = block_matrix([[B] for B in B_blocks])   # (n*64) x 19968
M = big_A.augment(big_B)                        # (n*64) x 20096
obs = vector(GF(2), sum([list(o) for o in obs_blocks], []))

solution = M.solve_right(obs)
h_bits = solution[:128]
state_bits = solution[128:]

print(h_bits)
print(state_bits)

# convert to a state of 624 words
mt_state = [0]*624
mt_state[i] = int(''.join(map(str,raw_state[i*32:(i+1)*32])), 2)

key_ints = reverse_init_by_array(mt_state, 8)
key_int = 0
for i in range(8):
    key_int |= (key_ints[i] << (32 * i))

key = key_int.to_bytes(32, 'big')
print(key)

# this key was used to encrypt flag. decrypt.
decrypted = AESGCM(key).decrypt(flag_nonce, flag_ciphertext, None)
print(decrypted)

