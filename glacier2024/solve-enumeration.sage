import os
os.environ["TERM"] = "xterm-256color"

from pwn import *
from Crypto.Util.number import *
import binascii
import hashlib
import random
import string

exe = ELF("./challenge")

context.binary = exe

def bytes_to_long_le(data: bytes) -> int:
    return int.from_bytes(data, byteorder='little')

def long_to_bytes_le(value: int, length: int) -> bytes:
    return value.to_bytes(length, byteorder='little')

def conn():
    if args.LOCAL:
        r = process([exe.path])
        if args.DEBUG:
            gdb.attach(r)
    else:
        r = remote("127.0.0.1", 1337)

    return r

def main():
    c = conn()

    l = 2 ^ 252 + 27742317777372353535851937790883648493
    B = 2 ^ 160

    # note that this is not n as described earlier (sorry), N = n + 1
    N = 10

    pk = binascii.unhexlify(c.recvline().decode().strip().split()[-1].encode())

    # set up min/max vectors, first and last columns of A
    mins = [0]
    maxs = [B]
    col0 = [B / l]
    coln = [0]

    for i in range(N-1):
        # generate a random string
        random_string = ''.join(random.choices(string.ascii_letters + string.digits, k=8))
        msg = random_string.encode()

        # send the random string when prompted
        h = hashlib.sha1()
        c.recvuntil(b'> ')
        c.sendline(msg)
        R, S = c.recvline().decode().strip().split()[1:]

        S = bytes_to_long_le(binascii.unhexlify(S.encode()))

        assert (S < l)

        # generate H(R || A || M)
        h.update(binascii.unhexlify(R.encode()))
        h.update(pk)
        h.update(msg)

        hi = h.digest()

        # Si = r + hi * s

        # populate min/max vectors, and first/last columns
        mins.append(0)
        maxs.append(B)
        col0.append(-1 * (bytes_to_long_le(hi) % l))
        coln.append(S)
    
    # finish first and last columns, and min/max vectors
    coln.append(B)

    mins.append(B)
    maxs.append(B)

    # Create the min and max vectors
    minvector = vector(QQ, mins)
    maxvector = vector(QQ, maxs)   

    # create the A matrix
    a_helper = [[0] * (N+1) for j in range(N+1)]
    for j in range(1,N):
        a_helper[j][j] = l
    for j in range(N):
        a_helper[j][0] = col0[j]
    for j in range(N+1):
        a_helper[j][N] = coln[j]

    A = matrix(QQ, a_helper)

    # Compute LLL (LLL in sage operates on rows so you need to do 
    # some transposes)
    # and compute inverse transform
    AL = A.transpose().LLL().transpose()
    ALi = AL.inverse()
    
    solutions = []

    # find all vertices of the "box" defined by the inequalities
    vertex_list = []
    for j in range(2**(N+1)):
        vertex = []
        for k in range(N+1):
            if j&(1 << k): 
                vertex.append(minvector[k])
            else:
                vertex.append(maxvector[k])

        vertex_list.append(vertex)
    
    # apply ALi to each vertex to find its LLL-transformed version
    transformed_vertex_list = []
    for i in range(2**(N+1)):
        vertex = ALi*vector(vertex_list[i])
        transformed_vertex_list.append(vertex)

    # Create a parallelotope with the transformed vertices
    # Output the number of integral points it contains
    # Output any integral points inside of it
    P = Polyhedron(vertices = transformed_vertex_list, backend='normaliz')
    print(P.integral_points_count())
    x = P.integral_points()
    for v in x:
        solutions.append(vector(v))    
    print(solutions)

    # determine s
    for solution in solutions:
        s = l / B * (AL * solution)[0]

    # we want to forge a signature now
    c.recvuntil(b'> ')
    c.sendline(b'')

    # get challenge message
    challenge_msg = c.recvline().decode().strip().split()[-1]
    c.recvuntil(b'> ')

    zeropoint = 1 # compressed format of (0,1)
    R = long_to_bytes_le(zeropoint,32)
    R_hex = binascii.hexlify(R).decode()

    h = hashlib.sha1()

    # compute H(R || A || M)
    h.update(R)
    h.update(pk)
    h.update(challenge_msg.encode())

    hram = bytes_to_long_le(h.digest())

    # compute the forged signature and send it
    S = (s * hram) % l
    S_hex = binascii.hexlify(long_to_bytes_le(S, 32)).decode()

    forged = (R_hex + ' ' + S_hex).encode()
    
    c.sendline(forged)

    c.interactive()

if __name__ == "__main__":
    main()