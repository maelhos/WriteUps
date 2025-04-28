from pwn import remote, process
from Crypto.Util.number import *
from sage.all import *
from itertools import product
import os
from chall import *

#io = process(["python", "chall.py"])
io = remote("chall.fcsc.fr", 2153)

def xor(a, b):
    return bytes(k ^ l for k, l in zip(a, b))


"""delta = {0: 0, 24: 129, 74: 7, 82: 134}

pos = list(delta.keys())

for diff in product(pos, repeat=16):
    state = list(diff)
    good = True
    for rnd in range(20):
        for i in range(16):
            if not state[i] in pos: 
                good = False
                if rnd > 1: print(rnd)
                break
            else:
                state[i] = delta[state[i]]
        if not good: break
        state = Permute(state)
    if not good: continue

    print("GOOD :", diff, "|", state)"""

full_diff_in  = (0, 0, 0, 0, 0, 74, 0, 0, 0, 0, 24, 0, 0, 74, 0, 0)
full_diff_out = (0, 0, 74, 0, 0, 0, 0, 0, 82, 0, 0, 24, 0, 0, 0, 0)

P = os.urandom(16)

####
io.recvuntil(b">>> ")
io.sendline(b"enc")
io.recvuntil(b">>> ")
io.sendline(xor(P, full_diff_in).hex().encode())
io.recvline()

C = bytes.fromhex(io.recvline().decode().strip())

####
io.recvuntil(b">>> ")
io.sendline(b"dec")
io.recvuntil(b">>> ")
io.sendline(xor(C, full_diff_out).hex().encode())
io.recvline()

A = bytes.fromhex(io.recvline().decode().strip())

####
io.recvuntil(b">>> ")
io.sendline(b"enc")
io.recvuntil(b">>> ")
io.sendline(xor(A, full_diff_in).hex().encode())
io.recvline()

B = bytes.fromhex(io.recvline().decode().strip())

###############
io.recvuntil(b">>> ")
io.sendline(P.hex().encode())

io.recvuntil(b">>> ")
io.sendline(xor(B, full_diff_out).hex().encode())

print(io.recvline())
print(io.recvline())