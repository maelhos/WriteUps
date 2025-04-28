from pwn import remote, process
from Crypto.Util.number import *
from sage.all import *
from gmo.all import *
import json

f = json.loads(open("out.txt", "r").read())
bs = 1024 // 32

iv1 = f[0]["iv"]
c1 = f[0]["c"]

iv2 = f[1]["iv"]
c2 = f[1]["c"]

lattice = [[c1, c2, iv1, iv2],
           [1,  0,  0,   0],
           [0,  1,  0,   0],
           [0,  0,  1,   0],
           [0,  0,  0,   1]]


lat = matrix(ZZ, lattice).transpose()
scale = diagonal_matrix([2**1024, 2**256, 2**256, 1, 1])

r = (lat * scale).BKZ() / scale
flag = b""
for v in r:
    if v[0] == 0:
        print(v)
        k2, k1, k2b1, k1b2 = list(map(int, v[1:]))
        if k2b1 % k2 == 0 and k1b2 % k1 == 0:
            b2 = k1b2 // k1
            b1 = k2b1 // k2
            if b1 < 0:
                b1 *= -1
                b2 *= -1
            print(int.to_bytes(b1, bs,"big") + int.to_bytes(b2, bs,"big"))
