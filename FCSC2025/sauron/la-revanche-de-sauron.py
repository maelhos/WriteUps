#!/usr/bin/env python3

import json
from Crypto.Util.number import *
from Crypto.Random.random import randrange
from math import gcd

class Cipher:

	def __init__(self, size = 1024):
		self.s = 2**size + randrange(2**size)
		self.bs = size // 32

	def encrypt(self, m):
		assert len(m) % self.bs == 0, f"Error: wrong length ({len(m)})"
		C = []
		for i in range(0, len(m), self.bs):
			iv = randrange(self.s)
			while gcd(iv, self.s) != 1:
				iv = randrange(self.s)
			b = int.from_bytes(m[i:i + self.bs],"big")
			C.append({
				"iv": iv,
				"c": (b * iv) % self.s,
			})
		return C

	def decrypt(self, c):
		r = b""
		for d in c:
			m = d["c"] * pow(d["iv"], -1, self.s) % self.s
			r += int.to_bytes(m, self.bs,"big")
		return r

if __name__ == "__main__":

	flag = open("flag.txt", "rb").read().strip()
	assert len(flag) == 64, "Error: wrong flag length."

	E = Cipher()
	C = E.encrypt(flag)
	assert flag == E.decrypt(C), "Error: decryption test failed."

	print(json.dumps(C, indent = 4))
