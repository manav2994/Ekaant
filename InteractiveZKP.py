#!/usr/bin/python
# -*- coding: utf-8 -*-
# Author: Manav Mahajan

''' 
This Script demonstrates an example of Interactive ZK Protocol
'''

import ECElgamal
import random
import hashlib

mod = pow(2, 256) - pow(2, 32) - pow(2, 9) - pow(2, 8) - pow(2, 7) - pow(2, 6) - pow(2, 4) - pow(2, 0)
order = 115792089237316195423570985008687907852837564279074904382605163141518161494337

#curve configuration
# y^2 = x^3 + a*x + b = y^2 = x^3 + 7
a = 0
b = 7


print("Here we chose G and H as agreed by the verifier and the prover:")

G = [55066263022277343669578718895168534326250603453777594175500187360389116729240, 32670510020758816978083085130507043184471273380659243275938904335757337482424]
print("G: ", G)
H = ECElgamal.ECadd(G[0], G[1], G[0], G[1], a, b, mod) #2G
print("H: ", H)
s = "Hello"
print("Prover's Message:", s)
#x = random.getrandbits(128)
x = int(hashlib.sha256(s.encode('utf-8')).hexdigest(), 16)

print("Prover's Secreet:", x)




xG = ECElgamal.ECmultiply(G[0], G[1], x, a, b, mod)
xH = ECElgamal.ECmultiply(H[0], H[1], x, a, b, mod)

print("xG: ", xG)
print("xH: ", xH)


#Challenge Creation by Verifier

c = random.getrandbits(128)

#Prover creates the proof

v = random.getrandbits(128)
vG = ECElgamal.ECmultiply(G[0], G[1], v, a, b, mod)
vH = ECElgamal.ECmultiply(H[0], H[1], v, a, b, mod)

r = v - (x * c)
print ('r =============', r)
rG = ECElgamal.ECmultiply(G[0], G[1], r, a, b, mod)
rH = ECElgamal.ECmultiply(H[0], H[1], r, a, b, mod)

#Check vG = rG + c(xG) and vH = rH + c(xH)
cxG = ECElgamal.ECmultiply(xG[0], xG[1], c, a, b, mod)
cxH = ECElgamal.ECmultiply(xH[0], xH[1], c, a, b, mod)

a = ECElgamal.ECadd(cxG[0], cxG[1], rG[0], rG[1], a, b , mod)
b = ECElgamal.ECadd(cxH[0], cxH[1], rH[0], rH[1], a, b , mod)
print("Check Proof")
print(b)
print(vG)
print(vH)