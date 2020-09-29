#!/usr/bin/python
# -*- coding: utf-8 -*-
# Author: Manav Mahajan

''' 
This Script demonstrates Collective Aggregation Protocol and Key Switching for Ekaant 
'''

import ECElgamal
import random

mod = pow(2, 256) - pow(2, 32) - pow(2, 9) - pow(2, 8) - pow(2, 7) - pow(2, 6) - pow(2, 4) - pow(2, 0)
order = 115792089237316195423570985008687907852837564279074904382605163141518161494337

#curve configuration
# y^2 = x^3 + a*x + b = y^2 = x^3 + 7
a = 0
b = 7

#base point on the curve  - G
base_point = [55066263022277343669578718895168534326250603453777594175500187360389116729240, 32670510020758816978083085130507043184471273380659243275938904335757337482424]



print("Public-Private key pair generation for servers (A,B,C) and Querier(Q)")
print("--------------------------------------------------------------")

#Private Key (k) |  ka, kb, kc, kq
privateKeyA = random.getrandbits(128)
privateKeyB = random.getrandbits(128)
privateKeyC = random.getrandbits(128)
privateKeyQ = random.getrandbits(128)


#Public Key (K = kG) | Ka, Kb, Kc
publicKeyA = ECElgamal.ECmultiply(base_point[0], base_point[1], privateKeyA, a, b, mod)
publicKeyB = ECElgamal.ECmultiply(base_point[0], base_point[1], privateKeyB, a, b, mod)
publicKeyC = ECElgamal.ECmultiply(base_point[0], base_point[1], privateKeyC, a, b, mod)
publicKeyQ = ECElgamal.ECmultiply(base_point[0], base_point[1], privateKeyQ, a, b, mod)


#Collective Authority Public Key (K = Ka + Kb + Kc)

caPublicKey1 = ECElgamal.ECadd(publicKeyA[0], publicKeyA[1], publicKeyB[0],publicKeyB[1], a, b, mod)
caPublicKey = ECElgamal.ECadd(caPublicKey1[0],caPublicKey1[1], publicKeyC[0],publicKeyC[1], a, b, mod)



print("\nPublic key: ", caPublicKey)

# Two Entities and their messages 
print("--------------------------------------------------------------")


M1 = input("Enter the Message from Entity 1 > ")
M2 = input("Enter the Message from Entity 2 > ")


plaintext1 = int(M1)
plaintext2 = int(M2)


#Coordinate Map (M = Gm)

plain_coordinates1 = ECElgamal.ECmultiply(base_point[0], base_point[1], plaintext1, a, b, mod)
print("M1 is represented as the following point coordinates")
print("plain coordinates: ", plain_coordinates1)

plain_coordinates2 = ECElgamal.ECmultiply(base_point[0], base_point[1], plaintext2, a, b, mod)
print("M1 is represented as the following point coordinates")
print("plain coordinates: ", plain_coordinates2)


print("Encryption")
print("--------------------------------------------------------------")

#Encryption of M1 and M2 using Collective Authority's Public Key

c11,c12 = ECElgamal.encryption(base_point, plain_coordinates1, caPublicKey, a, b, mod)
c21,c22 = ECElgamal.encryption(base_point, plain_coordinates2, caPublicKey, a, b, mod)


#Collective Aggregation of Encrypted Messages M1 and M2 by server A

c31,c32 = ECElgamal.addHE(c11, c12,c21, c22,a,b, mod)


#Collective Key Switching from CA's public key to Querier's Public Key 


#serverA
w1a, w2a = ECElgamal.keySwitch(c31, base_point, privateKeyA, publicKeyQ,a,b, mod)


#serverB
w1b, w2b = ECElgamal.keySwitch(c31, base_point, privateKeyB, publicKeyQ,a,b, mod)
w1 = ECElgamal.ECadd(w1a[0], w1a[1], w1b[0], w1b[1],a,b, mod)
w2 = ECElgamal.ECadd(w2a[0], w2a[1], w2b[0], w2b[1],a,b, mod)

#serverC
w1c, w2c = ECElgamal.keySwitch(c31, base_point,privateKeyC, publicKeyQ,a,b, mod)
w1 = ECElgamal.ECadd(w1c[0], w1c[1], w1[0], w1[1],a,b, mod)
w2 = ECElgamal.ECadd(w2[0], w2[1], w2c[0], w2c[1],a,b, mod)
#C2 + sig(w2)
w2 = ECElgamal.ECadd(c32[0], c32[1], w2[0], w2[1],a,b, mod)




print("\nDecryption")
print("---------------------------------------------------------------")


decrypted = ECElgamal.decryption(privateKeyQ , w1, w2, a, b, mod)

print("Decrypted coordinates: ",decrypted)


print("\n--------------------------------------------------------------\nBrute Forcing...")
ECElgamal.bruteforce(base_point, decrypted, order, a, b, mod)



