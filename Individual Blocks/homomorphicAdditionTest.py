#!/usr/bin/python
# -*- coding: utf-8 -*-
# Author: Manav Mahajan

''' 
This Script demonstrates Homomorphic Additive Property fot Eliptic Curve ElGamal Encryption
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



print("public key generation")
print("--------------------------------------------------------------")

#Private Key (k)
privateKey = random.getrandbits(128)

#Public Key (K = kG)
publicKey = ECElgamal.ECmultiply(base_point[0], base_point[1], privateKey, a, b, mod)

print("\nPublic key: ", publicKey)



M1 = input("Enter the 1st Message to be encrypted > ")
M2 = input("Enter the 2nd Message to be encrypted > ")
print("--------------------------------------------------------------")

# To Do Encoding

#plaintext1 = ECElgamal.textToInt(M1)
plaintext1 = int(M1)

#print("M1: ",M1,". it is numeric matching is ",plaintext1)


#plaintext2 = ECElgamal.textToInt(M2)
plaintext2 = int(M2)

#print("M2: ",M2,". it is numeric matching is ",plaintext2)



#Coordinate Map (M = Gm)
plain_coordinates1 = ECElgamal.ECmultiply(base_point[0], base_point[1], plaintext1, a, b, mod)
print("M1 is represented as the following point coordinates")
print("plain coordinates: ", plain_coordinates1)

plain_coordinates2 = ECElgamal.ECmultiply(base_point[0], base_point[1], plaintext2, a, b, mod)
print("M1 is represented as the following point coordinates")
print("plain coordinates: ", plain_coordinates2)

print("Encryption")
print("--------------------------------------------------------------")


c11,c12 = ECElgamal.encryption(base_point, plain_coordinates1, publicKey, a, b, mod)
c21,c22 = ECElgamal.encryption(base_point, plain_coordinates2, publicKey, a, b, mod)


print("Homomorphic Encryption")
print("--------------------------------------------------------------")

c31,c32 = ECElgamal.addHE(c11, c12,c21, c22,a,b, mod)


print("Decryption")
print("--------------------------------------------------------------")

decrypted = ECElgamal.decryption(privateKey, c31, c32, a, b, mod)


print("Decrypted coordinates for (M1 + M2): ",decrypted)


print("-------------------------------------------------------------- \n Brute Forcing...")

#brute force method for remapping the coordinates back to the graph

ECElgamal.bruteforce(base_point, decrypted, order, a, b, mod)


