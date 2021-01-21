#!/usr/bin/python
# -*- coding: utf-8 -*-
# Author: Manav Mahajan

''' 
This Script demonstrates Encryption and Decryption for Eliptic Curve ElGamal 
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



print("Public key generation")
print("--------------------------------------------------------------")

#Private Key (k)
privateKey = random.getrandbits(128)

#Public Key (K = kG)
publicKey = ECElgamal.ECmultiply(base_point[0], base_point[1], privateKey, a, b, mod)

print("\nPublic key: ", publicKey)

print("--------------------------------------------------------------")


M1 = input("Enter the Message to be encrypted > ")



plaintext1 = ECElgamal.textToInt(M1)

print("M1: ",M1,". it is numeric matching is ",plaintext1)




#Coordinate Map (M = Gm)
plain_coordinates1 = ECElgamal.ECmultiply(base_point[0], base_point[1], plaintext1, a, b, mod)
print("M1 is represented as the following point coordinates")
print("plain coordinates: ", plain_coordinates1)



print("Encryption")
print("--------------------------------------------------------------")


c11,c12 = ECElgamal.encryption(base_point, plain_coordinates1, publicKey, a, b, mod)
print("\nCiphertext")
print("c1: ", c11)
print("c2: ", c12)


print("\nDecryption")
print("---------------------------------------------------------------")


decrypted1 = ECElgamal.decryption(privateKey, c11, c12, a, b, mod)

print("Decrypted coordinates: ",decrypted1)

print("\n--------------------------------------------------------------\nBrute Forcing...")

new_point = ECElgamal.ECadd(base_point[0], base_point[1], base_point[0], base_point[1], a, b, mod) #2P

#brute force method
for i in range(3, order):
	new_point = ECElgamal.ECadd(new_point[0], new_point[1], base_point[0], base_point[1], a, b, mod)
	if new_point[0] == decrypted1[0] and new_point[1] == decrypted1[1]:
		
		print("Decrypted Message as numeric: ",i)
		print("decrypted Message: ",ECElgamal.intToText(i))
		
		break

