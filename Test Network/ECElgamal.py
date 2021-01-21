#!/usr/bin/python
# -*- coding: utf-8 -*-
# Author: Manav Mahajan

''' 
This library consists of Functions Required for EC ElGamal Encryption
'''
import random
import itertools
import codecs
import zksk
from zksk.primitives import rangeproof

'''
Global Variables
'''
dump = False
mod = pow(2, 256) - pow(2, 32) - pow(2, 9) - pow(2, 8) - pow(2, 7) - pow(2, 6) - pow(2, 4) - pow(2, 0)
order = 115792089237316195423570985008687907852837564279074904382605163141518161494337

#curve configuration
# y^2 = x^3 + a*x + b = y^2 = x^3 + 7
a = 0
b = 7

#base point on the curve  - G
base_point = [55066263022277343669578718895168534326250603453777594175500187360389116729240, 32670510020758816978083085130507043184471273380659243275938904335757337482424]

'''
Encoding
'''

def textToInt(text):
	encoded_text = text.encode('utf-8')
	hex_text = encoded_text.hex()
	int_text = int(hex_text, 16)
	return int_text

def intToText(int_text):
	import codecs
	hex_text = hex(int_text)
	hex_text = hex_text[2:] #remove 0x
	return codecs.decode(codecs.decode(hex_text,'hex'),'ascii')


'''
Extended Euclidean Algorithm/'division' in elliptic curves
'''

def modinv(a,mod): 

	while(a < 0):
		a = a + mod
	
	#a = a % mod
	
	x1 = 1; x2 = 0; x3 = mod
	y1 = 0; y2 = 1; y3 = a
	
	q = int(x3 / y3)
	t1 = x1 - q*y1
	t2 = x2 - q*y2
	t3 = x3 - (q*y3)
	
	if dump == True:
		print("q\tx1\tx2\tx3\ty1\ty2\ty3\tt1\tt2\tt3")
		print("----------------------------------------------------------------------------")
		print(q,"\t",x1,"\t",x2,"\t",x3,"\t",y1,"\t",y2,"\t",y3,"\t",t1,"\t",t2,"\t",t3)
	
	while(y3 != 1):
		x1 = y1; x2 = y2; x3 = y3
		
		y1 = t1; y2 = t2; y3 = t3
		
		q = int(x3 / y3)
		t1 = x1 - q*y1
		t2 = x2 - q*y2
		t3 = x3 - (q*y3)
		
		if dump == True:
			print(q,"\t",x1,"\t",x2,"\t",x3,"\t",y1,"\t",y2,"\t",y3,"\t",t1,"\t",t2,"\t",t3)
			print("----------------------------------------------------------------------------")
			print("")
	
	while(y2 < 0):
		y2 = y2 + mod
	
	return y2

def ECadd(x1, y1, x2, y2):  

	if x1 == x2 and y1 == y2:
		#doubling
		beta = (3*x1*x1 + a) * (modinv(2*y1, mod))
	
	else:
		#point addition
		beta = (y2 - y1)*(modinv((x2 - x1), mod))
	
	x3 = beta*beta - x1 - x2
	y3 = beta*(x1 - x3) - y1
	
	x3 = x3 % mod
	y3 = y3 % mod
	
	while(x3 < 0):
		x3 = x3 + mod
	
	while(y3 < 0):
		y3 = y3 + mod
	
	return x3, y3


#Double & add. Not true multiplication
def ECmultiply(x0, y0, k): 
	
	x_temp = x0
	y_temp = y0
	
	kAsBinary = bin(k) #0b1111111001
	kAsBinary = kAsBinary[2:len(kAsBinary)] #1111111001
	#print(kAsBinary)
	
	for i in range(1, len(kAsBinary)):
		currentBit = kAsBinary[i: i+1]
		#always apply doubling
		x_temp, y_temp = ECadd(x_temp, y_temp, x_temp, y_temp)
		
		if currentBit == '1':
			#add base point
			x_temp, y_temp = ECadd(x_temp, y_temp, x0, y0)
	
	return x_temp, y_temp

'''
Elgamal Encryption and Decryption
'''

# C1 = rB
# C2 = x + rK

def encryption(message, publicKey):
	plain_coordinates = ECmultiply(base_point[0], base_point[1], message)
	randomKey = random.getrandbits(128)
	c1 = ECmultiply(base_point[0], base_point[1], randomKey)
	c2 = ECmultiply(publicKey[0], publicKey[1], randomKey)
	c2 = ECadd(c2[0], c2[1], plain_coordinates[0], plain_coordinates[1])
	m = zksk.Secret(value=message)
	r= zksk.Secret(value=randomKey)
	#enc_stmt = zksk.primitives.dlrep.DLRep(c1, ECmultiply(base_point[0], base_point[1], randomKey)) & zksk.primitives.dlrep.DLRep(c2,c2)
	range_stmt = rangeproof.RangeStmt(c2, (base_point[0], base_point[1]), (publicKey[0],publicKey[1]), 0, 2000, m, r)
	#stmt = enc_stmt & range_stmt
	return(c1, c2,range_stmt)



def decryption(privateKey, c1, c2):

	#private key times c1
	dx, dy = ECmultiply(c1[0], c1[1], privateKey)
	#-private key times c1
	dy = dy * -1 #curve is symmetric about x-axis. in this way, inverse point found

	#c2 + private key * (-c1)
	decrypted = ECadd(c2[0], c2[1], dx, dy)
	return decrypted



#Adding Cipher Texts
def addHE(c11, c12,c21, c22):

	c31 = ECadd(c11[0], c11[1], c21[0], c21[1])
	c32 = ECadd(c12[0],c12[1], c22[0], c22[1])
	return c31, c32

def bruteforce(decrypted, order):

	new_point = ECadd(base_point[0], base_point[1], base_point[0], base_point[1]) #2P

	for i in range(3, order):
		new_point = ECadd(new_point[0], new_point[1], base_point[0], base_point[1])
		if new_point[0] == decrypted[0] and new_point[1] == decrypted[1]:
			
			print("Decrypted as numeric: ",i)
			#print("decrypted M1: ",ECElgamal.intToText(i))
			break

'''
Key Switching

C1,i = C1,i-1 + viB
C2,i = C2,i-1 -rKi + viU

vi = random nonce and U is querier's public key

'''
def keySwitch( c12, base_point,privateKey, querierKey):

	randomNonce = random.getrandbits(128)
	w1 = ECmultiply(base_point[0], base_point[1], randomNonce)

	dx, dy = ECmultiply(c12[0], c12[1], privateKey)
	dy = dy * -1 
	w21 = ECmultiply(querierKey[0],querierKey[1], randomNonce)
	w2 = ECadd(w21[0], w21[1], dx, dy)

	return w1, w2

	'''
	c1 = ECmultiply(base_point[0], base_point[1], randomNonce) 
	c1 = ECadd(c1[0], c1[1], c11[0], c11[1])


	c2z = 

	dx, dy = ECmultiply(privateKey[0], privateKey[1], randomKey)
	dy = dy * -1
	c2x = ECmultiply(querierKey[0], querierKey[1], randomNonce)

	c2y = ECadd(c2x[0], c2x[1], dx, dy)
	c2 = ECadd(c2y[0], c2y[1], c12[0], c12[1])
	'''

	return(c1, c2)