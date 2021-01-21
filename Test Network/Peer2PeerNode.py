#!/usr/bin/python
# -*- coding: utf-8 -*-
# Author: Manav Mahajan

''' 
This library consists functions for creating Peer-to-Peer Nodes
'''
import time
import csv
import ECElgamal
import random
import re
from p2pnetwork.node import Node

class collectiveAuthorityRoot (Node):

	# Python class constructor
	#import hashlib
	#hash_object = hashlib.md5((str(host)+str(port)).encode)
	#id = hash_object.hexdigest()
	def __init__(self, host, port):
		super(collectiveAuthorityRoot, self).__init__(host, port, None)
		print("CA Root Server: Started")

	# all the methods below are called when things happen in the network.
	def outbound_node_connected(self, node):
		print("outbound_node_connected: " + node.id)
		
	def inbound_node_connected(self, node):
		print("inbound_node_connected: " + node.id)

	def inbound_node_disconnected(self, node):
		print("inbound_node_disconnected: " + node.id)

	def outbound_node_disconnected(self, node):
		print("outbound_node_disconnected: " + node.id)


	#Private Key (k)
	def generate_private_key(self): 
		privateKey = random.getrandbits(128)
		return(privateKey)

	
	#Public Key (K = kG) 
	def generate_public_key(self, privateKey): 
		publicKey = ECElgamal.ECmultiply(ECElgamal.base_point[0], ECElgamal.base_point[1], privateKey)
		return(publicKey)

	#Returns (public, private) KeyPair and updates the initiates the keyfile    
	def create_key_file(self, name):
		with open("key_fileR", 'w', newline='') as f:
			writer = csv.writer(f)
			writer.writerow(["Msg_Type","Host", "Host_Type", "Public_Key","Private_Key"])
			privateKey = self.generate_private_key()
			publicKey = self.generate_public_key(privateKey)
			writer.writerow(["KeyPair", name, "CARoot", publicKey, privateKey])
			return(publicKey, privateKey)

	def send_to_outbound_nodes(self, data, exclude=[]):
		""" Send a message to all the nodes that are connected with this node. data is a python variable which is
			converted to JSON that is send over to the other node. exclude list gives all the nodes to which this
			data should not be sent."""
		self.message_count_send = self.message_count_send + 1
		
		for n in self.nodes_outbound:
			if n in exclude:
				self.debug_print("Node send_to_nodes: Excluding node in sending the message")
			else:
				self.send_to_node(n, data)

	#Message Handling Protocol
	def node_message(self, node, data):
		#print("node_message from " + node.id + ": " + str(data))
		#Collective Key Generation
		#Message Format: self.send_to_nodes({'Msg_Type': "CAKey", 'Host':"node_1", 'Host_Type':"CARoot",'Public_Key': str(caPublicKey)})
		if(data['Msg_Type'] == "KeyReply"):
			print("Updating Key_File!")
			with open("key_fileR", 'a', newline='') as f:
				if(data['Host_Type'] == "CANode"):
					writer = csv.writer(f)
					writer.writerow(["KeyPair", str(data['Host']), "CANode", str(data["Public_Key"]), "Private_Key"])
					print("Received CANode Key")
					if(data['Host'] =="node_3"):
						print("---Initialising Collective Key Aggregation---")
						csv_file = csv.reader(open('key_fileR', "r"), delimiter=",")
						for row in csv_file:
							if row[2]=="CARoot":
								x1= re.split(r',() ', row[3])
								PublicKeyA= [x1[0][1:], x1[2][:-1]]
								#print("CARoot success", PublicKeyA)
							if row[2]=="CANode":
								x1= re.split(r',() ', row[3])
								publicKeyB=[x1[0][1:], x1[2][:-1]]
								#print("CANode success", publicKeyB[1])
								break
						x1= re.split(r',() ',str(data["Public_Key"]))
						publicKeyC= [x1[0][1:], x1[2][:-1]]
						caPublicKey1 = ECElgamal.ECadd(int(PublicKeyA[0]), int(PublicKeyA[1]), int(publicKeyB[0]),int(publicKeyB[1]))
						caPublicKey = ECElgamal.ECadd(int(caPublicKey1[0]),int(caPublicKey1[1]), int(publicKeyC[0]),int(publicKeyC[1]))
						self.send_to_nodes({'Msg_Type': "CAKey", 'Host':"node_1", 'Host_Type':"CARoot",'Public_Key': str(caPublicKey)})
						writer.writerow(["CAKey", "CA", "CA", str(caPublicKey), "Private_Key"])
						print("------------------Collective Key Generated--------------------:", caPublicKey)
		#Query Handling
		#Message Format: self.send_to_outbound_nodes({'Msg_Type': "Query", 'Host':"node_1", 'Host_Type':"CARoot",'Query':str(data['Query']),'Public_Key': str(caPublicKey)})
		if(data['Msg_Type'] == "Query"):
			print("Querier Connected and Query Received")
			with open("key_fileR", 'a', newline='') as f:
				writer = csv.writer(f)
				writer.writerow(["KeyPair", str(data['Host']), "Q", str(data['Public_Key']), "Private_Key"])
			self.send_to_outbound_nodes({'Msg_Type': "Query", 'Host':"node_1", 'Host_Type':"CARoot",'Query':str(data['Query']),'Public_Key': str(data['Public_Key'])})
		#----Collective Aggregation --------
		#Message Format: {'Msg_Type': 'Query_Reply', 'Host': '88', 'Host_Type': 'DDB', 'Ciphertext1': '(1105, 73920)', 'Ciphertext2': '(27022, 19947)'}
		if(data['Msg_Type'] == "Query_Reply"):
			if(data['Host_Type'] == "CANode"):
				print("Query Results from CA Node")
				with open("data_file", 'a', newline='') as fn:
					writer = csv.writer(fn)
					writer.writerow(["DataAggregation", str(data['Host']), "CANode", str(data['Ciphertext1']), str(data['Ciphertext2'])])
					fn.close()
					csv_file = csv.reader(open('data_file', "r"), delimiter=",")
					data2=list(csv_file)
					row_count = len(data2)
					#change to number of total CA nodes -1
					if row_count==2:
						count=0
						#print("---COUNTT-----",count)
						csv_file = csv.reader(open('data_file', "r"), delimiter=",")
						for row in csv_file:
							if (count==1):
								x=re.split(r',() ', row[3])
								c21=[int(x[0][1:]), int(x[2][:-1])]
								x=re.split(r',() ', row[4])
								c22=[int(x[0][1:]), int(x[2][:-1])]
								c31,c32 = ECElgamal.addHE(c11, c12,c21, c22)

							else:
								x=re.split(r',() ', row[3])
								c11=[int(x[0][1:]), int(x[2][:-1])]
								x=re.split(r',() ', row[4])
								c12=[int(x[0][1:]), int(x[2][:-1])]
								count = count + 1
								#print("---COUNTT",count)
						print("----------Aggregated Results Generated-------------")
						print("----------Key_Switching PRotocol Initialising------")
						kfile = csv.reader(open('key_fileR', "r"), delimiter=",")
						for row in kfile:
							if(row[2]=="Q"):
								x=re.split(r',() ', row[3])
								qkey=[int(x[0][1:]), int(x[2][:-1])]
							if(row[2]=="CARoot"):
								prvK=int(row[4])
						w1a, w2a = ECElgamal.keySwitch(c31, ECElgamal.base_point, prvK, qkey)
						self.send_to_outbound_nodes({'Msg_Type': 'Key_Switch', 'Host': str(node.id), 'Host_Type': 'CARoot', 'Agr_C1': str(c31), 'Agr_C2': str(c32), 'KS_1': str(w1a), 'KS_2': str(w2a), 'Q_Public_Key':str(qkey)})
		#Key Switching Protocol
		if(data['Msg_Type'] == "Key_Switched"):
			print("Returning Results to Q")
			self.send_to_nodes({'Msg_Type': 'Query_Reply_to_Q', 'Host': str(node.id), 'Host_Type': 'CARoot','KS_1': data['KS_1'], 'KS_2': data['KS_2']})

					
	
	def node_disconnect_with_outbound_node(self, node):
		print("node wants to disconnect with oher outbound node: " + node.id)
		
	def node_request_to_stop(self):
		print("node is requested to stop!")



##############################################################################

class collectiveAuthority (Node):
	# Python class constructor
	def __init__(self, host, port):
		super(collectiveAuthority, self).__init__(host, port, None)
		print("CA Server: Started")
	# all the methods below are called when things happen in the network.
	def send_to_outbound_nodes(self, data, exclude=[]):
		""" Send a message to all the nodes that are connected with this node. data is a python variable which is
			converted to JSON that is send over to the other node. exclude list gives all the nodes to which this
			data should not be sent."""
		self.message_count_send = self.message_count_send + 1
		
		for n in self.nodes_outbound:
			if n in exclude:
				self.debug_print("Node send_to_nodes: Excluding node in sending the message")
			else:
				self.send_to_node(n, data)
	def outbound_node_connected(self, node):
		print("outbound_node_connected: " + node.id)
		
	def inbound_node_connected(self, node):
		print("inbound_node_connected: " + node.id)

	def inbound_node_disconnected(self, node):
		print("inbound_node_disconnected: " + node.id)

	def outbound_node_disconnected(self, node):
		print("outbound_node_disconnected: " + node.id)

	#Private Key (k)
	def generate_private_key(self): 
		privateKey = random.getrandbits(128)
		return(privateKey)

	
	#Public Key (K = kG) 
	def generate_public_key(self, privateKey): 
		publicKey = ECElgamal.ECmultiply(ECElgamal.base_point[0], ECElgamal.base_point[1], privateKey)
		return(publicKey)

	#Returns (public, private) KeyPair  
	def create_key_file(self,port, name):
		with open(str(port)+"_key_file", 'w', newline='') as f:
			writer = csv.writer(f)
			writer.writerow(["Msg_Type","Host", "Host_Type", "Public_Key","Private_Key"])
			privateKey = self.generate_private_key()
			publicKey = self.generate_public_key(privateKey)
			writer.writerow(["KeyPair", name, "CANode", publicKey, privateKey])
			return(publicKey, privateKey)
	
	#Message Handling Protocol
	def node_message(self, node, data):
		#print("node_message from " + node.id + ": " + str(data))
		#-----------Collective Key Aggregation----------
		if(data['Msg_Type'] == "KeyInit"):
			csv_file = csv.reader(open(str(self.port) +'_key_file', "r"), delimiter=",")
			for row in csv_file:
				if row[2]=="CANode":
					publicKey=row[3]
					break
				print("Received Root Key")
				print("Updating Key_File!")
			with open(str(self.port) +"_key_file", 'a', newline='') as f:
				if(data['Host_Type'] == "CARoot"):
					writer = csv.writer(f)
					writer.writerow(["KeyPair", str(data['Host']), "CARoot", str(data["Public_Key"]), "Private_Key"])
					#time.sleep(4)
					#self.connect_with_node('127.0.0.1', 8001)
					#self.send_to_nodes(self, {'Msg_Type': "KeyReply", 'Host':node, 'Host_Type':"CANode",'Public_Key': publicKey})
					#print("SEnt")              
		if(data['Msg_Type'] == "CAKey"):
			print("-----------------Received CA Key!------------------------")
			with open(str(self.port) +"_key_file", 'a', newline='') as f:
				writer = csv.writer(f)
				writer.writerow(["CAKey", "CA", "CA", str(data["Public_Key"]), "Private_Key"])
			print("Updated Key_File!")
		#------------------Query Handling----------------------
		if(data['Msg_Type'] == "Query"):
			if(data['Host_Type']=="CARoot"):
				print("Query Received")
				with open(str(self.port) +'_key_file', 'a', newline='') as f:
					writer = csv.writer(f)
					writer.writerow(["KeyPair", "Querier", "Q", str(data['Public_Key']), "Private_Key"])
				csv_file = csv.reader(open(str(self.port) +'_key_file', "r"), delimiter=",")
				for row in csv_file:
					if row[0]=="CAKey":
						caPublicKey=row[3]
						break    
				self.send_to_outbound_nodes({'Msg_Type': "Query", 'Host':str(data['Host']), 'Host_Type':"CANode",'Query':str(data['Query']),'Public_Key': str(caPublicKey)})
		#----Collective Aggregation --------
		#Message Format: {'Msg_Type': 'Query_Reply', 'Host': '88', 'Host_Type': 'DDB', 'Ciphertext1': '(1105, 73920)', 'Ciphertext2': '(27022, 19947)'}
		if(data['Msg_Type'] == "Query_Reply"):
			if(data['Host_Type']=="DDB"):
				print("Query Results from DDB")
				time.sleep(random.randint(0,5))
				self.send_to_nodes({'Msg_Type': 'Query_Reply', 'Host':str(node.id), 'Host_Type': "CANode", 'Ciphertext1': str(data['Ciphertext1']), 'Ciphertext2': str(data['Ciphertext2'])}, exclude=[data['Host']])
		#----Key Switch -----
		#self.send_to_outbound_nodes({'Msg_Type': 'Key_switch', 'Host': str(node.id), 'Host_Type': 'CARoot', 'Agr_C1': str(c31), 'Agr_C1': str(c32), 'KS_1': str(w1a), 'KS_2': str(w2a), 'Q_Public_Key':str(qkey)})
		if(data['Msg_Type'] == "Key_Switch"):
			if(data['Host_Type']=="CARoot"):
				print("Key Switching Message from CA Root")
				csv_file = csv.reader(open(str(self.port) +'_key_file', "r"), delimiter=",")
				for row in csv_file:
					if(row[4]!="Private_Key"):
						prvK=int(row[4])
				x=re.split(r',() ',data['Q_Public_Key'])
				qkey=[int(x[0][1:]), int(x[2][:-1])]

				x=re.split(r',() ',data['Agr_C1'])
				c31=[int(x[0][1:]), int(x[2][:-1])]		

				x=re.split(r',() ',data['KS_1'])
				w1a=[int(x[0][1:]), int(x[2][:-1])]

				x=re.split(r',() ',data['KS_2'])
				w2a=[int(x[0][1:]), int(x[2][:-1])]

				w1b, w2b = ECElgamal.keySwitch(c31, ECElgamal.base_point, prvK, qkey)
				w1 = ECElgamal.ECadd(w1a[0], w1a[1], w1b[0], w1b[1])
				w2 = ECElgamal.ECadd(w2a[0], w2a[1], w2b[0], w2b[1])
				self.send_to_outbound_nodes({'Msg_Type': 'Key_Switch', 'Host': str(node.id), 'Host_Type': 'CANode', 'Agr_C1': str(c31), 'Agr_C2': data['Agr_C2'], 'KS_1': str(w1), 'KS_2': str(w2), 'Q_Public_Key':str(qkey)})
			if(data['Host_Type']=="CANode"):
				print("Key Switching Message from CA Node")
				csv_file = csv.reader(open(str(self.port) +'_key_file', "r"), delimiter=",")
				for row in csv_file:
					if(row[4]!="Private_Key"):
						prvK=int(row[4])
				x=re.split(r',() ',data['Q_Public_Key'])
				qkey=[int(x[0][1:]), int(x[2][:-1])]

				x=re.split(r',() ',data['Agr_C1'])
				c31=[int(x[0][1:]), int(x[2][:-1])]		

				x=re.split(r',() ',data['Agr_C2'])
				c32=[int(x[0][1:]), int(x[2][:-1])]

				x=re.split(r',() ',data['KS_1'])
				w1=[int(x[0][1:]), int(x[2][:-1])]

				x=re.split(r',() ',data['KS_2'])
				w2=[int(x[0][1:]), int(x[2][:-1])]

				w1c, w2c = ECElgamal.keySwitch(c31, ECElgamal.base_point, prvK, qkey)
				w1 = ECElgamal.ECadd(w1c[0], w1c[1], w1[0], w1[1])
				w2 = ECElgamal.ECadd(w2[0], w2[1], w2c[0], w2c[1])
				#C2 + sig(w2)
				w2 = ECElgamal.ECadd(c32[0], c32[1], w2[0], w2[1])
				print("--------Key Switched-----------")
				self.send_to_nodes({'Msg_Type': 'Key_Switched', 'Host': str(node.id), 'Host_Type': 'CANode','KS_1': str(w1), 'KS_2': str(w2)})

	




	def node_disconnect_with_outbound_node(self, node):
		print("node wants to disconnect with oher outbound node: " + node.id)
		
	def node_request_to_stop(self):
		print("node is requested to stop!")



###############################################################################################3


class querier (Node):

	# Python class constructor
	def __init__(self, host, port):
		super(querier, self).__init__(host, port, None)
		print("Querier: Started")

	# all the methods below are called when things happen in the network.
	def outbound_node_connected(self, node):
		print("outbound_node_connected: " + node.id)
		
	def inbound_node_connected(self, node):
		print("inbound_node_connected: " + node.id)

	def inbound_node_disconnected(self, node):
		print("inbound_node_disconnected: " + node.id)

	def outbound_node_disconnected(self, node):
		print("outbound_node_disconnected: " + node.id)

	#Private Key (k)
	def generate_private_key(self): 
		privateKey = random.getrandbits(128)
		return(privateKey)

	
	#Public Key (K = kG) 
	def generate_public_key(self, privateKey): 
		publicKey = ECElgamal.ECmultiply(ECElgamal.base_point[0], ECElgamal.base_point[1], privateKey)
		return(publicKey)

	#Returns (public, private) KeyPair  
	def create_key_file(self,port, name):
		with open(str(port)+"_key_file", 'w', newline='') as f:
			writer = csv.writer(f)
			writer.writerow(["Msg_Type","Host", "Host_Type", "Public_Key","Private_Key"])
			privateKey = self.generate_private_key()
			publicKey = self.generate_public_key(privateKey)
			writer.writerow(["KeyPair", name, "Querier", publicKey, privateKey])
			return(publicKey, privateKey)
	

	#Message Handling Protocol
	def node_message(self, node, data):
		print("node_message from " + node.id + ": " + str(data))
		#-----------Query Results----------
		if(data['Msg_Type'] == "Query_Reply_to_Q"):
			print("Received Results")
			csv_file = csv.reader(open(str(self.port) +'_key_file', "r"), delimiter=",")
			for row in csv_file:
				if(row[4]!="Private_Key"):
					prvK=int(row[4])
			x=re.split(r',() ',data['KS_1'])
			w1=[int(x[0][1:]), int(x[2][:-1])]

			x=re.split(r',() ',data['KS_2'])
			w2=[int(x[0][1:]), int(x[2][:-1])]
			#self.send_to_nodes({'Msg_Type': 'Query_Reply_to_Q', 'Host': str(node.id), 'Host_Type': 'CARoot','KS_1': data['KS_1'], 'KS_2': data['KS_2']})
			decrypted = ECElgamal.decryption(prvK , w1, w2)
			print("Decrypted Coordinates:", decrypted)
			print("Brute Forcing..................")
			ECElgamal.bruteforce(decrypted, ECElgamal.order)


				
	def node_disconnect_with_outbound_node(self, node):
		print("node wants to disconnect with oher outbound node: " + node.id)
		
	def node_request_to_stop(self):
		print("node is requested to stop!")

###############################################################################################3


class distributedDatabase (Node):

	# Python class constructor
	def __init__(self, host, port):
		super(distributedDatabase, self).__init__(host, port, None)
		print("Distributed Database: Started")

	# all the methods below are called when things happen in the network.
	def send_to_outbound_nodes(self, data, exclude=[]):
		""" Send a message to all the nodes that are connected with this node. data is a python variable which is
			converted to JSON that is send over to the other node. exclude list gives all the nodes to which this
			data should not be sent."""
		self.message_count_send = self.message_count_send + 1
		
		for n in self.nodes_outbound:
			if n in exclude:
				self.debug_print("Node send_to_nodes: Excluding node in sending the message")
			else:
				self.send_to_node(n, data)
				
	def outbound_node_connected(self, node):
		print("outbound_node_connected: " + node.id)
		
	def inbound_node_connected(self, node):
		print("inbound_node_connected: " + node.id)

	def inbound_node_disconnected(self, node):
		print("inbound_node_disconnected: " + node.id)

	def outbound_node_disconnected(self, node):
		print("outbound_node_disconnected: " + node.id)

	#Message Handling Protocol
	def node_message(self, node, data):
		#print("node_message from " + node.id + ": " + str(data))
		#-----------Query Handling----------
		if(data['Msg_Type'] == "Query"):
			print("---------------Query Received-------------")
			caPublicKey=data["Public_Key"]
			query=data["Query"]
			result = random.getrandbits(12)
			print("RESULT to be Encrypted", result)
			enc_result1, enc_result2 = self.encryption(result, caPublicKey)
			self.send_to_nodes({'Msg_Type': "Query_Reply", 'Host':str(node.id), 'Host_Type':"DDB",'Ciphertext1':str(enc_result1),'Ciphertext2':str(enc_result2)})



	def encryption(self, result, caPublicKey):
		#Map results to Cuve(M = Gm)
		#plain_coordinates = ECElgamal.ECmultiply(ECElgamal.base_point[0], ECElgamal.base_point[1], result)
		#print("Coordiantes", plain_coordinates)
		#Encryption of M1 and M2 using Collective Authority's Public Key
		x1= re.split(r',() ', caPublicKey)
		caPublicKey=[int(x1[0][1:]), int(x1[2][:-1])]		
		enc_result1, enc_result2 = ECElgamal.encryption(result, caPublicKey)
		return(enc_result1, enc_result2)
		

		
	def node_disconnect_with_outbound_node(self, node):
		print("node wants to disconnect with oher outbound node: " + node.id)
		
	def node_request_to_stop(self):
		print("node is requested to stop!")