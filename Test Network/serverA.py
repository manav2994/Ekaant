#!/usr/bin/python
# -*- coding: utf-8 -*-
# Author: Manav Mahajan


'''' 
The parent server of B and C
Connected to Querier
'''

import argparse
import pymysql
import ECElgamal
import random
import sys
import time
sys.path.insert(0, '..') # Import the files where the modules are located

from Peer2PeerNode import collectiveAuthorityRoot

name = "node_1"
port = 8001
#For testing
open('data_file', 'w').close()		

'''
Central Authority Server Connections
'''

node_1 = collectiveAuthorityRoot("127.0.0.1", port)
node_1.start()
node_1.debug = True

time.sleep(4)
node_1.connect_with_node('127.0.0.1', 8002)
node_1.connect_with_node('127.0.0.1', 8003)
#node_1.all_nodes()




'''
Collective Authority Public Key Generation and Exchange(K = Ka + Kb + Kc)
'''
#Messgae Format (["Msg_Type","Host", "Host_Type", "Public_Key","Private_Key"])
(publicKey, privateKey) = node_1.create_key_file(name)

#node_1.create_message({"_public_key": publicKeyA})
node_1.send_to_nodes({'Msg_Type': "KeyInit", 'Host':name, 'Host_Type':"CARoot", "Public_Key":publicKey})





'''
Query Relaying
'''



'''
Query Result Aggregation
'''



'''
Key Switching a
'''


#print('end test')

