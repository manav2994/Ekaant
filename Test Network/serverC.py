#!/usr/bin/python
# -*- coding: utf-8 -*-
# Author: Manav Mahajan

''' 
Child Server of A
Connected to DDB2
'''
import argparse
import pymysql
import ECElgamal
import random
import sys
import time
sys.path.insert(0, '..') # Import the files where the modules are located

from Peer2PeerNode import collectiveAuthority

name = "node_3"
port = 8003


'''
Collective Authority Server Connections
'''

node_3 = collectiveAuthority("127.0.0.1", port)
node_3.start()
#node_3.connect_with_node('127.0.0.1', 8001)

(publicKey, privateKey) = node_3.create_key_file(port, name)
#node_3.connect_with_node('127.0.0.1', 8001)
time.sleep(6)

'''
Collective Authority Public Key Generation(K = Ka + Kb + Kc)
'''

node_3.send_to_nodes({'Msg_Type': "KeyReply", 'Host':name, 'Host_Type':"CANode",'Public_Key': publicKey})





'''
Connection to DDB2
'''
time.sleep(4)
node_3.connect_with_node('127.0.0.1', 12002)




#node_3.send_to_nodes({'Type': "KeyInit", 'Key':publicKeyC, 'Host':"CAroot"})