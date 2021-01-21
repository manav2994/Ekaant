#!/usr/bin/python
# -*- coding: utf-8 -*-
# Author: Manav Mahajan


''' 
Child of Server A
Connected to DDB1
'''

import argparse
import pymysql
import socket
import sys
import time
sys.path.insert(0, '..') # Import the files where the modules are located

from Peer2PeerNode import collectiveAuthority

name = "node_2"
port = 8002
'''
Collective Authority Server Connections
'''
node_2 = collectiveAuthority("127.0.0.1", port)
node_2.start()
node_2.debug = True
(publicKey, privateKey) = node_2.create_key_file(port, name)
time.sleep(4)

'''
Collective Authority Public Key Generation(K = Ka + Kb + Kc)
'''
node_2.send_to_nodes({'Msg_Type': "KeyReply", 'Host':name, 'Host_Type':"CANode",'Public_Key': publicKey})


'''
Connection to DDB1
'''
time.sleep(4)
node_2.connect_with_node('127.0.0.1', 12001)
node_2.connect_with_node('127.0.0.1', 8003)

