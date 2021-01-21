#!/usr/bin/python
# -*- coding: utf-8 -*-
# Author: Manav Mahajan

import argparse
import pymysql
import ECElgamal
import random

import sys
import time
sys.path.insert(0, '..') # Import the files where the modules are located

from Peer2PeerNode import querier

name = "querier_1"
port=10001


querier_1 = querier("127.0.0.1", port)
querier_1.start()
querier_1.debug = False


'''
Key Generation
'''

(publicKey, privateKey) = querier_1.create_key_file(port,name)
query="Test"


'''
Connection to the server
'''
querier_1.connect_with_node("127.0.0.1", 8001)

querier_1.send_to_nodes({'Msg_Type': "Query", 'Host':"Querier_1", 'Host_Type':"Q",'Query':str(query),'Public_Key': str(publicKey)})

#querier_1.connect_with_node("127.0.0.1", 12001)
#querier_1.send_to_outbound_nodes({'Msg_Type': 'Query', 'Host': 'node_1', 'Host_Type': 'CARoot', 'Query': 'Test', 'Public_Key': '(9268537443324568385696052232903287470166447790761467308537597983513492363237, 44575888762392688525882466338491888837450255239823756450185164273806404006300)'},exclude=['fc057f4bfb99019074452358e71ae55ec11770c1e78d5de20fc9238a5da961481adb5631337f251d3b80b931ad2e0da1406ee4c5b80569e6bb8093f3ac8e5ee9'])


#print(data)
