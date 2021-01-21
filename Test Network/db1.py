#!/usr/bin/python
# -*- coding: utf-8 -*-
# Author: Manav Mahajan


''' 
Distributed Database Server Connected to CA
'''


#import pymysql
import re
from urllib.request import Request, urlopen
import requests
import os
import sys
import time


from Peer2PeerNode import distributedDatabase


name = "DDB_1"
port = 12001


'''
Collective Authority Server Connections
'''

DDB_1 = distributedDatabase("127.0.0.1", port)
DDB_1.start()

#node_3.connect_with_node('127.0.0.1', 8001)
'''
Database Connection

connection = pymysql.connect(host='127.0.0.1', user='root', port=3306, password='', db='forensics', cursorclass=pymysql.cursors.DictCursor)
cursor = connection.cursor()
n = cursor.execute("SELECT * from papers") #Change to Query
c = cursor.fetchall()
'''
