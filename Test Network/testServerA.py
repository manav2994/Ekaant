import time
#import hashlib
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5 as PKCS1_v1_5_Cipher
from Crypto.Signature import PKCS1_v1_5 as PKCS1_v1_5_Signature
from Crypto.Hash import SHA512
from Crypto.Cipher import AES
from Crypto.Protocol.KDF import PBKDF2
from Crypto import Random
from base64 import b64decode, b64encode

import argparse
import pymysql
import ECElgamal
import random
import sys
import time
sys.path.insert(0, '..') # Import the files where the modules are located

from p2pnetwork.node import Node



'''
Central Authority Server Connections
'''

node_1 = collectiveAuthority("127.0.0.1", 8001)
node_1.start()


time.sleep(6)
node_1.connect_with_node('127.0.0.1', 8002)
node_1.connect_with_node('127.0.0.1', 8003)
time.sleep(2)
#node_1.all_nodes()
node_1.send_to_nodes("Hello: Server Here")



'''
Collective Authority Public Key Generation and Exchange(K = Ka + Kb + Kc)
'''

#Private Key (ka) 
privateKeyA = random.getrandbits(128)

#Public Key (K = kG) | Ka
publicKeyA = ECElgamal.ECmultiply(ECElgamal.base_point[0], ECElgamal.base_point[1], privateKeyA)

#node_1.create_message({"_public_key": publicKeyA})
