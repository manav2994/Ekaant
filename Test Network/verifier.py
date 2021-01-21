#!/usr/bin/python
# -*- coding: utf-8 -*-
# Author: Manav Mahajan


''' 
Verification Node
'''


import re
from urllib.request import Request, urlopen
import requests
import os
import sys
import time


from Peer2PeerNode import verifier




name = "VN"
port = 14001



VN = verifier("127.0.0.1", port)
VN.start()



