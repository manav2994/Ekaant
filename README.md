# Ekaant: Privacy Preserving Decentralised Data Sharing Framework

Ekaant is designed using Python and is modular in nature. Ekaant uses Privacy Enhancing Technologies (PET), with a native library for Additively Homomorphic EC ElGamal Encryption, Zero Knowledge Proofs (ZKP) and it is built upon a Peer-to-Peer Decentralised Architecture.

# Features 
 EKaant:
 - provides a library for homomorphicly Additive Elliptic Curve Elgamal Cryptosystem.
 - provides a verification system to authenticate the encrypted results using Zero Knowledge Range Proofs.
 - implements multiple decentralised protocols to ensure data sharing in a privacy preserving manner

Given the Modular nature of Ekaant, you can also:
  - Modify the tests to add additional Privacy Enhancing Tech to the top of the architecture.
  


### Tech

Ekaant uses a couple of open source projects:


* [Zero-Knowledge Swiss Knife:](https://github.com/spring-epfl/zksk) - A Python library for prototyping composable zero-knowledge proofs in the discrete-log setting.

* [p2p-network](https://github.com/macsnoeren/python-p2p-network) - Python implementation of a peer-to-peer decentralized network.


## 1. Individual Building Blocks

Contains Individual Blocks for Learning. Do not replace with the ECElgamal Library in the Lib folder. 
Read the code for more details.

## 2. Libraries
* [ECElgamal.py:] contains all the functions required to perform EC Elgamal Encryption, Collective Key Aggregation, Collective Aggregation, Key Switching and Verification.
* [Peer2Peer.py] contains different classes for Collective Authority Nodes, Querier, Verifier and Distributed Database. This also consists of the message Handling Protocol with Messages for (Key Initialisation, Query Handlind, and Key Switching)

## 2. Test Network for Ekaant

Contains the Test Network for Proof-of-Concept. 
Run all the nodes in the order below to verify the working.
DB1->DB2->Verifer->ServerA->SevrerB->ServerC->wait for key gen ->Querier










License
----
EULA




  
