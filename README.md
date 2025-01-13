# Logledger

As a part of my bachelors thesis Logledger was created. Logledger is a hybrid certificate transparency log which uses a blockchain-backing and threshold signing to ensure the security of the CT-system and prevent split world attacks. At the same time it tries not to be disruptive and follows the guidlines of RFC6962.

The GitHub project focuses on the changes to the system by Logledger. A full implementation would require a complete log system which is out of scope of this paper. It uses the Let's Encrypts OAK Log for H1 2025 as a base and only demonstrates the threshold signing and smart contract functionalities. 


# Files

## Requestor

The *requestor.py* file allows an easy interaction with Logledger. It will query the OAK Log for new certificates, insert their hashes in the blockchain and request a SCT for each of them. Afterwards it will fetch the latest STH from the OAK log and request a singning from Logledger. Moreover, it will validate the signatures locally.

The script gathers all the main functionalities.

## Blockchain interface

A file to facilitate the connection to the blockchain.

## CT interface

A file facilitating the connection to the OAK log.

## Auditor

A class which stores the methods to validate the consistency proof and the inclusion of certificates for the STH signing.

## Signing service

A class saving the functionalities for the threshold signing in a distributed network.

## api facilitator & api server
Api facilitator allows the access to the functionalities over an API. Simulates a real setup where multiple api servers of different signers work together over a network to create a signature for a STH or SCT.
