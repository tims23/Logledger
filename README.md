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

# Deployment
You can also deploy the implementation locally by running a api facilitator instance and 5 api servers for the signers.
### API facilitator
>python3 api_facilitator.py
### Singer
The signers take their identity from the configuration file. If you are running all in the same folder you can also overgive the configuration as command line argument.
>python3 api_server.py <signer_index>

The signers should have the indexes 1-n (n being 5 in the default setup)

## Configuration 
The deployment takes two configuration files. One for the blockchain:
>{"PRIVATE_KEY":  "", "ACCOUNT_ADDRESS": "", "NODE_URL": ""}

And one for the signers:
>{"index": "", "threshold": "", "total_signers": "", "public_key": "", "log_id": "", "key_folder": "", "urls": ""}

Moreover the BASE_URL can be changed in the facilitator interface to connect to the local deployment. 

If another smart contract is used the public key has to be changed in the bc_interface.

## Used external libraries

 - ggmpc
 - web3
 - flask
 - flask_caching