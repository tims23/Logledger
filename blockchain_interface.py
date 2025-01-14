from web3 import Web3
import requests
import json
import datetime
from configuration import bc_configuration

PRIVATE_KEY = bc_configuration["PRIVATE_KEY"] 
ACCOUNT_ADDRESS = bc_configuration["ACCOUNT_ADDRESS"] 
NODE_URL = bc_configuration["NODE_URL"]

GASSTATION = "https://gasstation.polygon.technology/amoy"
OLD_HASH_STORAGE_ADRESS = "0x1e7A8418e6262802601Cb25B21F6DEd54Dc520e3"
HASH_STORAGE_ADRESS = "0x54B802F966078242271967BA6b67F2EdAF14dD54"
RECEIPT_FOLDER = "bc_receipt"

def connect_to_amoy() -> Web3:
    return Web3(Web3.HTTPProvider(NODE_URL))    

def show_stats(web3: Web3 = None):
    if web3 == None:
        web3 = connect_to_amoy()
    print(f"Conncected: {web3.is_connected()}")
    print(f"Blocknumber: {web3.eth.block_number}")
    balance_wei = web3.eth.get_balance(ACCOUNT_ADDRESS)
    balance_gwei = balance_wei // 10**9
    print("Balance:",balance_gwei)

def get_gas_price():
    res = requests.get(GASSTATION).json()
    return res["fast"]["maxFee"]


def custom_serializer(obj):
    if isinstance(obj, bytes):
        return obj.hex()  # Convert bytes/HexBytes to a hex string
    if isinstance(obj, int):
        return obj  # Integers are already serializable
    if isinstance(obj, list):
        return [custom_serializer(i) for i in obj]  # Recursively handle lists
    if isinstance(obj, dict):
        return {k: custom_serializer(v) for k, v in obj.items()}  # Recursively handle dicts
    return str(obj)

def store_receipt(hashes_inserted: int, receipt, total_hashes):
    receipt = dict(receipt)
    receipt = custom_serializer(receipt)
    current_time = datetime.datetime.now()
    timestamp = current_time.strftime("%Y-%m-%d_%H:%M:%S")     
    receipt["hashes_inserted"] = hashes_inserted
    receipt["total_hashes"] = total_hashes
    with open(f"{RECEIPT_FOLDER}/{timestamp}_{hashes_inserted}.json", "w") as file:
        json.dump(receipt, file, indent=4)

class HashStorage:
    SC_ADRESS = HASH_STORAGE_ADRESS
    ABI = [{"inputs":[],"stateMutability":"nonpayable","type":"constructor"},{"inputs":[{"internalType":"bytes32[]","name":"_hashes","type":"bytes32[]"}],"name":"addHash","outputs":[],"stateMutability":"nonpayable","type":"function"},{"inputs":[{"internalType":"uint256","name":"index","type":"uint256"}],"name":"getHashByIndex","outputs":[{"internalType":"bytes32","name":"","type":"bytes32"}],"stateMutability":"view","type":"function"},{"inputs":[],"name":"getHashCount","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"},{"inputs":[{"internalType":"bytes32","name":"hash","type":"bytes32"}],"name":"isHashIncluded","outputs":[{"internalType":"bool","name":"","type":"bool"}],"stateMutability":"view","type":"function"}]
    def __init__(self, web3=None):
        if web3 == None:
            web3 = connect_to_amoy()
        self.web3 = web3
        self.roc_contract = web3.eth.contract(address=self.SC_ADRESS, abi=self.ABI)

    def add_hashes(self, hashes: list):
        # Build the transaction
                # Build the transaction        
        txn = self.roc_contract.functions.addHash(
            hashes
        ).build_transaction({
            'from': ACCOUNT_ADDRESS,
            'nonce': self.web3.eth.get_transaction_count(ACCOUNT_ADDRESS),
            'gas': 15_000_000,
            'gasPrice': self.web3.to_wei(get_gas_price(), 'gwei')
        })

        # Sign and send the transaction
        signed_txn = self.web3.eth.account.sign_transaction(txn, PRIVATE_KEY)
        tx_hash = self.web3.eth.send_raw_transaction(signed_txn.raw_transaction)
        receipt = self.web3.eth.wait_for_transaction_receipt(tx_hash)

        print(f"Transaction sent. Hash: {tx_hash.hex()}")
        print("receipt:", receipt)
        total_hashes = self.get_hash_count()
        store_receipt(len(hashes), receipt, total_hashes)
        return tx_hash.hex()

    def get_hash_by_index(self, index):
        hash_value = self.roc_contract.functions.getHashByIndex(index).call()
        return hash_value.hex()
    
    def get_hash_count(self):
        count = self.roc_contract.functions.getHashCount().call()
        return count

    def check_hash_exists(self, hash):
        """
        Fetches a specific hash by its index.
        """
        hash_value = self.roc_contract.functions.isHashIncluded(hash).call()
        return hash_value.hex()