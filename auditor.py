import base64
import hashlib
from CT_interface import ProofByHash, STH
import threading
from signature_verifier import verify_sth
from urllib.parse import unquote
import base64

def decode_base64(base64_str):
    return base64.b64decode(base64_str)

class FetchThread(threading.Thread):
    def __init__(self, fun, args):
        super().__init__()
        self.fun = fun
        self.args = args
        self.response = None
        self.exception = None

    def run(self):
        try:
            self.response = self.fun(*self.args)
        except Exception as e:
            self.exception = e

class Auditor:
    def __init__(self, get_entry_from_blockchain, get_entry_from_inclusion_service):
        self.get_entry_from_blockchain = get_entry_from_blockchain
        self.get_entry_from_inclusion_service = get_entry_from_inclusion_service

    def proof_input(self, old_sth: STH, new_mth: STH, consistency_path) -> bool:
        #Step 1: validate signature
        verifiable_sth = old_sth
        print("verified signature", verify_sth(verifiable_sth))

        #Step 2: validate consitency
        old_sth["sha256_root_hash"] = decode_base64(old_sth["sha256_root_hash"])
        new_mth["sha256_root_hash"] = decode_base64(new_mth["sha256_root_hash"])
        consistency_path = [decode_base64(path) for path in consistency_path]

        if not validate_consistency_proof(old_sth["sha256_root_hash"], 
                                        old_sth["tree_size"], 
                                        new_mth["sha256_root_hash"],
                                        new_mth["tree_size"], 
                                        consistency_path):
            print("consitency proof failed")
            return False
        print("consitency proof succeeded")

        # Step 3: validate inlusion
        threads = []
        for i in range(old_sth["ll_size"], new_mth["ll_size"]):
            thread = FetchThread(self.validate_inclusion, [i, new_mth])
            threads.append(thread)
            thread.start()

        for thread in threads:
            thread.join()  # Wait for all threads to finish
            if thread.exception:
                raise thread.exception
            if not thread.response:
                print("thread failed", thread.response )
                return False
                  # Exit immediately if

        print("inclusion proof succeeded")
        return True
    
    def validate_inclusion(self, i: int, new_mth: STH):
        try:
            bc_entry = self.get_entry_from_blockchain(i)
        except:
            raise KeyError
                    
        bc_entry_bytes = bytes.fromhex(bc_entry)
        bc_entry = base64.b64encode(bc_entry_bytes)
        off_chain_entry: ProofByHash = self.get_entry_from_inclusion_service(bc_entry, new_mth["tree_size"])
        if off_chain_entry == None:
            raise ConnectionError

        if not validate_merkle_inclusion_proof(off_chain_entry["leaf_index"],
                                        new_mth["tree_size"], 
                                        new_mth["sha256_root_hash"], 
                                        bc_entry_bytes, 
                                        off_chain_entry['audit_path']):
            print("inclusion proof failed for:",i , bc_entry)
            return False
        return True
            

def hash_function(data):
    """Compute the SHA256 hash."""
    return hashlib.sha256(data).digest()

def validate_merkle_inclusion_proof(leaf_index, tree_size, root_hash, input_hash, inclusion_path):
    """
    Validate a Merkle inclusion proof.
    
    :param leaf_index: Index of the leaf being proven.
    :param tree_size: Total number of leaves in the tree.
    :param root_hash: The root hash of the Merkle tree.
    :param input_hash: The hash of the input leaf to be proven.
    :param inclusion_path: The inclusion path array.
    :return: True if the proof is valid, False otherwise.
    """
    # Step 1: Compare leaf_index with tree_size
    if leaf_index >= tree_size:
        return False

    # Step 2: Set fn to leaf_index and sn to tree_size - 1
    fn = leaf_index
    sn = tree_size - 1

    # Step 3: Set r to input_hash
    r = input_hash

    # Step 4: Iterate over inclusion_path
    for p in inclusion_path:
        p = base64.b64decode(p)  # Decode the base64-encoded path element
        if sn == 0:
            return False

        if fn & 1 == 1 or fn == sn:
            # Case: LSB(fn) is set or fn == sn
            r = hash_function(b'\x01' + p + r)
        else:
            # Case: LSB(fn) is not set
            r = hash_function(b'\x01' + r + p)

        # Right-shift fn and sn by 1
        fn >>= 1
        sn >>= 1

    # Step 5: Compare sn to 0 and r to root_hash
    root_hash_bytes = root_hash
    #root_hash_bytes = base64.b64decode(root_hash)
    return sn == 0 and r == root_hash_bytes

def hash_node(prefix, left, right):
    """Compute the hash of a node with a given prefix."""
    return hash_function(prefix + left + right)

def validate_consistency_proof(first_hash, first_size, second_hash, second_size, consistency_path):
    """Validate the consistency proof for a Merkle tree."""
    # Step 1: If consistency_path is empty, fail the verification.
    if not consistency_path:
        raise ValueError("Consistency path is empty")

    # Step 2: Prepend first_hash if first_size is a power of 2.
    if (first_size & (first_size - 1)) == 0:  # Check if first_size is a power of 2
        consistency_path.insert(0, first_hash)

    fn = first_size - 1
    sn = second_size - 1

    # Step 4: Right-shift fn and sn equally until LSB(fn) is not set.
    while fn & 1:
        fn >>= 1
        sn >>= 1

    fr = consistency_path[0]
    sr = consistency_path[0]

    # Step 6: Iterate through the consistency path
    for i in range(1, len(consistency_path)):
        c = consistency_path[i]

        if sn == 0:
            raise ValueError("Proof verification failed: sn is zero during iteration")

        if fn & 1 or fn == sn:
            fr = hash_node(b'\x01', c, fr)
            sr = hash_node(b'\x01', c, sr)

            if fn & 1 == 0:
                while (fn & 1) == 0 and fn != 0:
                    fn >>= 1
                    sn >>= 1
        else:
            sr = hash_node(b'\x01', sr, c)

        # Right-shift fn and sn by one
        fn >>= 1
        sn >>= 1

    # Step 7: Verify the calculated fr and sr
    return fr == first_hash and sr == second_hash and sn == 0
