import ggmpc
import ggmpc.curves as curves
import os
import json
from flask_caching import Cache
from flask import Flask
import requests

class InsufficientSignSharesError(Exception):
    """Custom exception raised when no valid configuration is provided."""
    def __init__(self, message="Not enough sign shares given"):
        super().__init__(message)

class MultiSigner:
    def __init__(self,index, threshold, total_signers, cache: Cache, partial_private_key_file=None, mpc=None):
        """
        Initializes a signer with their own key share.

        :param mpc: The ggmpc object
        :param index: The unique index for this signer
        :param threshold: The threshold for signing
        :param total_signers: Total number of signers
        """
        if mpc == None:
            mpc = ggmpc.Eddsa(curves.ed25519)
        self.cache = cache
        self.mpc = mpc
        self.index = index
        self.namespace = f"signer_{index}"
        self.threshold = threshold
        self.total_signers = total_signers
        self.key_share = mpc.key_share(index, threshold, total_signers)

        if partial_private_key_file == None:
            partial_private_key_file = f"combined_key_{self.index}.json"
        self.filename = partial_private_key_file
        self.combined_key = None
        if os.path.exists(self.filename):
            print("Loaded key from:", self.filename)
            # Read the combined key from the file
            with open(self.filename, "r") as key_file:
                data = json.load(key_file)
                self.combined_key = {int(k): v for k, v in data.items()}

        self.foreign_key_shares = [None for _ in range(total_signers)]
        self.foreign_key_shares[index-1] = self.key_share[index]
    
    def combine_keys(self):
        """
        Combines keys for this signer and writes the combined key to a file.
        """
        # Combine the keys
        self.combined_key = self.mpc.key_combine(tuple(self.foreign_key_shares))
        
        print("combined key", self.combined_key)
        # Write the combined key to a file
        with open(self.filename, "w") as key_file:
            json.dump(self.combined_key, key_file)
        print(f"Combined key for signer {self.index} written to {self.filename}")
    
    def set_key_share(self, signer_index, key_share):
        """
        Sets the foreign key share from another signer.

        :param signer_index: The index of the foreign signer
        :param key_share: The key share provided by the foreign signer
        """
        self.foreign_key_shares[signer_index-1] = key_share

    def get_key_share(self, signer_index=None):
        """
        Gets the key share for a specific signer or for this signer.

        :param signer_index: The index of the signer (optional)
        :return: The key share
        """
        if signer_index is None:
            return self.key_share[self.index]
        return self.key_share[signer_index]        

    def sign_share(self, task, message):
        """
        Creates a sign share for this signer.

        :param message: The message to be signed
        """
        selected_signers = self.get_selected_signers(task)
        
        print("create sign share for:","task:", f"'{task}',", "message:", f"'{message}'")
        sign_shares = self.mpc.sign_share(message, 
                                          tuple(self.combined_key[signer_index]
                                                for signer_index in range(1, self.total_signers +1) 
                                                if signer_index in selected_signers)) #TODO: check
        self.set_sign_shares(task, sign_shares)
    
    def sign(self, task, message):
        """
        Signs the message using signing shares.

        :param message: The message to sign
        :param signing_shares: Signing shares from threshold signers
        :return: Signature share
        """
        foreign_sign_shares = self.get_foreign_sign_shares(task)
        foreign_sign_shares[self.index] = self.get_sign_share(task)
        selected_signers = self.get_selected_signers(task)
        sign_shares = None
        try:
            sign_shares = tuple(foreign_sign_shares[signer_index] for signer_index in selected_signers)
        except KeyError:
            raise InsufficientSignSharesError()
       
        return self.mpc.sign(message, sign_shares)
    
    def set_foreign_sign_share(self, task, signer_index, foreign_sign_share):
        """
        Sets a sign share for a specific signer.

        :param signer_index: The index of the signer providing the sign share
        :param sign_share: The sign share from that signer
        """
        self.cache.set(f"{self.namespace}:{task}.foreign_sign_shares.{signer_index}", foreign_sign_share)

    def get_sign_share(self, task, signer_index=None):
        """
        Retrieves a sign share for a specific signer or for this signer.

        :param signer_index: The index of the signer (optional)
        :return: The sign share
        """
        sign_shares = self.get_sign_shares(task)
        if signer_index is None:
            return sign_shares[self.index]
        return sign_shares[int(signer_index)]
    
    def get_selected_signers(self, task):
        return self.cache.get(f"{self.namespace}:{task}.selected_signers")

    def set_selected_signers(self, task, signers):
        self.cache.set(f"{self.namespace}:{task}.selected_signers", signers)
    
    def get_sign_shares(self, task):
        return self.cache.get(f"{self.namespace}:{task}.sign_shares")
    
    def set_sign_shares(self, task, sign_shares):
        self.cache.set(f"{self.namespace}:{task}.sign_shares", sign_shares)

    def get_foreign_sign_shares(self, task):
        res = {}
        for i in self.get_selected_signers(task):
            res_i = self.cache.get(f"{self.namespace}:{task}.foreign_sign_shares.{i}")
            if res_i:
                res[i] = res_i
        return res

class RemoteMultiSigner:
    def __init__(self, caller_id, url):
        self.index = caller_id
        self.url = url

    def set_foreign_sign_share(self, task, sign_share):
        data = {
            "id": self.index,
            "share": sign_share
        }
        res = requests.post(f"{self.url}/foreign_sign_share/{task}", json=data)
        if res.status_code != 200:
            raise ConnectionError

import base64
def encode_signature_base64(R, sigma):
    # Convert R and s from hex strings to bytes
    R_bytes = R.to_bytes(32, byteorder="little")
    s_bytes = sigma.to_bytes(32, byteorder="little")

    # Combine R and s into a single byte array
    combined_signature = R_bytes + s_bytes

    # Optionally, you can encode the combined signature in hex or base64 for transport/storage
    return base64.b64encode(combined_signature).decode("utf-8")

def decode_signature_base64(signature_base64):
    """
    Decodes a Base64-encoded EdDSA signature into its integer components R and s.

    Args:
        signature_base64 (str): Base64-encoded signature.

    Returns:
        dict: A dictionary with 'R' and 's' as integers.
    """
    # Decode the Base64 string into bytes
    signature_bytes = base64.b64decode(signature_base64)

    # Ensure the signature is the correct length (64 bytes for Ed25519)
    if len(signature_bytes) != 64:
        raise ValueError("Invalid signature length. Expected 64 bytes.")

    # Split the byte array into R (first 32 bytes) and s (last 32 bytes)
    R_bytes = signature_bytes[:32]
    s_bytes = signature_bytes[32:]

    # Convert bytes back to integers
    R = int.from_bytes(R_bytes, byteorder="little")
    s = int.from_bytes(s_bytes, byteorder="little")

    # Return as a dictionary
    return {"R": R, "sigma": s}

def test_3_in_3_of_5():
    # Initialize the MPC object
    mpc = ggmpc.Eddsa(curves.ed25519)
    threshold, total_signers = 3, 5

    app = Flask(__name__)
    config={
        'CACHE_TYPE': 'SimpleCache',  # Use in-memory caching
        'CACHE_DEFAULT_TIMEOUT': 300  # Default timeout for cached data (in seconds)
    }
    # Initialize 5 signers
    signers = [MultiSigner(i + 1, threshold, total_signers, Cache(app=app, config=config)) for i in range(total_signers)]

    """
    # Step 1: Exchange key shares
    for i, signer in enumerate(signers):
        for j, other_signer in enumerate(signers):
            if i != j:
                signer.set_key_share(other_signer.index, other_signer.get_key_share(signer.index))

    # Step 2: Combine keys for each signer
    for signer in signers:
        signer.combine_keys()
    """
    # Step 3: Select 3 signers for threshold signing (e.g., signers 1, 2, and 3)
    selected_signers = [1, 3, 5]

    # Step 4: Message to be signed
    message = b"Hello_World"

    TASK = "Hello_World"

    # Step 5: Each signer generates their sign share
    for signer_index in selected_signers:
        signer = signers[signer_index-1]
        signer.set_selected_signers(TASK,selected_signers)
        signer.sign_share(TASK,message)
        # Share the sign shares with the other selected signers
        for other_signer_index in selected_signers:
            other_signer = signers[other_signer_index-1]
            other_signer.set_foreign_sign_share(TASK, signer.index, signer.get_sign_share(TASK, other_signer.index))

    # Step 6: Each signer generates their partial signature
    partial_signatures = []
    for signer_index in selected_signers:
        signer = signers[signer_index-1]
        # Collect the sign shares from all selected signers
        partial_signature = signer.sign(TASK, message)
        partial_signatures.append(partial_signature)

    print("partial_signatures",partial_signatures)

    # Step 7: Combine partial signatures into a full signature
    final_signature = mpc.sign_combine(tuple(partial_signatures))
    print("Final Signature:", final_signature)

    # Step 8: Verify the signature
    is_valid = mpc.verify(message, final_signature)
    print("Is the signature valid?", is_valid)

if __name__ == "__main__":
    test_3_in_3_of_5()