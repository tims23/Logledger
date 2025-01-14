from flask import Flask, jsonify, request
import requests
import json
import requests
import threading
import ggmpc
from ggmpc import curves
from signing_service import encode_signature_base64
from blockchain_interface import HashStorage
import random
from CT_interface import STH, SCT, unquote_sth, get_consistency_proof
import base64
import time
import os
from flask_caching import Cache
from configuration import configuration

STH_FOLDER = "stored_sths"

app = Flask(__name__)
storage = HashStorage()
mpc = ggmpc.Eddsa(curves.ed25519)

# Configure Flask-Caching
cache = Cache(app, config={
    'CACHE_TYPE': 'SimpleCache',  # Use in-memory caching
    'CACHE_DEFAULT_TIMEOUT': 0  # Default timeout for cached data (in seconds)
})

def store_latest_STH(sth: STH):
    with open(f"{STH_FOLDER}/{sth['ll_size']}.json", "w") as file:
        json.dump(sth, file, indent=4)

def load_latest_STH():
    directory = STH_FOLDER
    files = os.listdir(directory)    
    numeric_files = [file for file in files if file.split('.')[0].isdigit()]
    
    if numeric_files:
        highest_file = max(numeric_files, key=lambda x: int(x.split('.')[0]))
        highest_file_path = os.path.join(directory, highest_file)
        
        with open(highest_file_path, 'r') as f:
            content = f.read()
        
        return json.loads(content)
    else:
        return None


PUBLIC_KEY_FILE = "public_key"

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

def fetch_url(url, text, selected_signers, timestamp):
    try:
        response = requests.get(f"{url}/sign_sct/{text}",
                                json = {
                                    "selected_signers": selected_signers,
                                    "timestamp": timestamp
                                })
        if response.status_code == 429:
            return 429
        return response.json()
    except Exception as e:
        print(f"Failed to fetch {url}: {e}")
        raise

def fetch_mth(url, sth: STH, mth: STH, consistency_proof, selected_signers):
    try:
        response = requests.get(f"{url}/sign_mth", 
                                json = {
                                    "selected_signers": selected_signers,
                                    "old_sth": sth,
                                    "new_mth": mth,
                                    "consistency_proof": consistency_proof
                                })
        if response.status_code == 429:
            return 429
        return response.json()
    except Exception as e:
        print(f"Failed to fetch {url}: {e}")
        raise

@app.route('/public_key', methods=['GET'])
def get_public_key():
    return jsonify(configuration["public_key"]), 200

SIGNER1_API_BASE_URL = "http://localhost:5001"   
LOG_ID_FILE = "log_id"

@app.route('/sign_sct/<index>', methods=['GET'])
def sign_sct(index):
    selected_signers_indexes = random.sample(range(1, 6), 3)

    timestamp = int(time.time())
    selected_signers = [url for key, url in configuration["urls"].items() if int(key) in selected_signers_indexes]
    threads = []
    for selected_signer_url in selected_signers:
        thread = FetchThread(fetch_url,[selected_signer_url, index, selected_signers_indexes, timestamp])
        threads.append(thread)
        thread.start()

    hash_thread = FetchThread(storage.get_hash_by_index, [int(index)])
    hash_thread.start()

    for thread in threads:
        thread.join()  # Wait for all threads to finish
        if thread.exception:
            print(f"Failed to fetch: {thread.exception}")
            return  # Exit immediately if

    
    partial_signatures = [thread.response for thread in threads]
    final_signature = mpc.sign_combine(tuple(partial_signatures))
    final_signature_b64 = encode_signature_base64(final_signature["R"], final_signature["sigma"])

    hash_thread.join()
    if hash_thread.exception:
        return jsonify({"error": f"Failed to fetch blockchain data."}), 500
    hashed_cert = bytes.fromhex(hash_thread.response)
    hashed_cert = base64.b64encode(hashed_cert).decode("utf-8")

    result: SCT = { 
        "hashed_certificate": hashed_cert,
        "signed_hash": final_signature_b64,
        "id": configuration["log_id"],
        "sct_version": "v1",
        "timestamp": timestamp
    }
    return jsonify(result), 200

@app.route('/sign_mth', methods=['GET'])
def sign_mth():
    data = request.get_json()
    old_sth: STH = {}
    try:
        old_sth = data["old_sth"]
    except KeyError:
        old_sth = cache.get("latest_STH")
   
    new_mth: STH = data["new_mth"]
    new_mth["timestamp"] = int(time.time())
    consistency_proof = None
    try:
        consistency_proof = data["consistency_proof"]
    except KeyError:
        consistency_proof = get_consistency_proof(int(old_sth["tree_size"]), int(new_mth["tree_size"]))

    selected_signers_indexes = random.sample(range(1, 6), 3)

    selected_signers = [url for key, url in configuration["urls"].items() if int(key) in selected_signers_indexes]
    threads = []
    for selected_signer_url in selected_signers:
        thread = FetchThread(fetch_mth,
                             [selected_signer_url, 
                              old_sth, new_mth, 
                              consistency_proof, 
                              selected_signers_indexes])
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()  # Wait for all threads to finish
        if thread.exception:
            print(f"Failed to fetch: {thread.exception}")
            return  # Exit immediately if

    partial_signatures = [thread.response for thread in threads]
    print(partial_signatures)
    if 429 in partial_signatures:
        return jsonify({"error":"Too many requests"}), 429
    final_signature = mpc.sign_combine(tuple(partial_signatures))
    print("final_signature",final_signature)
    final_signature_b64 = encode_signature_base64(final_signature["R"], final_signature["sigma"])

    result = unquote_sth(new_mth)
    result["tree_head_signature"] = final_signature_b64
    store_latest_STH(result)
    cache.set("latest_STH", result)

    return jsonify(result), 200

if __name__ == '__main__':
    latest_STH = load_latest_STH()
    cache.set("latest_STH", latest_STH)
    app.run(debug=True, port=5000)