from flask import Flask, request, jsonify
from blockchain_interface import HashStorage
from signing_service import MultiSigner, RemoteMultiSigner, InsufficientSignSharesError
import json
from dataclasses import dataclass
from flask_caching import Cache
import time
from auditor import Auditor
from CT_interface import STH, SCT
from CT_interface import get_proof_by_hash
from configuration import configuration, Configuration

app = Flask(__name__)
configuration: Configuration = {**configuration}
store = HashStorage()
auditor = None
signer: MultiSigner = None
remote_signer: dict[int: RemoteMultiSigner] = {}

cache = Cache(app, config={
    'CACHE_TYPE': 'SimpleCache',  # Use in-memory caching
    'CACHE_DEFAULT_TIMEOUT': 300  # Default timeout for cached data (in seconds)
})

def wait_for_signature(task, data):
    for _ in range(30):
        time.sleep(1)
        try:
            res = signer.sign(task, data)
            return res
        except InsufficientSignSharesError:
            continue

    return jsonify({"error": f"Failed to receive all signing shares."}), 500

@app.route('/sign_sct/<index>', methods=['GET'])
def sign_sct(index):
    data = request.get_json()

    index = int(index)
    selected_signers = data["selected_signers"]
    selected_signers = [int(selected_signer) for selected_signer in selected_signers]
    timestamp = int(data["timestamp"])
    task = f"SCT_signing_{index}"

    hash = store.get_hash_by_index(index)
    if not hash:
        jsonify({"error": f"Requested certificate not included."}), 404

    certificate_timestamp: SCT = {
        "hashed_certificate": hash,
        "id": configuration["log_id"],
        "sct_version": "v1",
        "timestamp": timestamp
    }

    signable_data = json.dumps(certificate_timestamp, sort_keys=True).encode("utf-8")

    # Step 5: Each signer generates their sign share
    signer.set_selected_signers(task,selected_signers)
    signer.sign_share(task,signable_data)
    # Share the sign shares with the other selected signers
    for other_signer_index in selected_signers:
        if other_signer_index == signer.index:
            continue
        other_signer = remote_signers[other_signer_index]
        share = signer.get_sign_share(task, other_signer_index)
        other_signer.set_foreign_sign_share(task, share)

    return wait_for_signature(task, signable_data)

@app.route('/sign_mth', methods=['GET'])
def sign_mth():
    data = request.get_json()
    old_sth: STH = data["old_sth"]
    new_mth: STH = data["new_mth"]
    consistency_proof = data["consistency_proof"]

    try:
        if not auditor.proof_input(old_sth, new_mth, consistency_proof):
            return jsonify({"error": f"Validation failed"}), 400
    except ConnectionError:
        return jsonify({"error": f"Too many requests"}), 429
    
    selected_signers = data["selected_signers"]
    selected_signers = [int(selected_signer) for selected_signer in selected_signers]
    
    task = f"SCT_signing_{new_mth['ll_size']}"
    new_mth.pop("tree_head_signature")
    new_mth["sha256_root_hash"] = new_mth["sha256_root_hash"].hex()
    
    signable_data = json.dumps(new_mth, sort_keys=True).encode("utf-8")
    print("signable_data", signable_data)

    signer.set_selected_signers(task, selected_signers)
    signer.sign_share(task,signable_data)

    # Share the sign shares with the other selected signers
    for other_signer_index in selected_signers:
        if other_signer_index == signer.index:
            continue
        other_signer = remote_signers[other_signer_index]
        share = signer.get_sign_share(task, other_signer_index)
        other_signer.set_foreign_sign_share(task, share)

    return wait_for_signature(task, signable_data)

@app.route('/foreign_sign_share/<task>', methods = ['POST'])
def foreign_sign_shares(task):
    data = request.json
    signer.set_foreign_sign_share(task, int(data["id"]), data["share"])
    return jsonify({}), 200

if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1:
        configuration["index"] = int(sys.argv[1])

    
    KEY_FILE = f"combined_key_{configuration['index']}.json"
    KEY_PATH = f"{configuration['key_folder']}/{KEY_FILE}"

    print("Signing Configuration:", configuration)
    signer = MultiSigner(configuration["index"], 
                         configuration["threshold"], 
                         configuration["total_signers"], 
                         cache, 
                         KEY_PATH)
    remote_signers = {int(id):RemoteMultiSigner(signer.index, 
                                                configuration["urls"][id]) 
                                                for id in configuration["urls"].keys()}

    auditor = Auditor(store.get_hash_by_index, get_proof_by_hash)

    app.run(debug=True, port=5000+configuration["index"])
