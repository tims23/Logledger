from CT_interface import get_entries, SCT, STH, get_sth
from blockchain_interface import HashStorage, show_stats
import base64
import hashlib
import threading
from facilitator_interface import sign_sct, sign_mth
import json
import time
from signature_verifier import verify_sct, verify_sth

hash_storage = HashStorage()

BATCH_SIZE = 10
BLOCK_TIME = 2.19
SCT_FOLDER = "requestor_scts"
STH_FOLDER = "requestor_sths"

def decode_base64(base64_str):
    return base64.b64decode(base64_str)

def hash_cert(cert):
    sha256_hash = hashlib.sha256(b'\x00' + cert).digest()
    return "0x" + sha256_hash.hex()

def store_sct(sct: SCT, index):
    with open(f"{SCT_FOLDER}/index_{index}.json", "w") as file:
        json.dump(sct, file, indent=4)

def store_sth(sth: STH, index):
    with open(f"{STH_FOLDER}/size_{index}.json", "w") as file:
        json.dump(sth, file, indent=4)

def submit_certificates():
    count = hash_storage.get_hash_count() 
    new_count = count + BATCH_SIZE
    entries = get_entries(count, new_count-1)
    hashes = [
        hash_cert(base64.b64decode(entry["leaf_input"])) for entry in entries
    ]
    print("Certificate hashes:", hashes)
    hash_storage.add_hashes(hashes)
    return (count, new_count)

def request_sct(index):
    sct = sign_sct(index)
    verification = verify_sct(sct) 
    print("SCT:", sct, "\n", "Is valid:", verification,"\n")
    store_sct(sct, index)

def request_scts(start, end):
    threads:list[threading.Thread] = []
    for cert_index in range(start, end):
        thread = threading.Thread(target=request_sct, args=(cert_index,))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

def request_sth():
    count = hash_storage.get_hash_count() 
    mth: STH = get_sth()
    mth["ll_size"] = count -1
    sth = sign_mth(mth)
    print("STH:", sth)
    print("Is valid:", verify_sth(sth),"\n")
    store_sth(sth, count-1)

if __name__ == "__main__":
    show_stats()
    #(oldCount, new_count) = submit_certificates()
    #time.sleep(1.5 * BLOCK_TIME)
    #request_scts(oldCount, new_count)
    request_sth()
