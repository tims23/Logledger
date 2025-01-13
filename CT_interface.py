import requests
from typing import TypedDict
import urllib.parse
from urllib.parse import unquote

BASE_URL = "https://oak.ct.letsencrypt.org/2025h1/ct/v1/"

class SCT(TypedDict):
    sct_version: str
    id: str
    timestamp: int
    hashed_certificate: bytes
    signed_hash: bytes

class Entry(TypedDict):
    leaf_input: str
    extra_data: str

def get_entries(start: int, end: int) -> list[Entry]:
    try:
        return requests.get(f"{BASE_URL}get-entries?start={start}&end={end}").json()["entries"]
    except:
        return

class STH(TypedDict):
    tree_size: int
    timestamp: int
    sha256_root_hash: bytes
    tree_head_signature: bytes
    ll_size: int

def get_sth() -> STH:
    return requests.get(f"{BASE_URL}get-sth").json()

def get_consistency_proof(first: int, second: int) -> list:
    try: 
        return requests.get(f"{BASE_URL}get-sth-consistency?first={first}&second={second}").json()["consistency"]
    except:
        return

class EntryAndProof(TypedDict):
    leaf_input: str
    extra_data: str
    audit_path: list[str]

def get_entry_and_proof(leaf_index: int, tree_size: int) -> EntryAndProof:
    try:
        r = requests.get(f"{BASE_URL}get-entry-and-proof?leaf_index={leaf_index}&tree_size={tree_size}").json()
        print("res", r)
        return r
    except Exception as e:
        return

class ProofByHash(TypedDict):
    leaf_index: int
    audit_path: list[str]

def get_proof_by_hash(hash: str, tree_size: int) -> ProofByHash:
    try: 
        encoded_hash = urllib.parse.quote(hash)
        return requests.get(f"{BASE_URL}get-proof-by-hash?hash={encoded_hash}&tree_size={tree_size}").json()
    except Exception as e: 
        return

def unquote_sth(sth: STH) -> STH:
    sth["sha256_root_hash"] = unquote(sth["sha256_root_hash"])
    sth["tree_head_signature"] = unquote(sth["tree_head_signature"])
    return sth