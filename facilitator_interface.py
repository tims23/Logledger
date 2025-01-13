from CT_interface import SCT, STH
import requests

BASE_URL = "http://13.51.195.75" #change to local setup if neccesarry

def sign_sct(index: int) -> SCT:
    try:
        return requests.get(f"{BASE_URL}/sign_sct/{index}").json()
    except Exception as e: 
        print("sign_sct exception", e)
    
def sign_mth(mth: STH, sth = None, consistency_proof = None) -> STH:
    try:
        #mth["ll_size"] = 600 add this with a value 10 higher than the latest sth if constant failure
        body_json = { "new_mth": mth }
        if sth != None:
            body_json["old_sth"] = sth
        if consistency_proof != None:
            body_json["consistency_proof"] = consistency_proof
        return requests.get(f"{BASE_URL}/sign_mth", json=body_json).json()
    except Exception as e: 
        print("sign_sth exception", e)