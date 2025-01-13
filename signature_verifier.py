from CT_interface import STH, SCT
from signing_service import decode_signature_base64
from ggmpc import curves, Eddsa
import json
import base64

PUBLIC_KEY = 108277726953003826667175796147551996205307660203894155405100504010803472647562

mpc = Eddsa(curves.ed25519)

def verify_signature(message, signature):
    signature = decode_signature_base64(signature)
    signature["y"] = PUBLIC_KEY

    try:
        mpc.verify(message, signature)
        return True
    except:
        return False

def verify_sct(input_sct: SCT) -> bool:
    sct = {**input_sct}
    signature = sct.pop("signed_hash")
    sct["hashed_certificate"] = decode_base64(sct["hashed_certificate"]).hex()
    sct_encoded = json.dumps(sct, sort_keys=True).encode("utf-8")
    return verify_signature(sct_encoded, signature)

def decode_base64(base64_str):
    return base64.b64decode(base64_str)

def verify_sth(input_sth: STH) -> bool:
    sth = {**input_sth}
    signature = sth.pop("tree_head_signature")
    sth["sha256_root_hash"] = decode_base64(sth["sha256_root_hash"]).hex()
    mth_encoded = json.dumps(sth, sort_keys=True).encode("utf-8")
    return verify_signature(mth_encoded, signature)

if __name__ == "__main__":
    SCT_RES = {
        "hashed_certificate": "y/F81o3Tc8Bt+emjX9c5O+bEIf3wsLPd7EgaLtX5//U=",
        "id": "LOG_ID",
        "sct_version": "v1",
        "signed_hash": "83MGPl0LrvXeGckPvizqNLN4Z12f8C8bPlOx+B9lR0uBnTtD3sOc8oeeukGAtX5oXrjy4f82x6d72AqRYpsPDQ==",
        "timestamp": 1736776437
    }
    
    STH_RES = {
        "ll_size": 470,
        "sha256_root_hash": "nj0shwdgvtET15Qy6FQByckUX1YYC64DTgGlGmnLS1U=",
        "timestamp": 1736776402,
        "tree_head_signature": "84V7fOGujZWK9tEOrMJyhPMUsaTM/zXnqebbGy2VDsROuvS3DBzYoqLDmU8JEEJauw3TVcdrQZji4RhFKbNtBw==",
        "tree_size": 493376048
    }
    print("SCT:",verify_sct(SCT_RES))
    print("STH", verify_sth(STH_RES))
