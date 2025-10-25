"""
demo_pycryptodome_crypto.py
Demonstrates AES-GCM (modern, recommended) and 3DES-CBC+HMAC (legacy) encryption
using PyCryptodome, following current best practices.
"""

import os, base64, hmac
from hashlib import sha256
from Crypto.Cipher import AES, DES3
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes


# ---------- Utility helpers ----------

def b64(x: bytes) -> str:
    return base64.b64encode(x).decode("utf-8")

def ub64(x: str) -> bytes:
    return base64.b64decode(x.encode("utf-8"))

# ---------- Key derivation ----------

def derive_key(password: str, salt: bytes, length: int = 32, iterations: int = 200_000) -> bytes:
    """
    Derive a symmetric key from a password using PBKDF2-HMAC-SHA256.
    """
    return PBKDF2(password, salt, dkLen=length, count=iterations, hmac_hash_module=sha256)

# ---------- AES-GCM (modern AEAD) ----------

def aes_gcm_encrypt(key: bytes, plaintext: bytes, aad: bytes = None) -> dict:
    cipher = AES.new(key, AES.MODE_GCM, nonce=get_random_bytes(12))
    if aad:
        cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return {
        "nonce": b64(cipher.nonce),
        "ciphertext": b64(ciphertext),
        "tag": b64(tag),
        "aad": b64(aad) if aad else None,
    }

def aes_gcm_decrypt(key: bytes, nonce_b64: str, ciphertext_b64: str, tag_b64: str, aad_b64: str = None) -> bytes:
    nonce = ub64(nonce_b64)
    ciphertext = ub64(ciphertext_b64)
    tag = ub64(tag_b64)
    aad = ub64(aad_b64) if aad_b64 else None
    cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
    if aad:
        cipher.update(aad)
    return cipher.decrypt_and_verify(ciphertext, tag)

# ---------- TripleDES-CBC + HMAC (legacy) ----------

def triple_des_encrypt(key: bytes, plaintext: bytes, hmac_key: bytes) -> dict:
    """
    Legacy 3DES encryption (CBC) + HMAC-SHA256 authentication.
    """
    iv = get_random_bytes(8)
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    padded = pad(plaintext, 8)
    ciphertext = cipher.encrypt(padded)
    # compute HMAC over (iv || ciphertext)
    tag = hmac.new(hmac_key, iv + ciphertext, sha256).digest()
    return {
        "iv": b64(iv),
        "ciphertext": b64(ciphertext),
        "hmac": b64(tag),
    }

def triple_des_decrypt(key: bytes, hmac_key: bytes, iv_b64: str, ciphertext_b64: str, hmac_b64: str) -> bytes:
    iv = ub64(iv_b64)
    ciphertext = ub64(ciphertext_b64)
    tag = ub64(hmac_b64)
    # verify HMAC before decryption
    calc_tag = hmac.new(hmac_key, iv + ciphertext, sha256).digest()
    if not hmac.compare_digest(calc_tag, tag):
        raise ValueError("HMAC verification failed — data tampered or key incorrect.")
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    padded = cipher.decrypt(ciphertext)
    return unpad(padded, 8)

# ---------- Demo ----------

def demo():
    plaintext = b"Lorem ipsum dolor sit amet, consectetur adipiscing elit. " \
                b"Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua."
    print("Plaintext:", plaintext.decode(), "\n")

    password = "correct horse battery staple"
    salt_aes = get_random_bytes(16)
    salt_3des = get_random_bytes(16)

    # AES key (32 bytes = AES-256)
    aes_key = derive_key(password, salt_aes, length=32)
    aad = b"metadata:example"

    aes_box = aes_gcm_encrypt(aes_key, plaintext, aad)
    print("=== AES-GCM (modern) ===")
    print("salt:", b64(salt_aes))
    print("nonce:", aes_box["nonce"])
    print("ciphertext:", aes_box["ciphertext"])
    print("tag:", aes_box["tag"])
    recovered = aes_gcm_decrypt(
        aes_key, aes_box["nonce"], aes_box["ciphertext"], aes_box["tag"], b64(aad)
    )
    print("Decrypted OK?", recovered == plaintext)

    # 3DES (legacy)
    print("\n=== 3DES-CBC + HMAC (legacy, deprecated) ===")
    key_3des = derive_key(password, salt_3des, length=24)  # 24B -> 3-key TDES
    hmac_key = derive_key(password + "-auth", salt_3des, length=32)

    td_box = triple_des_encrypt(key_3des, plaintext, hmac_key)
    print("salt:", b64(salt_3des))
    print("iv:", td_box["iv"])
    print("ciphertext:", td_box["ciphertext"])
    print("hmac:", td_box["hmac"])

    recovered2 = triple_des_decrypt(key_3des, hmac_key, td_box["iv"], td_box["ciphertext"], td_box["hmac"])
    print("Decrypted OK?", recovered2 == plaintext)

if __name__ == "__main__":
    demo()