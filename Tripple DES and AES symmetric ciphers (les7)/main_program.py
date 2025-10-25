import base64
from Crypto.Cipher import AES, DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import lorem  # pip install lorem

# ---------- Utility Helpers ----------

def b64(x: bytes) -> str:
    return base64.b64encode(x).decode()

def ub64(x: str) -> bytes:
    return base64.b64decode(x.encode())

# ---------- AES-EAX Implementation ----------

def encrypt_with_aes_eax(key: bytes, plaintext: bytes, aad: bytes = None) -> dict:
    cipher = AES.new(key, AES.MODE_EAX, nonce=get_random_bytes(16))
    if aad:
        cipher.update(aad)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return {
        "nonce": b64(cipher.nonce),
        "ciphertext": b64(ciphertext),
        "tag": b64(tag),
        "aad": b64(aad) if aad else None,
    }

def decrypt_with_aes_eax(key: bytes, encrypted_package: dict) -> bytes:
    nonce = ub64(encrypted_package["nonce"])
    ciphertext = ub64(encrypted_package["ciphertext"])
    tag = ub64(encrypted_package["tag"])
    aad = ub64(encrypted_package["aad"]) if encrypted_package.get("aad") else None
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    if aad:
        cipher.update(aad)
    return cipher.decrypt_and_verify(ciphertext, tag)

# ---------- TripleDES-CBC Implementation (No HMAC) ----------

def encrypt_with_3des(key: bytes, plaintext: bytes) -> dict:
    iv = get_random_bytes(8)
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, 8))
    return {"iv": b64(iv), "ciphertext": b64(ciphertext)}

def decrypt_with_3des(key: bytes, encrypted_package: dict) -> bytes:
    iv = ub64(encrypted_package["iv"])
    ciphertext = ub64(encrypted_package["ciphertext"])
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    padded = cipher.decrypt(ciphertext)
    return unpad(padded, 8)

# ---------- Unified Interface ----------

def encrypt_message(algorithm: str, plaintext: bytes):
    if algorithm == "AES":
        key = get_random_bytes(32)
        aad = b"metadata"
        encrypted_package = encrypt_with_aes_eax(key, plaintext, aad)
        encrypted_package.update({"algorithm": "AES-EAX", "key": b64(key)})
        return encrypted_package
    elif algorithm == "3DES":
        key = DES3.adjust_key_parity(get_random_bytes(24))
        encrypted_package = encrypt_with_3des(key, plaintext)
        encrypted_package.update({"algorithm": "3DES-CBC", "key": b64(key)})
        return encrypted_package

def decrypt_message(encrypted_package: dict) -> bytes:
    algorithm = encrypted_package["algorithm"]
    if algorithm == "AES-EAX":
        key = ub64(encrypted_package["key"])
        return decrypt_with_aes_eax(key, encrypted_package)
    elif algorithm == "3DES-CBC":
        key = ub64(encrypted_package["key"])
        return decrypt_with_3des(key, encrypted_package)
    else:
        raise ValueError("Unknown algorithm metadata.")

# ---------- Menu ----------

def menu():
    while True:
        print("Encryption Menu")
        print("1. Triple DES")
        print("2. AES")
        choice = input("Enter your choice (1 or 2): ").strip()
        if choice == "1":
            return "3DES"
        elif choice == "2":
            return "AES"
        else:
            print("Invalid choice! Please enter 1 or 2.\n")

# ---------- Main ----------

def main():
    # Generate random Lorem Ipsum each run
    lorem_text = lorem.paragraph()
    plaintext = lorem_text.encode()

    print("Generated Lorem Ipsum:")
    print(lorem_text, "\n")

    algorithm = menu()
    print(f"\nSelected algorithm: {algorithm}\n")

    # Encrypt
    encrypted_package = encrypt_message(algorithm, plaintext)
    print("Encryption Result:")
    for k, v in encrypted_package.items():
        print(f"{k}: {v[:80]}{'...' if len(v) > 80 else ''}")

    # Decrypt
    decrypted = decrypt_message(encrypted_package)
    print("\nDecryption Result:")
    print("Recovered message:", decrypted.decode())
    print("Decryption OK?", decrypted == plaintext)

if __name__ == "__main__":
    main()
