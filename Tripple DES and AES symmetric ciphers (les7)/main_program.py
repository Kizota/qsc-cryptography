import base64
from Crypto.Cipher import AES, DES3
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import lorem  # pip install lorem



def b64(x: bytes) -> str:
    """
    Encode bytes into a Base64 string.
    Used to safely display or store binary data (keys, ciphertext).
    """
    return base64.b64encode(x).decode()

def ub64(x: str) -> bytes:
    """
    Decode a Base64 string back into bytes.
    Used when recovering keys or ciphertext for decryption.
    """
    return base64.b64decode(x.encode())



def encrypt_with_aes_eax(key: bytes, plaintext: bytes, aad: bytes = None) -> dict:
    """
    Encrypt plaintext using AES in EAX mode (provides authenticity and confidentiality).
    
    Parameters:
        key (bytes): The AES key (must be 16, 24, or 32 bytes long).
        plaintext (bytes): The data to encrypt.
        aad (bytes): Optional 'additional authenticated data' to protect extra metadata.
    
    Returns:
        dict: Contains Base64-encoded nonce, ciphertext, tag, and optionally aad.
    """
    cipher = AES.new(key, AES.MODE_EAX, nonce=get_random_bytes(16))  # Create AES-EAX cipher with random nonce
    if aad:
        cipher.update(aad)  # Add associated data (optional)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)  # Encrypt and generate authentication tag
    return {
        "nonce": b64(cipher.nonce),
        "ciphertext": b64(ciphertext),
        "tag": b64(tag),
        "aad": b64(aad) if aad else None,
    }

def decrypt_with_aes_eax(key: bytes, encrypted_package: dict) -> bytes:
    """
    Decrypt AES-EAX encrypted data and verify authenticity using the tag.
    
    Parameters:
        key (bytes): AES key used during encryption.
        encrypted_package (dict): Contains nonce, ciphertext, tag, and optional aad.
    
    Returns:
        bytes: The original plaintext if verification succeeds.
    """
    nonce = ub64(encrypted_package["nonce"])
    ciphertext = ub64(encrypted_package["ciphertext"])
    tag = ub64(encrypted_package["tag"])
    aad = ub64(encrypted_package["aad"]) if encrypted_package.get("aad") else None

    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    if aad:
        cipher.update(aad)
    return cipher.decrypt_and_verify(ciphertext, tag)  # Decrypt and verify tag integrity


def encrypt_with_3des(key: bytes, plaintext: bytes) -> dict:
    """
    Encrypt plaintext using Triple DES in CBC mode.
    
    Parameters:
        key (bytes): The 24-byte 3DES key.
        plaintext (bytes): The data to encrypt.
    
    Returns:
        dict: Contains Base64-encoded IV and ciphertext.
    """
    iv = get_random_bytes(8)  # Initialization vector (8 bytes)
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(plaintext, 8))  # Pad to 8-byte blocks before encryption
    return {"iv": b64(iv), "ciphertext": b64(ciphertext)}

def decrypt_with_3des(key: bytes, encrypted_package: dict) -> bytes:
    """
    Decrypt Triple DES CBC-encrypted data.
    
    Parameters:
        key (bytes): The same 3DES key used for encryption.
        encrypted_package (dict): Contains IV and ciphertext.
    
    Returns:
        bytes: The original plaintext after unpadding.
    """
    iv = ub64(encrypted_package["iv"])
    ciphertext = ub64(encrypted_package["ciphertext"])
    cipher = DES3.new(key, DES3.MODE_CBC, iv)
    padded = cipher.decrypt(ciphertext)
    return unpad(padded, 8)



def encrypt_message(algorithm: str, plaintext: bytes):
    """
    Encrypts a message using either AES or Triple DES based on user choice.
    
    Parameters:
        algorithm (str): 'AES' or '3DES'.
        plaintext (bytes): The message to encrypt.
    
    Returns:
        dict: The complete encryption package (key, algorithm, ciphertext, etc.).
    """
    if algorithm == "AES":
        key = get_random_bytes(32)  # 256-bit AES key
        aad = b"metadata"
        encrypted_package = encrypt_with_aes_eax(key, plaintext, aad)
        encrypted_package.update({"algorithm": "AES-EAX", "key": b64(key)})
        return encrypted_package
    elif algorithm == "3DES":
        key = DES3.adjust_key_parity(get_random_bytes(24))  # 192-bit Triple DES key
        encrypted_package = encrypt_with_3des(key, plaintext)
        encrypted_package.update({"algorithm": "3DES-CBC", "key": b64(key)})
        return encrypted_package

def decrypt_message(encrypted_package: dict) -> bytes:
    """
    Decrypts a message automatically based on algorithm metadata in the package.
    
    Parameters:
        encrypted_package (dict): The encryption package containing algorithm info.
    
    Returns:
        bytes: The decrypted plaintext.
    """
    algorithm = encrypted_package["algorithm"]
    if algorithm == "AES-EAX":
        key = ub64(encrypted_package["key"])
        return decrypt_with_aes_eax(key, encrypted_package)
    elif algorithm == "3DES-CBC":
        key = ub64(encrypted_package["key"])
        return decrypt_with_3des(key, encrypted_package)
    else:
        raise ValueError("Unknown algorithm metadata.")



def menu():
    """
    Display a simple menu to let the user choose between AES and Triple DES.
    Keeps prompting until a valid choice is made.
    """
    while True:
        print("Encryption Choice")
        print("1. Triple DES")
        print("2. AES")
        choice = input("Enter your choice (1 or 2): ").strip()
        if choice == "1":
            return "3DES"
        elif choice == "2":
            return "AES"
        else:
            print("Invalid choice! Please enter 1 or 2.\n")



def main():
    """
    Main driver function.
    1. Generates a random Lorem Ipsum paragraph.
    2. Lets the user choose AES or Triple DES.
    3. Encrypts the message.
    4. Optionally decrypts and verifies correctness.
    """
    # Step 1: Generate random Lorem Ipsum each time
    lorem_text = lorem.paragraph()
    plaintext = lorem_text.encode()

    print("Generated Lorem Ipsum:")
    print(lorem_text, "\n")

    # Step 2: Let user choose encryption algorithm
    algorithm = menu()
    print(f"\nSelected algorithm: {algorithm}\n")

    # Step 3: Encrypt message
    encrypted_package = encrypt_message(algorithm, plaintext)
    print("Encryption Result:")
    for k, v in encrypted_package.items():
        print(f"{k}: {v[:80]}{'...' if len(v) > 80 else ''}")

    # Step 4: Ask if user wants to decrypt
    decrypt_choice = input("\nDo you want to decrypt the message now? (y/n): ").strip().lower()
    if decrypt_choice == "y":
        decrypted = decrypt_message(encrypted_package)
        print("\nDecryption Result:")
        print("Recovered message:", decrypted.decode())
        print("Decryption OK?", decrypted == plaintext)
    else:
        print("\nDecryption skipped.")

if __name__ == "__main__":
    main()
