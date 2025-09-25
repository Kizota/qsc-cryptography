#generate asymmetric key pair
# TODO - impementing RSA algorithm 

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

#generate private key
private_key = rsa.generate_private_key(
    public_exponent=65537, 
    key_size=2048,
    )

#generate public key from private key
public_key = private_key.public_key()

#save the private key to a file
with open("private_key.pem","wb") as f:
    f.write(private_key.private_bytes(
        encoding=serialization.Encoding.PEM ,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm = serialization.NoEncryption()
    ))

#save the public key to a file 
with open("public_key.pem","wb") as f:
    f.write(public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ))





from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding 


# Message to be signed 
message = b"hello, this is a random message!"

#load the private key
with open("private_key.pem","rb") as f:
    private_Key = serialization.load_pem_private_key(
        f.read(),
        password=None)

#sign the message 
signature = private_key.sign(
    message, 
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
    )

#save the signature to a file 
with open("signature.bin","wb") as f:
    f.write(signature)


#load the public key
with open("public_Key.pem","rb") as f:
     public_key = serialization.load_pem_public_key(f.read())

#load the signature 
with open("signature.bin","rb") as f:
    signature = f.read()

#Message to be verified
message = b"hello, this is a random message!"

#verify the signature 
try:
     public_key.verify(
         signature,
         message,
         padding.PSS(
             mgf=padding.MGF1(hashes.SHA256()),
             salt_length=padding.PSS.MAX_LENGTH
         ),
         hashes.SHA256()
     )
     print ("the signature is valid.")

except:
    [print("the signature is invalid.")]

