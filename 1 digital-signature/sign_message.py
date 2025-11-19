# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.asymmetric import padding 

# # Message to be signed 
# message = b"hello, this is a random message!"

# #sign the message 
# signature = private_key.sign(
#     message, 
#     padding.PSS(
#         mgf=padding.MGF1.(hashes.SHA25()),
#         salt_length=padding.PSS.MAX_LENGTH
#     ),
#     hash
#     )