from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from secrets import token_bytes 
#generate the key 
key = token_bytes(16)

#AES encrypting function
def AES_encrypt(msg):
   cipher = AES.new(key, AES.MODE_EAX)
   nonce = cipher.nonce
   ciphertext, tag = cipher.encrypt_and_digest(msg.encode("ascii"))
   return nonce, ciphertext, tag 

#AES decrypting function
def AES_decrypt(nonce, ciphertext, tag):
   cipher = AES.new(key, AES.MODE_EAX, nonce = nonce)
   plaintext = cipher.decrypt(ciphertext)
   try:  
      cipher.verify(tag)
      return plaintext.decode('ascii')
   except:
      return False
  
#main program