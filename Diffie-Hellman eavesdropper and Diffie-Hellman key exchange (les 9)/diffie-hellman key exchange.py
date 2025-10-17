# diffie-hellman key exchange


# get diffie-hellman variables
g = 5 # TODO generate g p a b automatically
p = 47 # TODO make p sufficiently large so it can be send publicly
a = 3 # not larger than p
b = 7 # not larger than p

# calculate message
h_a = (g**a) %p
h_b = (g**b) %p

# send message over open/public channel
print(f"person A sends g^a mod p = {h_a}")
print(f"person B sends g^b mod p = {h_b}\n")

# receive message
print(f"person A uses a and message from B to calculate the key")
print(f"key = (message B)^a mod p = {(h_b**a) %p}\n")

print(f"person B uses b and message from A to calculate the key")
print(f"key = (message A)^b mod p = {(h_a**b) %p}\n")

# get key
if ((h_a**b)%p) == ((h_b**a)%p):
    key = (h_a**b) %p

# end of key exchange
print("The key can be used to start a symmetric encryption.")
print(f"In this case the key is {key}")
