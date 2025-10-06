# diffie-hellman evedropper
g = 5
p = 47
h_a = 38
h_b = 3

# find a and b
for n in range(p):
    if (g**n) %p == h_a:
        a = n
    if (g**n) %p == h_b:
        b = n

print(f"{a} {h_a} -> {g}^{a} mod {p} = {(g**a) %p}")
print(f"{b} {h_b} -> {g}^{b} mod {p} = {(g**b) %p}")
key = (h_b**a)%p
print(f"key = {(h_a**b) %p} = {(h_b**a)%p}")

for char in ("EQPITCVWNCVKQPU"):
    x = chr(ord(char)-key)
    print(x)

# longer-diffie hellman
print('\nlonger:\n')
g = 1234
p = 1007
h_a = 2345
h_b = 4567

# find a and b
for n in range(p):
    if (g**n) %p == h_a:
        a = n
    if (g**n) %p == h_b:
        b = n

print(f"{a} {h_a} -> {g}^{a} mod {p} = {(g**a) %p}")
print(f"{b} {h_b} -> {g}^{b} mod {p} = {(g**b) %p}")
key = (h_b**a)%p
print(f"key = {(h_a**b) %p} = {(h_b**a)%p}")