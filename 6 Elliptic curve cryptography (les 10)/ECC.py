# ECC


# euclides extened algoritm for inverse modulus
def euclides_extened(a: int, b: int) -> (int, int, int):
    """
        Uses the euclides algoritm to find the gcd(a,b)

        requirements:
            None

        example:
        >>> euclides_extened(900,1140)
        (60, -5, 4)

    """
    #
    assert type(a) == int, "a must be whole integer."
    assert type(b) == int, "b must be whole integer."
    assert a != b, "a and b must be different."
    assert a != 0, "a must not be 0."
    assert b != 0, "b must not be 0."

    # set a en b where a > b
    if a < b:
        rem = a
        a = b
        b = rem
        switch = True
    else:
        rem = b
        switch = False

    # do eulclides extended algoritm (AI)
    x0, x1 = 1, 0
    y0, y1 = 0, 1

    while b != 0:
        q = a // b  # only whole devision
        a, b = b, a % b  # modulus
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
        # print(a, y0, x0)

    if switch:  # conpensatie if a and b where switched in the beginning
        return a, y0, x0  # gcd, x, y
    else:
        return a, x0, y0  # gcd, x, y

# eliptic curve cryptography add function
def ECC_add(P: (int, int), Q: (int, int), a=2, b=2, p=17):
        """
            adds point P + Q in eliptic curve cryptography.
            with Y^3 = x^3 + aX^2 + b mod p

            requirements:
                None

            example:
            >>> ECC_add((2,7),(5,2))
            [9, 16]
            >>> ECC_add([3,6],[3,6])
            [12, 2]
            >>> ECC_add([5,4],[0,3],a=3,b=2,p=7)
            [4, 6]
        """
        assert (4 * (a ** 3) + 27 * (
                    b ** 2)) % p != 0, '4a^3 +27b^2 = 0 mod p condition detected \neliptic curve not valid'

        R = [0, 0]

        if P == Q:

            # modular inverse of labda
            deler = (2 * P[1])

            if deler < 0:  # neagtive correction
                deler = abs(deler)
                neg = -1
            else:
                neg = 1

            t1, t2, t3 = euclides_extened(deler, p)
            if ((deler * t2) % p) == 1:
                deler = t2
            else:
                deler = t3

            labda = ((3 * (P[0] ** 2) + a) * neg * deler) % p
            R[0] = (labda ** 2 - 2 * P[0]) % p
            R[1] = (labda * (P[0] - R[0]) - P[1]) % p

        elif P[0] == 0 and P[1] == 0:  # give loop after O
            R = Q
        elif P[0] == Q[0] and P[1] == p - 1 * Q[1]:  # set 0 ,0
            print(f'p = -p -> {P} = {Q}')
            print("dy/dx -> inf with dx = 0")
        else:

            # modular inverse of labda
            deler = (Q[0] - P[0])

            if deler < 0:  # neagtive correction
                deler = abs(deler)
                neg = -1
            else:
                neg = 1

            t1, t2, t3 = euclides_extened(deler, p)
            if ((deler * t2) % p) == 1:
                deler = t2
            else:
                deler = t3

            labda = ((Q[1] - P[1]) * neg * deler) % p
            R[0] = (labda ** 2 - P[0] - Q[0]) % p
            R[1] = (labda * (P[0] - R[0]) - P[1]) % p

        return R

# exercises

# 9.5
for n in range(8):
    print(f'{n} -> {(n**2) %7}')

P = [0,3]
E = P
print(f'1P -> {E}')
for n in range(10):
    E = ECC_add(E,P,a= 3,b=2,p=7)
    print(f'{n+2}P -> {E}')


#9.8
P = (8,10)
Q = (14,23)

P16 = ECC_add(P,Q,a= 4,b=20,p=29)
print(f'16P -> {P16}')
P2 = ECC_add(P,P,a= 4,b=20,p=29)
print(f'2P -> {P2}')

#9.9
print('DHKE protocol based on elliptic curves\n---\n')
bP = [5,9]
P = [0,0] # ?
a = 1
b = 6
p = 11

#print('public key B = (5,9)')

print('person A chooses private key a = 6')
# calculate aP

# aP = P
# for n in range(5): # 1P +1P*(n-1) with n {0,1,2,...}
#     aP = ECC_add(aP,P,a=a,b=b,p=p)
# print(f"aP = {aP}")

print('person B chooses private key b = ?')

print('person B sends public key B = (5,9)')
#print(f'person A sends public key A = aP = 6*P = {aP}')

print('Person A calculates a(bP) = a*B')
#print('Person B calculates b(aP) = b*A')
## calculate a*B = abP
abP = bP
for n in range(5): # 1P +1P*(n-1) with n {0,1,2,...} a_k = 6
    abP = ECC_add(abP,bP,a=a,b=b,p=p)
print(f"abP = {abP}")

print(f'Person A and person B both have symmetric  key abP = {abP}')
