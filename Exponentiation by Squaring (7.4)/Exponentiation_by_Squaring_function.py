def exponentiation_by_squaring(bas: int, exp: int, N: int = 0):
    """
        calculates bas^exp mod N.
        if no N is inputted than no modules is applied.
        uses the binary exponentiation by squaring algorithm.

        requirements:
            None

        examples:
        >>> exponentiation_by_squaring(7,6)
        117649
        >>> exponentiation_by_squaring(7,6,7)
        0

    """
    if N != 0:

        result = 1  # start value
        bas = bas % N  # reduce base modulo N first

        while exp > 0:
            if exp % 2 == 1:
                # print(result,'*',bas,'mod',N,'=',(bas*result%N)) # show steps
                result = (result * bas) % N  # multiply if bit is 1
            # print('(',bas,')^2','mod',N,'=',(bas*bas)%N) # show steps
            bas = (bas * bas) % N
            exp = exp // 2  # is the same shifting the binary representation one bit to the right — just like popping off the least significant bit.

        return result
    else:
        result = 1  # start value

        while exp > 0:
            if exp % 2 == 1:
                result = (result * bas)  # multiply if bit is 1
            bas = (bas * bas)  # square
            exp = exp // 2  # is the same shifting the binary representation one bit to the right — just like popping off the least significant bit.

        return result

print(exponentiation_by_squaring(5,17,29))
print(exponentiation_by_squaring(5,15,29))
