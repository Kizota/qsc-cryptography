import numpy as np

add_count = 0
mul_count = 0
shift_count = 0

MOD = 998244353   # large prime modulus
ROOT = 3          # primitive root modulo MOD

def mul_NTT(poly1: np.ndarray, poly2: np.ndarray) -> np.ndarray:
    """
        Uses the NTT method to multiply two polynomials modulo MOD.
        Highest order last.
        Example: (1+2x)(2+3x) = 2 + 7x + 6x^2

        requirements:
            numpy

        examples:

        >>> mul_NTT([1, 2], [2, 3])
        array([2, 7, 6])

        >>> mul_NTT([6, 10, 3, 12], [5, 2, 7, 9])
        array([ 30,  62,  77, 190, 135, 111, 108])
    """

    # convert input
    if isinstance(poly1, (list, tuple)):
        poly1 = np.array(poly1, dtype=int)
    if isinstance(poly2, (list, tuple)):
        poly2 = np.array(poly2, dtype=int)

    # checks
    assert isinstance(poly1, np.ndarray), "poly1 must be a numpy array."
    assert isinstance(poly2, np.ndarray), "poly2 must be a numpy array."

    assert np.issubdtype(poly1.dtype, np.integer), "All elements of poly1 must be int."
    assert np.issubdtype(poly2.dtype, np.integer), "All elements of poly2 must be int."

    # trivial solution
    if np.all(poly1 == 0) or np.all(poly2 == 0):
        print(f"Total multiplications: 0, additions/subtractions: 0, bit shifts: 0")
        return np.array([0], dtype=int)

    # counters
    global add_count, mul_count, shift_count
    add_count = 0
    mul_count = 0
    shift_count = 0



    # ---------------- NTT IMPLEMENTATION (list-based, Python ints) ----------------
    def mod_pow(base, exp, mod):
        result = 1
        base %= mod
        while exp > 0:
            if exp & 1:
                result = (result * base) % mod
            base = (base * base) % mod
            exp >>= 1
        return result

    def bit_reverse_permute(a):
        # In-place bit-reversal permutation
        n = len(a)
        j = 0
        for i in range(1, n):
            bit = n >> 1
            while j & bit:
                j ^= bit
                bit >>= 1
            j ^= bit
            if i < j:
                a[i], a[j] = a[j], a[i]

    def NTT(a, invert=False):
        n = len(a)
        bit_reverse_permute(a)

        length = 2
        while length <= n:
            wlen = mod_pow(ROOT, (MOD - 1) // length, MOD)
            if invert:
                wlen = mod_pow(wlen, MOD - 2, MOD)
            for i in range(0, n, length):
                w = 1
                half = length // 2
                for j in range(i, i + half):
                    u = a[j]
                    v = (a[j + half] * w) % MOD
                    a[j] = (u + v) % MOD
                    a[j + half] = (u - v) % MOD
                    if a[j + half] < 0:
                        a[j + half] += MOD
                    w = (w * wlen) % MOD
            length <<= 1

        if invert:
            inv_n = mod_pow(n, MOD - 2, MOD)
            for i in range(n):
                a[i] = (a[i] * inv_n) % MOD

        return a

    # pad to next power of two (must be >= len1+len2-1)
    needed = len(poly1) + len(poly2) - 1
    n = 1
    while n < needed:
        n <<= 1

    # Work with Python ints in lists to avoid overflow
    f = [int(x) % MOD for x in poly1] + [0] * (n - len(poly1))
    g = [int(x) % MOD for x in poly2] + [0] * (n - len(poly2))

    # Forward NTT
    NTT(f, invert=False)
    NTT(g, invert=False)

    # Pointwise multiplication
    for i in range(n):
        f[i] = (f[i] * g[i]) % MOD

    # Inverse NTT
    NTT(f, invert=True)

    # Trim to exact length and convert back to numpy ints
    result = np.array(f[:needed], dtype=int)

    return result



def mul_NTT_c(poly1: np.ndarray, poly2: np.ndarray) -> np.ndarray:
    """
        Uses the NTT method to multiply two polynomials modulo MOD.
        Highest order last.
        Example: (1+2x)(2+3x) = 2 + 7x + 6x^2

        This version prints the amount of additions, multiplications, and bit shifts.

        requirements:
            numpy

        examples:

        >>> mul_NTT_c([1, 2], [2, 3])
        Total multiplications: 413, additions/subtractions: 30, bit shifts: 272
        array([2, 7, 6])

        >>> mul_NTT_c([6, 10, 3, 12], [5, 2, 7, 9])
        Total multiplications: 626, additions/subtractions: 84, bit shifts: 396
        array([ 30,  62,  77, 190, 135, 111, 108])
    """

    # convert input
    if isinstance(poly1, (list, tuple)):
        poly1 = np.array(poly1, dtype=int)
    if isinstance(poly2, (list, tuple)):
        poly2 = np.array(poly2, dtype=int)

    # checks
    assert isinstance(poly1, np.ndarray), "poly1 must be a numpy array."
    assert isinstance(poly2, np.ndarray), "poly2 must be a numpy array."

    assert np.issubdtype(poly1.dtype, np.integer), "All elements of poly1 must be int."
    assert np.issubdtype(poly2.dtype, np.integer), "All elements of poly2 must be int."

    # trivial solution
    if np.all(poly1 == 0) or np.all(poly2 == 0):
        print(f"Total multiplications: 0, additions/subtractions: 0, bit shifts: 0")
        return np.array([0], dtype=int)

    # counters
    global add_count, mul_count, shift_count
    add_count = 0
    mul_count = 0
    shift_count = 0



    # ---------------- NTT IMPLEMENTATION (list-based, Python ints) ----------------
    def mod_pow(base, exp, mod):
        global mul_count, shift_count
        result = 1
        base %= mod
        while exp > 0:
            if exp & 1:
                result = (result * base) % mod
                mul_count += 1
            base = (base * base) % mod
            mul_count += 1
            exp >>= 1
            shift_count += 1
        return result

    def bit_reverse_permute(a):
        # In-place bit-reversal permutation
        global add_count, shift_count
        n = len(a)
        j = 0
        for i in range(1, n):
            bit = n >> 1
            while j & bit:
                j ^= bit
                bit >>= 1
                shift_count += 1
            j ^= bit
            if i < j:
                a[i], a[j] = a[j], a[i]
                add_count += 2  # count swap as two assignments

    def NTT(a, invert=False):
        global add_count, mul_count, shift_count
        n = len(a)
        bit_reverse_permute(a)

        length = 2
        while length <= n:
            wlen = mod_pow(ROOT, (MOD - 1) // length, MOD)
            if invert:
                wlen = mod_pow(wlen, MOD - 2, MOD)
            for i in range(0, n, length):
                w = 1
                half = length // 2
                for j in range(i, i + half):
                    u = a[j]
                    v = (a[j + half] * w) % MOD
                    mul_count += 1
                    a[j] = (u + v) % MOD
                    a[j + half] = (u - v) % MOD
                    if a[j + half] < 0:
                        a[j + half] += MOD
                    add_count += 2
                    w = (w * wlen) % MOD
                    mul_count += 1
            length <<= 1
            shift_count += 1

        if invert:
            inv_n = mod_pow(n, MOD - 2, MOD)
            for i in range(n):
                a[i] = (a[i] * inv_n) % MOD
                mul_count += 1

        return a

    # pad to next power of two (must be >= len1+len2-1)
    needed = len(poly1) + len(poly2) - 1
    n = 1
    while n < needed:
        n <<= 1
        shift_count += 1

    # Work with Python ints in lists to avoid overflow
    f = [int(x) % MOD for x in poly1] + [0] * (n - len(poly1))
    g = [int(x) % MOD for x in poly2] + [0] * (n - len(poly2))

    # Forward NTT
    NTT(f, invert=False)
    NTT(g, invert=False)

    # Pointwise multiplication
    for i in range(n):
        f[i] = (f[i] * g[i]) % MOD
        mul_count += 1

    # Inverse NTT
    NTT(f, invert=True)

    # Trim to exact length and convert back to numpy ints
    result = np.array(f[:needed], dtype=int)

    print(f"Total multiplications: {mul_count}, additions/subtractions: {add_count}, bit shifts: {shift_count}")
    return result



# examples
print(mul_NTT([1, 2], [2, 3]))
print(mul_NTT([6, 10, 3, 12], [5, 2, 7, 9]) ,'\n')

print(mul_NTT_c([1, 2], [2, 3]))
# [2, 7, 6]

print(mul_NTT_c([6, 10, 3, 12], [5, 2, 7, 9]))
# [ 30  62  77 190 135 111 108]