import numpy as np

def mul_karatsuba(poly1: np.ndarray, poly2: np.ndarray) -> np.ndarray:
    """
        Uses Karatsuba’s method method to multiply two polynomials.
        highest order last
        just like (1+2x)(2+3x) = 2 +7x +6x^2


        requirements:
            numpy

        examples:

        >>> mul_karatsuba([1, 2], [2, 3])
        array([2, 7, 6])

        >>> mul_karatsuba([6, 10, 3, 12], [5, 2, 7, 9])
        array([ 30,  62,  77, 190, 135, 111, 108])

    """
    # try to convert input to np.ndarray
    if type(poly1) == list or type(poly1) == tuple:
        poly1 = np.array(poly1, dtype=int)
    if type(poly2) == list or type(poly2) == tuple:
        poly2 = np.array(poly2, dtype=int)

    # checks
    assert isinstance(poly1, np.ndarray), "poly1 must be a numpy array."
    assert isinstance(poly2, np.ndarray), "poly2 must be a numpy array."

    assert np.issubdtype(poly1.dtype, np.integer), "All elements of poly1 must be int."
    assert np.issubdtype(poly2.dtype, np.integer), "All elements of poly2 must be int."

    # trivial solution check (all zeros in one of the polynominals)
    if np.all(poly1 == 0) or np.all(poly2 == 0):
        return np.array([0])

    # Karatsuba’s method prep
    degreemax_1 = len(poly1)
    degreemax_2 = len(poly2)
    degreemax_3 = degreemax_1 + degreemax_2 - 1
    poly3 = np.zeros(degreemax_3, dtype=int)
    layers = 1  # 0 -> 2 parts, 1 -> 4 parts -> Karatsuba’s method 1x, 2 -> 8 parts -> Karatsuba’s method 2x

    if degreemax_1 > degreemax_2:
        while degreemax_1 / (2 ** layers) >= 1:
            layers += 1
    else:
        while degreemax_2 / (2 ** layers) >= 1:
            layers += 1



    # Pad to same length, next power of 2
    n = max(len(poly1), len(poly2))
    m = 1 << (n - 1).bit_length()
    poly1 = np.pad(poly1, (0, m - len(poly1)), 'constant')
    poly2 = np.pad(poly2, (0, m - len(poly2)), 'constant')

    # Recursive Karatsuba
    def karatsuba(a, b):
        if len(a) == 1:
            return np.array([a[0] * b[0]], dtype=int)

        half = len(a) // 2
        a0, a1 = a[:half], a[half:]
        b0, b1 = b[:half], b[half:]

        p0 = karatsuba(a0, b0)
        p2 = karatsuba(a1, b1)
        p1 = karatsuba(a0 + a1, b0 + b1) - p0 - p2

        res = np.zeros(len(a) + len(b) - 1, dtype=int)
        res[:len(p0)] += p0
        res[half:half + len(p1)] += p1
        res[2 * half:2 * half + len(p2)] += p2
        return res

    return karatsuba(poly1, poly2)

# Global counters
add_count = 0
mul_count = 0



def mul_karatsuba_c(poly1: np.ndarray, poly2: np.ndarray) -> np.ndarray:
    """
        Uses Karatsuba’s method method to multiply two polynomials.
        highest order last
        just like (1+2x)(2+3x) = 2 +7x +6x^2

        This version of the function prints the amounth of additions and multiplications.

        requirements:
            numpy

        examples:

        >>> mul_karatsuba_c([1, 2], [2, 3])
        Total multiplications: 3, additions/subtractions: 9
        array([2, 7, 6])

        >>> mul_karatsuba_c([6, 10, 3, 12], [5, 2, 7, 9])
        Total multiplications: 9, additions/subtractions: 50
        array([ 30,  62,  77, 190, 135, 111, 108])
    """
    # try to convert input to np.ndarray
    if type(poly1) == list or type(poly1) == tuple:
        poly1 = np.array(poly1, dtype=int)
    if type(poly2) == list or type(poly2) == tuple:
        poly2 = np.array(poly2, dtype=int)

    # checks
    assert isinstance(poly1, np.ndarray), "poly1 must be a numpy array."
    assert isinstance(poly2, np.ndarray), "poly2 must be a numpy array."

    assert np.issubdtype(poly1.dtype, np.integer), "All elements of poly1 must be int."
    assert np.issubdtype(poly2.dtype, np.integer), "All elements of poly2 must be int."

    # trivial solution check (all zeros in one of the polynominals)
    if np.all(poly1 == 0) or np.all(poly2 == 0):
        return np.array([0])



    global add_count, mul_count
    add_count = 0
    mul_count = 0

    # Pad to same length, next power of 2
    n = max(len(poly1), len(poly2))
    m = 1 << (n - 1).bit_length()
    poly1 = np.pad(poly1, (0, m - len(poly1)), 'constant')
    poly2 = np.pad(poly2, (0, m - len(poly2)), 'constant')

    def karatsuba(a, b):
        global add_count, mul_count

        # Base case: scalar multiplication
        if len(a) == 1:
            mul_count += 1
            return np.array([a[0] * b[0]], dtype=int)

        half = len(a) // 2
        a0, a1 = a[:half], a[half:]
        b0, b1 = b[:half], b[half:]

        # Recursive calls
        p0 = karatsuba(a0, b0)
        p2 = karatsuba(a1, b1)

        # (a0+a1), (b0+b1)
        add_count += len(a0) + len(a1)  # additions for a0+a1
        add_count += len(b0) + len(b1)  # additions for b0+b1
        p1 = karatsuba(a0 + a1, b0 + b1)

        # Subtractions
        add_count += len(p0) + len(p2)
        p1 = p1 - p0 - p2

        # Combine results
        res = np.zeros(len(a) + len(b) - 1, dtype=int)
        res[:len(p0)] += p0;
        add_count += len(p0)
        res[half:half + len(p1)] += p1;
        add_count += len(p1)
        res[2 * half:2 * half + len(p2)] += p2;
        add_count += len(p2)

        return res

    result = karatsuba(poly1, poly2)
    print(f"Total multiplications: {mul_count}, additions/subtractions: {add_count}")
    return result



# examples

print(mul_karatsuba([1, 2], [0, 0]))
# [0]

print(mul_karatsuba([6, 10, 3, 12], [5, 2, 7, 9]))
# [ 30  62  77 190 135 111 108]

print(mul_karatsuba([1, 2], [2, 3]))
# [2 7 6]

print(mul_karatsuba([6, 10, 3, 12], [5, 2, 7, 9]))
print(mul_karatsuba_c([6, 10, 3, 12], [5, 2, 7, 9]))