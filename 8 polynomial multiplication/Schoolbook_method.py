import numpy as np

def mul_school(poly1: np.ndarray, poly2: np.ndarray) -> np.ndarray:
    """
        Uses the school method to multiply two polynomials.
        highest order last
        just like (1+2x)(2+3x) = 2 +7x +6x^2

        this method works by doing every step individualy:
        1*2 +1*3x +2x*2 +2x*3x

        requirements:
            numpy

        examples:

        >>> mul_school([1, 2], [2, 3])
        array([2, 7, 6])

        >>> mul_school([0, 0], [2, 3])
        array([0])

        >>> mul_school([6, 10, 3, 12], [5, 2, 7, 9])
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

    # schoolbook method
    degreemax_1 = len(poly1)
    degreemax_2 = len(poly2)
    degreemax_3 = degreemax_1 + degreemax_2 - 1
    poly3 = np.zeros(degreemax_3, dtype=int)

    for n in range(degreemax_1):
        for n2 in range(degreemax_2):
            poly3[n + n2] = poly3[n + n2] + poly1[n] * poly2[n2]

    return poly3


# same function with couter
def mul_school_c(poly1: np.ndarray, poly2: np.ndarray) -> np.ndarray:
    """
        Uses the school method to multiply two polynomials.
        Highest order last,
        just like (1+2x)(2+3x) = 2 +7x +6x^2

        this method works by doing every step individualy:
        1*2 +1*3x +2x*2 +2x*3x

        This version of the function prints the amounth of additions and multiplications.

        requirements:
            numpy

        examples:

        >>> mul_school_c([1, 2], [2, 3])
        We have multiplied 4 times and added 4 times.
        array([2, 7, 6])

        >>> mul_school_c([0, 0], [2, 3])
        We have multiplied 0 times and added 0 times.
        array([0])

        >>> mul_school_c([6, 10, 3, 12], [5, 2, 7, 9])
        We have multiplied 16 times and added 16 times.
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

    # couter
    add = 0
    mul = 0

    # trivial solution check (all zeros in one of the polynominals)
    if np.all(poly1 == 0) or np.all(poly2 == 0):
        print(f"We have multiplied 0 times and added 0 times.")
        return np.array([0])

    # schoolbook method
    degreemax_1 = len(poly1)
    degreemax_2 = len(poly2)
    degreemax_3 = degreemax_1 + degreemax_2 - 1
    poly3 = np.zeros(degreemax_3, dtype=int)

    for n in range(degreemax_1):
        for n2 in range(degreemax_2):
            poly3[n + n2] = poly3[n + n2] + poly1[n] * poly2[n2]
            add += 1
            mul += 1

    print(f"We have multiplied {mul} times and added {add} times.")
    return poly3


# examples

print(mul_school_c([1, 2], [2, 3]))
print(mul_school_c([6, 10, 3, 12], [5, 2, 7, 9]))
print(mul_school([1, 2], [3, 4]))
# mul_school([6, 10, 3, 12], [5, 2, 7, 9])
mul_school_c([0, 0], [2, 3])