import matplotlib.pyplot as plt
import numpy as np
from fractions import Fraction

# Create x values
x1 = np.linspace(0, 10, 10 + 1)
y1 = np.zeros((len(x1), 1))
y2 = np.zeros((len(x1), 1))
y3 = np.zeros((len(x1), 1))
y4 = np.zeros((len(x1), 1))
y5 = np.zeros((len(x1), 1))
y6 = np.zeros((len(x1), 1))

x2 = np.linspace(0, 1000, int(1000 + 1))
y1a = np.zeros((len(x2), 1))
y2a = np.zeros((len(x2), 1))
y3a = np.zeros((len(x2), 1))
y4a = np.zeros((len(x2), 1))
y5a = np.zeros((len(x2), 1))
y6a = np.zeros((len(x2), 1))


# counters_func-------------------------------------------------------------\
def mul_school_c(poly1: np.ndarray, poly2: np.ndarray) -> np.ndarray:
    """
        Uses the school method to multiply two polynominals.
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

    # print(f"We have multiplied {mul} times and added {add} times.")
    return [poly3, mul, add, 0]


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
    # print(f"Total multiplications: {mul_count}, additions/subtractions: {add_count}")

    return result, mul_count, add_count, 0


def toom3_mul_c(poly1, poly2):
    """
    Multiply two polynomials using Toom-3 (Toom-Cook 3-way split).
    Input: lists of coefficients [a0, a1, ..., an] for a0 + a1*x + ...
    Output: list of integer coefficients of the product (no trailing zeros).
    Also prints counts of multiplications, additions/subtractions, and shifts.

    examples:

        >>> toom3_mul_c([1, 2], [2, 3])
        Operation counts → multiplies: 17 adds/subs: 44 shifts: 3
        [2, 7, 6]

        >>> toom3_mul_c([0, 0], [2, 3])
        Operation counts → multiplies: 17 adds/subs: 40 shifts: 3
        [0]

        >>> toom3_mul_c([6, 10, 3, 12], [5, 2, 7, 9])
        Operation counts → multiplies: 47 adds/subs: 111 shifts: 9
        [30, 62, 77, 190, 135, 111, 108]
    """

    # --- counters ---
    counts = {"mult": 0, "addsub": 0, "shift": 0}

    # --- helpers inline ---
    def to_frac(p):
        return [Fraction(x) for x in p]

    def poly_add(p, q):
        n = max(len(p), len(q))
        res = []
        for i in range(n):
            val = (p[i] if i < len(p) else Fraction(0)) + (q[i] if i < len(q) else Fraction(0))
            res.append(val)
            counts["addsub"] += 1
        return res

    def poly_sub(p, q):
        n = max(len(p), len(q))
        res = []
        for i in range(n):
            val = (p[i] if i < len(p) else Fraction(0)) - (q[i] if i < len(q) else Fraction(0))
            res.append(val)
            counts["addsub"] += 1
        return res

    def poly_scalar_mul(p, c):
        res = []
        for coeff in p:
            res.append(c * coeff)
            counts["mult"] += 1
        return res

    def poly_shift(p, k):
        counts["shift"] += len(p)  # count each coefficient shift
        return [Fraction(0)] * k + p

    def base_mul(p, q):
        res = [Fraction(0)] * (len(p) + len(q) - 1) if p and q else []
        for i in range(len(p)):
            for j in range(len(q)):
                res[i + j] += p[i] * q[j]
                counts["mult"] += 1
                if res[i + j] != 0:  # addition into slot
                    counts["addsub"] += 1
        return res

    poly1 = to_frac(poly1)
    poly2 = to_frac(poly2)

    # --- split into 3 parts ---
    m = max(len(poly1), len(poly2))
    k = (m + 2) // 3
    a0, a1p, a2 = poly1[:k], poly1[k:2 * k], poly1[2 * k:]
    b0, b1p, b2 = poly2[:k], poly2[k:2 * k], poly2[2 * k:]

    def eval_parts(parts, x):
        p0, p1, p2 = parts
        return poly_add(p0,
                        poly_add(poly_scalar_mul(p1, x),
                                 poly_scalar_mul(p2, x * x)))

    # --- evaluate at points ---
    R0 = base_mul(eval_parts((a0, a1p, a2), 0), eval_parts((b0, b1p, b2), 0))  # C0
    R1 = base_mul(eval_parts((a0, a1p, a2), 1), eval_parts((b0, b1p, b2), 1))
    Rm1 = base_mul(eval_parts((a0, a1p, a2), -1), eval_parts((b0, b1p, b2), -1))
    R2 = base_mul(eval_parts((a0, a1p, a2), 2), eval_parts((b0, b1p, b2), 2))
    Rinf = base_mul(a2, b2)  # C4

    # --- interpolation ---
    C0 = R0
    C4 = Rinf

    V1 = poly_sub(poly_sub(R1, C0), C4)  # C1 + C2 + C3
    Vm1 = poly_sub(poly_sub(Rm1, C0), C4)  # -C1 + C2 - C3
    V2 = poly_sub(poly_sub(R2, C0), poly_scalar_mul(C4, 16))  # 2C1 + 4C2 + 8C3

    S = poly_sub(V1, Vm1)  # 2C1 + 2C3
    C2 = poly_scalar_mul(poly_add(V1, Vm1), Fraction(1, 2))  # (V1+Vm1)/2

    V2_prime = poly_sub(V2, poly_scalar_mul(C2, 4))  # 2C1 + 8C3
    C3 = poly_scalar_mul(poly_sub(V2_prime, S), Fraction(1, 6))  # (V2' - S)/6
    C1 = poly_scalar_mul(poly_sub(S, poly_scalar_mul(C3, 2)), Fraction(1, 2))  # (S - 2C3)/2

    # --- recombine ---
    res = C0
    res = poly_add(res, poly_shift(C1, k))
    res = poly_add(res, poly_shift(C2, 2 * k))
    res = poly_add(res, poly_shift(C3, 3 * k))
    res = poly_add(res, poly_shift(C4, 4 * k))

    # convert Fractions back to ints if exact
    out = []
    for c in res:
        out.append(int(c) if c.denominator == 1 else float(c))

    # --- trim trailing zeros ---
    while out and out[-1] == 0:
        out.pop()

    # --- print counts ---
    # print("Operation counts → multiplies:", counts["mult"],
    #       "adds/subs:", counts["addsub"],
    #       "shifts:", counts["shift"])

    if out == []:
        return [0]
    else:
        return out, counts["mult"], counts["addsub"], counts["shift"]


def mul_toom3_school_c(poly1, poly2, threshold=4):
    """
    Hybrid Toom-3 / schoolbook polynomial multiplication with operation counts.
    At each recursive multiplication, the threshold is checked:
    - If polynomials are small (len <= threshold), use schoolbook multiplication.
    - Otherwise, use Toom-3 splitting and recurse.
    Prints counts of multiplications, additions/subtractions, and shifts.

        examples:

        >>> mul_toom3_school_c([1, 2], [2, 3])
        Operation counts → multiplies: 4 adds/subs: 4 shifts: 0
        [2, 7, 6]

        >>> mul_toom3_school_c([0, 0], [2, 3])
        Operation counts → multiplies: 4 adds/subs: 4 shifts: 0
        [0]

        >>> mul_toom3_school_c([6, 10, 3, 12], [5, 2, 7, 9])
        Operation counts → multiplies: 16 adds/subs: 16 shifts: 0
        [30, 62, 77, 190, 135, 111, 108]

        >>> mul_toom3_school_c([6, 10, 3, 12], [5, 2, 7, 9],3)
        Operation counts → multiplies: 47 adds/subs: 111 shifts: 9
        [30, 62, 77, 190, 135, 111, 108]
    """

    counts = {"mult": 0, "addsub": 0, "shift": 0}

    # --- helpers ---
    def to_frac(p):
        return [Fraction(x) for x in p]

    def poly_add(p, q):
        n = max(len(p), len(q))
        res = []
        for i in range(n):
            val = (p[i] if i < len(p) else Fraction(0)) + (q[i] if i < len(q) else Fraction(0))
            res.append(val)
            counts["addsub"] += 1
        return res

    def poly_sub(p, q):
        n = max(len(p), len(q))
        res = []
        for i in range(n):
            val = (p[i] if i < len(p) else Fraction(0)) - (q[i] if i < len(q) else Fraction(0))
            res.append(val)
            counts["addsub"] += 1
        return res

    def poly_scalar_mul(p, c):
        res = []
        for coeff in p:
            res.append(c * coeff)
            counts["mult"] += 1
        return res

    def poly_shift(p, k):
        counts["shift"] += len(p)  # count each coefficient shift
        return [Fraction(0)] * k + p

    def schoolbook_mul(p, q):
        if not p or not q:
            return []
        res = [Fraction(0)] * (len(p) + len(q) - 1)
        for i in range(len(p)):
            for j in range(len(q)):
                res[i + j] += p[i] * q[j]
                counts["mult"] += 1
                counts["addsub"] += 1
        return res

    def recurse(p, q):
        aF = to_frac(p)
        bF = to_frac(q)
        m = max(len(aF), len(bF))

        if m <= threshold:
            return schoolbook_mul(aF, bF)

        # --- Toom-3 split ---
        k = (m + 2) // 3
        a0, a1p, a2 = aF[:k], aF[k:2 * k], aF[2 * k:]
        b0, b1p, b2 = bF[:k], bF[k:2 * k], bF[2 * k:]

        def eval_parts(parts, x):
            p0, p1, p2 = parts
            n = max(len(p0), len(p1), len(p2))
            res = []
            for i in range(n):
                v = (p0[i] if i < len(p0) else Fraction(0)) \
                    + (p1[i] if i < len(p1) else Fraction(0)) * x \
                    + (p2[i] if i < len(p2) else Fraction(0)) * x * x
                res.append(v)
                counts["addsub"] += 2
                if i < len(p1): counts["mult"] += 1
                if i < len(p2): counts["mult"] += 2
            return res

        # --- recursive multiplications ---
        R0 = recurse(eval_parts((a0, a1p, a2), 0), eval_parts((b0, b1p, b2), 0))
        R1 = recurse(eval_parts((a0, a1p, a2), 1), eval_parts((b0, b1p, b2), 1))
        Rm1 = recurse(eval_parts((a0, a1p, a2), -1), eval_parts((b0, b1p, b2), -1))
        R2 = recurse(eval_parts((a0, a1p, a2), 2), eval_parts((b0, b1p, b2), 2))
        Rinf = recurse(a2, b2)

        # --- interpolation ---
        C0 = R0
        C4 = Rinf

        V1 = poly_sub(poly_sub(R1, C0), C4)
        Vm1 = poly_sub(poly_sub(Rm1, C0), C4)
        V2 = poly_sub(poly_sub(R2, C0), poly_scalar_mul(C4, 16))

        S = poly_sub(V1, Vm1)
        C2 = poly_scalar_mul(poly_add(V1, Vm1), Fraction(1, 2))

        V2_prime = poly_sub(V2, poly_scalar_mul(C2, 4))
        C3 = poly_scalar_mul(poly_sub(V2_prime, S), Fraction(1, 6))
        C1 = poly_scalar_mul(poly_sub(S, poly_scalar_mul(C3, 2)), Fraction(1, 2))

        # --- recombine ---
        res = C0
        res = poly_add(res, poly_shift(C1, k))
        res = poly_add(res, poly_shift(C2, 2 * k))
        res = poly_add(res, poly_shift(C3, 3 * k))
        res = poly_add(res, poly_shift(C4, 4 * k))

        return res

    # --- run recursion ---
    res = recurse(poly1, poly2)

    # convert Fractions back to ints if exact
    out = [int(c) if c.denominator == 1 else float(c) for c in res]

    # trim trailing zeros
    while out and out[-1] == 0:
        out.pop()

    # print("Operation counts → multiplies:", counts["mult"],
    #       "adds/subs:", counts["addsub"],
    #       "shifts:", counts["shift"])

    return [0] if out == [] else out, counts["mult"], counts["addsub"], counts["shift"]


add_count = 0
mul_count = 0
shift_count = 0

MOD = 998244353  # large prime modulus
ROOT = 3  # primitive root modulo MOD


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

    # print(f"Total multiplications: {mul_count}, additions/subtractions: {add_count}, bit shifts: {shift_count}")
    return result, mul_count, add_count, shift_count


# counters_func-------------------------------------------------------------/

def trim(arr):
    last_nonzero = np.max(np.nonzero(arr)) if np.any(arr) else -1
    # Slice up to that index
    return arr[:last_nonzero + 1]


# Define three functions of x
for n in range(len(x1)):
    if n > 1 and n < len(x1):
        ans1, mul, add, shift = mul_school_c([x for x in range(int(x1[0]), int(x1[n]))],
                                             [x for x in range(int(x1[0]), int(x1[n]))])
        if np.all(ans1 == ans1):
            y1[n] = mul * 4 + add + shift

        ans2, mul, add, shift = mul_karatsuba_c([x for x in range(int(x1[0]), int(x1[n]))],
                                                [x for x in range(int(x1[0]), int(x1[n]))])
        ans2 = trim(ans2)
        if np.all(ans2 == ans1):
            y2[n] = mul * 4 + add + shift
        # mul_toom3_school_c([x for x in range(1, int(10e3), 1)], [x for x in range(1, int(10e3), 1)], 3))

        ans2, mul, add, shift = toom3_mul_c([x for x in range(int(x1[0]), int(x1[n]))],
                                            [x for x in range(int(x1[0]), int(x1[n]))])
        ans2 = trim(ans2)
        if np.all(ans2 == ans1):
            y3[n] = mul * 4 + add + shift

        ans2, mul, add, shift = mul_toom3_school_c([x for x in range(int(x1[0]), int(x1[n]))],
                                                   [x for x in range(int(x1[0]), int(x1[n]))])
        ans2 = trim(ans2)
        if np.all(ans2 == ans1):
            y4[n] = mul * 4 + add + shift

        ans2, mul, add, shift = mul_toom3_school_c([x for x in range(int(x1[0]), int(x1[n]))],
                                                   [x for x in range(int(x1[0]), int(x1[n]))], 3)
        ans2 = trim(ans2)
        if np.all(ans2 == ans1):
            y5[n] = mul * 4 + add + shift

        ans2, mul, add, shift = mul_NTT_c([x for x in range(int(x1[0]), int(x1[n]))],
                                          [x for x in range(int(x1[0]), int(x1[n]))])
        ans2 = trim(ans2)
        if np.all(ans2 == ans1):
            y6[n] = mul * 4 + add + shift

        # y2[n] = x1[n]
        # y3[n] = x1[n]
        # y4[n] = x1[n]
        # y5[n] = x1[n]
        # y6[n] = x1[n]

for n in range(len(x2)):
    if n > 1 and n < len(x2):
        ans1, mul, add, shift = mul_school_c([x for x in range(int(x2[0]), int(x2[n]))],
                                             [x for x in range(int(x2[0]), int(x2[n]))])
        if np.all(ans1 == ans1):
            y1a[n] = mul * 4 + add + shift

        ans2, mul, add, shift = mul_karatsuba_c([x for x in range(int(x2[0]), int(x2[n]))],
                                                [x for x in range(int(x2[0]), int(x2[n]))])
        ans2 = trim(ans2)
        if np.all(ans2 == ans1):
            y2a[n] = mul * 4 + add + shift

        ans2, mul, add, shift = toom3_mul_c([x for x in range(int(x2[0]), int(x2[n]))],
                                            [x for x in range(int(x2[0]), int(x2[n]))])
        ans2 = trim(ans2)
        if np.all(ans2 == ans1):
            y3a[n] = mul * 4 + add + shift

        ans2, mul, add, shift = mul_toom3_school_c([x for x in range(int(x2[0]), int(x2[n]))],
                                                   [x for x in range(int(x2[0]), int(x2[n]))])
        ans2 = trim(ans2)
        if np.all(ans2 == ans1):
            y4a[n] = mul * 4 + add + shift

        ans2, mul, add, shift = mul_toom3_school_c([x for x in range(int(x2[0]), int(x2[n]))],
                                                   [x for x in range(int(x2[0]), int(x2[n]))], 3)
        ans2 = trim(ans2)
        if np.all(ans2 == ans1):
            y5a[n] = mul * 4 + add + shift

        ans2, mul, add, shift = mul_NTT_c([x for x in range(int(x2[0]), int(x2[n]))],
                                          [x for x in range(int(x2[0]), int(x2[n]))])
        ans2 = trim(ans2)
        if np.all(ans2 == ans1):
            y6a[n] = mul * 4 + add + shift

# Create two subplots side by side
fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(12, 5))

# First plot
ax1.plot(x1, y1, label='schoolbook')
ax1.plot(x1, y2, label='karatsuba')
ax1.plot(x1, y3, label='toom3')
ax1.plot(x1, y4, label='toom3+school')
ax1.plot(x1, y5, label='toom3+school3')
ax1.plot(x1, y6, label='NTT')
ax1.set_xlabel('size')
ax1.set_ylabel('cost')
# ax1.set_title('Graph 1: small range')
ax1.legend()

# Second plot
ax2.plot(x2, y1a, label='schoolbook')
ax2.plot(x2, y2a, label='karatsuba')
ax2.plot(x2, y3a, label='toom3')
ax2.plot(x2, y4a, label='toom3+school')
ax2.plot(x2, y5a, label='toom3+school3')
ax2.plot(x2, y6a, label='NTT')
ax2.set_xlabel('size')
ax2.set_ylabel('cost')
# ax2.set_title('Graph 2: large range')
ax2.legend()

# Adjust layout and show
plt.tight_layout()
plt.show()
fig.savefig("my_plot.png")