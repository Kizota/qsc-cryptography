from fractions import Fraction

def mul_toom3_school(poly1, poly2, threshold=4):
    """
    Multiply two polynomials using a hybrid Toom-3 / schoolbook approach.
    At each recursive multiplication, the threshold is checked:
    - If polynomials are small (len <= threshold), use schoolbook multiplication.
    - Otherwise, use Toom-3 splitting and recurse.

    examples:

        >>> mul_toom3_school([1, 2], [2, 3])
        [2, 7, 6]

        >>> mul_toom3_school([0, 0], [2, 3])
        [0]

        >>> mul_toom3_school([6, 10, 3, 12], [5, 2, 7, 9])
        [30, 62, 77, 190, 135, 111, 108]
    """

    # --- helpers ---
    def to_frac(p): return [Fraction(x) for x in p]

    def poly_add(p, q):
        n = max(len(p), len(q))
        return [(p[i] if i < len(p) else Fraction(0)) +
                (q[i] if i < len(q) else Fraction(0)) for i in range(n)]

    def poly_sub(p, q):
        n = max(len(p), len(q))
        return [(p[i] if i < len(p) else Fraction(0)) -
                (q[i] if i < len(q) else Fraction(0)) for i in range(n)]

    def poly_scalar_mul(p, c):
        return [c * coeff for coeff in p]

    def poly_shift(p, k):
        return [Fraction(0)]*k + p

    def schoolbook_mul(p, q):
        if not p or not q:
            return []
        res = [Fraction(0)]*(len(p)+len(q)-1)
        for i in range(len(p)):
            for j in range(len(q)):
                res[i+j] += p[i]*q[j]
        return res

    # --- convert to Fractions ---
    aF = to_frac(poly1)
    bF = to_frac(poly2)

    # --- check threshold ---
    m = max(len(aF), len(bF))
    if m <= threshold:
        res = schoolbook_mul(aF, bF)
        out = [int(c) if c.denominator == 1 else float(c) for c in res]
        while out and out[-1] == 0:
            out.pop()
        return [0] if out == [] else out

    # --- Toom-3 split ---
    k = (m + 2) // 3
    a0, a1p, a2 = aF[:k], aF[k:2*k], aF[2*k:]
    b0, b1p, b2 = bF[:k], bF[k:2*k], bF[2*k:]

    def eval_parts(parts, x):
        p0, p1, p2 = parts
        n = max(len(p0), len(p1), len(p2))
        return [(p0[i] if i < len(p0) else Fraction(0))
              + (p1[i] if i < len(p1) else Fraction(0)) * x
              + (p2[i] if i < len(p2) else Fraction(0)) * x * x
              for i in range(n)]

    # --- recursive multiplications ---
    R0   = mul_toom3_school(eval_parts((a0,a1p,a2), 0),  eval_parts((b0,b1p,b2), 0), threshold)
    R1   = mul_toom3_school(eval_parts((a0,a1p,a2), 1),  eval_parts((b0,b1p,b2), 1), threshold)
    Rm1  = mul_toom3_school(eval_parts((a0,a1p,a2), -1), eval_parts((b0,b1p,b2), -1), threshold)
    R2   = mul_toom3_school(eval_parts((a0,a1p,a2), 2),  eval_parts((b0,b1p,b2), 2), threshold)
    Rinf = mul_toom3_school(a2, b2, threshold)

    # --- interpolation ---
    C0 = R0
    C4 = Rinf

    V1  = poly_sub(poly_sub(R1,  C0), C4)                            # C1 + C2 + C3
    Vm1 = poly_sub(poly_sub(Rm1, C0), C4)                            # -C1 + C2 - C3
    V2  = poly_sub(poly_sub(R2,  C0), poly_scalar_mul(C4, 16))       # 2C1 + 4C2 + 8C3

    S   = poly_sub(V1, Vm1)                                          # 2C1 + 2C3
    C2  = poly_scalar_mul(poly_add(V1, Vm1), Fraction(1,2))          # (V1+Vm1)/2

    V2_prime = poly_sub(V2, poly_scalar_mul(C2, 4))                  # 2C1 + 8C3
    C3  = poly_scalar_mul(poly_sub(V2_prime, S), Fraction(1,6))      # (V2' - S)/6
    C1  = poly_scalar_mul(poly_sub(S, poly_scalar_mul(C3, 2)), Fraction(1,2)) # (S - 2C3)/2

    # --- recombine ---
    res = C0
    res = poly_add(res, poly_shift(C1,  k))
    res = poly_add(res, poly_shift(C2, 2*k))
    res = poly_add(res, poly_shift(C3, 3*k))
    res = poly_add(res, poly_shift(C4, 4*k))

    # convert Fractions back to ints if exact
    out = [int(c) if c.denominator == 1 else float(c) for c in res]

    # --- trim trailing zeros ---
    while out and out[-1] == 0:
        out.pop()

    return [0] if out == [] else out



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

    counts = {"mult":0, "addsub":0, "shift":0}

    # --- helpers ---
    def to_frac(p): return [Fraction(x) for x in p]

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
        return [Fraction(0)]*k + p

    def schoolbook_mul(p, q):
        if not p or not q:
            return []
        res = [Fraction(0)]*(len(p)+len(q)-1)
        for i in range(len(p)):
            for j in range(len(q)):
                res[i+j] += p[i]*q[j]
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
        a0, a1p, a2 = aF[:k], aF[k:2*k], aF[2*k:]
        b0, b1p, b2 = bF[:k], bF[k:2*k], bF[2*k:]

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
        R0   = recurse(eval_parts((a0,a1p,a2), 0),  eval_parts((b0,b1p,b2), 0))
        R1   = recurse(eval_parts((a0,a1p,a2), 1),  eval_parts((b0,b1p,b2), 1))
        Rm1  = recurse(eval_parts((a0,a1p,a2), -1), eval_parts((b0,b1p,b2), -1))
        R2   = recurse(eval_parts((a0,a1p,a2), 2),  eval_parts((b0,b1p,b2), 2))
        Rinf = recurse(a2, b2)

        # --- interpolation ---
        C0 = R0
        C4 = Rinf

        V1  = poly_sub(poly_sub(R1,  C0), C4)
        Vm1 = poly_sub(poly_sub(Rm1, C0), C4)
        V2  = poly_sub(poly_sub(R2,  C0), poly_scalar_mul(C4, 16))

        S   = poly_sub(V1, Vm1)
        C2  = poly_scalar_mul(poly_add(V1, Vm1), Fraction(1,2))

        V2_prime = poly_sub(V2, poly_scalar_mul(C2, 4))
        C3  = poly_scalar_mul(poly_sub(V2_prime, S), Fraction(1,6))
        C1  = poly_scalar_mul(poly_sub(S, poly_scalar_mul(C3, 2)), Fraction(1,2))

        # --- recombine ---
        res = C0
        res = poly_add(res, poly_shift(C1,  k))
        res = poly_add(res, poly_shift(C2, 2*k))
        res = poly_add(res, poly_shift(C3, 3*k))
        res = poly_add(res, poly_shift(C4, 4*k))

        return res

    # --- run recursion ---
    res = recurse(poly1, poly2)

    # convert Fractions back to ints if exact
    out = [int(c) if c.denominator == 1 else float(c) for c in res]

    # trim trailing zeros
    while out and out[-1] == 0:
        out.pop()

    print("Operation counts → multiplies:", counts["mult"],
          "adds/subs:", counts["addsub"],
          "shifts:", counts["shift"])

    return [0] if out == [] else out


# --- examples ---

print(mul_toom3_school([1, 2], [2, 3]))                 # small → schoolbook
print(mul_toom3_school([6, 10, 3, 12], [5, 2, 7, 9]))   # larger → Toom-3, but subproblems fall back
print(mul_toom3_school([6, 10, 3, 12], [5, 2, 7, 9], 3)) # force Toom-3 earlier

print(mul_toom3_school_c([1, 2], [2, 3]))                 # small → schoolbook
print(mul_toom3_school_c([6, 10, 3, 12], [5, 2, 7, 9]))   # larger → Toom-3, subproblems fall back
print(mul_toom3_school_c([6, 10, 3, 12], [5, 2, 7, 9], 3)) # force Toom-3 earlier

print()
# print(mul_toom3_school_c([x for x in range(1, int(10e3), 1)], [x for x in range(1, int(10e3), 1)], 3)) # force Toom-3 earlier
# print(mul_toom3_school_c([x for x in range(1, int(10e3), 1)], [x for x in range(1, int(10e3), 1)], 6)) # force Toom-3 earlier
# print(mul_toom3_school_c([x for x in range(1, int(10e3), 1)], [x for x in range(1, int(10e3), 1)], 9)) # force Toom-3 earlier
# print(mul_toom3_school_c([x for x in range(1, int(10e3), 1)], [x for x in range(1, int(10e3), 1)], 12)) # force Toom-3 earlier
# print(mul_toom3_school_c([x for x in range(1, int(10e3), 1)], [x for x in range(1, int(10e3), 1)], 15)) # force Toom-3 earlier
# print(mul_toom3_school_c([x for x in range(1, int(10e3), 1)], [x for x in range(1, int(10e3), 1)], 10e6)) # force Toom-3 earlier