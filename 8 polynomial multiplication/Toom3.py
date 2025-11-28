from fractions import Fraction

def toom3_mul(poly1, poly2):
    """
    Multiply two polynomials using Toom-3 (Toom-Cook 3-way split).
    Input: lists of coefficients [a0, a1, ..., an] for a0 + a1*x + ...
    Output: list of integer coefficients of the product (no trailing zeros).

    examples:

        >>> toom3_mul([1, 2], [2, 3])
        [2, 7, 6]

        >>> toom3_mul([0, 0], [2, 3])
        [0]

        >>> toom3_mul([6, 10, 3, 12], [5, 2, 7, 9])
        [30, 62, 77, 190, 135, 111, 108]
    """

    # --- helpers inline ---
    def to_frac(p): return [Fraction(x) for x in p]
    def poly_add(p, q):
        n = max(len(p), len(q))
        return [(p[i] if i < len(p) else Fraction(0)) +
                (q[i] if i < len(q) else Fraction(0)) for i in range(n)]
    def poly_sub(p, q):
        n = max(len(p), len(q))
        return [(p[i] if i < len(p) else Fraction(0)) -
                (q[i] if i < len(q) else Fraction(0)) for i in range(n)]
    def poly_scalar_mul(p, c): return [c * coeff for coeff in p]
    def poly_shift(p, k): return [Fraction(0)]*k + p
    def base_mul(p, q):
        res = [Fraction(0)]*(len(p)+len(q)-1) if p and q else []
        for i in range(len(p)):
            for j in range(len(q)):
                res[i+j] += p[i]*q[j]
        return res

    poly1 = to_frac(poly1)
    poly2 = to_frac(poly2)

    # --- split into 3 parts ---
    m = max(len(poly1), len(poly2))
    k = (m + 2) // 3
    a0, a1p, a2 = poly1[:k], poly1[k:2 * k], poly1[2 * k:]
    b0, b1p, b2 = poly2[:k], poly2[k:2*k], poly2[2*k:]

    def eval_parts(parts, x):
        p0, p1, p2 = parts
        return poly_add(p0,
               poly_add(poly_scalar_mul(p1, x),
                        poly_scalar_mul(p2, x*x)))

    # --- evaluate at points ---
    R0   = base_mul(eval_parts((a0,a1p,a2), 0),  eval_parts((b0,b1p,b2), 0))   # C0
    R1   = base_mul(eval_parts((a0,a1p,a2), 1),  eval_parts((b0,b1p,b2), 1))
    Rm1  = base_mul(eval_parts((a0,a1p,a2), -1), eval_parts((b0,b1p,b2), -1))
    R2   = base_mul(eval_parts((a0,a1p,a2), 2),  eval_parts((b0,b1p,b2), 2))
    Rinf = base_mul(a2, b2)  # C4

    # --- interpolation ---
    C0 = R0
    C4 = Rinf

    V1  = poly_sub(poly_sub(R1,  C0), C4)          # C1 + C2 + C3
    Vm1 = poly_sub(poly_sub(Rm1, C0), C4)          # -C1 + C2 - C3
    V2  = poly_sub(poly_sub(R2,  C0), poly_scalar_mul(C4, 16))  # 2C1 + 4C2 + 8C3

    S   = poly_sub(V1, Vm1)                        # 2C1 + 2C3
    C2  = poly_scalar_mul(poly_add(V1, Vm1), Fraction(1,2))     # (V1+Vm1)/2

    V2_prime = poly_sub(V2, poly_scalar_mul(C2, 4))             # 2C1 + 8C3
    C3  = poly_scalar_mul(poly_sub(V2_prime, S), Fraction(1,6)) # (V2' - S)/6
    C1  = poly_scalar_mul(poly_sub(S, poly_scalar_mul(C3, 2)), Fraction(1,2)) # (S - 2C3)/2

    # --- recombine ---
    res = C0
    res = poly_add(res, poly_shift(C1,  k))
    res = poly_add(res, poly_shift(C2, 2*k))
    res = poly_add(res, poly_shift(C3, 3*k))
    res = poly_add(res, poly_shift(C4, 4*k))

    # convert Fractions back to ints if exact
    out = []
    for c in res:
        out.append(int(c) if c.denominator == 1 else float(c))

    # --- trim trailing zeros ---
    while out and out[-1] == 0:
        out.pop()

    if out == []:
        return [0]
    else:
        return out


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
    counts = {"mult":0, "addsub":0, "shift":0}

    # --- helpers inline ---
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

    def base_mul(p, q):
        res = [Fraction(0)]*(len(p)+len(q)-1) if p and q else []
        for i in range(len(p)):
            for j in range(len(q)):
                res[i+j] += p[i]*q[j]
                counts["mult"] += 1
                if res[i+j] != 0:  # addition into slot
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
                        poly_scalar_mul(p2, x*x)))

    # --- evaluate at points ---
    R0   = base_mul(eval_parts((a0,a1p,a2), 0),  eval_parts((b0,b1p,b2), 0))   # C0
    R1   = base_mul(eval_parts((a0,a1p,a2), 1),  eval_parts((b0,b1p,b2), 1))
    Rm1  = base_mul(eval_parts((a0,a1p,a2), -1), eval_parts((b0,b1p,b2), -1))
    R2   = base_mul(eval_parts((a0,a1p,a2), 2),  eval_parts((b0,b1p,b2), 2))
    Rinf = base_mul(a2, b2)  # C4

    # --- interpolation ---
    C0 = R0
    C4 = Rinf

    V1  = poly_sub(poly_sub(R1,  C0), C4)          # C1 + C2 + C3
    Vm1 = poly_sub(poly_sub(Rm1, C0), C4)          # -C1 + C2 - C3
    V2  = poly_sub(poly_sub(R2,  C0), poly_scalar_mul(C4, 16))  # 2C1 + 4C2 + 8C3

    S   = poly_sub(V1, Vm1)                        # 2C1 + 2C3
    C2  = poly_scalar_mul(poly_add(V1, Vm1), Fraction(1,2))     # (V1+Vm1)/2

    V2_prime = poly_sub(V2, poly_scalar_mul(C2, 4))             # 2C1 + 8C3
    C3  = poly_scalar_mul(poly_sub(V2_prime, S), Fraction(1,6)) # (V2' - S)/6
    C1  = poly_scalar_mul(poly_sub(S, poly_scalar_mul(C3, 2)), Fraction(1,2)) # (S - 2C3)/2

    # --- recombine ---
    res = C0
    res = poly_add(res, poly_shift(C1,  k))
    res = poly_add(res, poly_shift(C2, 2*k))
    res = poly_add(res, poly_shift(C3, 3*k))
    res = poly_add(res, poly_shift(C4, 4*k))

    # convert Fractions back to ints if exact
    out = []
    for c in res:
        out.append(int(c) if c.denominator == 1 else float(c))

    # --- trim trailing zeros ---
    while out and out[-1] == 0:
        out.pop()

    # --- print counts ---
    print("Operation counts → multiplies:", counts["mult"],
          "adds/subs:", counts["addsub"],
          "shifts:", counts["shift"])

    if out == []:
        return [0]
    else:
        return out


# examples
print(toom3_mul([1, 2], [2, 3]))
print(toom3_mul([6, 10, 3, 12], [5, 2, 7, 9]))
print(toom3_mul_c([1, 2], [2, 3]))
print(toom3_mul_c([6, 10, 3, 12], [5, 2, 7, 9]))

