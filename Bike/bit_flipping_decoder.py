import random
import time
import hashlib
import matplotlib.pyplot as plt

# =========================
# BIKE parameters
# =========================
r = 1023
w = 45
row_weight = 70
MAX_ITERS = 100
THRESHOLD = 20

ADD_COST = 1
MUL_COST = 4

# =========================
# Helper functions
# =========================
def random_sparse_poly(length, weight):
    poly = [0] * length
    for p in random.sample(range(length), weight):
        poly[p] = 1
    return poly

def rotate(poly, k):
    k %= len(poly)
    return poly[-k:] + poly[:-k]

# =========================
# Syndrome computation with cost
# =========================
def compute_syndrome(h0, h1, e0, e1):
    s = [0] * r
    cost = 0

    for i in range(r):
        row_h0 = rotate(h0, i)
        row_h1 = rotate(h1, i)
        acc = 0
        for j in range(r):
            acc ^= row_h0[j] & e0[j]
            cost += MUL_COST + ADD_COST
            acc ^= row_h1[j] & e1[j]
            cost += MUL_COST + ADD_COST
        s[i] = acc

    return s, cost

# =========================
# Bit-Flipping Decoder with cost
# =========================
def bit_flipping_decode(h0, h1, syndrome):
    e0_hat = [0] * r
    e1_hat = [0] * r
    s = syndrome[:]
    total_cost = 0

    for iteration in range(1, MAX_ITERS + 1):
        unsat_0 = [0] * r
        unsat_1 = [0] * r

        current_threshold = THRESHOLD + random.randint(-5, 5)

        # Count unsatisfied parity checks
        for i in range(r):
            if s[i] == 1:
                row_h0 = rotate(h0, i)
                row_h1 = rotate(h1, i)
                for j in range(r):
                    if row_h0[j]:
                        unsat_0[j] += 1
                        total_cost += ADD_COST
                    if row_h1[j]:
                        unsat_1[j] += 1
                        total_cost += ADD_COST

        flipped = False

        for j in range(r):
            if unsat_0[j] > current_threshold:
                e0_hat[j] ^= 1
                total_cost += ADD_COST
                flipped = True
            if unsat_1[j] > current_threshold:
                e1_hat[j] ^= 1
                total_cost += ADD_COST
                flipped = True

        s, cost = compute_syndrome(h0, h1, e0_hat, e1_hat)
        total_cost += cost

        if sum(s) == 0:
            return e0_hat, e1_hat, iteration, total_cost

        if not flipped:
            break

    return None, None, iteration, total_cost

# =========================
# Main experiment
# =========================
def main():
    print("Generating BIKE system...")
    h0 = random_sparse_poly(r, row_weight)
    h1 = random_sparse_poly(r, row_weight)
    e0 = random_sparse_poly(r, w)
    e1 = random_sparse_poly(r, w)

    syndrome, _ = compute_syndrome(h0, h1, e0, e1)

    key_sizes = [16, 24, 32, 64]  # bytes
    decoding_costs = []
    iterations_list = []

    for key_size in key_sizes:
        e0_rec, e1_rec, iters, cost = bit_flipping_decode(h0, h1, syndrome)

        decoding_costs.append(cost)
        iterations_list.append(iters)

        if e0_rec is None:
            print(f"Decoder failed for {key_size*8} bits")
            continue

        print(f"Key size: {key_size*8} bits | Iterations: {iters} | Cost: {cost}")

    # =========================
    # Visualization
    # =========================
    plt.figure(figsize=(8,5))
    plt.plot([k*8 for k in key_sizes], decoding_costs, 'o-')
    plt.xlabel("Shared secret size (bits)")
    plt.ylabel("Computational cost")
    plt.title("BIKE Decoder Computational Cost vs Shared Secret Size")
    plt.grid(True)
    plt.show()

    plt.figure(figsize=(8,5))
    plt.plot([k*8 for k in key_sizes], iterations_list, 'o-', color='purple')
    plt.xlabel("Shared secret size (bits)")
    plt.ylabel("Decoder iterations")
    plt.title("BIKE Decoder Iterations vs Shared Secret Size")
    plt.grid(True)
    plt.show()

if __name__ == "__main__":
    main()
