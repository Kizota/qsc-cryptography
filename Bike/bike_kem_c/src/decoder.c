/**
 * BGF (Bit-Flipping Gauss) Decoder for BIKE
 * Implements iterative bit-flipping decoder for error correction
 */

#include "bike_defs.h"
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

/* Forward declarations */
extern void gf2x_add(uint8_t *result, const uint8_t *a, const uint8_t *b);
extern uint64_t g_add_count;  /* Track GF(2) additions (XOR operations) */

/**
 * Compute error weight at a specific position
 * Returns how many syndrome bits would be corrected by flipping this bit
 * 
 * Computational cost: R_BITS bit operations (each GET_BIT is a bit operation)
 */
static uint32_t compute_error_weight(const uint8_t *syndrome, const uint8_t *h, int position) {
    uint32_t score = 0;
    
    /* Track computational cost: each iteration checks one bit position */
    /* We count bit operations as additions (GF(2) operations) */
    for (int i = 0; i < R_BITS; i++) {
        int h_pos = (position - i + R_BITS) % R_BITS;
        if (GET_BIT(h, h_pos)) {
            /* This position contributes to syndrome bit i */
            if (GET_BIT(syndrome, i)) {
                score++;
            }
        }
        /* Each iteration involves bit operations (equivalent to GF(2) additions) */
        g_add_count++;  /* Count bit check operations */
    }
    
    return score;
}

/**
 * Compute threshold for current iteration
 */
static uint32_t compute_threshold(int iteration) {
    uint64_t threshold = THRESHOLD_COEFF0 - (THRESHOLD_COEFF1 * (uint64_t)iteration);
    threshold = threshold >> THRESHOLD_SHR_CONST;
    
    if (threshold < THRESHOLD_MIN) {
        return THRESHOLD_MIN;
    }
    return (uint32_t)threshold;
}

/**
 * Check if syndrome is zero
 */
static int is_syndrome_zero(const uint8_t *syndrome) {
    for (int i = 0; i < R_BYTES; i++) {
        if (syndrome[i] != 0) {
            return 0;
        }
    }
    return 1;
}

/**
 * BGF Decoder - Recover error vectors e0, e1 from ciphertext
 * 
 * WHY IT'S COMPUTATIONALLY EXPENSIVE:
 * 
 * 1. Iterative Process: Up to 20 iterations
 * 2. Error Weight Computation: For each iteration, computes weight for ALL R_BITS positions
 *    - Complexity: O(R_BITS²) per iteration = O(20 × R_BITS²) total
 *    - For Level 1 (R=12,323): ~3 billion bit operations!
 * 3. Syndrome Updates: Each bit flip updates R_BITS syndrome bits via XOR
 *    - Each XOR operation is a GF(2) addition (tracked)
 * 
 * COMPUTATIONAL COST TRACKING:
 * - Error weight computation: R_BITS additions per position × R_BITS positions = R_BITS² per iteration
 * - Syndrome updates: R_BITS additions per flip × number of flips
 * - Total: O(20 × R_BITS²) additions in worst case
 * 
 * @param e0: output error vector 0 (R_BYTES)
 * @param e1: output error vector 1 (R_BYTES)
 * @param c0: ciphertext component 0 (R_BYTES)
 * @param h0: secret polynomial h0 (R_BYTES)
 * @param h1: secret polynomial h1 (R_BYTES)
 * 
 * @return: 0 on success, -1 on decode failure
 */
int bgf_decode(uint8_t *e0, uint8_t *e1, const uint8_t *c0, const uint8_t *h0, const uint8_t *h1) {
    uint8_t syndrome[R_BYTES];
    uint8_t e0_estimate[R_BYTES];
    uint32_t *weights = (uint32_t *)malloc(R_BITS * sizeof(uint32_t));
    
    if (!weights) {
        return -1;  /* Memory allocation failed */
    }
    
    /* Initialize error estimate to zero */
    memset(e0_estimate, 0, R_BYTES);
    memset(e1, 0, R_BYTES);  /* Simplified: only decode e0 for now */
    
    /* Initialize syndrome from c0 */
    memcpy(syndrome, c0, R_BYTES);
    
    /* Iterative bit-flipping decoder */
    const int max_iterations = 20;
    for (int iteration = 0; iteration < max_iterations; iteration++) {
        /* Compute error weight for each bit position */
        for (int pos = 0; pos < R_BITS; pos++) {
            weights[pos] = compute_error_weight(syndrome, h0, pos);
        }
        
        /* Compute threshold for this iteration */
        uint32_t threshold = compute_threshold(iteration);
        
        /* Find bits to flip (weights above threshold) */
        int flip_count = 0;
        for (int pos = 0; pos < R_BITS; pos++) {
            if (weights[pos] > threshold) {
                /* Flip bit at position */
                TOGGLE_BIT(e0_estimate, pos);
                
                /* Update syndrome: syndrome = syndrome XOR (h0 shifted by pos) */
                /* Each syndrome update involves R_BITS XOR operations */
                for (int i = 0; i < R_BITS; i++) {
                    int h_pos = (pos - i + R_BITS) % R_BITS;
                    if (GET_BIT(h0, h_pos)) {
                        TOGGLE_BIT(syndrome, i);  /* XOR operation = GF(2) addition */
                        g_add_count++;  /* Track each syndrome bit update */
                    }
                }
                
                flip_count++;
            }
        }
        
        /* If no bits to flip, decoder converged */
        if (flip_count == 0) {
            break;
        }
        
        /* Check if syndrome is zero (success) */
        if (is_syndrome_zero(syndrome)) {
            memcpy(e0, e0_estimate, R_BYTES);
            free(weights);
            return 0;  /* Success */
        }
    }
    
    /* Check final syndrome */
    if (is_syndrome_zero(syndrome)) {
        memcpy(e0, e0_estimate, R_BYTES);
        free(weights);
        return 0;  /* Success */
    }
    
    free(weights);
    return -1;  /* Decode failure */
}
