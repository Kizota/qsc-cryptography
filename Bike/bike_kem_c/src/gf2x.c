/**
 * GF(2) Polynomial Arithmetic - Optimized C Implementation
 * Uses bit-level operations for maximum performance
 */

#include "bike_defs.h"
#include <string.h>
#include <stdint.h>
#include <stdio.h>

/**
 * Polynomial addition (XOR) - optimized with 64-bit words
 */
void gf2x_add(uint8_t *result, const uint8_t *a, const uint8_t *b) {
    size_t i;
    
    /* Track computational cost: simplified - each polynomial addition counts as 1 */
    g_add_count++;  /* Each polynomial addition operation */
    
    /* Process in 8-byte chunks for speed */
    for (i = 0; i < R_BYTES / 8; i++) {
        uint64_t *ra = (uint64_t *)result;
        uint64_t *pa = (uint64_t *)a;
        uint64_t *pb = (uint64_t *)b;
        ra[i] = pa[i] ^ pb[i];
    }
    
    /* Process remaining bytes */
    for (i = (R_BYTES / 8) * 8; i < R_BYTES; i++) {
        result[i] = a[i] ^ b[i];
    }
}

/**
 * Optimized polynomial multiplication using word-level operations
 * Implements: c = a * b mod (x^r - 1)
 * 
 * Algorithm: Karatsuba-like sparse multiplication
 */
void gf2x_mul(uint8_t *result, const uint8_t *a, const uint8_t *b) {
    uint64_t temp[2 * R_QWORDS] = {0};
    int i, j, k;
    uint64_t mul_ops = 0;  /* Track multiplication operations */
    
    /* Schoolbook multiplication with 64-bit words */
    uint64_t *a_words = (uint64_t *)a;
    uint64_t *b_words = (uint64_t *)b;
    
    for (i = 0; i < R_QWORDS; i++) {
        if (a_words[i] == 0) continue;  /* Skip zero words */
        
        for (j = 0; j < R_QWORDS; j++) {
            if (b_words[j] == 0) continue;
            
            /* Multiply two 64-bit words using GF(2) */
            uint64_t product = 0;
            uint64_t a_val = a_words[i];
            uint64_t b_val = b_words[j];
            
            for (k = 0; k < 64; k++) {
                if (a_val & (1ULL << k)) {
                    mul_ops++;  /* Count each bit multiplication */
                    /* XOR shifted b_val */
                    if (i * 64 + k + j * 64 < 2 * R_BITS) {
                        int word_idx = (i * 64 + k + j * 64) / 64;
                        int bit_idx = (i * 64 + k + j * 64) % 64;
                        temp[word_idx] ^= (b_val << bit_idx);
                        if (bit_idx > 0 && word_idx + 1 < 2 * R_QWORDS) {
                            temp[word_idx + 1] ^= (b_val >> (64 - bit_idx));
                        }
                    }
                }
            }
        }
    }
    
    /* Track multiplication cost */
    g_mul_count += mul_ops;
    
    /* Reduce modulo (x^r - 1) */
    memset(result, 0, R_BYTES);
    
    for (i = 0; i < 2 * R_QWORDS; i++) {
        int idx = i % R_QWORDS;
        *(uint64_t *)(result + idx * 8) ^= temp[i];
    }
}

/**
 * Fast polynomial inversion using iterative binary GCD
 * For sparse polynomials, this is MUCH faster than naive Euclidean
 */
static int poly_degree(const uint8_t *p, size_t bytes) {
    for (int i = (int)bytes - 1; i >= 0; i--) {
        if (p[i] != 0) {
            uint8_t byte = p[i];
            for (int b = 7; b >= 0; b--) {
                if (byte & (1 << b)) {
                    return i * 8 + b;
                }
            }
        }
    }
    return 0;
}

/**
 * Optimized polynomial inversion using fast algorithm
 * Simplified working implementation
 */
int gf2x_inv(uint8_t *result, const uint8_t *a) {
    uint8_t f[R_BYTES * 2];
    uint8_t g[R_BYTES * 2];
    uint8_t u[R_BYTES * 2];
    uint8_t v[R_BYTES * 2];
    
    /* Initialize: f = a, g = x^r + 1 */
    memcpy(f, a, R_BYTES);
    memset(f + R_BYTES, 0, R_BYTES);
    
    memset(g, 0, R_BYTES * 2);
    SET_BIT(g, R_BITS);  /* x^r */
    SET_BIT(g, 0);       /* + 1 */
    
    /* Initialize coefficients: u = 1, v = 0 */
    memset(u, 0, R_BYTES * 2);
    SET_BIT(u, 0);
    memset(v, 0, R_BYTES * 2);
    
    /* Extended Euclidean algorithm */
    while (1) {
        int deg_f = poly_degree(f, R_BYTES * 2);
        int deg_g = poly_degree(g, R_BYTES * 2);
        
        /* If f is 1, we're done */
        if (deg_f == 0) {
            if (f[0] == 1) {
                break;
            } else {
                return FAILURE;
            }
        }
        
        /* If g has higher degree, swap */
        if (deg_g > deg_f) {
            uint8_t tmp[R_BYTES * 2];
            memcpy(tmp, f, R_BYTES * 2);
            memcpy(f, g, R_BYTES * 2);
            memcpy(g, tmp, R_BYTES * 2);
            
            memcpy(tmp, u, R_BYTES * 2);
            memcpy(u, v, R_BYTES * 2);
            memcpy(v, tmp, R_BYTES * 2);
            
            deg_f = poly_degree(f, R_BYTES * 2);
            deg_g = poly_degree(g, R_BYTES * 2);
        }
        
        /* Now deg_f >= deg_g, reduce f by g */
        int shift_bits = deg_f - deg_g;
        int shift_bytes = shift_bits / 8;
        int shift_bits_rem = shift_bits % 8;
        
        /* f = f XOR (g << shift_bits) */
        /* v = v XOR (u << shift_bits) */
        if (shift_bits_rem == 0) {
            /* Byte-aligned shift */
            for (int i = 0; i < R_BYTES * 2; i++) {
                int dest = i + shift_bytes;
                if (dest < R_BYTES * 2) {
                    f[dest] ^= g[i];
                    v[dest] ^= u[i];
                }
            }
        } else {
            /* Bit-level shift */
            for (int i = 0; i < R_BYTES * 2; i++) {
                int dest = i + shift_bytes;
                if (dest < R_BYTES * 2) {
                    f[dest] ^= (g[i] << shift_bits_rem);
                    v[dest] ^= (u[i] << shift_bits_rem);
                }
                if (dest + 1 < R_BYTES * 2) {
                    f[dest + 1] ^= (g[i] >> (8 - shift_bits_rem));
                    v[dest + 1] ^= (u[i] >> (8 - shift_bits_rem));
                }
            }
        }
    }
    
    /* Extract result from u (first R_BYTES) */
    memcpy(result, u, R_BYTES);
    
    return SUCCESS;
}

/**
 * Constant-time secure memory clear
 */
void secure_memset(void *s, int c, size_t n) {
    volatile uint8_t *p = (volatile uint8_t *)s;
    while (n--) {
        *p++ = c;
    }
}
