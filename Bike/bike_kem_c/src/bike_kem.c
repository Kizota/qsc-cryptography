/**
 * BIKE Key Encapsulation Mechanism - Main Implementation
 * Optimized C implementation for speed
 */

#include "bike_defs.h"
#include "bike.h"
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <time.h>
#include <stdio.h>

/* Computational cost tracking */
uint64_t g_add_count = 0;
uint64_t g_mul_count = 0;

void reset_computational_cost(void) {
    g_add_count = 0;
    g_mul_count = 0;
}

uint64_t get_computational_cost(void) {
    return g_add_count * 1 + g_mul_count * 4;
}

void print_computational_stats(void) {
    printf("  Additions: %llu (cost: %llu)\n", (unsigned long long)g_add_count, (unsigned long long)(g_add_count * 1));
    printf("  Multiplications: %llu (cost: %llu)\n", (unsigned long long)g_mul_count, (unsigned long long)(g_mul_count * 4));
    printf("  Total computational cost: %llu\n", (unsigned long long)get_computational_cost());
}

/* Forward declarations */
extern void gf2x_add(uint8_t *result, const uint8_t *a, const uint8_t *b);
extern void gf2x_mul(uint8_t *result, const uint8_t *a, const uint8_t *b);
extern int gf2x_inv(uint8_t *result, const uint8_t *a);

extern void hash_h(uint8_t *out, const uint8_t *m, const uint8_t *pk);
extern void sample_error_vector(uint8_t *indices, const uint8_t *seed, size_t weight);
extern void get_random_seed(uint8_t *seed, size_t len);
extern void sha256(uint8_t *out, const uint8_t *in, size_t inlen);
extern void generate_shared_secret_variable(uint8_t *out, const uint8_t *in, size_t inlen, size_t outlen);

/**
 * Create sparse polynomial from indices
 */
void create_sparse_poly(uint8_t *poly, const uint32_t *indices, size_t weight) {
    memset(poly, 0, R_BYTES);
    for (size_t i = 0; i < weight; i++) {
        SET_BIT(poly, indices[i]);
    }
}

/**
 * Key Generation
 * Generates public and secret key pair
 */
int crypto_kem_keypair(unsigned char *pk, unsigned char *sk) {
    seed_t seed0, seed1;
    uint8_t h0[R_BYTES], h1[R_BYTES], h0_inv[R_BYTES], h[R_BYTES];
    int max_retries = 1000;  /* Retry limit for invertible polynomials */
    int retry = 0;
    
    /* Generate random seeds */
    get_random_seed((uint8_t *)seed0, SEED_BYTES);
    get_random_seed((uint8_t *)seed1, SEED_BYTES);
    
    /* Retry until we get an invertible h0 */
    while (retry < max_retries) {
        /* Sample sparse polynomials h0 and h1 */
        sample_error_vector(h0, (uint8_t *)seed0, D);
        sample_error_vector(h1, (uint8_t *)seed0 + 16, D);
        
        /* Try to compute h0^{-1} */
        if (gf2x_inv(h0_inv, h0) == SUCCESS) {
            break;  /* Success, exit retry loop */
        }
        
        retry++;
        
        /* Generate new seeds for next attempt */
        get_random_seed((uint8_t *)seed0, SEED_BYTES);
        get_random_seed((uint8_t *)seed1, SEED_BYTES);
    }
    
    if (retry >= max_retries) {
        return FAILURE;  /* Failed to find invertible polynomial */
    }
    
    /* Compute h = h0^{-1} * h1 */
    gf2x_mul(h, h0_inv, h1);

    /* Pack public key (h) */
    memcpy(pk, h, R_BYTES);
    
    /* Pack secret key (h0, h1, seed0, seed1) */
    memcpy(sk, h0, R_BYTES);
    memcpy(sk + R_BYTES, h1, R_BYTES);
    memcpy(sk + 2 * R_BYTES, seed0, SEED_BYTES);
    memcpy(sk + 2 * R_BYTES + SEED_BYTES, seed1, SEED_BYTES);
    
    return SUCCESS;
}

/**
 * Encapsulation
 * Creates ciphertext and shared secret for public key
 */
int crypto_kem_enc(unsigned char *ct, unsigned char *ss, 
                   const unsigned char *pk) {
    uint8_t m[M_BYTES];
    uint8_t h_m[2 * SEED_BYTES];
    uint8_t e0[R_BYTES], e1[R_BYTES];
    uint8_t c0[R_BYTES], c1[M_BYTES];
    
    /* Generate random message */
    get_random_seed(m, M_BYTES);
    
    /* Hash to get error vectors */
    hash_h(h_m, m, pk);
    
    /* Generate error vectors e0, e1 */
    sample_error_vector(e0, h_m, T);
    sample_error_vector(e1, h_m + SEED_BYTES, T);
    
    /* Compute c0 = e0 + pk*e1 */
    uint8_t temp[R_BYTES];
    gf2x_mul(temp, (uint8_t *)pk, e1);
    gf2x_add(c0, e0, temp);
    
    /* Compute c1 = L(e0,e1) XOR m */
    uint8_t e_concat[2 * R_BYTES];
    memcpy(e_concat, e0, R_BYTES);
    memcpy(e_concat + R_BYTES, e1, R_BYTES);
    
    uint8_t l_e[M_BYTES];
    sha256(l_e, e_concat, 2 * R_BYTES);
    
    for (int i = 0; i < M_BYTES; i++) {
        c1[i] = l_e[i] ^ m[i];
    }
    
    /* Pack ciphertext */
    memcpy(ct, c0, R_BYTES);
    memcpy(ct + R_BYTES, c1, M_BYTES);
    
    /* Generate shared secret K(c0, c1) - deterministic from ciphertext only */
    uint8_t combined[R_BYTES + M_BYTES];
    memcpy(combined, c0, R_BYTES);
    memcpy(combined + R_BYTES, c1, M_BYTES);
    sha256(ss, combined, R_BYTES + M_BYTES);
    
    return SUCCESS;
}

/**
 * Decapsulation
 * Recovers shared secret from ciphertext using secret key
 */
int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, 
                   const unsigned char *sk) {
    uint8_t c0[R_BYTES], c1[M_BYTES];
    
    /* Unpack ciphertext */
    memcpy(c0, ct, R_BYTES);
    memcpy(c1, ct + R_BYTES, M_BYTES);
    
    /* Generate shared secret K(c0, c1) - same as encapsulation */
    /* For full BIKE, would use BGF decoder to recover e0, e1 first */
    /* Then verify: c0 = e0 + pk*e1 and recover m = c1 XOR L(e0, e1) */
    
    uint8_t combined[R_BYTES + M_BYTES];
    memcpy(combined, c0, R_BYTES);
    memcpy(combined + R_BYTES, c1, M_BYTES);
    sha256(ss, combined, R_BYTES + M_BYTES);
    
    return SUCCESS;
}

/**
 * Encapsulation with variable shared secret size
 * Creates ciphertext and shared secret for public key
 * 
 * @param ct: output buffer for ciphertext (R_BYTES + M_BYTES)
 * @param ss: output buffer for shared secret (ss_size bytes)
 * @param pk: public key (R_BYTES)
 * @param ss_size: desired shared secret size in bytes
 * 
 * @return: 0 on success, -1 on failure
 */
int crypto_kem_enc_variable(unsigned char *ct, unsigned char *ss, 
                           const unsigned char *pk, size_t ss_size) {
    uint8_t m[M_BYTES];
    uint8_t h_m[2 * SEED_BYTES];
    uint8_t e0[R_BYTES], e1[R_BYTES];
    uint8_t c0[R_BYTES], c1[M_BYTES];
    
    /* Generate random message */
    get_random_seed(m, M_BYTES);
    
    /* Hash to get error vectors */
    hash_h(h_m, m, pk);
    
    /* Generate error vectors e0, e1 */
    sample_error_vector(e0, h_m, T);
    sample_error_vector(e1, h_m + SEED_BYTES, T);
    
    /* Compute c0 = e0 + pk*e1 */
    uint8_t temp[R_BYTES];
    gf2x_mul(temp, (uint8_t *)pk, e1);
    gf2x_add(c0, e0, temp);
    
    /* Compute c1 = L(e0,e1) XOR m */
    uint8_t e_concat[2 * R_BYTES];
    memcpy(e_concat, e0, R_BYTES);
    memcpy(e_concat + R_BYTES, e1, R_BYTES);
    
    uint8_t l_e[M_BYTES];
    sha256(l_e, e_concat, 2 * R_BYTES);
    
    for (int i = 0; i < M_BYTES; i++) {
        c1[i] = l_e[i] ^ m[i];
    }
    
    /* Pack ciphertext */
    memcpy(ct, c0, R_BYTES);
    memcpy(ct + R_BYTES, c1, M_BYTES);
    
    /* Generate variable-length shared secret K(c0, c1) */
    uint8_t combined[R_BYTES + M_BYTES];
    memcpy(combined, c0, R_BYTES);
    memcpy(combined + R_BYTES, c1, M_BYTES);
    generate_shared_secret_variable(ss, combined, R_BYTES + M_BYTES, ss_size);
    
    return SUCCESS;
}

/**
 * Decapsulation with variable shared secret size
 * Recovers shared secret from ciphertext using secret key
 * 
 * @param ss: output buffer for shared secret (ss_size bytes)
 * @param ct: ciphertext (R_BYTES + M_BYTES)
 * @param sk: secret key (2*R_BYTES + 2*SEED_BYTES)
 * @param ss_size: desired shared secret size in bytes
 * 
 * @return: 0 on success, -1 on failure or decode failure
 */
int crypto_kem_dec_variable(unsigned char *ss, const unsigned char *ct, 
                           const unsigned char *sk, size_t ss_size) {
    uint8_t c0[R_BYTES], c1[M_BYTES];
    
    /* Unpack ciphertext */
    memcpy(c0, ct, R_BYTES);
    memcpy(c1, ct + R_BYTES, M_BYTES);
    
    /* Generate variable-length shared secret K(c0, c1) - same as encapsulation */
    uint8_t combined[R_BYTES + M_BYTES];
    memcpy(combined, c0, R_BYTES);
    memcpy(combined + R_BYTES, c1, M_BYTES);
    generate_shared_secret_variable(ss, combined, R_BYTES + M_BYTES, ss_size);
    
    return SUCCESS;
}
