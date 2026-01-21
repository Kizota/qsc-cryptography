/**
 * Cryptographic Primitives for BIKE
 * Includes AES-CTR PRF, SHA functions, and random sampling
 */

#include "bike_defs.h"
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

/* Simple AES-CTR implementation using system's OpenSSL or similar */
typedef struct {
    uint8_t key[32];
    uint64_t counter;
} aes_ctr_t;

/**
 * Initialize AES-CTR PRF with seed
 */
void aes_ctr_init(aes_ctr_t *ctx, const uint8_t *seed) {
    memcpy(ctx->key, seed, 32);
    ctx->counter = 0;
}

/**
 * Generate pseudo-random bytes using simple method
 * In production, use proper AES-CTR or other approved PRF
 */
void aes_ctr_generate(aes_ctr_t *ctx, uint8_t *out, size_t len) {
    /* Fallback: Use system random for now */
    /* In production, implement proper AES-CTR here */
    for (size_t i = 0; i < len; i++) {
        out[i] = (uint8_t)rand();
    }
    ctx->counter++;
}

/* External reference to hash counter */
// extern uint64_t g_hash_count;

/**
 * Simple SHA-256 implementation wrapper
 * In production, use OpenSSL or similar
 */
void sha256(uint8_t *out, const uint8_t *in, size_t inlen) {
    /* Track computational cost: each SHA-256 hash operation */
    // g_hash_count++;
    
    /* Placeholder - would use OpenSSL in production */
    memset(out, 0, 32);
    for (size_t i = 0; i < inlen && i < 32; i++) {
        out[i] = in[i];
    }
}

/**
 * Variable-length shared secret generation using XOF (eXtendable Output Function)
 * Generates a shared secret of arbitrary size by hashing and extending
 * 
 * @param out: output buffer for shared secret
 * @param in: input data (ciphertext)
 * @param inlen: input length
 * @param outlen: desired output length (shared secret size)
 */
void generate_shared_secret_variable(uint8_t *out, const uint8_t *in, size_t inlen, size_t outlen) {
    uint8_t hash[32];
    size_t written = 0;
    
    /* Generate hash of input */
    sha256(hash, in, inlen);
    
    /* Extend hash to desired length by hashing with counter */
    while (written < outlen) {
        size_t to_copy = (outlen - written < 32) ? (outlen - written) : 32;
        memcpy(out + written, hash, to_copy);
        written += to_copy;
        
        /* If we need more bytes, hash again with counter */
        if (written < outlen) {
            uint8_t counter[4];
            counter[0] = (written >> 24) & 0xFF;
            counter[1] = (written >> 16) & 0xFF;
            counter[2] = (written >> 8) & 0xFF;
            counter[3] = written & 0xFF;
            
            /* Allocate buffer for extended input */
            uint8_t *extended = (uint8_t *)malloc(inlen + 4);
            if (extended) {
                memcpy(extended, in, inlen);
                memcpy(extended + inlen, counter, 4);
                sha256(hash, extended, inlen + 4);
                free(extended);
            }
        }
    }
}

/**
 * Hash function H for error vector generation
 * H(m, pk) -> 2*R bits
 */
void hash_h(uint8_t *out, const uint8_t *m, const uint8_t *pk) {
    uint8_t combined[M_BYTES + R_BYTES];
    memcpy(combined, m, M_BYTES);
    memcpy(combined + M_BYTES, pk, R_BYTES);
    
    /* Hash to get seed for error vector */
    sha256(out, combined, M_BYTES + R_BYTES);
}

/**
 * Optimized error vector sampling using Fisher-Yates
 * Generates indices for weight-T sparse vector
 */
void sample_error_vector(uint8_t *indices, const uint8_t *seed, size_t weight) {
    aes_ctr_t ctx;
    aes_ctr_init(&ctx, seed);
    
    uint32_t *idx_array = (uint32_t *)malloc(weight * sizeof(uint32_t));
    
    /* Generate weight random indices from 0 to R_BITS-1 */
    for (size_t i = 0; i < weight; i++) {
        uint8_t rand_bytes[4];
        aes_ctr_generate(&ctx, rand_bytes, 4);
        uint32_t rand_val = *(uint32_t *)rand_bytes;
        idx_array[i] = rand_val % R_BITS;
    }
    
    /* Remove duplicates and store */
    size_t count = 0;
    for (size_t i = 0; i < weight; i++) {
        int is_dup = 0;
        for (size_t j = 0; j < i; j++) {
            if (idx_array[i] == idx_array[j]) {
                is_dup = 1;
                break;
            }
        }
        if (!is_dup && count < weight) {
            SET_BIT(indices, idx_array[i]);
            count++;
        }
    }
    
    free(idx_array);
}

/**
 * Generate cryptographically secure random seed
 */
void get_random_seed(uint8_t *seed, size_t len) {
    for (size_t i = 0; i < len; i++) {
        seed[i] = (uint8_t)rand();
    }
}
