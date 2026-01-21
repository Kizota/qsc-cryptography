/**
 * BIKE Definitions - Parameters for NIST Security Levels
 * Based on BIKE Round 4 Specification v5.1
 * 
 * This header defines all constants for BIKE KEM
 */

#ifndef BIKE_DEFS_H
#define BIKE_DEFS_H

#include <stdint.h>
#include <string.h>

/* Default security level (can be overridden) */
#ifndef LEVEL
#define LEVEL 1
#endif

/* ============ BIKE Parameters ============ */

#if (LEVEL == 1)
    /* 64-bit quantum security */
    #define R_BITS              12323
    #define D                   71
    #define T                   134
    #define MAX_RAND_INDICES_T  271
    #define BLOCK_BITS          16384

#elif (LEVEL == 3)
    /* 192-bit quantum security */
    #define R_BITS              24659
    #define D                   103
    #define T                   199
    #define MAX_RAND_INDICES_T  373
    #define BLOCK_BITS          32768

#elif (LEVEL == 5)
    /* 256-bit quantum security */
    #define R_BITS              40973
    #define D                   137
    #define T                   264
    #define MAX_RAND_INDICES_T  605
    #define BLOCK_BITS          65536

#else
    #error "LEVEL must be 1, 3, or 5"
#endif

/* Common constants */
#define N0                      2
#define NUM_OF_SEEDS            2
#define SS_BYTES                32  /* 256 bits */
#define M_BYTES                 32  /* 256 bits */
#define SEED_BYTES              32  /* SHA-256 output */

/* Derived constants */
#define R_BYTES                 ((R_BITS + 7) / 8)
#define R_QWORDS                ((R_BITS + 63) / 64)
#define N_BITS                  (R_BITS * N0)
#define N_BYTES                 ((N_BITS + 7) / 8)

/* Decoder thresholds */
#if (LEVEL == 1)
    #define THRESHOLD_COEFF0    1353000000ULL
    #define THRESHOLD_COEFF1    697220ULL
    #define THRESHOLD_MIN       36
    
#elif (LEVEL == 3)
    #define THRESHOLD_COEFF0    1525880000ULL
    #define THRESHOLD_COEFF1    526500ULL
    #define THRESHOLD_MIN       52
    
#elif (LEVEL == 5)
    #define THRESHOLD_COEFF0    1787850000ULL
    #define THRESHOLD_COEFF1    402312ULL
    #define THRESHOLD_MIN       69
#endif

#define THRESHOLD_MUL_CONST     12379400392853802749ULL
#define THRESHOLD_SHR_CONST     26

/* Success/Error codes */
#define SUCCESS                 0
#define FAILURE                 -1
#define DECODE_FAILURE          -2

/* Macros for bit operations */
#define BITMASK(b)              ((uint8_t)(1U << ((b) & 7)))
#define BYTEB(b)                ((b) >> 3)
#define GET_BIT(v, b)           (((v)[BYTEB(b)] >> ((b) & 7)) & 1)
#define SET_BIT(v, b)           ((v)[BYTEB(b)] |= BITMASK(b))
#define CLR_BIT(v, b)           ((v)[BYTEB(b)] &= ~BITMASK(b))
#define TOGGLE_BIT(v, b)        ((v)[BYTEB(b)] ^= BITMASK(b))

/* Type definitions */
typedef uint8_t  r_t[R_BYTES];          /* Polynomial in GF(2) */
typedef uint8_t  m_t[M_BYTES];          /* Message */
typedef uint8_t  seed_t[SEED_BYTES];    /* Random seed */
typedef uint8_t  ss_t[SS_BYTES];        /* Shared secret */

/* Public key and secret key structures */
typedef struct {
    r_t h;                      /* Public key polynomial */
} pk_t;

typedef struct {
    r_t h0;                     /* First secret polynomial */
    r_t h1;                     /* Second secret polynomial */
    seed_t seed0;               /* Seed 0 for h0, h1 generation */
    seed_t seed1;               /* Seed 1 for sigma */
} sk_t;

/* Ciphertext */
typedef struct {
    r_t c0;                     /* First ciphertext component */
    m_t c1;                     /* Second ciphertext component (XORed message) */
} ct_t;

/* Error vector */
typedef struct {
    r_t e0;                     /* First error vector */
    r_t e1;                     /* Second error vector */
} e_t;

/* Computational cost tracking - external */
extern uint64_t g_add_count;
extern uint64_t g_mul_count;

void reset_computational_cost(void);
uint64_t get_computational_cost(void);
void print_computational_stats(void);

#endif /* BIKE_DEFS_H */
