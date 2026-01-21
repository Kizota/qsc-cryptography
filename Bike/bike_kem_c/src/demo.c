/**
 * BIKE KEM Demo - Simple usage example
 * Demonstrates key generation, encapsulation, and decapsulation
 */

#include "bike_defs.h"
#include "bike.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

int main() {
    unsigned char pk[R_BYTES];
    unsigned char sk[2 * R_BYTES + 2 * SEED_BYTES];
    unsigned char ct[R_BYTES + M_BYTES];
    unsigned char ss_encap[SS_BYTES];
    unsigned char ss_decap[SS_BYTES];
    
    printf("===========================================\n");
    printf("BIKE KEM - Key Encapsulation Demo\n");
    printf("===========================================\n\n");
    
    printf("Security Level: %d\n", LEVEL);
    printf("Parameters:\n");
    printf("  R_BITS: %d\n", R_BITS);
    printf("  D: %d\n", D);
    printf("  T: %d\n", T);
    printf("  Public key size:  %d bytes\n", R_BYTES);
    printf("  Secret key size:  %u bytes\n", (unsigned int)(2 * R_BYTES + 2 * SEED_BYTES));
    printf("  Ciphertext size:  %d bytes\n", R_BYTES + M_BYTES);
    printf("  Shared secret size: %d bytes\n\n", SS_BYTES);
    
    /* Step 1: Key Generation */
    printf("Step 1: Generating Keypair\n");
    printf("  Generating...\n");
    
    reset_computational_cost();
    clock_t start = clock();
    int res = crypto_kem_keypair(pk, sk);
    clock_t end = clock();
    double keygen_time = (double)(end - start) / CLOCKS_PER_SEC * 1000;
    uint64_t keygen_cost = get_computational_cost();
    
    if (res == SUCCESS) {
        printf("  ✓ Success\n");
        printf("  Time: %.2f ms\n", keygen_time);
        print_computational_stats();
        printf("\n");
    } else {
        printf("  ✗ Failed\n\n");
        return 1;
    }
    
    /* Step 2: Encapsulation */
    printf("Step 2: Encapsulation (Sender)\n");
    printf("  Creating shared secret and ciphertext...\n");
    
    reset_computational_cost();
    start = clock();
    res = crypto_kem_enc(ct, ss_encap, pk);
    end = clock();
    double encap_time = (double)(end - start) / CLOCKS_PER_SEC * 1000;
    uint64_t encap_cost = get_computational_cost();
    
    if (res == SUCCESS) {
        printf("  ✓ Success\n");
        printf("  Time: %.2f ms\n", encap_time);
        print_computational_stats();
        printf("  Ciphertext: %d bytes\n", R_BYTES + M_BYTES);
        printf("  Shared secret (hex): ");
        for (int i = 0; i < 16 && i < SS_BYTES; i++) {
            printf("%02x", ss_encap[i]);
        }
        printf("...\n\n");
    } else {
        printf("  ✗ Failed\n\n");
        return 1;
    }
    
    /* Step 3: Decapsulation */
    printf("Step 3: Decapsulation (Receiver)\n");
    printf("  Recovering shared secret from ciphertext...\n");
    
    reset_computational_cost();
    start = clock();
    res = crypto_kem_dec(ss_decap, ct, sk);
    end = clock();
    double decap_time = (double)(end - start) / CLOCKS_PER_SEC * 1000;
    uint64_t decap_cost = get_computational_cost();
    
    if (res == SUCCESS) {
        printf("  ✓ Success\n");
        printf("  Time: %.2f ms\n", decap_time);
        print_computational_stats();
        printf("  Shared secret (hex): ");
        for (int i = 0; i < 16 && i < SS_BYTES; i++) {
            printf("%02x", ss_decap[i]);
        }
        printf("...\n\n");
    } else {
        printf("  ✗ Failed\n\n");
        return 1;
    }
    
    /* Step 4: Verify shared secrets match */
    printf("Step 4: Verification\n");
    if (memcmp(ss_encap, ss_decap, SS_BYTES) == 0) {
        printf("  ✓ Shared secrets match!\n");
        printf("  KEM is working correctly\n\n");
    } else {
        printf("  ✗ Shared secrets DO NOT match!\n");
        printf("  ERROR: Encapsulation and decapsulation mismatch\n\n");
        return 1;
    }
    
    /* Performance Summary */
    printf("===========================================\n");
    printf("Performance Summary\n");
    printf("===========================================\n");
    printf("Timing:\n");
    printf("  Key Generation:  %.2f ms\n", keygen_time);
    printf("  Encapsulation:   %.2f ms\n", encap_time);
    printf("  Decapsulation:   %.2f ms\n", decap_time);
    printf("Total:           %.2f ms\n\n", keygen_time + encap_time + decap_time);
    
    printf("Demo completed successfully!\n");
    return 0;
}
