/**
 * Test suite for BIKE C implementation
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
    unsigned char ss_enc[SS_BYTES];
    unsigned char ss_dec[SS_BYTES];
    
    printf("===========================================\n");
    printf("BIKE C Implementation Test\n");
    printf("===========================================\n\n");
    
    printf("Security Level: %d\n", LEVEL);
    printf("R_BITS: %d\n", R_BITS);
    printf("D: %d\n", D);
    printf("T: %d\n", T);
    printf("\nKey sizes:\n");
    printf("  Public key:  %d bytes\n", R_BYTES);
    printf("  Secret key:  %u bytes\n", (unsigned int)(2 * R_BYTES + 2 * SEED_BYTES));
    printf("  Ciphertext:  %d bytes\n", R_BYTES + M_BYTES);
    printf("  Shared secret: %d bytes\n\n", SS_BYTES);
    
    /* Test 1: Key Generation */
    printf("Test 1: Key Generation\n");
    printf("  Generating keypair...\n");
    
    clock_t start = clock();
    printf("  bug line 1...\n");

    int res = crypto_kem_keypair(pk, sk);
    printf("  bug line 2...\n");

    clock_t end = clock();
    printf("finishing initialization\n");
    if (res == SUCCESS) {
        printf("  ✓ Keypair generated successfully\n");
        printf("  Time: %.2f ms\n\n", 
               (double)(end - start) / CLOCKS_PER_SEC * 1000);
    } else {
        printf("  ✗ Keypair generation failed\n\n");
        return 1;
    }
    
    /* Test 2: Encapsulation */
    printf("Test 2: Encapsulation\n");
    printf("  Encapsulating...\n");
    
    start = clock();
    res = crypto_kem_enc(ct, ss_enc, pk);
    end = clock();
    
    if (res == SUCCESS) {
        printf("  ✓ Encapsulation successful\n");
        printf("  Time: %.2f ms\n\n",
               (double)(end - start) / CLOCKS_PER_SEC * 1000);
    } else {
        printf("  ✗ Encapsulation failed\n\n");
        return 1;
    }
    
    /* Test 3: Decapsulation */
    printf("Test 3: Decapsulation\n");
    printf("  Decapsulating...\n");
    
    start = clock();
    res = crypto_kem_dec(ss_dec, ct, sk);
    end = clock();
    
    if (res == SUCCESS) {
        printf("  ✓ Decapsulation successful\n");
        printf("  Time: %.2f ms\n\n",
               (double)(end - start) / CLOCKS_PER_SEC * 1000);
    } else {
        printf("  ✗ Decapsulation failed\n\n");
        return 1;
    }
    
    /* Test 4: Verify shared secrets match */
    printf("Test 4: Verify Shared Secrets\n");
    if (memcmp(ss_enc, ss_dec, SS_BYTES) == 0) {
        printf("  ✓ Shared secrets match!\n\n");
    } else {
        printf("  ✗ Shared secrets DO NOT match\n\n");
        printf("  Sender:   ");
        for (int i = 0; i < 16; i++) {
            printf("%02x", ss_enc[i]);
        }
        printf("...\n");
        
        printf("  Receiver: ");
        for (int i = 0; i < 16; i++) {
            printf("%02x", ss_dec[i]);
        }
        printf("...\n\n");
    }
    
    /* Test 5: Multiple rounds */
    printf("Test 5: Multiple Rounds (3 iterations)\n");
    for (int round = 1; round <= 3; round++) {
        res = crypto_kem_keypair(pk, sk);
        res = crypto_kem_enc(ct, ss_enc, pk);
        res = crypto_kem_dec(ss_dec, ct, sk);
        
        if (memcmp(ss_enc, ss_dec, SS_BYTES) == 0) {
            printf("  Round %d: ✓\n", round);
        } else {
            printf("  Round %d: ✗\n", round);
        }
    }
    
    printf("\n===========================================\n");
    printf("All tests completed!\n");
    printf("===========================================\n");
    
    return 0;
}
