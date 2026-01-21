/**
 * BIKE KEM Computational Cost Evaluation
 * Evaluates computational costs for different shared secret key sizes
 */

#include "bike_defs.h"
#include "bike.h"
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>

/* Forward declarations for variable-size functions */
extern int crypto_kem_enc_variable(unsigned char *ct, unsigned char *ss, 
                                   const unsigned char *pk, size_t ss_size);
extern int crypto_kem_dec_variable(unsigned char *ss, const unsigned char *ct, 
                                   const unsigned char *sk, size_t ss_size);

/* Evaluation data structure */
typedef struct {
    int key_size;
    uint64_t keygen_cost;
    uint64_t encap_cost;
    uint64_t decap_cost;
    uint64_t total_cost;
    double keygen_time;
    double encap_time;
    double decap_time;
} eval_result_t;

/* Run evaluation for all key sizes */
void run_evaluation(void) {
    eval_result_t results[301];
    int num_results = 0;
    
    unsigned char pk[R_BYTES];
    unsigned char sk[2 * R_BYTES + 2 * SEED_BYTES];
    
    printf("===========================================\n");
    printf("BIKE KEM - Computational Cost Evaluation\n");
    printf("===========================================\n");
    printf("Testing shared secret sizes from 0 to 300 bytes...\n");
    printf("(Testing with ACTUAL variable key sizes)\n\n");
    
    printf("%-5s | %-15s\n", "Size", "Total Cost");
    printf("------|---------------\n");
    
    /* Test different shared secret sizes */
    for (int key_size = 0; key_size <= 300; key_size += 10) {
        /* Skip key_size = 0, use minimum of 1 byte */
        size_t ss_size = (key_size == 0) ? 1 : (size_t)key_size;
        
        /* Dynamically allocate buffers for variable-size shared secret */
        unsigned char *ct = (unsigned char *)malloc(R_BYTES + M_BYTES);
        unsigned char *ss_encap = (unsigned char *)malloc(ss_size);
        unsigned char *ss_decap = (unsigned char *)malloc(ss_size);
        
        if (!ct || !ss_encap || !ss_decap) {
            printf("Error: Memory allocation failed for key_size=%d\n", key_size);
            free(ct);
            free(ss_encap);
            free(ss_decap);
            continue;
        }
        
        uint64_t total_keygen_cost = 0;
        uint64_t total_encap_cost = 0;
        uint64_t total_decap_cost = 0;
        double total_keygen_time = 0;
        double total_encap_time = 0;
        double total_decap_time = 0;
        
        /* Number of runs per key size */
        int num_runs = (key_size == 0 || key_size <= 50) ? 5 : 
                       (key_size <= 150) ? 3 : 2;
        
        for (int run = 0; run < num_runs; run++) {
            /* Key Generation (independent of shared secret size) */
            reset_computational_cost();
            clock_t start = clock();
            int res = crypto_kem_keypair(pk, sk);
            clock_t end = clock();
            
            if (res == SUCCESS) {
                total_keygen_cost += get_computational_cost();
                total_keygen_time += (double)(end - start) / CLOCKS_PER_SEC * 1000;
                
                /* Encapsulation with variable shared secret size */
                reset_computational_cost();
                start = clock();
                res = crypto_kem_enc_variable(ct, ss_encap, pk, ss_size);
                end = clock();
                
                if (res == SUCCESS) {
                    total_encap_cost += get_computational_cost();
                    total_encap_time += (double)(end - start) / CLOCKS_PER_SEC * 1000;
                    
                    /* Decapsulation with variable shared secret size */
                    reset_computational_cost();
                    start = clock();
                    res = crypto_kem_dec_variable(ss_decap, ct, sk, ss_size);
                    end = clock();
                    
                    if (res == SUCCESS) {
                        total_decap_cost += get_computational_cost();
                        total_decap_time += (double)(end - start) / CLOCKS_PER_SEC * 1000;
                    }
                }
            }
        }
        
        /* Average the results */
        eval_result_t result;
        result.key_size = key_size;
        result.keygen_cost = total_keygen_cost / num_runs;
        result.encap_cost = total_encap_cost / num_runs;
        result.decap_cost = total_decap_cost / num_runs;
        result.total_cost = result.keygen_cost + result.encap_cost + result.decap_cost;
        result.keygen_time = total_keygen_time / num_runs;
        result.encap_time = total_encap_time / num_runs;
        result.decap_time = total_decap_time / num_runs;
        
        results[num_results++] = result;
        
        printf("%3d B | %15llu\n",
               key_size,
               (unsigned long long)result.total_cost);
        
        /* Free allocated memory */
        free(ct);
        free(ss_encap);
        free(ss_decap);
    }
    
    /* Save results to CSV file */
    FILE *csv_file = NULL;
#ifdef _MSC_VER
    /* Use secure variant on MSVC to avoid C4996 warning */
    if (fopen_s(&csv_file, "bike_eval_results.csv", "w") != 0 || csv_file == NULL) {
        printf("Error: Could not open bike_eval_results.csv for writing\n");
        return;
    }
#else
    csv_file = fopen("bike_eval_results.csv", "w");
    if (csv_file == NULL) {
        printf("Error: Could not open bike_eval_results.csv for writing\n");
        return;
    }
#endif

    /* Save only the key size and total computational cost (per your request) */
    fprintf(csv_file, "KeySize,TotalComputationalCost\n");
    for (int i = 0; i < num_results; i++) {
        fprintf(csv_file, "%d,%llu\n",
               results[i].key_size,
               (unsigned long long)results[i].total_cost);
    }
    fclose(csv_file);
    
    printf("===========================================\n");
    printf("Evaluation Results\n");
    printf("===========================================\n\n");
    
    printf("Results saved to: bike_eval_results.csv\n");
    printf("Total key sizes tested: %d\n", num_results);
    
    uint64_t avg_total = 0;
    uint64_t max_total = 0;
    for (int i = 0; i < num_results; i++) {
        avg_total += results[i].total_cost;
        if (results[i].total_cost > max_total) max_total = results[i].total_cost;
    }
    avg_total /= num_results;

    printf("Average Total cost:  %llu\n", (unsigned long long)avg_total);
    printf("Maximum Total cost:  %llu\n", (unsigned long long)max_total);
    printf("\nRun 'python plot_evaluation.py' to generate visualization.\n");
    printf("Evaluation complete!\n");
}

int main(void) {
    run_evaluation();
    return 0;
}
