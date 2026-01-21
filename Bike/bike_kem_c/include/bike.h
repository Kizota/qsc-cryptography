/**
 * BIKE API - High-level interface
 * Provides NIST-standard KEM API
 */

#ifndef BIKE_H
#define BIKE_H

#include "bike_defs.h"

/* NIST KEM API */

/**
 * crypto_kem_keypair - Generate a keypair
 * 
 * @param pk: output buffer for public key (R_BYTES)
 * @param sk: output buffer for secret key (2*R_BYTES + 2*SEED_BYTES)
 * 
 * @return: 0 on success, -1 on failure
 */
int crypto_kem_keypair(unsigned char *pk, unsigned char *sk);

/**
 * crypto_kem_enc - Encapsulate
 * 
 * @param ct: output buffer for ciphertext (R_BYTES + M_BYTES)
 * @param ss: output buffer for shared secret (SS_BYTES)
 * @param pk: public key (R_BYTES)
 * 
 * @return: 0 on success, -1 on failure
 */
int crypto_kem_enc(unsigned char *ct, unsigned char *ss, const unsigned char *pk);

/**
 * crypto_kem_dec - Decapsulate
 * 
 * @param ss: output buffer for shared secret (SS_BYTES)
 * @param ct: ciphertext (R_BYTES + M_BYTES)
 * @param sk: secret key (2*R_BYTES + 2*SEED_BYTES)
 * 
 * @return: 0 on success, -1 on failure or decode failure
 */
int crypto_kem_dec(unsigned char *ss, const unsigned char *ct, const unsigned char *sk);

#endif /* BIKE_H */
