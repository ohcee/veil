/**********************************************************************
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_BULLETPROOF_TESTS
#define SECP256K1_MODULE_BULLETPROOF_TESTS

#include "include/secp256k1_bulletproofs.h"

/* Regression guard for the Veil generator fix.
 *
 * The bulletproof blinding generator MUST be the standard generator G (not H):
 * Veil's native 5-arg secp256k1_pedersen_commit blinds on G (commit = blind*G +
 * value*H), so a proof only verifies against such a commitment when its blind
 * generator is G. If a future library sync, refactor, or optimization pass
 * silently resets blinding_gen to H -- or changes the pedersen convention --
 * this test fails loudly instead of shipping non-verifying proofs. */
static void test_bulletproof_veil_pedersen_roundtrip(void) {
    /* Standard generator G serialized as a secp256k1_generator: tag 0x0a
     * (even Y) followed by G.x. */
    static const unsigned char G_generator_ser[33] = {
        0x0a, 0x79,0xBE,0x66,0x7E,0xF9,0xDC,0xBB,0xAC,0x55,0xA0,0x62,0x95,0xCE,0x87,0x0B,
        0x07,0x02,0x9B,0xFC,0xDB,0x2D,0xCE,0x28,0xD9,0x59,0xF2,0x81,0x5B,0x16,0xF8,0x17,0x98
    };
    secp256k1_scratch_space *scratch = secp256k1_scratch_space_create(ctx, 1024 * 1024);
    secp256k1_generator genG;
    secp256k1_bulletproof_generators *gens;
    secp256k1_pedersen_commitment commit;
    unsigned char blind[32];
    unsigned char proof[2000];
    unsigned char nonce[32];
    size_t plen = sizeof(proof);
    const uint64_t value = 123456789ULL;
    uint64_t varr[1];
    const unsigned char *bptr[1];
    size_t i;

    CHECK(scratch != NULL);
    CHECK(secp256k1_generator_parse(ctx, &genG, G_generator_ser) == 1);
    gens = secp256k1_bulletproof_generators_create(ctx, &genG, 256);
    CHECK(gens != NULL);

    for (i = 0; i < 32; i++) {
        blind[i] = (unsigned char)(0x5A + i);
    }
    secp256k1_rand256(nonce);
    varr[0] = value;
    bptr[0] = blind;

    /* Veil native 5-arg commitment: blind*G + value*H. */
    CHECK(secp256k1_pedersen_commit(ctx, &commit, blind, value, secp256k1_generator_h) == 1);

    /* Prove. commits==NULL: the prover recomputes the commitment internally as
     * blind*G + value*H via Veil's pedersen_ecmult (blind on G). */
    CHECK(secp256k1_bulletproof_rangeproof_prove(
        ctx, scratch, gens, proof, &plen, NULL, NULL, NULL,
        varr, NULL, bptr, NULL, 1, secp256k1_generator_h, 64,
        nonce, NULL, NULL, 0, NULL) == 1);

    /* The load-bearing assertion: the proof verifies against Veil's commitment. */
    CHECK(secp256k1_bulletproof_rangeproof_verify(
        ctx, scratch, gens, proof, plen, NULL, &commit, 1, 64,
        secp256k1_generator_h, NULL, 0) == 1);

    /* Negative control: a tampered proof must NOT verify. */
    proof[plen / 2] ^= 0x01;
    CHECK(secp256k1_bulletproof_rangeproof_verify(
        ctx, scratch, gens, proof, plen, NULL, &commit, 1, 64,
        secp256k1_generator_h, NULL, 0) == 0);

    secp256k1_bulletproof_generators_destroy(ctx, gens);
    secp256k1_scratch_space_destroy(scratch);
}

void run_bulletproof_tests(void) {
    int i;
    for (i = 0; i < 8; i++) {
        test_bulletproof_veil_pedersen_roundtrip();
    }
}

#endif /* SECP256K1_MODULE_BULLETPROOF_TESTS */
