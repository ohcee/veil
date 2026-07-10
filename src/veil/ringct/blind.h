// Copyright (c) 2017-2019 The Particl Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef VEIL_BLIND_H
#define VEIL_BLIND_H

#include <secp256k1.h>
#include <secp256k1_rangeproof.h>   // secp256k1_pedersen_commitment
#include <secp256k1_generator.h>    // secp256k1_generator
#include <inttypes.h>
#include <vector>

#include <amount.h>

extern secp256k1_context *secp256k1_ctx_blind;

// --- Classic Bulletproofs (v1) backend -------------------------------------
// Declarations only. Implementations are provided by libsecp256k1 once the
// classic bulletproof module is grafted into src/secp256k1 (validated
// separately on the Grin-lineage secp256k1-zkp). These signatures match that
// module exactly, so pulling in the real <secp256k1_bulletproofs.h> later does
// not conflict. blind_scratch / blind_bp_gens are allocated in ECC_Start_Blinding.
typedef struct secp256k1_scratch_space_struct secp256k1_scratch_space;
typedef struct secp256k1_bulletproof_generators secp256k1_bulletproof_generators;

extern secp256k1_scratch_space *blind_scratch;
extern secp256k1_bulletproof_generators *blind_bp_gens;

#ifdef __cplusplus
extern "C" {
#endif
secp256k1_scratch_space* secp256k1_scratch_space_create(const secp256k1_context* ctx, size_t max_size);
void secp256k1_scratch_space_destroy(secp256k1_scratch_space* scratch);

secp256k1_bulletproof_generators* secp256k1_bulletproof_generators_create(
    const secp256k1_context* ctx, const secp256k1_generator* blinding_gen, size_t n);
void secp256k1_bulletproof_generators_destroy(
    const secp256k1_context* ctx, secp256k1_bulletproof_generators* gens);

int secp256k1_bulletproof_rangeproof_prove(
    const secp256k1_context* ctx,
    secp256k1_scratch_space* scratch,
    const secp256k1_bulletproof_generators* gens,
    unsigned char* proof,
    size_t* plen,
    unsigned char* tau_x,
    secp256k1_pubkey* t_one,
    secp256k1_pubkey* t_two,
    const uint64_t* value,
    const uint64_t* min_value,
    const unsigned char* const* blind,
    const secp256k1_pedersen_commitment* const* commits,
    size_t n_commits,
    const secp256k1_generator* value_gen,
    size_t nbits,
    const unsigned char* nonce,
    const unsigned char* private_nonce,
    const unsigned char* extra_commit,
    size_t extra_commit_len,
    const unsigned char* message);

int secp256k1_bulletproof_rangeproof_verify(
    const secp256k1_context* ctx,
    secp256k1_scratch_space* scratch,
    const secp256k1_bulletproof_generators* gens,
    const unsigned char* proof,
    size_t plen,
    const uint64_t* min_value,
    const secp256k1_pedersen_commitment* commit,
    size_t n_commits,
    size_t nbits,
    const secp256k1_generator* value_gen,
    const unsigned char* extra_commit,
    size_t extra_commit_len);
#ifdef __cplusplus
}
#endif

int SelectRangeProofParameters(uint64_t nValueIn, uint64_t &minValue, int &exponent, int &nBits);

int GetRangeProofInfo(const std::vector<uint8_t> &vRangeproof, int &rexp, int &rmantissa, CAmount &min_value, CAmount &max_value);

void ECC_Start_Blinding();
void ECC_Stop_Blinding();

#endif //VEIL_BLIND_H
