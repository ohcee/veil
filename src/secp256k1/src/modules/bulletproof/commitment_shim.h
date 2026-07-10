/* The bulletproof module's commitment helpers (secp256k1_pedersen_commitment_load,
 * secp256k1_pedersen_ecmult) are provided by Veil's rangeproof module, which is
 * included before this module in secp256k1.c. Nothing to add here -- this keeps
 * Veil's native 5-arg secp256k1_pedersen_commit untouched. */
#ifndef SECP256K1_MODULE_BULLETPROOF_COMMITMENT_SHIM_H
#define SECP256K1_MODULE_BULLETPROOF_COMMITMENT_SHIM_H
#endif
