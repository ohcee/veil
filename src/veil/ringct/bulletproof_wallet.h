// Copyright (c) 2024 The Veil developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef VEIL_RINGCT_BULLETPROOF_WALLET_H
#define VEIL_RINGCT_BULLETPROOF_WALLET_H

#include <amount.h>
#include <primitives/transaction.h>   // CEcdhInfo
#include <secp256k1_rangeproof.h>     // secp256k1_pedersen_commitment

#include <string>
#include <vector>
#include <cstdint>

/**
 * Bulletproof (v1) wallet prover/scanner for the CEcdhInfo data-carrying layer.
 *
 * These helpers take the ECDH shared secret `ss` as input (ss = SHA256(
 * sEphem.ECDH(pkTo)) on the prover side, SHA256(scanKey.ECDH(pkEphem)) on the
 * recipient side), so they are independent of the wallet key machinery and can
 * be unit-tested in isolation. Wire the prover into AddCTData's proof-generation
 * site and the scanner into the incoming-tx scan (replacing rangeproof_rewind).
 */

/**
 * Prover. Fills `ecdhInfoOut` with the encrypted amount/blind/narration and
 * produces the Bulletproof `vRangeproofOut` for `commitment`. Returns false on
 * failure (sError set). `commitment` must already be the Pedersen commitment to
 * (amount, blind) built with secp256k1_generator_h, matching the verifier.
 */
bool CreateBulletproofOutput(
    const uint8_t ss[32],
    const uint8_t pkEphem[33],
    CAmount amount,
    const uint8_t blind[32],
    const std::string& narration,
    const secp256k1_pedersen_commitment& commitment,
    CEcdhInfo& ecdhInfoOut,
    std::vector<uint8_t>& vRangeproofOut,
    std::string& sError);

/**
 * Recipient scan. Order matters:
 *   1. view-tag fast reject (no EC math on non-matches),
 *   2. decrypt amount/blind/narration,
 *   3. THE load-bearing bind-check: recompute the Pedersen commitment from the
 *      decrypted (amount, blind) and require byte-equality with `commitment`.
 * Returns true (and fills outputs) only if the bind-check holds -- this is what
 * authenticates the payload; the view tag is only a scan-speed optimization.
 */
bool ScanBulletproofOutput(
    const uint8_t ss[32],
    const uint8_t pkEphem[33],
    const CEcdhInfo& ecdhInfo,
    const secp256k1_pedersen_commitment& commitment,
    CAmount& amountOut,
    uint8_t blindOut[32],
    std::string& narrationOut);

#endif // VEIL_RINGCT_BULLETPROOF_WALLET_H
