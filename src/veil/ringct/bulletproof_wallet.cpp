// Copyright (c) 2024 The Veil developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <veil/ringct/bulletproof_wallet.h>

#include <veil/ringct/blind.h>        // BP backend decls + blind_scratch/blind_bp_gens + secp256k1_ctx_blind + secp256k1_generator_h
#include <crypto/hmac_sha256.h>
#include <crypto/chacha20.h>
#include <support/cleanse.h>         // memory_cleanse

#include <algorithm>
#include <cstring>

namespace {

// HKDF-SHA256 (RFC 5869) built on Veil's CHMAC_SHA256.
void HkdfSha256(const uint8_t* salt, size_t saltlen,
                const uint8_t* ikm, size_t ikmlen,
                const uint8_t* info, size_t infolen,
                uint8_t* okm, size_t L)
{
    uint8_t prk[32];
    CHMAC_SHA256(salt, saltlen).Write(ikm, ikmlen).Finalize(prk);

    uint8_t t[32];
    size_t tlen = 0, done = 0;
    uint8_t ctr = 1;
    while (done < L) {
        CHMAC_SHA256 h(prk, sizeof(prk));
        if (tlen) h.Write(t, tlen);
        h.Write(info, infolen);
        h.Write(&ctr, 1);
        h.Finalize(t);
        tlen = sizeof(t);
        size_t take = std::min(L - done, sizeof(t));
        memcpy(okm + done, t, take);
        done += take;
        ctr++;
    }
    memory_cleanse(prk, sizeof(prk));
    memory_cleanse(t, sizeof(t));
}

// okm layout: [0]=viewTag, [1..9)=k_amount, [9..41)=k_blind, [41..73)=k_narr
constexpr size_t OKM_LEN = 73;
const char* const HKDF_INFO = "veil-bp-ecdh-v1";

void DeriveOkm(const uint8_t ss[32], const uint8_t pkEphem[33], uint8_t okm[OKM_LEN])
{
    HkdfSha256(pkEphem, 33, ss, 32,
               reinterpret_cast<const uint8_t*>(HKDF_INFO), strlen(HKDF_INFO),
               okm, OKM_LEN);
}

// ChaCha20 keystream XOR (stream cipher: encrypt == decrypt).
void ChaChaXor(const uint8_t key[32], const uint8_t* in, uint8_t* out, size_t len)
{
    if (len == 0) return;
    ChaCha20 c(key, 32);
    c.SetIV(0);
    c.Seek(0);
    std::vector<uint8_t> ks(len);
    c.Keystream(ks.data(), ks.size());
    for (size_t i = 0; i < len; ++i) out[i] = in[i] ^ ks[i];
    memory_cleanse(ks.data(), ks.size());
}

} // namespace

bool CreateBulletproofOutput(
    const uint8_t ss[32],
    const uint8_t pkEphem[33],
    CAmount amount,
    const uint8_t blind[32],
    const std::string& narration,
    const secp256k1_pedersen_commitment& commitment,
    CEcdhInfo& ecdhInfoOut,
    std::vector<uint8_t>& vRangeproofOut,
    std::string& sError)
{
    uint8_t okm[OKM_LEN];
    DeriveOkm(ss, pkEphem, okm);

    // --- Encrypt the payload -------------------------------------------------
    ecdhInfoOut.SetNull();
    ecdhInfoOut.vchViewTag[0] = okm[0];

    const uint64_t leAmount = static_cast<uint64_t>(amount);
    for (int i = 0; i < 8; ++i)
        ecdhInfoOut.vchAmount[i] = static_cast<uint8_t>((leAmount >> (i * 8)) & 0xff) ^ okm[1 + i];
    for (int i = 0; i < 32; ++i)
        ecdhInfoOut.vchBlind[i] = blind[i] ^ okm[9 + i];

    if (!narration.empty()) {
        ecdhInfoOut.vNarration.resize(narration.size());
        ChaChaXor(okm + 41,
                  reinterpret_cast<const uint8_t*>(narration.data()),
                  ecdhInfoOut.vNarration.data(),
                  narration.size());
    }

    // --- Generate the Bulletproof -------------------------------------------
    // ss is used directly as the proof nonce; nbits pinned to 64.
    if (blind_scratch == nullptr || blind_bp_gens == nullptr) {
        sError = "Bulletproof backend not initialized (ECC_Start_Blinding)";
        memory_cleanse(okm, sizeof(okm));
        return false;
    }

    const uint64_t value[1] = { static_cast<uint64_t>(amount) };
    const uint8_t* blindPtr[1] = { blind };
    const secp256k1_pedersen_commitment* commitPtr[1] = { &commitment };

    vRangeproofOut.assign(1024, 0); // BULLETPROOF_MAX_LEN
    size_t plen = vRangeproofOut.size();

    int rv = secp256k1_bulletproof_rangeproof_prove(
        secp256k1_ctx_blind, blind_scratch, blind_bp_gens,
        vRangeproofOut.data(), &plen,
        nullptr /*tau_x*/, nullptr /*t_one*/, nullptr /*t_two*/,
        value, nullptr /*min_value*/, blindPtr, commitPtr, 1 /*n_commits*/,
        secp256k1_generator_h, 64 /*nbits*/,
        ss /*nonce*/, nullptr /*private_nonce*/, nullptr /*extra_commit*/, 0, nullptr /*message*/);

    memory_cleanse(okm, sizeof(okm));

    if (rv != 1) {
        sError = "secp256k1_bulletproof_rangeproof_prove failed";
        return false;
    }
    vRangeproofOut.resize(plen);
    return true;
}

bool ScanBulletproofOutput(
    const uint8_t ss[32],
    const uint8_t pkEphem[33],
    const CEcdhInfo& ecdhInfo,
    const secp256k1_pedersen_commitment& commitment,
    CAmount& amountOut,
    uint8_t blindOut[32],
    std::string& narrationOut)
{
    uint8_t okm[OKM_LEN];
    DeriveOkm(ss, pkEphem, okm);

    // 1. View-tag fast reject: no EC math for non-matching outputs.
    if (ecdhInfo.vchViewTag[0] != okm[0]) {
        memory_cleanse(okm, sizeof(okm));
        return false;
    }

    // 2. Decrypt.
    uint64_t leAmount = 0;
    for (int i = 0; i < 8; ++i)
        leAmount |= static_cast<uint64_t>(static_cast<uint8_t>(ecdhInfo.vchAmount[i] ^ okm[1 + i])) << (i * 8);
    amountOut = static_cast<CAmount>(leAmount);
    for (int i = 0; i < 32; ++i)
        blindOut[i] = ecdhInfo.vchBlind[i] ^ okm[9 + i];

    narrationOut.clear();
    if (!ecdhInfo.vNarration.empty()) {
        std::vector<uint8_t> pt(ecdhInfo.vNarration.size());
        ChaChaXor(okm + 41, ecdhInfo.vNarration.data(), pt.data(), pt.size());
        narrationOut.assign(reinterpret_cast<const char*>(pt.data()), pt.size());
        memory_cleanse(pt.data(), pt.size());
    }
    memory_cleanse(okm, sizeof(okm));

    // 3. Load-bearing bind-check: a valid amount must be non-negative and the
    //    recomputed commitment must exactly equal the on-chain one. This is what
    //    authenticates the payload (a forged ecdhInfo cannot pass it).
    if (!MoneyRange(amountOut))
        return false;

    secp256k1_pedersen_commitment check;
    if (secp256k1_pedersen_commit(secp256k1_ctx_blind, &check, blindOut,
                                  static_cast<uint64_t>(amountOut), secp256k1_generator_h) != 1)
        return false;

    return memcmp(check.data, commitment.data, 33) == 0;
}
