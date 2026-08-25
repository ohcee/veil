// ethash: C/C++ implementation of Ethash, the Ethereum Proof of Work algorithm.
// Copyright 2018-2019 Pawel Bylica.
// Licensed under the Apache License, Version 2.0.

/// @file
///
/// ProgPoW API
///
/// This file provides the public API for ProgPoW as the Ethash API extension.

#include <crypto/ethash/include/ethash/ethash.hpp>

namespace progpow
{
using namespace ethash;  // Include ethash namespace.


/// The ProgPoW algorithm revision implemented as specified in the spec
/// https://github.com/ifdefelse/ProgPOW#change-history.
constexpr auto revision = "0.9.4";

constexpr int period_length = 10;
constexpr uint32_t num_regs = 32;
constexpr size_t num_lanes = 16;
constexpr int num_cache_accesses = 11;
constexpr int num_math_operations = 18;
constexpr size_t l1_cache_size = 16 * 1024;
constexpr size_t l1_cache_num_items = l1_cache_size / sizeof(uint32_t);

// The `period` argument is the number of consecutive blocks that share one random
// program (see period_length). It defaults to the vendored constant so existing
// callers and the ProgPoW spec test vectors are unaffected; Veil passes a
// height-dependent value (CChainParams::GetProgPowPeriod) to shorten it at a fork.
result hash(const epoch_context& context, int block_number, const hash256& header_hash,
    uint64_t nonce, int period = period_length) noexcept;

result hash(const epoch_context_full& context, int block_number, const hash256& header_hash,
    uint64_t nonce, int period = period_length) noexcept;

bool verify(const epoch_context& context, int block_number, const hash256& header_hash,
    const hash256& mix_hash, uint64_t nonce, const hash256& boundary,
    int period = period_length) noexcept;

search_result search_light(const epoch_context& context, int block_number,
    const hash256& header_hash, const hash256& boundary, uint64_t start_nonce,
    size_t iterations, int period = period_length) noexcept;

search_result search(const epoch_context_full& context, int block_number,
    const hash256& header_hash, const hash256& boundary, uint64_t start_nonce,
    size_t iterations, int period = period_length) noexcept;

}  // namespace progpow
