// Copyright (c) 2026 The Veil developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

// Consensus unit tests for RingCT proof-of-stake.
//
// These cover the pure, chain-independent parts of the staking soundness
// model — the pieces where a silent bug is a direct inflation or
// stake-weight-forgery vector:
//   * stakeTargetHit()          — kernel difficulty comparison incl. the
//                                 safeMultiply overflow -> auto-pass path.
//   * GetRingCTWeightForValue() — the bracketed stake weight, and the
//                                 critical invariant weight(v) <= v that the
//                                 whole "you cannot claim more weight than
//                                 your coin is worth" argument rests on.
//
// They deliberately use no ECC context, node, or chain state so they run in
// microseconds and can guard every future change under the sanitizer CI job.

#include <boost/test/unit_test.hpp>

#include <amount.h>
#include <arith_uint256.h>
#include <limits>
#include <stdint.h>

#include <test/test_veil.h>

// --- Functions under test -------------------------------------------------
// stakeTargetHit is declared in veil/proofofstake/kernel.h. GetRingCTWeightForValue
// and fast_log16 are external-linkage free functions defined in
// veil/proofofstake/stakeinput.cpp with no public header; forward-declared here so
// the test links against the real symbols without any production-code change.
bool stakeTargetHit(arith_uint256 hashProofOfStake, int64_t nValueIn, arith_uint256 bnTargetPerCoinDay);
CAmount GetRingCTWeightForValue(const CAmount& nValueIn);
int fast_log16(uint64_t value);

BOOST_FIXTURE_TEST_SUITE(ringct_staking_tests, BasicTestingSetup)

// ===========================================================================
// stakeTargetHit  (#1 overflow path, #2 boundary cases)
// ===========================================================================
//
// stakeTargetHit computes bnTarget = nValueIn * bnTargetPerCoinDay and returns
// (hashProofOfStake < bnTarget). On multiplication overflow the real target
// saturates to ~0 (MAX_UINT256), an intentional auto-pass so a legitimately
// huge weight is never penalised by wraparound.

BOOST_AUTO_TEST_CASE(staketargethit_boundary_no_overflow)
{
    // weight * per-coin-day target = 1000 * 1000 = 1,000,000, no overflow.
    const int64_t nValueIn = 1000;
    const arith_uint256 bnTarget(1000);

    // Comparison is strict "<": just under passes, exactly-at and just-over fail.
    BOOST_CHECK(stakeTargetHit(arith_uint256(999999), nValueIn, bnTarget));       // hash <  target
    BOOST_CHECK(!stakeTargetHit(arith_uint256(1000000), nValueIn, bnTarget));     // hash == target
    BOOST_CHECK(!stakeTargetHit(arith_uint256(1000001), nValueIn, bnTarget));     // hash >  target
}

BOOST_AUTO_TEST_CASE(staketargethit_zero_weight_never_passes)
{
    // A zero-weight coin yields target 0; nothing is < 0, so it can never stake.
    // This is the arithmetic backstop behind CheckProofOfStake's nValue==0 guard.
    const arith_uint256 bnTarget(1000);
    BOOST_CHECK(!stakeTargetHit(arith_uint256(0), 0, bnTarget));
    BOOST_CHECK(!stakeTargetHit(arith_uint256(1), 0, bnTarget));
}

BOOST_AUTO_TEST_CASE(staketargethit_overflow_autopasses)
{
    // nValueIn ~ 2^63 and bnTargetPerCoinDay = 2^200 -> product ~ 2^263 overflows
    // 256 bits -> target saturates to MAX -> any hash strictly below MAX passes,
    // regardless of how large the hash is.
    const int64_t nHugeWeight = std::numeric_limits<int64_t>::max();
    arith_uint256 bnHugeTarget(1);
    bnHugeTarget <<= 200;

    arith_uint256 hashHigh(1);
    hashHigh <<= 255;                       // 2^255, still < MAX_UINT256

    BOOST_CHECK(stakeTargetHit(arith_uint256(0), nHugeWeight, bnHugeTarget));
    BOOST_CHECK(stakeTargetHit(hashHigh, nHugeWeight, bnHugeTarget));

    // Only the single MAX value fails the strict "<" against a saturated target.
    BOOST_CHECK(!stakeTargetHit(~arith_uint256(), nHugeWeight, bnHugeTarget));
}

// ===========================================================================
// GetRingCTWeightForValue  (#3 bracket table vs documented behaviour)
// ===========================================================================

BOOST_AUTO_TEST_CASE(ringct_weight_ineligibility_floor)
{
    // Values at or below the bare minimum (16 sats) are not stakeable: weight 0.
    for (CAmount v = 0; v <= 16; ++v)
        BOOST_CHECK_EQUAL(GetRingCTWeightForValue(v), CAmount(0));

    // The first stakeable value (17) has non-zero weight.
    BOOST_CHECK(GetRingCTWeightForValue(17) > 0);
}

BOOST_AUTO_TEST_CASE(ringct_weight_low_bracket_boundaries_exact)
{
    // Brackets 1..7 carry no reduction: weight == bracket floor == 16^k + 1.
    // Each bracket k covers input values (16^k, 16^(k+1)]; the weight is constant
    // across the bracket and steps up only when the input crosses 16^(k+1).
    struct { CAmount lo; CAmount hi; CAmount weight; } cases[] = {
        {          17,          256,          17 },   // bracket 1: 16^1+1 .. 16^2
        {         257,         4096,         257 },   // bracket 2
        {        4097,        65536,        4097 },   // bracket 3
        {       65537,      1048576,       65537 },   // bracket 4
        {     1048577,     16777216,     1048577 },   // bracket 5
        {    16777217,    268435456,    16777217 },   // bracket 6
        {   268435457,   4294967296,   268435457 },   // bracket 7: 16^7+1 .. 16^8
    };
    for (const auto& c : cases) {
        BOOST_CHECK_EQUAL(GetRingCTWeightForValue(c.lo), c.weight);   // at floor
        BOOST_CHECK_EQUAL(GetRingCTWeightForValue(c.hi), c.weight);   // at ceiling (still same bracket)
        BOOST_CHECK_EQUAL(GetRingCTWeightForValue(c.lo + 1), c.weight);
    }
}

BOOST_AUTO_TEST_CASE(ringct_weight_high_brackets_reduced)
{
    // Brackets 8..13 apply the documented reduction factors (95/91/71/50/30/10 %).
    // Assert both the exact documented value AND that it is strictly below the
    // un-reduced floor (16^k+1) — a bug that dropped the reduction would leave
    // weight == floor and be caught here.
    struct { CAmount floorVal; CAmount weight; } cases[] = {
        { (CAmount(1) << 32) + 1, (((CAmount(1) << 32) + 1) * 95) / 100 }, // bracket 8
        { (CAmount(1) << 36) + 1, (((CAmount(1) << 36) + 1) * 91) / 100 }, // bracket 9
        { (CAmount(1) << 40) + 1, (((CAmount(1) << 40) + 1) * 71) / 100 }, // bracket 10
        { (CAmount(1) << 44) + 1, (((CAmount(1) << 44) + 1) *  5) /  10 }, // bracket 11
        { (CAmount(1) << 48) + 1, (((CAmount(1) << 48) + 1) *  3) /  10 }, // bracket 12
        { (CAmount(1) << 52) + 1,  ((CAmount(1) << 52) + 1)       /  10 }, // bracket 13
    };
    for (const auto& c : cases) {
        BOOST_CHECK_EQUAL(GetRingCTWeightForValue(c.floorVal), c.weight);
        BOOST_CHECK(c.weight < c.floorVal);   // reduction is actually applied
    }
}

BOOST_AUTO_TEST_CASE(ringct_weight_saturates_top_bracket)
{
    // Values above bracket 13 clamp to the top bracket weight and must not
    // overflow/wrap. Bracket 13 floor is 16^13+1 = 2^52+1.
    const CAmount top = GetRingCTWeightForValue((CAmount(1) << 52) + 1);
    BOOST_CHECK_EQUAL(GetRingCTWeightForValue(CAmount(1) << 56), top);
    BOOST_CHECK_EQUAL(GetRingCTWeightForValue(CAmount(1) << 60), top);
    BOOST_CHECK_EQUAL(GetRingCTWeightForValue(MAX_MONEY), top);
    BOOST_CHECK(top > 0);
}

BOOST_AUTO_TEST_CASE(ringct_weight_never_exceeds_value)
{
    // THE staking soundness invariant: the weight granted to a coin can never
    // exceed the coin's own value. weight(v) is the (possibly reduced) bracket
    // floor, which is <= v by construction. If this ever fails, a smaller coin
    // can claim a larger coin's stake weight = forgery / inflation vector.
    const CAmount samples[] = {
        17, 18, 100, 255, 256, 257, 4096, 4097, 65536, 65537,
        1048577, 16777217, 268435457,
        (CAmount(1) << 32) + 1, (CAmount(1) << 36) + 1, (CAmount(1) << 40) + 1,
        (CAmount(1) << 44) + 1, (CAmount(1) << 48) + 1, (CAmount(1) << 52) + 1,
        (CAmount(1) << 56), MAX_MONEY,
    };
    for (const CAmount v : samples)
        BOOST_CHECK_MESSAGE(GetRingCTWeightForValue(v) <= v,
                            "weight(" << v << ") = " << GetRingCTWeightForValue(v) << " exceeds value");

    // Dense sweep across the low-bracket boundaries to catch off-by-one edges.
    for (CAmount v = 17; v <= 300000; ++v)
        BOOST_CHECK(GetRingCTWeightForValue(v) <= v);
}

BOOST_AUTO_TEST_CASE(ringct_weight_monotonic_nondecreasing)
{
    // Weight must never decrease as value increases across bracket boundaries;
    // a mis-ordered table or broken fast_log16 would violate this.
    CAmount prev = 0;
    const CAmount boundaries[] = {
        17, 257, 4097, 65537, 1048577, 16777217, 268435457,
        (CAmount(1) << 32) + 1, (CAmount(1) << 36) + 1, (CAmount(1) << 40) + 1,
        (CAmount(1) << 44) + 1, (CAmount(1) << 48) + 1, (CAmount(1) << 52) + 1,
    };
    for (const CAmount v : boundaries) {
        const CAmount w = GetRingCTWeightForValue(v);
        BOOST_CHECK(w >= prev);
        prev = w;
    }
}

BOOST_AUTO_TEST_CASE(fast_log16_boundaries)
{
    // fast_log16(x) = floor(log16(x)). Bracket assignment depends on it exactly
    // stepping at powers of 16.
    BOOST_CHECK_EQUAL(fast_log16(0), 0);
    BOOST_CHECK_EQUAL(fast_log16(1), 0);
    BOOST_CHECK_EQUAL(fast_log16(15), 0);
    BOOST_CHECK_EQUAL(fast_log16(16), 1);
    BOOST_CHECK_EQUAL(fast_log16(255), 1);
    BOOST_CHECK_EQUAL(fast_log16(256), 2);
    BOOST_CHECK_EQUAL(fast_log16(4095), 2);
    BOOST_CHECK_EQUAL(fast_log16(4096), 3);
    BOOST_CHECK_EQUAL(fast_log16(uint64_t(1) << 52), 13);  // 16^13
}

BOOST_AUTO_TEST_SUITE_END()
