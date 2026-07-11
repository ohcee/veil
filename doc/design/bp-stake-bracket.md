# Design: Bulletproof RingCT stake-value bracketing

Status: **DRAFT / pre-audit.** Not implemented in consensus. The shipped state
is the fail-closed guard in `src/veil/proofofstake/stakeinput.cpp`
(`PublicRingCTStake::GetMinimumInputValue`), which rejects Bulletproof RingCT
coins from public staking. This document specifies how to lift that restriction
safely; it must not be activated on any chain before external review.

## Problem

RingCT staking verifies a staked coin's weight **publicly**, without the owner's
key, so any validator can check the kernel difficulty. Weight is bracketed:
`GetRingCTWeightForValue(v)` maps a value to a bracket floor. The public input to
that mapping is the coinstake output's provable minimum value:

- Legacy Borromean rangeproofs encode a parseable `min_value`. `GetRangeProofInfo`
  reads it; `GetMinimumInputValue` returns it; weight = `GetRingCTWeightForValue(min_value)`.
- Soundness: the proof guarantees `committed_value >= min_value`, and MLSAG binds
  `coinstake_input == coinstake_output`, so `weight(min_value) <= weight(true_value)`.
  A staker cannot inflate weight; honest emission pins `min_value` at the bracket
  floor to maximize claimable weight without lying.

Bulletproofs as emitted here prove `[0, 2^64)` with `min_value = 0` and expose no
parseable public bracket. Post-activation, all new RingCT outputs are BP, so their
stake value cannot be publicly verified — hence the fail-closed rejection.

## Enabling fact

`secp256k1_bulletproof_rangeproof_prove` and `..._verify` both already accept a
`min_value` argument (prove signature carries `const uint64_t* min_value`; the
consensus verify in `CheckAnonOutput` currently passes `nullptr`). A bulletproof
built with `min_value = B` proves `committed_value in [B, B + 2^nbits)`, i.e.
`value >= B`. `min_value` is **not** embedded in the proof bytes — it is a public
input both prover and verifier must supply and agree on.

## Design (Option A — carry an explicit hash-bound floor; do not modify the generator)

1. **Serialization.** Add a public `nStakeMinValue` (uint64) field to the coinstake
   RingCT output. **Load-bearing requirement:** it MUST be covered by
   `CTransaction::GetOutputsHash()`, the MLSAG message, and the RingCT block
   signature. If it is not hash-bound, it is malleable and an attacker rewrites
   `B` upward post-signing to forge weight. This single binding is the whole
   security of the scheme.

2. **Emission** (`RingCTStake::CreateCoinStake` / coinstake output build). For the
   coinstake BP output only: compute `B = GetBracketMinValue()` (already exists) and
   pass `min_value = &B` into `secp256k1_bulletproof_rangeproof_prove`; write `B`
   into `nStakeMinValue`. Ordinary (non-stake) BP outputs keep `min_value = 0`.

3. **Verification** (`CheckAnonOutput`, BP branch, staking outputs). Pass
   `min_value = &out->nStakeMinValue` into `secp256k1_bulletproof_rangeproof_verify`.
   Success ⟹ `value >= nStakeMinValue`.

4. **Weight** (`PublicRingCTStake::GetMinimumInputValue`). Return `nStakeMinValue`
   instead of failing closed; `GetWeight()` = `GetRingCTWeightForValue(nStakeMinValue)`,
   identical to the Borromean path.

## Soundness

`verify(min_value = B)` succeeds ⟹ `value >= B` ⟹ `weight(B) <= weight(value)`.
Setting `B` above the true value → proof fails. Setting `B` in a lower bracket →
less weight, self-defeating. MLSAG binds input == output, so `B` also floors the
input. No weight inflation.

## Privacy

Revealing `B` discloses the coin's bracket — exactly what the Borromean staking
path already leaks. No new regression; bracket-granular anonymity preserved.
Non-staking BP outputs continue to reveal nothing (`min_value = 0`).

## What must be audited before activation

1. **Malleability / hash coverage.** Prove `nStakeMinValue` is included in every
   signed/hashed structure (`GetOutputsHash`, MLSAG preimage, block-sig coverage);
   no path may leave it uncovered.
2. **`min_value + 2^nbits` vs `MoneyRange`.** With `nbits = 64`, the proven upper
   bound is `B + 2^64`, which overflows uint64 and exceeds `MAX_MONEY` (~2^55). A
   nonzero `min_value` widens the provable ceiling. `nbits` almost certainly needs
   to be reduced (e.g. sized per bracket so `B + 2^nbits <= MoneyRange`), or an
   explicit upper-bound check added. Getting this wrong re-opens a mint surface.
   This is the subtle one.
3. **Tally interaction.** `min_value` does not enter the Pedersen sum, so
   `VerifyCoinbase` / MLSAG tallies are unaffected — confirm no path double-counts
   `B` into value accounting.

## Alternatives considered

- **Modify the bulletproof generator to enforce a lower bound.** Rejected: keeps
  the crypto primitive non-stock and expands the audit surface into the proving
  engine. Option A confines the change to emission + serialization + verify dispatch.

## Test coverage

`test/functional/privacy_lifecycle_matrix.py` Scenario B already asserts the
current fail-closed behavior. When this design is implemented, Scenario B's
fail-closed assertion is replaced with a positive staking assertion behind the
BP-active chain, and a malleability negative test (rewrite `nStakeMinValue`,
expect `bad-*` rejection) must be added.
