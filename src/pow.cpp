// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2019 The Bitcoin Core developers
// Copyright (c) 2019-2020 Veil developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <pow.h>

#include <chain.h>
#include <primitives/block.h>
#include <uint256.h>
#include <tinyformat.h>
#include <boost/thread.hpp>

#include <algorithm>
#include <cstring>
#include <vector>

// ProgPow
#include <crypto/ethash/lib/ethash/endianness.hpp>

// RandomX
#include <crypto/randomx/randomx.h>
#include <miner.h>
#include <validation.h>
#include <chainparams.h>

// TODO, build an class object that holds this data
// Used by CPU miner for randomx
CCriticalSection cs_randomx_mining;
static uint256 mining_key_block;
static randomx_cache *myMiningCache;
static randomx_dataset *myMiningDataset;
std::vector<randomx_vm*> vecRandomXVM;
std::vector<std::thread> vecRandomXThreads;
bool fKeyBlockedChanged = false;

// Used by Validator
CCriticalSection cs_randomx_validator;
static uint256 validation_key_block;
static randomx_cache *myCacheValidating;
static randomx_vm *myMachineValidating;
static bool fLightCacheInited = false;

bool IsRandomXLightInit()
{
    LOCK(cs_randomx_validator);
    return fLightCacheInited;
}

void InitRandomXLightCache(const int32_t& height) {
    LOCK(cs_randomx_validator);
    if (fLightCacheInited)
        return;

    validation_key_block = GetKeyBlock(height);

    global_randomx_flags = (int)randomx_get_flags();
    myCacheValidating = randomx_alloc_cache((randomx_flags)global_randomx_flags);
    randomx_init_cache(myCacheValidating, &validation_key_block, sizeof uint256());
    LogPrintf("%s: Spinning up a new vm at new block height: %d\n", __func__, height);
    myMachineValidating = randomx_create_vm_timed((randomx_flags)global_randomx_flags, myCacheValidating, NULL, true);
    fLightCacheInited = true;
}

void KeyBlockChanged(const uint256& new_block) {
    LOCK(cs_randomx_validator);
    validation_key_block = new_block;

    DeallocateRandomXLightCache();
    myCacheValidating = randomx_alloc_cache((randomx_flags)global_randomx_flags);
    randomx_init_cache(myCacheValidating, &validation_key_block, sizeof uint256());
    LogPrintf("%s: Spinning up a new vm at new block: %s\n", __func__, new_block.GetHex());
    myMachineValidating = randomx_create_vm_timed((randomx_flags)global_randomx_flags, myCacheValidating, NULL, true);
    fLightCacheInited = true;
}

uint256 GetCurrentKeyBlock() {

    return validation_key_block;
}

randomx_vm* GetMyMachineValidating() {
    return myMachineValidating;
}

randomx_flags GetRandomXFlags() {
    return (randomx_flags)global_randomx_flags;
}

bool CheckIfMiningKeyShouldChange(const uint256& check_block)
{
    LOCK(cs_randomx_validator);
    return check_block != mining_key_block;
}
void CheckIfValidationKeyShouldChangeAndUpdate(const uint256& check_block)
{
    LOCK(cs_randomx_validator);
    if (check_block != validation_key_block)
        KeyBlockChanged(check_block);
}

void DeallocateRandomXLightCache() {
    LOCK(cs_randomx_validator);
    if (!fLightCacheInited) {
        LogPrintf("%s: Return because light cache isn't inited\n", __func__);
        return;
    }

    if (myMachineValidating) {
        LogPrintf("%s: Releasing the vm\n",__func__);
        randomx_destroy_vm(myMachineValidating);
        myMachineValidating = nullptr;
    }

    if (myCacheValidating) {
        LogPrintf("%s: Releasing the validating cache\n",__func__);
        randomx_release_cache(myCacheValidating);
        myCacheValidating = nullptr;
    }

    fLightCacheInited = false;
}

arith_uint256 GetPowLimit(int nPoWType)
{
    const Consensus::Params& params = Params().GetConsensus();
    // Select the correct pow limit
    if (nPoWType & CBlockHeader::PROGPOW_BLOCK) {
        return UintToArith256(params.powLimitProgPow);
    } else if (nPoWType & CBlock::RANDOMX_BLOCK) {
        return UintToArith256(params.powLimitRandomX);
    } else if (nPoWType & CBlock::SHA256D_BLOCK) {
        return UintToArith256(params.powLimitSha256);
    } else {
        return UintToArith256(params.powLimit);
    }
}

unsigned int GetNextWorkRequired(const CBlockIndex* pindexLast, const CBlockHeader *pblock,
                                    const Consensus::Params& params, bool fProofOfStake, int nPoWType)
{
    assert(pindexLast != nullptr);

    unsigned int nProofOfWorkLimit = UintToArith256(params.powLimit).GetCompact();

    if (nPoWType & CBlock::RANDOMX_BLOCK) {
        nProofOfWorkLimit = UintToArith256(params.powLimitRandomX).GetCompact();
    }

    if (!fProofOfStake && !nPoWType && (pindexLast->GetBlockTime() >= Params().PowUpdateTimestamp())) {
        // If it's the old algo, don't even waste time calculating the difficulty.
        return UintToArith256(params.powLimit).GetCompact();
    }

    if (params.fPowNoRetargeting) // regtest only
        return nProofOfWorkLimit;

    if (pindexLast->GetBlockTime() < Params().PowUpdateTimestamp()) {
        // Use old algo
        return DGW_old(pindexLast, params, fProofOfStake);
    }

    if (!fProofOfStake && (nPoWType & CBlockHeader::SHA256D_BLOCK) && pindexLast->nHeight + 1 >= params.nSha256dLwmaHeight) {
        // SHA256d retargets with the LWMA rule from the activation height
        return LwmaRetarget(pindexLast, params, nPoWType, params.nSha256dLwmaHeight);
    }

    // Retarget every block with DarkGravityWave
    return DarkGravityWave(pindexLast, params, fProofOfStake, nPoWType);
}

unsigned int DGW_old(const CBlockIndex* pindexLast, const Consensus::Params& params, bool fProofOfStake) {
    /* current difficulty formula, veil - DarkGravity v3, written by Evan Duffield - evan@dash.org */
    const arith_uint256 bnPowLimit = UintToArith256(params.powLimit);

    const CBlockIndex *pindex = pindexLast;
    const CBlockIndex* pindexLastMatchingProof = nullptr;
    arith_uint256 bnPastTargetAvg = 0;

    unsigned int nCountBlocks = 0;
    while (nCountBlocks < params.nDgwPastBlocks_old) {
        // Ran out of blocks, return pow limit
        if (!pindex)
            return bnPowLimit.GetCompact();

        // Only consider PoW or PoS blocks but not both
        if (pindex->IsProofOfStake() != fProofOfStake) {
            pindex = pindex->pprev;
            continue;
        } else if (!pindexLastMatchingProof) {
            pindexLastMatchingProof = pindex;
        }

        arith_uint256 bnTarget = arith_uint256().SetCompact(pindex->nBits);
        bnPastTargetAvg = (bnPastTargetAvg * nCountBlocks + bnTarget) / (nCountBlocks + 1);

        if (++nCountBlocks != params.nDgwPastBlocks_old)
            pindex = pindex->pprev;
    }

    arith_uint256 bnNew(bnPastTargetAvg);

    //Should only happen on the first PoS block
    if (pindexLastMatchingProof)
        pindexLastMatchingProof = pindexLast;

    int64_t nActualTimespan = pindexLastMatchingProof->GetBlockTime() - pindex->GetBlockTime();
    int64_t nTargetTimespan = params.nDgwPastBlocks_old * params.nPowTargetSpacing;

    if (nActualTimespan < nTargetTimespan/3)
        nActualTimespan = nTargetTimespan/3;
    if (nActualTimespan > nTargetTimespan*3)
        nActualTimespan = nTargetTimespan*3;
    // Retarget
    bnNew *= nActualTimespan;
    bnNew /= nTargetTimespan;

    if (bnNew > bnPowLimit) {
        bnNew = bnPowLimit;
    }

    return bnNew.GetCompact();
}

unsigned int DarkGravityWave(const CBlockIndex* pindexLast, const Consensus::Params& params, bool fProofOfStake, int nPoWType) {
    /* current difficulty formula, veil - DarkGravity v3, written by Evan Duffield - evan@dash.org */
    arith_uint256 bnPowLimit = GetPowLimit(nPoWType);

    const CBlockIndex *pindex = pindexLast;
    const CBlockIndex *pStart = pindexLast;
    const CBlockIndex* pindexLastMatchingProof = nullptr;
    const CBlockIndex* pindexOneBack = nullptr;
    arith_uint256 bnPastTargetAvg = 0;

    unsigned int nCountBlocks = 0;
    int64_t nPastBlocks = Params().GetDwgPastBlocks(pindexLast, nPoWType, fProofOfStake);
    bool fNewPoW = true;
    while (nCountBlocks < nPastBlocks) {
        // Ran out of blocks, return pow limit
        if (!pindex)
            return bnPowLimit.GetCompact();

        fNewPoW = false;
        // If we're looking for new algo blocks
        if (nPoWType & (CBlockHeader::PROGPOW_BLOCK | CBlockHeader::RANDOMX_BLOCK | CBlockHeader::SHA256D_BLOCK)) {
            // Check if we've walked to before the switchover
            fNewPoW = true;
            if (pindex->GetBlockTime() < Params().PowUpdateTimestamp()) {
                // We don't have enough of the blocks, get out and use what we have
                break;
            }
        }

        // Only consider PoW or PoS blocks but not both
        if (pindex->IsProofOfStake() != fProofOfStake) {
            pindex = pindex->pprev;
            continue;
        } else if ((nPoWType & CBlockHeader::PROGPOW_BLOCK) && !pindex->IsProgProofOfWork()) {
            pindex = pindex->pprev;
            continue;
        } else if ((nPoWType & CBlockHeader::RANDOMX_BLOCK) && !pindex->IsRandomXProofOfWork()) {
            pindex = pindex->pprev;
            continue;
        } else if ((nPoWType & CBlockHeader::SHA256D_BLOCK) && !pindex->IsSha256DProofOfWork()) {
            pindex = pindex->pprev;
            continue;
        } else if (pindex->IsX16RTProofOfWork() && !fProofOfStake && nPoWType != 0) {
            pindex = pindex->pprev;
            continue;
        } else if (!pindexLastMatchingProof) {
            // save the tip block for the proof
            pindexLastMatchingProof = pindex;
        } else if (!pindexOneBack) {
            // save the second one back in case the tip is the mined one
            pindexOneBack = pindex;
        }

        arith_uint256 bnTarget = arith_uint256().SetCompact(pindex->nBits);
        bnPastTargetAvg = (bnPastTargetAvg * nCountBlocks + bnTarget) / (nCountBlocks + 1);

        if (++nCountBlocks < nPastBlocks)
            pindex = pindex->pprev;
    }

    arith_uint256 bnNew(bnPastTargetAvg);

    //Should only happen on the first PoS block
    if (pindexLastMatchingProof && !pindex->IsProgProofOfWork() &&
            !pindex->IsRandomXProofOfWork() && !pindex->IsSha256DProofOfWork()) {
        pindexLastMatchingProof = pindexLast;
    }

    if (!pindexLastMatchingProof) {
        // If the algo isn't mined yet, set to min difficulty and be done
        return bnPowLimit.GetCompact();
    }

    int64_t nPowSpacing  = Params().GetTargetSpacing(pindexLast, nPoWType, fProofOfStake);

    int64_t nActualTimespan;
    int64_t nTargetTimespan;
    if (fProofOfStake) {
        // Proof of Stake will judge the whole chain spacing, and adjust in case there isn't
        // enough mining to maintain optimum spacing
        nActualTimespan = pStart->GetBlockTime() - pindex->GetBlockTime();
        nTargetTimespan =(pStart->nHeight - pindex->nHeight) * nPowSpacing;
    } else {
        nActualTimespan = pindexLastMatchingProof->GetBlockTime() - pindex->GetBlockTime();
        nTargetTimespan = nCountBlocks * nPowSpacing;
    }

    // If we are calculating the diff for RandomX, Sha256, or ProgPow
    // We want to take into account the latest block tip time into the calculation
    int64_t nTipToLastMatchingProof = pindexLast->GetBlockTime() - pindexLastMatchingProof->GetBlockTime();
    int64_t nOverdueTime = nTipToLastMatchingProof - nPowSpacing;
    if (!nTipToLastMatchingProof) {
        // Tip is our algo, so look one more back to see where we're at
        if (pindexOneBack) {
            nOverdueTime = pindexLastMatchingProof->GetBlockTime() - pindexOneBack->GetBlockTime() - nPowSpacing;
        }
    }

    if (fProofOfStake) {
        // The concept of Overdue is variable; as it's anywhere from 60 to 120s, based on how many blocks
        // over the timespan.
        // pStart->nHeight - pindex->nHeight = number of blocks in measured sequence.
        // number of blocks in sequence - nCountBlocks = number of non-PoS blocks in measured sequence
        // number of blocks in sequence >> 1 = number of Non-PoS blocks there is supposed to be
        // spacing = 60 + 60 * (actual / supposed)
        // e.g. 60 + 60 * 30/30 = 120.   60 + 60 * 15/30 = 90.  60 + 60 * 0/30 = 60.
        int64_t nBlocksMeasured = (pStart->nHeight - pindex->nHeight) + 1;
        int64_t nBlocksPoW = nBlocksMeasured - nCountBlocks;
        int64_t nBlocksIntended = nBlocksMeasured >> 1; // 50%
        int64_t nPosSpacing = nPowSpacing + (nPowSpacing * nBlocksPoW / nBlocksIntended);
        nOverdueTime = nTipToLastMatchingProof - nPosSpacing;
        if (!nTipToLastMatchingProof && pindexOneBack) {
            // Tip is our algo, so look one more back to see where we're at
            nOverdueTime = pindexLastMatchingProof->GetBlockTime() - pindexOneBack->GetBlockTime() - nPosSpacing;
        }

        LogPrint(BCLog::BLOCKCREATION,
                 "%s: Blocks Measured=%d, PoS Blocks=%d, ActualPoWBlocks=%d, ExpectedPoWBlocks=%d, nPosSpacing=%d Overdue=%d (%s)\n",
                 __func__, nBlocksMeasured, nCountBlocks, nBlocksPoW, nBlocksIntended,
                 nPosSpacing, nOverdueTime, GetMiningType(nPoWType, fProofOfStake).c_str());
    } else {
        // In the case of fProofOfStake, the actual timespan already runs to the tip, so
        // we're not going to add in the time from last of the proof to tip.
        if (fNewPoW && nOverdueTime > 0) {
            // We're overdue and may need to adjust more.
            nActualTimespan += nOverdueTime;
        }
    }

    LogPrint(BCLog::BLOCKCREATION, "%s: nActualTimespan=%d, nTargetTimespan=%d Overdue=%d (%s)\n", __func__,
             nActualTimespan, nTargetTimespan, nOverdueTime, GetMiningType(nPoWType, fProofOfStake).c_str());
    // ***
    // Make sure we don't overadjust

    if ((nActualTimespan < nTargetTimespan) && (nOverdueTime > 0)) {
        // if we're ahead and adjusting, we might already be where we need
        // to be.  Don't make it more difficult if we're already overdue.
        LogPrint(BCLog::BLOCKCREATION, "%s: %s is ahead but now overdue, don't adjust anymore.\n",
                 __func__, GetMiningType(nPoWType, fProofOfStake).c_str());
        return bnNew.GetCompact();
    }

    if ((nActualTimespan > nTargetTimespan) && (nOverdueTime <= 0)) {
        // if we're behind, and we're not overdue, we might be where we need to be
        LogPrint(BCLog::BLOCKCREATION, "%s: %s is behind but moving don't adjust anymore.\n",
            __func__, GetMiningType(nPoWType, fProofOfStake).c_str());
        return bnNew.GetCompact();
    }
    // ***

    LogPrint(BCLog::BLOCKCREATION, "%s: Adjusting %s: old target: %s\n",
             __func__, GetMiningType(nPoWType, fProofOfStake).c_str(), bnNew.GetHex());

    arith_uint256 bnOld(bnNew); // Save the old target

    // Retarget
    bnNew *= nActualTimespan;
    bnNew /= nTargetTimespan;

    if (bnNew > bnPowLimit) {
        bnNew = bnPowLimit;
    }

    if ((nActualTimespan > nTargetTimespan) && (bnOld > bnNew)) {
        // If we should be reducing the difficulty, and the target has gone down, we've overflowed.
        LogPrint(BCLog::BLOCKCREATION, "%s: Multiplier %.4f for %s overflowed.  Setting Min Difficulty.\n",
                 __func__, (double) ((double)nActualTimespan / (double)nTargetTimespan),
                 GetMiningType(nPoWType, fProofOfStake).c_str());
        bnNew = bnPowLimit;
    }

    LogPrint(BCLog::BLOCKCREATION, "%s: Adjusting %s: new target: %s\n",
             __func__, GetMiningType(nPoWType, fProofOfStake).c_str(), bnNew.GetHex());
    return bnNew.GetCompact();
}

namespace {

struct LwmaBlock {
    int64_t nTime;       // the block's own time
    int64_t nPrevTime;   // time of the block it was built on (what its miner saw as the tip)
    int64_t nSinceLast;  // seconds from the previous block of the algo to that tip, 0 for the oldest
    int nHeight;
    arith_uint256 bnTarget;
};

bool IsAlgoBlock(const CBlockIndex* pindex, int nPoWType)
{
    if (pindex->IsProofOfStake())
        return false;
    if (nPoWType & CBlockHeader::PROGPOW_BLOCK)
        return pindex->IsProgProofOfWork();
    if (nPoWType & CBlockHeader::RANDOMX_BLOCK)
        return pindex->IsRandomXProofOfWork();
    if (nPoWType & CBlockHeader::SHA256D_BLOCK)
        return pindex->IsSha256DProofOfWork();
    return false;
}

arith_uint512 Widen(const arith_uint256& a)
{
    uint256 u = ArithToUint256(a);
    uint512 v;
    memcpy(v.begin(), u.begin(), u.size());
    return UintToArith512(v);
}

// Caller guarantees a < 2^256
arith_uint256 Narrow(const arith_uint512& a)
{
    uint512 v = ArithToUint512(a);
    uint256 u;
    memcpy(u.begin(), v.begin(), u.size());
    return UintToArith256(u);
}

/**
 * Level of the window: the target at which the blocks would have come exactly nSpacing apart,
 * estimated as weighted time over weighted work (Zawy's LWMA weights, newest heaviest).
 * Each block's work is taken at the level its miner was held to, i.e. the time factor that
 * lowered its requirement is divided back out; blocks mined before the activation height had
 * no such factor. vBlocks is oldest first, the first entry only provides the starting time.
 * Returns 2^256 * sum(i * solvetime_i) / sum(i * work_i * factor_i) as a 512 bit value.
 */
arith_uint512 LwmaLevel(const std::vector<LwmaBlock>& vBlocks, int64_t nSpacing, int nActivationHeight)
{
    int64_t nPrevTime = vBlocks[0].nTime;
    int64_t nSumTime = 0;
    arith_uint512 bnSumWork = 0;
    for (size_t i = 1; i < vBlocks.size(); i++) {
        const LwmaBlock& block = vBlocks[i];
        // Solvetimes are at least one second; Veil only allows a block time 15 s before its
        // parent and 75 s into the future, so no clamp on long solvetimes is needed.
        int64_t nTime = block.nTime > nPrevTime ? block.nTime : nPrevTime + 1;
        int64_t nSolveTime = nTime - nPrevTime;
        nPrevTime = nTime;
        nSumTime += nSolveTime * (int64_t)i;

        int64_t nFactor = nSpacing;
        if (block.nHeight >= nActivationHeight && block.nSinceLast > nSpacing)
            nFactor = block.nSinceLast;

        // Same work formula as GetBlockProof: 2^256 / (target + 1)
        arith_uint512 bnWork = Widen((~block.bnTarget / (block.bnTarget + 1)) + 1);
        bnWork *= arith_uint512((uint64_t)nFactor);
        bnWork *= arith_uint512((uint64_t)i);
        bnSumWork += bnWork;
    }
    if (bnSumWork == 0)
        return arith_uint512(0);
    arith_uint512 bnLevel = 1;
    bnLevel <<= 256;
    bnLevel *= arith_uint512((uint64_t)nSumTime);
    bnLevel /= bnSumWork;
    return bnLevel;
}

} // namespace

unsigned int LwmaRetarget(const CBlockIndex* pindexLast, const Consensus::Params& params, int nPoWType, int nActivationHeight)
{
    const arith_uint256 bnPowLimit = GetPowLimit(nPoWType);
    const int64_t nSpacing = Params().GetTargetSpacing(pindexLast, nPoWType, false);
    const int64_t nPastBlocks = params.nLwmaPastBlocks;
    const int64_t nWindowSeconds = params.nLwmaWindowMultiplier * nPastBlocks * nSpacing;
    const int64_t nTipTime = pindexLast->GetBlockTime();

    // The newest nPastBlocks + 1 blocks of the algo, oldest first
    std::vector<LwmaBlock> vBlocks;
    vBlocks.reserve(nPastBlocks + 1);
    for (const CBlockIndex* pindex = pindexLast; pindex && (int64_t)vBlocks.size() < nPastBlocks + 1; pindex = pindex->pprev) {
        if (pindex->GetBlockTime() < Params().PowUpdateTimestamp())
            break;
        if (!IsAlgoBlock(pindex, nPoWType))
            continue;
        LwmaBlock block;
        block.nTime = pindex->GetBlockTime();
        block.nPrevTime = pindex->pprev ? pindex->pprev->GetBlockTime() : block.nTime;
        block.nSinceLast = 0;
        block.nHeight = pindex->nHeight;
        block.bnTarget.SetCompact(pindex->nBits);
        vBlocks.push_back(block);
    }
    if (vBlocks.size() < 2)
        return bnPowLimit.GetCompact();
    std::reverse(vBlocks.begin(), vBlocks.end());
    for (size_t i = 1; i < vBlocks.size(); i++) {
        int64_t nSinceLast = vBlocks[i].nPrevTime - vBlocks[i - 1].nTime;
        vBlocks[i].nSinceLast = nSinceLast > 0 ? nSinceLast : 0;
    }

    // Window bounded by time, so after the algo has been dark the level follows whoever is
    // still mining. Always keep the newest two.
    std::vector<LwmaBlock> vWindow;
    for (const LwmaBlock& block : vBlocks) {
        if (block.nTime >= nTipTime - nWindowSeconds)
            vWindow.push_back(block);
    }
    if (vWindow.size() < 2)
        vWindow.assign(vBlocks.end() - 2, vBlocks.end());

    arith_uint512 bnLevel = LwmaLevel(vWindow, nSpacing, nActivationHeight);

    // Burst brake: never easier than nLwmaBrakeFactor times the level over the last
    // nLwmaBrakeBlocks. Inert while blocks arrive normally, bites within a few blocks when a
    // large miner returns to a lowered requirement.
    bool fBraked = false;
    if ((int64_t)vBlocks.size() >= params.nLwmaBrakeBlocks + 1) {
        std::vector<LwmaBlock> vShort(vBlocks.end() - (params.nLwmaBrakeBlocks + 1), vBlocks.end());
        arith_uint512 bnShort = LwmaLevel(vShort, nSpacing, nActivationHeight);
        bnShort *= arith_uint512((uint64_t)params.nLwmaBrakeFactor);
        if (bnShort < bnLevel) {
            bnLevel = bnShort;
            fBraked = true;
        }
    }

    // Time decay: from one spacing after the last block of the algo the requirement falls in
    // proportion to the time since that block (no block for x seconds means the hashrate is at
    // most what would produce one block in x seconds).
    int64_t nSinceLast = nTipTime - vBlocks.back().nTime;
    if (nSinceLast < nSpacing)
        nSinceLast = nSpacing;
    arith_uint512 bnNew = bnLevel;
    bnNew *= arith_uint512((uint64_t)nSinceLast);
    bnNew /= arith_uint512((uint64_t)nSpacing);

    const arith_uint512 bnLimit = Widen(bnPowLimit);
    if (bnNew > bnLimit || bnLevel == 0)
        bnNew = bnLimit;

    LogPrint(BCLog::BLOCKCREATION, "%s: %s window=%d blocks, since last=%d s, braked=%d, new target: %s\n", __func__,
             GetMiningType(nPoWType, false).c_str(), (int)vWindow.size(), nTipTime - vBlocks.back().nTime, fBraked,
             Narrow(bnNew).GetHex());
    return Narrow(bnNew).GetCompact();
}

bool CheckProofOfWork(uint256 hash, unsigned int nBits, const Consensus::Params& params, int algo)
{
    bool fNegative;
    bool fOverflow;
    arith_uint256 bnTarget;
    arith_uint256 bnPowLimit = GetPowLimit(algo);

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > bnPowLimit) {
        return false;
    }

    // Check proof of work matches claimed amount
    return UintToArith256(hash) < bnTarget;
}

#define KEY_CHANGE 2048
#define SWITCH_KEY 64

uint256 GetKeyBlock(const uint32_t& nHeight)
{
    static uint256 current_key_block = uint256();

    uint32_t checkMultiplier = 0;

    // We don't want to go negative
    if (nHeight >= SWITCH_KEY)
        checkMultiplier = (nHeight - SWITCH_KEY) / KEY_CHANGE;

    int checkHeight = checkMultiplier * KEY_CHANGE;

    if (chainActive.Height() >= checkHeight) {
	    current_key_block = chainActive[checkHeight]->GetBlockHash();
    } else {
	    LogPrintf("%s: Not synched for KeyBlock(%d) @ %d, Synched Height: %d\n", __func__,
                  checkHeight, nHeight, chainActive.Height());
    }

    if (current_key_block == uint256())
        current_key_block = chainActive.Genesis()->GetBlockHash();

    return current_key_block;
}

bool CheckRandomXProofOfWork(const CBlockHeader& block, unsigned int nBits, const Consensus::Params& params)
{
    LOCK(cs_randomx_validator);
    InitRandomXLightCache(block.nHeight);

    // This will check if the key block needs to change and will take down the cache and vm, and spin up the new ones
    CheckIfValidationKeyShouldChangeAndUpdate(GetKeyBlock(block.nHeight));

    // Create the eth_boundary from the nBits
    arith_uint256 bnTarget;
    bool fNegative;
    bool fOverflow;

    bnTarget.SetCompact(nBits, &fNegative, &fOverflow);

    // Check range
    if (fNegative || bnTarget == 0 || fOverflow || bnTarget > UintToArith256(params.powLimitRandomX)) {
        return false;
    }

    uint256 hash_blob = block.GetRandomXHeaderHash();

    char hash[RANDOMX_HASH_SIZE];

    randomx_calculate_hash(GetMyMachineValidating(), &hash_blob, sizeof uint256(), hash);

    uint256 nHash = RandomXHashToUint256(hash);

    // Check proof of work matches claimed amount
    return UintToArith256(nHash) < bnTarget;

}

uint256 RandomXHashToUint256(const char* p_char)
{
    int i;
    std::vector<unsigned char> vec;
    for (i = 0; i < RANDOMX_HASH_SIZE; i++) {
        vec.push_back(p_char[i]);
    }

    std::string hexStr = HexStr(vec.begin(), vec.end());
    return uint256S(hexStr);
}

void StartRandomXMining(void* pPowThreadGroup, const int nThreads, std::shared_ptr<CReserveScript> pCoinbaseScript)
{
    bool fInitialized = false;
    auto threadGroup = (boost::thread_group *) pPowThreadGroup;
    while (true) {
        boost::this_thread::interruption_point();
        if (!fInitialized) {
            boost::this_thread::interruption_point();
            auto full_flags = RANDOMX_FLAG_FULL_MEM | randomx_get_flags();
            LogPrint(BCLog::BLOCKCREATION, "%s: RandomX flags set to %s\n", __func__, full_flags);
            myMiningCache = randomx_alloc_cache(full_flags);

            /// Create the RandomX Dataset
            myMiningDataset = randomx_alloc_dataset(full_flags);
            mining_key_block = GetKeyBlock(chainActive.Height());

            randomx_init_cache(myMiningCache, &mining_key_block, sizeof(mining_key_block));

            auto nTime1 = GetTimeMillis();
            LogPrintf("%s: Starting dataset creation\n", __func__);

            CreateRandomXInitDataSet(nThreads, myMiningDataset, myMiningCache);
            boost::this_thread::interruption_point();

            auto nTime2 = GetTimeMillis();
            LogPrintf("%s: Finished dataset creation %.2fms\n", __func__, nTime2 - nTime1);

            boost::this_thread::interruption_point();
            /// Create the RandomX Virtual Machines
            for (int i = 0; i < nThreads; ++i) {
                randomx_vm *vm = randomx_create_vm(full_flags, nullptr, myMiningDataset);
                if (vm == nullptr) {
                    LogPrintf("%s: Cannot create VM\n", __func__);
                    return;
                }
                vecRandomXVM.push_back(vm);
            }
            boost::this_thread::interruption_point();
            auto nTime3 = GetTimeMillis();
            LogPrintf("%s: Finished vm creation %.2fms\n", __func__, nTime3 - nTime2);
            boost::this_thread::interruption_point();
            uint32_t startNonce = 0;
            for (int i = 0; i < nThreads; i++) {
                threadGroup->create_thread(boost::bind(&ThreadRandomXBitcoinMiner, pCoinbaseScript, i, startNonce));
                startNonce += 100000;
            }
            boost::this_thread::interruption_point();
            fInitialized = true;
        }

        if (fKeyBlockedChanged) {
            boost::this_thread::interruption_point();
            threadGroup->interrupt_all();
            threadGroup->join_all();
            DeallocateVMVector();
            DeallocateDataSet();
            fInitialized = false;
            fKeyBlockedChanged = false;
        }
    }
}

void CreateRandomXInitDataSet(int nThreads, randomx_dataset* dataset, randomx_cache* cache)
{
    uint32_t datasetItemCount = randomx_dataset_item_count();

    if (nThreads > 1) {
        uint32_t datasetItemCount = randomx_dataset_item_count();
        auto perThread = datasetItemCount / nThreads;
        auto remainder = datasetItemCount % nThreads;
        uint32_t startItem = 0;
        for (int i = 0; i < nThreads; ++i) {
            auto count = perThread + (i == nThreads - 1 ? remainder : 0);
            vecRandomXThreads.push_back(std::thread(&randomx_init_dataset, dataset, cache, startItem, count));
            startItem += count;
        }

        for (unsigned i = 0; i < vecRandomXThreads.size(); ++i) {
            vecRandomXThreads[i].join();
        }
    } else {
        randomx_init_dataset(dataset, cache, 0, datasetItemCount);
    }

    randomx_release_cache(cache);
    cache = nullptr;
    vecRandomXThreads.clear();
}

void DeallocateVMVector()
{
    if (vecRandomXVM.size()) {
        for (unsigned i = 0; i < vecRandomXVM.size(); ++i)
            randomx_destroy_vm(vecRandomXVM[i]);
    }

    vecRandomXVM.clear();
}

void DeallocateDataSet()
{
    if (myMiningDataset == nullptr)
        return;

    randomx_release_dataset(myMiningDataset);
    myMiningDataset = nullptr;
}

void DeallocateCache()
{
    LOCK(cs_randomx_validator);
    if (myMiningCache == nullptr)
        return;

    randomx_release_cache(myMiningCache);
    myMiningCache = nullptr;
}

