// Copyright (c) 2019 The Veil developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef VEIL_BLOCKVALIDATION_H
#define VEIL_BLOCKVALIDATION_H

class CBlock;

namespace veil {

/** Validate the PoS block signature for zerocoin stakes and check basic stake
 *  transaction structure. Context-free; called from CheckBlock. RingCT stake
 *  signatures are NOT checked here - see ValidateRingCTBlockSignature. */
bool ValidateBlockSignature(const CBlock& block);

/** Validate the PoS block signature for RingCT stakes against the ring member
 *  public keys. Requires the RCT output index, so this must only be called at
 *  connect time (ConnectBlock), when all prior blocks are indexed. Returns
 *  true for PoW blocks and zerocoin stakes. */
bool ValidateRingCTBlockSignature(const CBlock& block);

}

#endif //VEIL_BLOCKVALIDATION_H
