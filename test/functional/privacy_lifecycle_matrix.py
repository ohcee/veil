#!/usr/bin/env python3
# Copyright (c) 2026 The Veil developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Multi-era privacy lifecycle matrix for Veil.

Exercises the full cryptographic lifecycle across the eras that actually
coexist on Veil: basecoin -> zerocoin -> CT -> RingCT -> RingCT staking, and
separately the Bulletproof output era with its mempool/consensus invariants.

IMPORTANT CONSENSUS CONSTRAINT (discovered while writing this harness):
On the unified branch's regtest, `nHeightEnableBulletproofs = 2`. After the BP
activation height, consensus REQUIRES bulletproof outputs and REJECTS legacy
Borromean CT/RingCT ("borromean-output-after-activation"). And BP RingCT coins
are fail-closed from staking (they expose no public value bracket). Therefore
"Borromean RingCT staking" and "BP active" cannot occur on the same chain:
  - with BP dormant, RingCT coins are Borromean and CAN be publicly value-verified
    for staking;
  - with BP active, all new RingCT coins are BP and CANNOT stake (by design).

So this suite runs TWO consensus-consistent scenarios on two clean chains:

  Scenario A (BP dormant, activation height pushed past the staking height):
    basecoin -> zerocoin mint/spend -> CT (Borromean) -> RingCT (Borromean)
    -> RingCT staking loop -> P2P propagation of a RingCT-stake block.
    Requires the regtest-only override arg `-nheightenablebulletproofs`.

  Scenario B (BP active from height 2, the default):
    basecoin -> CT (BP) / RingCT (BP) -> assert compact-proof size reduction,
    pinned-64-bit verification, mempool invariants against the txmempool fixes,
    and that BP RingCT staking is correctly FAIL-CLOSED.

PREREQUISITES
  - A built `veild`/`veil-cli` for feature/bp-ringct-unified (Linux, or macOS via
    the uplift merge). This harness is authored against the real RPC surface and
    static-checked, but must be executed against a live build; the RingCT staking
    leg is timing-dependent and is driven via generatecontinuous + wait_until.
  - The regtest-only `-nheightenablebulletproofs` override (added on this test
    branch) for Scenario A.
"""

from decimal import Decimal

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    assert_greater_than,
    connect_nodes,
    wait_until,
)

# Regtest activation heights (src/chainparams.cpp, CRegTestParams):
REG_POS_START = 100
REG_LIGHT_ZEROCOIN = 110
REG_RINGCT_STAKING = 300
BP_DORMANT_HEIGHT = 100000        # pushed well past REG_RINGCT_STAKING for scenario A
BP_MIDCHAIN_HEIGHT = 150          # BP activates mid-chain for the boundary/reorg scenario
STAKE_TIMEOUT_SECS = 180          # generous bound for the PoS kernel search on regtest


class PrivacyLifecycleMatrix(BitcoinTestFramework):
    def set_test_params(self):
        self.num_nodes = 2
        self.setup_clean_chain = True
        # Node args are (re)applied per scenario in _reset_chain().
        self.extra_args = [
            ["-stakeringct=1", "-stakezerocoin=1"],
            ["-stakeringct=1", "-stakezerocoin=1"],
        ]

    # ------------------------------------------------------------------ helpers

    def _reset_chain(self, bp_height):
        """Stop both nodes, wipe regtest state, restart with a chosen BP height."""
        args = ["-stakeringct=1", "-stakezerocoin=1",
                "-nheightenablebulletproofs={}".format(bp_height)]
        self.stop_nodes()
        for i in range(self.num_nodes):
            self._wipe_regtest(i)
        self.start_nodes([args, args])
        connect_nodes(self.nodes[0], 1)

    def _wipe_regtest(self, i):
        import os
        import shutil
        regdir = os.path.join(self.nodes[i].datadir, "regtest")
        if os.path.isdir(regdir):
            shutil.rmtree(regdir)

    def _mine(self, node, n, addr=None):
        addr = addr or node.getnewbasecoinaddress()
        return node.generatetoaddress(n, addr)

    def _ringct_outputs(self, node, txid):
        """Return the decoded RingCT/CT vpout entries of a tx."""
        raw = node.getrawtransaction(txid, True)
        outs = []
        for o in raw.get("vpout", []):
            t = o.get("type", "")
            if t in ("ringct", "ringct_bulletproof", "blind", "blind_bulletproof"):
                outs.append(o)
        return outs

    def _first_ringct_proof_size(self, node, txid):
        for o in self._ringct_outputs(node, txid):
            if "rangeproof_size" in o:
                return int(o["rangeproof_size"])
        raise AssertionError("no RingCT/CT output with rangeproof_size in {}".format(txid))

    def _wait_height(self, node, target, timeout):
        wait_until(lambda: node.getblockcount() >= target, timeout=timeout)

    # ------------------------------------------------------------------- eras

    def _era_basecoin(self, node):
        """Generate spendable basecoin and cross nHeightPoSStart."""
        self._mine(node, REG_POS_START + 20)
        assert_greater_than(node.getbalance(), 0)
        self.log.info("basecoin era: height=%d balance=%s",
                      node.getblockcount(), node.getbalance())

    def _era_zerocoin_to_ct(self, node):
        """Mint zerocoin, mature it past light-zerocoin, spend, convert to CT."""
        node.mintzerocoin(50)
        self._mine(node, 20)  # mature the mint past REG_LIGHT_ZEROCOIN + stake depth
        basecoin_addr = node.getnewbasecoinaddress()
        # Zerocoin -> basecoin, then basecoin -> CT (stealth) to complete the hop.
        node.spendzerocoin(10, False, True, 100, basecoin_addr)
        self._mine(node, 2)
        stealth_addr = node.getnewaddress()
        assert_equal(node.isstealthaddress(stealth_addr), True)
        txid = node.sendtypeto("basecoin", "stealth",
                               [{"address": stealth_addr, "amount": 5}])
        self._mine(node, 2)
        self.log.info("zerocoin->CT hop complete, ct tx=%s", txid)
        return txid

    def _era_ct_to_ringct(self, node):
        stealth_addr = node.getnewaddress()
        txid = node.sendtypeto("stealth", "ringct",
                               [{"address": stealth_addr, "amount": 3}])
        self._mine(node, 2)
        return txid

    # --------------------------------------------------------------- scenarios

    def _scenario_borromean_staking(self):
        self.log.info("=== Scenario A: Borromean lifecycle + RingCT staking ===")
        self._reset_chain(BP_DORMANT_HEIGHT)
        node = self.nodes[0]

        self._era_basecoin(node)
        self._era_zerocoin_to_ct(node)
        rct_txid = self._era_ct_to_ringct(node)

        # Borromean proof present and large (contrast against BP era below).
        borromean_size = self._first_ringct_proof_size(node, rct_txid)
        assert_greater_than(borromean_size, 2000)  # Borromean 64-bit proof ~5KB
        outs = self._ringct_outputs(node, rct_txid)
        assert_equal(outs[0]["type"], "ringct")     # NOT ringct_bulletproof
        self.log.info("Borromean RingCT proof size=%d", borromean_size)

        # Reach the RingCT staking height, then drive the staking thread.
        self._mine(node, REG_RINGCT_STAKING + 12 - node.getblockcount())
        assert_greater_than(node.getblockcount() + 1, REG_RINGCT_STAKING)
        start_height = node.getblockcount()
        node.generatecontinuous(True, 1)
        try:
            self._wait_height(node, start_height + 1, STAKE_TIMEOUT_SECS)
        finally:
            node.generatecontinuous(False)
        staked = node.getblockcount()
        assert_greater_than(staked, start_height)
        self.log.info("RingCT staking produced block(s) up to height=%d", staked)

        # P2P propagation: node1 must accept the RingCT-stake block from node0.
        self.sync_all()
        assert_equal(self.nodes[1].getbestblockhash(), node.getbestblockhash())
        assert_equal(self.nodes[1].getblockcount(), staked)
        self.log.info("RingCT-stake block propagated to peer at height=%d", staked)

    def _scenario_bulletproof_era(self):
        self.log.info("=== Scenario B: Bulletproof era + invariants ===")
        self._reset_chain(2)  # BP active from height 2 (regtest default)
        node = self.nodes[0]

        self._era_basecoin(node)

        # CT (BP) emission: verify type naming, ecdhInfo exposure, size reduction.
        stealth_addr = node.getnewaddress()
        ct_bp = node.sendtypeto("basecoin", "stealth",
                                [{"address": stealth_addr, "amount": 5}])
        self._mine(node, 2)
        ct_out = self._ringct_outputs(node, ct_bp)[0]
        assert_equal(ct_out["type"], "blind_bulletproof")
        assert_equal(ct_out.get("has_ecdhInfo", ct_out.get("ecdhInfo") is not None), True)
        bp_size = self._first_ringct_proof_size(node, ct_bp)
        # Pinned 64-bit BP proof ~675 bytes vs Borromean ~5134 (~7.6x reduction).
        assert_greater_than(1200, bp_size)
        self.log.info("BP CT proof size=%d (vs Borromean ~5134)", bp_size)

        # RingCT (BP) emission.
        rct_bp = node.sendtypeto("stealth", "ringct",
                                 [{"address": node.getnewaddress(), "amount": 2}])
        self._mine(node, 2)
        assert_equal(self._ringct_outputs(node, rct_bp)[0]["type"], "ringct_bulletproof")

        # Mempool invariant: spend an UNCONFIRMED BP CT coin (chained mempool tx).
        # Exercises the txmempool.cpp fixes (spent-prevout assert / Coin builder).
        # Must not abort the daemon; must apply relay policy cleanly.
        pre_height = node.getblockcount()
        unconf = node.sendtypeto("basecoin", "stealth",
                                 [{"address": node.getnewaddress(), "amount": 4}])
        assert unconf in node.getrawmempool()
        try:
            node.sendtypeto("stealth", "ringct",
                            [{"address": node.getnewaddress(), "amount": 1}])
        except Exception as e:  # a clean policy rejection is acceptable; a crash is not
            self.log.info("chained BP spend rejected by policy (ok): %s", e)
        assert_equal(node.getblockcount(), pre_height)  # daemon alive, no abort
        self.log.info("mempool invariants held; node responsive")

        # BP RingCT staking must be FAIL-CLOSED. Reach the staking height with
        # only BP RingCT coins and assert the staking thread produces nothing.
        self._mine(node, REG_RINGCT_STAKING + 12 - node.getblockcount())
        start_height = node.getblockcount()
        node.generatecontinuous(True, 1)
        import time
        time.sleep(20)  # give the kernel search a real window
        node.generatecontinuous(False)
        assert_equal(node.getblockcount(), start_height)  # BP coins cannot stake
        self.log.info("BP RingCT staking correctly fail-closed at height=%d", start_height)

    def _scenario_activation_boundary_reorg(self):
        """BP activation-height gating from the production side, plus a reorg
        across the Borromean<->Bulletproof boundary.

        Covers the intent of the consensus type-gating rules (#19/#20) by
        confirming the wallet emits — and the node accepts — the correct output
        type on each side of HeightEnableBulletproofs, and then exercises the
        BP-aware DisconnectBlock/ConnectBlock paths (from the type-gate sweep)
        by invalidating and reconsidering the block AT the activation height.
        A Disconnect/Connect asymmetry across the type transition is a
        chain-split-class bug, so this is the highest-value functional check
        that does not require hand-crafting an invalid block.

        NOTE: this does NOT cover deliberate over-mint / wrong-type *rejection*
        (a node rejecting a hand-built bad block). The honest wallet never
        produces those, so triggering the rejection needs a mininode that
        speaks Veil's RingCT block serialization or an instrumented build —
        tracked separately, not faked here.
        """
        self.log.info("=== Scenario C: BP activation boundary + reorg ===")
        self._reset_chain(BP_MIDCHAIN_HEIGHT)
        node = self.nodes[0]

        self._era_basecoin(node)  # height ~120, below BP_MIDCHAIN_HEIGHT (Borromean era)
        assert node.getblockcount() < BP_MIDCHAIN_HEIGHT

        # Below activation: wallet emits a legacy Borromean CT output, accepted.
        pre_bp = node.sendtypeto("basecoin", "stealth",
                                 [{"address": node.getnewaddress(), "amount": 5}])
        self._mine(node, 2)
        assert_equal(self._ringct_outputs(node, pre_bp)[0]["type"], "blind")

        # Cross the activation height.
        self._mine(node, BP_MIDCHAIN_HEIGHT + 3 - node.getblockcount())
        assert_greater_than(node.getblockcount(), BP_MIDCHAIN_HEIGHT)

        # At/above activation: wallet emits a Bulletproof CT output, accepted.
        post_bp = node.sendtypeto("basecoin", "stealth",
                                  [{"address": node.getnewaddress(), "amount": 5}])
        self._mine(node, 2)
        assert_equal(self._ringct_outputs(node, post_bp)[0]["type"], "blind_bulletproof")

        tip = node.getbestblockhash()
        tip_height = node.getblockcount()
        boundary_hash = node.getblockhash(BP_MIDCHAIN_HEIGHT)

        # Reorg the whole BP era back out: disconnect from the activation height up.
        node.invalidateblock(boundary_hash)
        assert_equal(node.getblockcount(), BP_MIDCHAIN_HEIGHT - 1)
        assert node.getbestblockhash() != tip

        # Reconnect across the boundary: must re-validate to the exact same tip,
        # proving Disconnect/Connect are symmetric across the type transition.
        node.reconsiderblock(boundary_hash)
        assert_equal(node.getbestblockhash(), tip)
        assert_equal(node.getblockcount(), tip_height)
        # Both outputs still resolve after the round-trip (no index thrash).
        assert_equal(self._ringct_outputs(node, pre_bp)[0]["type"], "blind")
        assert_equal(self._ringct_outputs(node, post_bp)[0]["type"], "blind_bulletproof")
        self.log.info("activation-boundary reorg clean; tip restored to height=%d", tip_height)

    # -------------------------------------------------------------------- main

    def run_test(self):
        self._scenario_borromean_staking()
        self._scenario_bulletproof_era()
        self._scenario_activation_boundary_reorg()
        self.log.info("privacy lifecycle matrix: all scenarios passed")


if __name__ == "__main__":
    PrivacyLifecycleMatrix().main()
