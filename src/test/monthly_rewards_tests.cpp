#include <chainparams.h>
#include <veil/budget.h>
#include <test/test_veil.h>
#include <boost/test/unit_test.hpp>


BOOST_FIXTURE_TEST_SUITE(monthly_rewards_tests, BasicTestingSetup)


/**
 *  Tests to make sure that the proper rewards are sent with the given block height
 */

BOOST_AUTO_TEST_CASE(testRewardAfterSet)
{
    CAmount nBlockReward, nFounderPayment, nFoundationPayment, nBudgetPayment = 0;
    int nBlocksPerPeriod = 43200;
    veil::Budget().GetBlockRewards(1, nBlockReward, nFounderPayment, nFoundationPayment, nBudgetPayment);

    BOOST_CHECK(nBlockReward == 50 * COIN);
    BOOST_CHECK(nFounderPayment == 0);
    BOOST_CHECK(nFoundationPayment == 0);
    BOOST_CHECK(nBudgetPayment == 0);

    veil::Budget().GetBlockRewards(2, nBlockReward, nFounderPayment, nFoundationPayment, nBudgetPayment);

    BOOST_CHECK(nBlockReward == 50 * COIN);
    BOOST_CHECK(nFounderPayment == 0);
    BOOST_CHECK(nFoundationPayment == 0);
    BOOST_CHECK(nBudgetPayment == 0);

    veil::Budget().GetBlockRewards(nBlocksPerPeriod, nBlockReward, nFounderPayment, nFoundationPayment, nBudgetPayment);

    BOOST_CHECK(nBlockReward == 50 * COIN);
    BOOST_CHECK(nFounderPayment == 10 * nBlocksPerPeriod * COIN);
    BOOST_CHECK(nFoundationPayment == 10 * nBlocksPerPeriod * COIN);
    BOOST_CHECK(nBudgetPayment == 30 * nBlocksPerPeriod * COIN);

    veil::Budget().GetBlockRewards(nBlocksPerPeriod + 1, nBlockReward, nFounderPayment, nFoundationPayment, nBudgetPayment);

    BOOST_CHECK(nBlockReward == 50 * COIN);
    BOOST_CHECK(nFounderPayment == 0);
    BOOST_CHECK(nFoundationPayment == 0);
    BOOST_CHECK(nBudgetPayment == 0);

    veil::Budget().GetBlockRewards(12 * nBlocksPerPeriod, nBlockReward, nFounderPayment, nFoundationPayment, nBudgetPayment);

    BOOST_CHECK(nBlockReward == 40 * COIN);
    BOOST_CHECK(nFounderPayment == 8 * nBlocksPerPeriod * COIN);
    BOOST_CHECK(nFoundationPayment == 8 * nBlocksPerPeriod * COIN);
    BOOST_CHECK(nBudgetPayment == 24 * nBlocksPerPeriod * COIN);

    veil::Budget().GetBlockRewards(12 * nBlocksPerPeriod + 1, nBlockReward, nFounderPayment, nFoundationPayment, nBudgetPayment);

    BOOST_CHECK(nBlockReward == 40 * COIN);
    BOOST_CHECK(nFounderPayment == 0);
    BOOST_CHECK(nFoundationPayment == 0);
    BOOST_CHECK(nBudgetPayment == 0);

    veil::Budget().GetBlockRewards(24 * nBlocksPerPeriod, nBlockReward, nFounderPayment, nFoundationPayment, nBudgetPayment);

    BOOST_CHECK(nBlockReward == 30 * COIN);
    BOOST_CHECK(nFounderPayment == 6 * nBlocksPerPeriod * COIN);
    BOOST_CHECK(nFoundationPayment == 6 * nBlocksPerPeriod * COIN);
    BOOST_CHECK(nBudgetPayment == 18 * nBlocksPerPeriod * COIN);

    veil::Budget().GetBlockRewards(24 * nBlocksPerPeriod + 1, nBlockReward, nFounderPayment, nFoundationPayment, nBudgetPayment);

    BOOST_CHECK(nBlockReward == 30 * COIN);
    BOOST_CHECK(nFounderPayment == 0);
    BOOST_CHECK(nFoundationPayment == 0);
    BOOST_CHECK(nBudgetPayment == 0);

    veil::Budget().GetBlockRewards(36 * nBlocksPerPeriod, nBlockReward, nFounderPayment, nFoundationPayment, nBudgetPayment);

    BOOST_CHECK(nBlockReward == 20 * COIN);
    BOOST_CHECK(nFounderPayment == 4 * nBlocksPerPeriod * COIN);
    BOOST_CHECK(nFoundationPayment == 4 * nBlocksPerPeriod * COIN);
    BOOST_CHECK(nBudgetPayment == 12 * nBlocksPerPeriod * COIN);

    veil::Budget().GetBlockRewards(36 * nBlocksPerPeriod + 1, nBlockReward, nFounderPayment, nFoundationPayment, nBudgetPayment);

    BOOST_CHECK(nBlockReward == 20 * COIN);
    BOOST_CHECK(nFounderPayment == 0);
    BOOST_CHECK(nFoundationPayment == 0);
    BOOST_CHECK(nBudgetPayment == 0);

    veil::Budget().GetBlockRewards(48 * nBlocksPerPeriod, nBlockReward, nFounderPayment, nFoundationPayment, nBudgetPayment);

    BOOST_CHECK(nBlockReward == 10 * COIN);
    BOOST_CHECK(nFounderPayment == 2 * nBlocksPerPeriod * COIN);
    BOOST_CHECK(nFoundationPayment == 2 * nBlocksPerPeriod * COIN);
    BOOST_CHECK(nBudgetPayment == 6 * nBlocksPerPeriod * COIN);

    veil::Budget().GetBlockRewards(48 * nBlocksPerPeriod + 1, nBlockReward, nFounderPayment, nFoundationPayment, nBudgetPayment);

    BOOST_CHECK(nBlockReward == 10 * COIN);
    BOOST_CHECK(nFounderPayment == 0);
    BOOST_CHECK(nFoundationPayment == 0);
    BOOST_CHECK(nBudgetPayment == 0);

    veil::Budget().GetBlockRewards(60 * nBlocksPerPeriod, nBlockReward, nFounderPayment, nFoundationPayment, nBudgetPayment);

    BOOST_CHECK(nBlockReward == 10 * COIN);
    BOOST_CHECK(nFounderPayment == 0);
    BOOST_CHECK(nFoundationPayment == 2 * nBlocksPerPeriod * COIN);
    BOOST_CHECK(nBudgetPayment == 8 * nBlocksPerPeriod * COIN);

    veil::Budget().GetBlockRewards(60 * nBlocksPerPeriod + 1, nBlockReward, nFounderPayment, nFoundationPayment, nBudgetPayment);

    BOOST_CHECK(nBlockReward == 10 * COIN);
    BOOST_CHECK(nFounderPayment == 0);
    BOOST_CHECK(nFoundationPayment == 0);
    BOOST_CHECK(nBudgetPayment == 0);
}

BOOST_AUTO_TEST_CASE(testRewardAfterSet_testnet)
{
    SelectParams("test");
    CAmount nBlockReward, nFounderPayment, nFoundationPayment, nBudgetPayment = 0;
    int nBlocksPerPeriod = 43200;
    veil::Budget().GetBlockRewards(1, nBlockReward, nFounderPayment, nFoundationPayment, nBudgetPayment);

    BOOST_CHECK(nBlockReward == 50 * COIN);
    BOOST_CHECK(nFounderPayment == 10 * nBlocksPerPeriod * COIN);
    BOOST_CHECK(nFoundationPayment == 10 * nBlocksPerPeriod * COIN);
    BOOST_CHECK(nBudgetPayment == 30 * nBlocksPerPeriod * COIN);

    veil::Budget().GetBlockRewards(2, nBlockReward, nFounderPayment, nFoundationPayment, nBudgetPayment);

    BOOST_CHECK(nBlockReward == 50 * COIN);
    BOOST_CHECK(nFounderPayment == 0);
    BOOST_CHECK(nFoundationPayment == 0);
    BOOST_CHECK(nBudgetPayment == 0);

    veil::Budget().GetBlockRewards(20000, nBlockReward, nFounderPayment, nFoundationPayment, nBudgetPayment);

    BOOST_CHECK(nBlockReward == 50 * COIN);
    BOOST_CHECK(nFounderPayment == 10 * nBlocksPerPeriod * COIN);
    BOOST_CHECK(nFoundationPayment == 10 * nBlocksPerPeriod * COIN);
    BOOST_CHECK(nBudgetPayment == 30 * nBlocksPerPeriod * COIN);

    veil::Budget().GetBlockRewards(20001, nBlockReward, nFounderPayment, nFoundationPayment, nBudgetPayment);

    BOOST_CHECK(nBlockReward == 50 * COIN);
    BOOST_CHECK(nFounderPayment == 0);
    BOOST_CHECK(nFoundationPayment == 0);
    BOOST_CHECK(nBudgetPayment == 0);

    veil::Budget().GetBlockRewards(12 * nBlocksPerPeriod + 20000, nBlockReward, nFounderPayment, nFoundationPayment, nBudgetPayment);

    BOOST_CHECK(nBlockReward == 40 * COIN);
    BOOST_CHECK(nFounderPayment == 8 * nBlocksPerPeriod * COIN);
    BOOST_CHECK(nFoundationPayment == 8 * nBlocksPerPeriod * COIN);
    BOOST_CHECK(nBudgetPayment == 24 * nBlocksPerPeriod * COIN);

    veil::Budget().GetBlockRewards(12 * nBlocksPerPeriod + 20001, nBlockReward, nFounderPayment, nFoundationPayment, nBudgetPayment);

    BOOST_CHECK(nBlockReward == 40 * COIN);
    BOOST_CHECK(nFounderPayment == 0);
    BOOST_CHECK(nFoundationPayment == 0);
    BOOST_CHECK(nBudgetPayment == 0);

    veil::Budget().GetBlockRewards(24 * nBlocksPerPeriod + 20000, nBlockReward, nFounderPayment, nFoundationPayment, nBudgetPayment);

    BOOST_CHECK(nBlockReward == 30 * COIN);
    BOOST_CHECK(nFounderPayment == 6 * nBlocksPerPeriod * COIN);
    BOOST_CHECK(nFoundationPayment == 6 * nBlocksPerPeriod * COIN);
    BOOST_CHECK(nBudgetPayment == 18 * nBlocksPerPeriod * COIN);

    veil::Budget().GetBlockRewards(24 * nBlocksPerPeriod + 20001, nBlockReward, nFounderPayment, nFoundationPayment, nBudgetPayment);

    BOOST_CHECK(nBlockReward == 30 * COIN);
    BOOST_CHECK(nFounderPayment == 0);
    BOOST_CHECK(nFoundationPayment == 0);
    BOOST_CHECK(nBudgetPayment == 0);

    veil::Budget().GetBlockRewards(36 * nBlocksPerPeriod + 20000, nBlockReward, nFounderPayment, nFoundationPayment, nBudgetPayment);

    BOOST_CHECK(nBlockReward == 20 * COIN);
    BOOST_CHECK(nFounderPayment == 4 * nBlocksPerPeriod * COIN);
    BOOST_CHECK(nFoundationPayment == 4 * nBlocksPerPeriod * COIN);
    BOOST_CHECK(nBudgetPayment == 12 * nBlocksPerPeriod * COIN);

    veil::Budget().GetBlockRewards(36 * nBlocksPerPeriod + 20001, nBlockReward, nFounderPayment, nFoundationPayment, nBudgetPayment);

    BOOST_CHECK(nBlockReward == 20 * COIN);
    BOOST_CHECK(nFounderPayment == 0);
    BOOST_CHECK(nFoundationPayment == 0);
    BOOST_CHECK(nBudgetPayment == 0);

    veil::Budget().GetBlockRewards(48 * nBlocksPerPeriod + 20000, nBlockReward, nFounderPayment, nFoundationPayment, nBudgetPayment);

    BOOST_CHECK(nBlockReward == 10 * COIN);
    BOOST_CHECK(nFounderPayment == 2 * nBlocksPerPeriod * COIN);
    BOOST_CHECK(nFoundationPayment == 2 * nBlocksPerPeriod * COIN);
    BOOST_CHECK(nBudgetPayment == 6 * nBlocksPerPeriod * COIN);

    veil::Budget().GetBlockRewards(48 * nBlocksPerPeriod + 20001, nBlockReward, nFounderPayment, nFoundationPayment, nBudgetPayment);

    BOOST_CHECK(nBlockReward == 10 * COIN);
    BOOST_CHECK(nFounderPayment == 0);
    BOOST_CHECK(nFoundationPayment == 0);
    BOOST_CHECK(nBudgetPayment == 0);

    veil::Budget().GetBlockRewards(60 * nBlocksPerPeriod + 20000, nBlockReward, nFounderPayment, nFoundationPayment, nBudgetPayment);

    BOOST_CHECK(nBlockReward == 10 * COIN);
    BOOST_CHECK(nFounderPayment == 0);
    BOOST_CHECK(nFoundationPayment == 2 * nBlocksPerPeriod * COIN);
    BOOST_CHECK(nBudgetPayment == 8 * nBlocksPerPeriod * COIN);

    veil::Budget().GetBlockRewards(60 * nBlocksPerPeriod + 20001, nBlockReward, nFounderPayment, nFoundationPayment, nBudgetPayment);

    BOOST_CHECK(nBlockReward == 10 * COIN);
    BOOST_CHECK(nFounderPayment == 0);
    BOOST_CHECK(nFoundationPayment == 0);
    BOOST_CHECK(nBudgetPayment == 0);


}

/**
 * Tests to make sure that in a 12 month period, 12 rewards have been
 * given
 */
BOOST_AUTO_TEST_CASE(countRwards)
{

    CAmount nBlockReward, nFounderPayment, nFoundationPayment, nBudgetPayment = 0;
    int nBlockRewardsCount = 0;
    int nRewardsCount = 0;

    for(int i = 0; i <= 518400; i++) {
        veil::Budget().GetBlockRewards(i, nBlockReward, nFounderPayment, nFoundationPayment, nBudgetPayment);
        if(nFounderPayment > 0)
            nRewardsCount++;
        if(nBlockReward > 0)
            nBlockRewardsCount++;
    }

    BOOST_CHECK(nRewardsCount == 12);
    BOOST_CHECK(nBlockRewardsCount == 518400);
}

/**
 * Superblocks retire at nHeightSuperblockEnd. Everything below that height has to keep
 * paying exactly what it always paid, otherwise those blocks blow past nCreationLimit in
 * ConnectBlock() and a node syncing from genesis rejects the chain.
 */
BOOST_AUTO_TEST_CASE(superblockRetirement)
{
    CAmount nBlockReward, nFounderPayment, nFoundationPayment, nBudgetPayment = 0;
    const int nBlocksPerPeriod = 43200;
    const int nEnd = veil::BudgetParams::SuperblockEndHeight();

    BOOST_CHECK_EQUAL(nEnd, 4104000);
    BOOST_CHECK(nEnd % nBlocksPerPeriod == 0);

    // The last paying superblock sits one period below the cutover and is untouched.
    const int nLastPaid = nEnd - nBlocksPerPeriod;
    BOOST_CHECK(veil::BudgetParams::IsSuperBlock(nLastPaid));
    veil::Budget().GetBlockRewards(nLastPaid, nBlockReward, nFounderPayment, nFoundationPayment, nBudgetPayment);
    BOOST_CHECK(nBlockReward == 10 * COIN);
    BOOST_CHECK(nFounderPayment == 0);
    BOOST_CHECK(nFoundationPayment == 2 * nBlocksPerPeriod * COIN);
    BOOST_CHECK(nBudgetPayment == 8 * nBlocksPerPeriod * COIN);

    // The cutover height is a period boundary but is no longer a superblock.
    BOOST_CHECK(!veil::BudgetParams::IsSuperBlock(nEnd));

    // No superblock pays again, all the way out to the extended supply stop. Miners keep
    // taking the flat 10 VEIL tail the whole way.
    for (int h = nEnd; h <= Params().HeightSupplyCreationStop(); h += nBlocksPerPeriod) {
        BOOST_CHECK(!veil::BudgetParams::IsSuperBlock(h));
        veil::Budget().GetBlockRewards(h, nBlockReward, nFounderPayment, nFoundationPayment, nBudgetPayment);
        BOOST_CHECK(nBlockReward == 10 * COIN);
        BOOST_CHECK(nFounderPayment == 0);
        BOOST_CHECK(nFoundationPayment == 0);
        BOOST_CHECK(nBudgetPayment == 0);
    }

    // Emission stops dead at the new height, it does not run on forever.
    veil::Budget().GetBlockRewards(Params().HeightSupplyCreationStop(), nBlockReward, nFounderPayment, nFoundationPayment, nBudgetPayment);
    BOOST_CHECK(nBlockReward == 10 * COIN);
    veil::Budget().GetBlockRewards(Params().HeightSupplyCreationStop() + 1, nBlockReward, nFounderPayment, nFoundationPayment, nBudgetPayment);
    BOOST_CHECK(nBlockReward == 0);
    BOOST_CHECK(nFoundationPayment == 0);
    BOOST_CHECK(nBudgetPayment == 0);
}

/**
 * The point of retiring the superblocks is to redirect the budget half into a longer
 * mining tail, not to destroy it. Total coins ever created must come out identical to
 * the pre-fork schedule, and PoW must run for exactly as long as emission does.
 */
BOOST_AUTO_TEST_CASE(totalSupplyUnchangedByRetirement)
{
    CAmount nBlockReward, nFounderPayment, nFoundationPayment, nBudgetPayment = 0;
    CAmount nTotal = 0;
    CAmount nToMiners = 0;

    for (int h = 1; h <= Params().HeightSupplyCreationStop(); h++) {
        veil::Budget().GetBlockRewards(h, nBlockReward, nFounderPayment, nFoundationPayment, nBudgetPayment);
        nToMiners += nBlockReward;
        nTotal += nBlockReward + nFounderPayment + nFoundationPayment + nBudgetPayment;
    }

    // Same total the original 9816000 block schedule produced.
    BOOST_CHECK_EQUAL(nTotal, CAmount(288153560) * COIN);
    // Miners go from 149999960 under the old split to that plus the freed 57456000.
    BOOST_CHECK_EQUAL(nToMiners, CAmount(149999960 + 57456000) * COIN);
    // PoW has to stay alive for the whole extended tail or the freed coins are unmineable.
    BOOST_CHECK_EQUAL(Params().LAST_POW_BLOCK(), Params().HeightSupplyCreationStop());
}

BOOST_AUTO_TEST_SUITE_END()
