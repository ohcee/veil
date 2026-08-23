// Copyright (c) 2015-2019 The Bitcoin Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <chain.h>
#include <chainparams.h>
#include <pow.h>
#include <random.h>
#include <util/system.h>
#include <test/test_veil.h>

#include <boost/test/unit_test.hpp>

BOOST_FIXTURE_TEST_SUITE(pow_tests, BasicTestingSetup)

/* Test calculation of next difficulty target with no constraints applying */
BOOST_AUTO_TEST_CASE(get_next_work)
{
    const auto chainParams = CreateChainParams(CBaseChainParams::MAIN);
    int64_t nLastRetargetTime = 1261130161; // Block #30240
    CBlockIndex pindexLast;
    pindexLast.nHeight = 32255;
    pindexLast.nTime = 1262152739;  // Block #32255
    pindexLast.nBits = 0x1d00ffff;
    // Add test for DarkGravityWave
    //BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, chainParams->GetConsensus()), 0x1d00d86aU);
}

/* Test the constraint on the upper bound for next work */
BOOST_AUTO_TEST_CASE(get_next_work_pow_limit)
{
    const auto chainParams = CreateChainParams(CBaseChainParams::MAIN);
    int64_t nLastRetargetTime = 1231006505; // Block #0
    CBlockIndex pindexLast;
    pindexLast.nHeight = 2015;
    pindexLast.nTime = 1233061996;  // Block #2015
    pindexLast.nBits = 0x1d00ffff;
    // Add test for DarkGravityWave
    //BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, chainParams->GetConsensus()), 0x1d00ffffU);
}

/* Test the constraint on the lower bound for actual time taken */
BOOST_AUTO_TEST_CASE(get_next_work_lower_limit_actual)
{
    const auto chainParams = CreateChainParams(CBaseChainParams::MAIN);
    int64_t nLastRetargetTime = 1279008237; // Block #66528
    CBlockIndex pindexLast;
    pindexLast.nHeight = 68543;
    pindexLast.nTime = 1279297671;  // Block #68543
    pindexLast.nBits = 0x1c05a3f4;
    // Add test for DarkGravityWave
    //BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, chainParams->GetConsensus()), 0x1c0168fdU);
}

/* Test the constraint on the upper bound for actual time taken */
BOOST_AUTO_TEST_CASE(get_next_work_upper_limit_actual)
{
    const auto chainParams = CreateChainParams(CBaseChainParams::MAIN);
    int64_t nLastRetargetTime = 1263163443; // NOTE: Not an actual block time
    CBlockIndex pindexLast;
    pindexLast.nHeight = 46367;
    pindexLast.nTime = 1269211443;  // Block #46367
    pindexLast.nBits = 0x1c387f6f;
    // Add test for DarkGravityWave
    //BOOST_CHECK_EQUAL(CalculateNextWorkRequired(&pindexLast, nLastRetargetTime, chainParams->GetConsensus()), 0x1d00e1fdU);
}

BOOST_AUTO_TEST_CASE(GetBlockProofEquivalentTime_test)
{
    const auto chainParams = CreateChainParams(CBaseChainParams::MAIN);
    std::vector<CBlockIndex> blocks(10000);
    for (int i = 0; i < 10000; i++) {
        blocks[i].pprev = i ? &blocks[i - 1] : nullptr;
        blocks[i].nHeight = i;
        blocks[i].nTime = 1269211443 + i * chainParams->GetConsensus().nPowTargetSpacing;
        blocks[i].nBits = 0x207fffff; /* target 0x7fffff000... */
        blocks[i].nChainWork = i ? blocks[i - 1].nChainWork + GetBlockProof(blocks[i - 1]) : arith_uint256(0);
    }

    for (int j = 0; j < 1000; j++) {
        CBlockIndex *p1 = &blocks[InsecureRandRange(10000)];
        CBlockIndex *p2 = &blocks[InsecureRandRange(10000)];
        CBlockIndex *p3 = &blocks[InsecureRandRange(10000)];

        int64_t tdiff = GetBlockProofEquivalentTime(*p1, *p2, *p3, chainParams->GetConsensus());
        BOOST_CHECK_EQUAL(tdiff, p1->GetBlockTime() - p2->GetBlockTime());
    }
}


/* LWMA retarget for SHA256d (LwmaRetarget). The vectors come from the Python reference in the
 * veil-sha256d-daa replay tooling: a synthetic chain of 70 DarkGravityWave blocks before the
 * activation height, then steady mining, three days with the rig gone and a 100 MH/s miner
 * (lone blocks, time decay, window bound), a burst return (brake) and steady mining again. */
struct LwmaVector {
    int64_t tipTime;
    int64_t blockTime;  // 0: a PoS block at tipTime, check the SHA256d requirement there
    uint32_t nBits;     // the block's bits, or the expected requirement for a probe
    int kind;           // 0 seed (build only), 1 pre fork (DarkGravityWave), 2 post fork (LwmaRetarget), 3 probe
};

static const LwmaVector lwma_vectors[] = {
    {1780000600, 1780001200, 0x1b04ae5f, 0},
    {1780001800, 1780002400, 0x1b04ae5f, 0},
    {1780003000, 1780003600, 0x1b04ae5f, 0},
    {1780004200, 1780004800, 0x1b04ae5f, 0},
    {1780005400, 1780006000, 0x1b04ae5f, 0},
    {1780006600, 1780007200, 0x1b04ae5f, 0},
    {1780007800, 1780008400, 0x1b04ae5f, 0},
    {1780009000, 1780009600, 0x1b04ae5f, 0},
    {1780010200, 1780010800, 0x1b04ae5f, 0},
    {1780011400, 1780012000, 0x1b04ae5f, 0},
    {1780012600, 1780013200, 0x1b04ae5f, 0},
    {1780013800, 1780014400, 0x1b04ae5f, 0},
    {1780015000, 1780015600, 0x1b04ae5f, 0},
    {1780016200, 1780016800, 0x1b04ae5f, 0},
    {1780017400, 1780018000, 0x1b04ae5f, 0},
    {1780018600, 1780019200, 0x1b04ae5f, 0},
    {1780019800, 1780020400, 0x1b04ae5f, 0},
    {1780021000, 1780021600, 0x1b04ae5f, 0},
    {1780022200, 1780022800, 0x1b04ae5f, 0},
    {1780023400, 1780024000, 0x1b04ae5f, 0},
    {1780024600, 1780025200, 0x1b04ae5f, 0},
    {1780025800, 1780026400, 0x1b04ae5f, 0},
    {1780027000, 1780027600, 0x1b04ae5f, 0},
    {1780028200, 1780028800, 0x1b04ae5f, 0},
    {1780029400, 1780030000, 0x1b04ae5f, 0},
    {1780030600, 1780031200, 0x1b04ae5f, 0},
    {1780031800, 1780032400, 0x1b04ae5f, 0},
    {1780033000, 1780033600, 0x1b04ae5f, 0},
    {1780034200, 1780034800, 0x1b04ae5f, 0},
    {1780035400, 1780036000, 0x1b04ae5f, 0},
    {1780036600, 1780037200, 0x1b04ae5f, 0},
    {1780037800, 1780038400, 0x1b04ae5f, 0},
    {1780039000, 1780039600, 0x1b04ae5f, 0},
    {1780040200, 1780040800, 0x1b04ae5f, 0},
    {1780041400, 1780042000, 0x1b04ae5f, 0},
    {1780042600, 1780043200, 0x1b04ae5f, 0},
    {1780043800, 1780044400, 0x1b04ae5f, 0},
    {1780045000, 1780045600, 0x1b04ae5f, 0},
    {1780046200, 1780046800, 0x1b04ae5f, 0},
    {1780047400, 1780048000, 0x1b04ae5f, 0},
    {1780048600, 1780049200, 0x1b04ae5f, 0},
    {1780049800, 1780050400, 0x1b04ae5f, 0},
    {1780051000, 1780051600, 0x1b04ae5f, 0},
    {1780052200, 1780052800, 0x1b04ae5f, 0},
    {1780053400, 1780054000, 0x1b04ae5f, 0},
    {1780054600, 1780055200, 0x1b04ae5f, 0},
    {1780055800, 1780056400, 0x1b04ae5f, 0},
    {1780057000, 1780057600, 0x1b04ae5f, 0},
    {1780058200, 1780058800, 0x1b04ae5f, 0},
    {1780059400, 1780060000, 0x1b04ae5f, 0},
    {1780060600, 1780061200, 0x1b04ae5f, 0},
    {1780061800, 1780062400, 0x1b04ae5f, 0},
    {1780063000, 1780063600, 0x1b04ae5f, 0},
    {1780064200, 1780064800, 0x1b04ae5f, 0},
    {1780065400, 1780066000, 0x1b04ae5f, 0},
    {1780066600, 1780067200, 0x1b04ae5f, 0},
    {1780067800, 1780068400, 0x1b04ae5f, 0},
    {1780069000, 1780069600, 0x1b04ae5f, 0},
    {1780070200, 1780070800, 0x1b04ae5f, 0},
    {1780071400, 1780072000, 0x1b04ae5f, 0},
    {1780072600, 1780073200, 0x1b04ae5f, 0},
    {1780076053, 1780076103, 0x1b04b5e9, 1},
    {1780076103, 1780076242, 0x1b04d337, 1},
    {1780076546, 1780076624, 0x1b04a5d1, 1},
    {1780076779, 1780076865, 0x1b04980d, 1},
    {1780081817, 1780082020, 0x1b04c62f, 1},
    {1780082781, 1780082881, 0x1b04aefe, 1},
    {1780083507, 1780083724, 0x1b04af00, 1},
    {1780084682, 1780084810, 0x1b04af03, 1},
    {1780086650, 1780086679, 0x1b04c72b, 1},
    {1780087146, 1780087348, 0x1b04af70, 1},
    {1780088121, 1780088218, 0x1b04af74, 1},
    {1780089092, 1780089280, 0x1b04af79, 1},
    {1780092193, 1780092435, 0x1b04d406, 1},
    {1780094840, 1780094902, 0x1b04ecca, 1},
    {1780095070, 1780095253, 0x1b04b128, 1},
    {1780095538, 1780095620, 0x1b04b134, 1},
    {1780097452, 1780097600, 0x1b04dd7f, 1},
    {1780098638, 1780098836, 0x1b04b209, 1},
    {1780098885, 1780098932, 0x1b04b219, 1},
    {1780099591, 1780099786, 0x1b04b229, 1},
    {1780101524, 1780101670, 0x1b04d259, 1},
    {1780102009, 1780102032, 0x1b04b2d3, 1},
    {1780104433, 1780104520, 0x1b04db8c, 1},
    {1780104910, 1780105131, 0x1b04b3a6, 1},
    {1780105629, 1780105745, 0x1b04b3bd, 1},
    {1780106113, 1780106167, 0x1b04b3d4, 1},
    {1780106846, 1780106870, 0x1b04b3eb, 1},
    {1780107086, 1780107313, 0x1b04b403, 1},
    {1780107789, 1780107971, 0x1b04a89e, 1},
    {1780108272, 1780108311, 0x1b049f75, 1},
    {1780110408, 1780110623, 0x1b04b3c3, 1},
    {1780110641, 1780110712, 0x1b04a384, 1},
    {1780111603, 1780111621, 0x1b0490c3, 1},
    {1780111621, 1780111636, 0x1b048b6c, 1},
    {1780111844, 1780111882, 0x1b047711, 1},
    {1780112083, 1780112261, 0x1b046644, 1},
    {1780113054, 1780113187, 0x1b045774, 1},
    {1780114023, 1780114202, 0x1b04518c, 1},
    {1780115236, 1780115287, 0x1b044d0b, 1},
    {1780117131, 1780117334, 0x1b04abda, 1},
    {1780117616, 1780117649, 0x1b0457ac, 1},
    {1780117649, 1780117757, 0x1b0447a6, 1},
    {1780119771, 1780119953, 0x1b04a8a7, 1},
    {1780120006, 1780120085, 0x1b044466, 1},
    {1780123110, 1780123239, 0x1b04a6cb, 1},
    {1780124078, 1780124250, 0x1b045151, 1},
    {1780125485, 1780125703, 0x1b04a51d, 1},
    {1780125962, 1780126086, 0x1b0450cb, 1},
    {1780126086, 1780126095, 0x1b0441de, 1},
    {1780126445, 1780126610, 0x1b042c99, 1},
    {1780127178, 1780127189, 0x1b041f63, 1},
    {1780127189, 1780127371, 0x1b041314, 1},
    {1780128143, 1780128197, 0x1b040021, 1},
    {1780132454, 1780132517, 0x1b04978e, 1},
    {1780134364, 1780134383, 0x1b04972c, 1},
    {1780135566, 1780135611, 0x1b04349c, 1},
    {1780135611, 1780135732, 0x1b0494c2, 1},
    {1780137242, 1780137433, 0x1b049455, 1},
    {1780138201, 1780138431, 0x1b042902, 1},
    {1780139170, 1780139366, 0x1b0423b5, 1},
    {1780140565, 1780140705, 0x1b0401b5, 1},
    {1780141287, 1780141508, 0x1b041279, 1},
    {1780143194, 1780143243, 0x1b048926, 1},
    {1780144416, 1780144437, 0x1b042e0a, 1},
    {1780145606, 1780145812, 0x1b03eca8, 1},
    {1780147288, 1780147295, 0x1b048347, 1},
    {1780147295, 1780147372, 0x1b04828c, 1},
    {1780150457, 1780150641, 0x1b0481cf, 1},
    {1780152361, 1780152577, 0x1b04810e, 1},
    {1780154041, 1780154144, 0x1b047fe3, 1},
    {1780154993, 1780155196, 0x1b044b98, 2},
    {1780155223, 1780155352, 0x1b04482d, 2},
    {1780156182, 1780156399, 0x1b04292e, 2},
    {1780157644, 1780157819, 0x1b044cc8, 2},
    {1780157819, 1780157863, 0x1b042d35, 2},
    {1780160571, 1780160728, 0x1b0922ec, 2},
    {1780161539, 1780161601, 0x1b04407b, 2},
    {1780163182, 1780163324, 0x1b058fbb, 2},
    {1780163419, 1780163578, 0x1b044ade, 2},
    {1780164880, 1780165005, 0x1b048c56, 2},
    {1780165353, 1780165523, 0x1b0439ef, 2},
    {1780167728, 1780167754, 0x1b07a20a, 2},
    {1780169870, 1780170020, 0x1b078dad, 2},
    {1780171559, 1780171740, 0x1b05aa86, 2},
    {1780172754, 1780172987, 0x1b047e51, 2},
    {1780173254, 1780173423, 0x1b048385, 2},
    {1780173496, 1780173616, 0x1b04702e, 2},
    {1780173616, 1780173730, 0x1b0454e6, 2},
    {1780173977, 1780174122, 0x1b0436a5, 2},
    {1780174710, 1780174729, 0x1b042005, 2},
    {1780175660, 1780175686, 0x1b040f59, 2},
    {1780175905, 1780176072, 0x1b040899, 2},
    {1780176861, 1780177088, 0x1b03f152, 2},
    {1780178807, 1780178832, 0x1b059e57, 2},
    {1780179548, 1780179729, 0x1b03fc5a, 2},
    {1780180283, 1780180353, 0x1b03f338, 2},
    {1780181231, 1780181447, 0x1b03e17d, 2},
    {1780182657, 1780182884, 0x1b03e546, 2},
    {1780184792, 1780184998, 0x1b062d45, 2},
    {1780185038, 1780185208, 0x1b03fbd3, 2},
    {1780186750, 1780186907, 0x1b04f7ea, 2},
    {1780188424, 1780188562, 0x1b04f454, 2},
    {1780188657, 1780188800, 0x1b03f748, 2},
    {1780189372, 1780189507, 0x1b03d9d7, 2},
    {1780189507, 1780189507, 0x1b03ca22, 2},
    {1780191761, 1780191883, 0x1b06d943, 2},
    {1780193674, 1780193695, 0x1b05a0d2, 2},
    {1780195363, 1780195609, 0x1b05546d, 2},
    {1780195611, 1780195811, 0x1b03e925, 2},
    {1780217664, 0, 0x1b4523bf, 3},
    {1780239329, 0, 0x1c0089af, 3},
    {1780239329, 1780239449, 0x1c0089af, 2},
    {1780260945, 0, 0x1c009813, 3},
    {1780262865, 1780262994, 0x1c00a5a9, 2},
    {1780271551, 1780271628, 0x1b507901, 2},
    {1780282580, 0, 0x1b782397, 3},
    {1780304197, 0, 0x1c01ccb9, 3},
    {1780304437, 1780304649, 0x1c01d01e, 2},
    {1780307300, 1780307339, 0x1b356c02, 2},
    {1780312848, 1780313079, 0x1b7ff115, 2},
    {1780325857, 0, 0x1c0246fb, 3},
    {1780325857, 1780325974, 0x1c0246fb, 2},
    {1780328523, 1780328547, 0x1c008bee, 2},
    {1780332139, 1780332263, 0x1c00fd4e, 2},
    {1780332618, 1780332857, 0x1b5fb10e, 2},
    {1780336954, 1780337037, 0x1c020541, 2},
    {1780341562, 1780341582, 0x1c035a70, 2},
    {1780347604, 0, 0x1c04e9ab, 3},
    {1780350728, 1780350961, 0x1c07761a, 2},
    {1780354311, 1780354527, 0x1c0360b4, 2},
    {1780358619, 1780358768, 0x1c045d8f, 2},
    {1780363441, 1780363669, 0x1c055a5a, 2},
    {1780369430, 0, 0x1c072c71, 3},
    {1780373287, 1780373295, 0x1c0bf9f2, 2},
    {1780376179, 1780376255, 0x1c044545, 2},
    {1780376255, 1780376387, 0x1c01d694, 2},
    {1780379317, 1780379359, 0x1c0464f9, 2},
    {1780382452, 1780382607, 0x1c04cee2, 2},
    {1780384387, 1780384435, 0x1c0351e2, 2},
    {1780389612, 1780389787, 0x1c09ca3b, 2},
    {1780390093, 1780390299, 0x1c027acf, 2},
    {1780390589, 1780390661, 0x1c0271b0, 2},
    {1780391072, 0, 0x1c026661, 3},
    {1780394191, 1780394358, 0x1c070f4c, 2},
    {1780397043, 1780397245, 0x1c05ab42, 2},
    {1780399214, 1780399257, 0x1c044ec3, 2},
    {1780403029, 1780403108, 0x1c08648d, 2},
    {1780407104, 1780407297, 0x1c0aa335, 2},
    {1780407586, 1780407785, 0x1c03664f, 2},
    {1780410933, 1780411172, 0x1c08c9e8, 2},
    {1780412624, 1780412659, 0x1c043d43, 2},
    {1780412862, 0, 0x1c03861c, 3},
    {1780417658, 1780417727, 0x1c102873, 2},
    {1780421738, 1780421809, 0x1c0e0c48, 2},
    {1780422701, 1780422940, 0x1c047245, 2},
    {1780424622, 1780424813, 0x1c06395e, 2},
    {1780425356, 1780425424, 0x1c047f8e, 2},
    {1780426312, 1780426388, 0x1c047287, 2},
    {1780428196, 1780428326, 0x1c06ab79, 2},
    {1780431570, 1780431710, 0x1c0c2430, 2},
    {1780434463, 0, 0x1c0abe0f, 3},
    {1780435399, 1780435597, 0x1c0e650f, 2},
    {1780435633, 1780435690, 0x1c04eb2f, 2},
    {1780436355, 1780436464, 0x1c04d22b, 2},
    {1780436464, 1780436477, 0x1c04c883, 2},
    {1780436836, 1780436942, 0x1c04ad8c, 2},
    {1780438998, 1780439230, 0x1c07e729, 2},
    {1780440669, 1780440850, 0x1c05a5b0, 2},
    {1780441630, 1780441702, 0x1c04bf21, 2},
    {1780443097, 1780443162, 0x1c057b64, 2},
    {1780445246, 1780445467, 0x1c083acb, 2},
    {1780446926, 1780446989, 0x1c05e172, 2},
    {1780446989, 1780447126, 0x1c04dd7f, 2},
    {1780448105, 1780448115, 0x1c04c570, 2},
    {1780449057, 1780449080, 0x1c050eb3, 2},
    {1780451458, 1780451594, 0x1c0a722b, 2},
    {1780451705, 1780451823, 0x1c0568ae, 2},
    {1780453889, 1780454008, 0x1c09234e, 2},
    {1780455086, 1780455090, 0x1c0568f1, 2},
    {1780455090, 1780455092, 0x1c0565d1, 2},
    {1780455092, 1780455093, 0x1c05463a, 2},
    {1780455093, 1780455094, 0x1c0526c7, 2},
    {1780455094, 1780455098, 0x1c050784, 2},
    {1780455098, 1780455107, 0x1c04e88a, 2},
    {1780455107, 1780455120, 0x1c04c9ed, 2},
    {1780455120, 1780455129, 0x1c045bce, 2},
    {1780455129, 1780455134, 0x1c02707b, 2},
    {1780455134, 1780455145, 0x1c012cb9, 2},
    {1780455145, 1780455158, 0x1b409917, 2},
    {1780455323, 1780455383, 0x1b073bbd, 2},
    {1780458199, 1780458365, 0x1b0d3205, 2},
    {1780458445, 1780458642, 0x1b219dc4, 2},
    {1780458921, 1780459063, 0x1b218b6a, 2},
    {1780459165, 1780459232, 0x1b230a47, 2},
    {1780459232, 1780459270, 0x1b21d1d6, 2},
    {1780459270, 1780459327, 0x1b1ef91d, 2},
    {1780459643, 1780459849, 0x1b1c123f, 2},
    {1780459887, 1780459929, 0x1b1ed161, 2},
    {1780459929, 1780460042, 0x1b1bddcc, 2},
    {1780460042, 1780460086, 0x1b18b947, 2},
    {1780460125, 1780460186, 0x1b1369d7, 2},
    {1780460186, 1780460329, 0x1b0d05ce, 2},
    {1780460363, 1780460445, 0x1b0a4907, 2},
    {1780460445, 1780460496, 0x1b07c437, 2},
    {1780461062, 1780461254, 0x1b055e2c, 2},
    {1780462742, 1780462835, 0x1b0a039c, 2},
    {1780463222, 1780463269, 0x1b0ef984, 2},
    {1780463469, 1780463643, 0x1b0dec0f, 2},
    {1780464177, 1780464232, 0x1b0ce427, 2},
    {1780464422, 1780464579, 0x1b0c0d32, 2},
    {1780465380, 1780465540, 0x1b0b20c2, 2},
    {1780465854, 1780465973, 0x1b0aa367, 2},
    {1780466572, 1780466578, 0x1b09ded8, 2},
    {1780466578, 1780466697, 0x1b094099, 2},
    {1780466821, 1780467045, 0x1b086b8b, 2},
    {1780468039, 1780468283, 0x1b07c624, 2},
    {1780468522, 1780468566, 0x1b0798c0, 2},
    {1780470458, 1780470486, 0x1b0b0f08, 2},
    {1780471889, 1780472024, 0x1b085bea, 2},
    {1780472613, 1780472831, 0x1b07211c, 2},
    {1780475018, 1780475215, 0x1b0c7589, 2},
    {1780475263, 1780475319, 0x1b0722d9, 2},
    {1780476724, 1780476882, 0x1b07c890, 2},
    {1780477684, 1780477788, 0x1b06af7b, 2},
    {1780479124, 1780479317, 0x1b073f28, 2},
    {1780480088, 1780480133, 0x1b0688d7, 2},
    {1780481526, 1780481570, 0x1b075d38, 2},
    {1780481570, 1780481575, 0x1b065702, 2},
    {1780483228, 1780483270, 0x1b082fa6, 2},
    {1780483711, 1780483753, 0x1b0605c0, 2},
    {1780485655, 1780485764, 0x1b092ab2, 2},
    {1780485904, 1780486112, 0x1b05f23d, 2},
    {1780486627, 1780486733, 0x1b05b37e, 2},
    {1780487112, 1780487277, 0x1b058868, 2},
    {1780487360, 1780487393, 0x1b0559a3, 2},
    {1780487590, 1780487697, 0x1b0513b7, 2},
    {1780488780, 1780488890, 0x1b04dace, 2},
    {1780490695, 1780490877, 0x1b074693, 2},
    {1780492116, 1780492184, 0x1b0525e3, 2},
    {1780494259, 1780494337, 0x1b08a5ca, 2},
    {1780495431, 1780495530, 0x1b052ff8, 2},
    {1780496857, 1780496973, 0x1b05bbb5, 2},
};

static const int64_t LWMA_TEST_TIME = 1780000000; // after nPowTimeStampActive on every network

static void LwmaSetBlock(CBlockIndex& index, int nHeight, CBlockIndex* pprev, int64_t nTime, bool fSha, uint32_t nBits)
{
    index.nHeight = nHeight;
    index.pprev = pprev;
    index.nTime = nTime;
    index.nBits = nBits;
    index.fProofOfStake = !fSha;
    index.nVersion = fSha ? (0x30000000 | CBlockHeader::SHA256D_BLOCK) : 0x30000000;
}

/* Build a PoS / SHA256d chain where the SHA256d blocks come every nSpacing seconds at nBits, with
 * a PoS block halfway between. Returns the number of blocks written. */
static int LwmaSteadyChain(std::vector<CBlockIndex>& chain, int nShaBlocks, int64_t nSpacing, uint32_t nBits)
{
    int n = 0;
    int64_t t = LWMA_TEST_TIME;
    for (int i = 0; i < nShaBlocks; i++) {
        LwmaSetBlock(chain[n], n, n ? &chain[n - 1] : nullptr, t + nSpacing / 2, false, 0x1d00ffff);
        n++;
        LwmaSetBlock(chain[n], n, &chain[n - 1], t + nSpacing, true, nBits);
        n++;
        t += nSpacing;
    }
    return n;
}

static double LwmaTargetRatio(uint32_t nBitsA, uint32_t nBitsB)
{
    arith_uint256 a, b;
    a.SetCompact(nBitsA);
    b.SetCompact(nBitsB);
    return a.getdouble() / b.getdouble();
}

BOOST_AUTO_TEST_CASE(lwma_sha256d_vectors)
{
    const size_t nRows = sizeof(lwma_vectors) / sizeof(lwma_vectors[0]);
    std::vector<CBlockIndex> chain(2 * nRows + 1);
    std::vector<int> vTipIndex(nRows);
    int n = 0;
    int nActivationHeight = -1;
    for (size_t r = 0; r < nRows; r++) {
        const LwmaVector& row = lwma_vectors[r];
        if (row.blockTime == 0 || n == 0 || chain[n - 1].nTime != row.tipTime) {
            LwmaSetBlock(chain[n], n, n ? &chain[n - 1] : nullptr, row.tipTime, false, 0x1d00ffff);
            n++;
        }
        vTipIndex[r] = n - 1;
        if (row.blockTime == 0)
            continue;
        if (row.kind == 2 && nActivationHeight < 0)
            nActivationHeight = n;
        LwmaSetBlock(chain[n], n, &chain[n - 1], row.blockTime, true, row.nBits);
        n++;
    }
    BOOST_REQUIRE(nActivationHeight > 0);

    Consensus::Params consensus = Params().GetConsensus();
    consensus.nSha256dLwmaHeight = nActivationHeight;
    int nChecked = 0;
    for (size_t r = 0; r < nRows; r++) {
        const LwmaVector& row = lwma_vectors[r];
        if (row.kind == 0)
            continue;
        const CBlockIndex* pindexLast = &chain[vTipIndex[r]];
        unsigned int nRequired = GetNextWorkRequired(pindexLast, nullptr, consensus, false, CBlockHeader::SHA256D_BLOCK);
        BOOST_CHECK_MESSAGE(nRequired == row.nBits, strprintf("row %d kind %d tip height %d: got %08x want %08x",
                                                                (int)r, row.kind, pindexLast->nHeight, nRequired, row.nBits));
        // the gate picks the right rule on both sides of the activation height
        unsigned int nDirect = (pindexLast->nHeight + 1 >= nActivationHeight)
                                   ? LwmaRetarget(pindexLast, consensus, CBlockHeader::SHA256D_BLOCK, nActivationHeight)
                                   : DarkGravityWave(pindexLast, consensus, false, CBlockHeader::SHA256D_BLOCK);
        BOOST_CHECK_EQUAL(nRequired, nDirect);
        nChecked++;
    }
    BOOST_CHECK(nChecked > 200);
}

BOOST_AUTO_TEST_CASE(lwma_sha256d_too_few_blocks)
{
    const Consensus::Params& consensus = Params().GetConsensus();
    const unsigned int nLimit = UintToArith256(consensus.powLimitSha256).GetCompact();
    std::vector<CBlockIndex> chain(4);
    LwmaSetBlock(chain[0], 0, nullptr, LWMA_TEST_TIME, false, 0x1d00ffff);
    LwmaSetBlock(chain[1], 1, &chain[0], LWMA_TEST_TIME + 600, true, 0x1b04ae5f);
    LwmaSetBlock(chain[2], 2, &chain[1], LWMA_TEST_TIME + 1200, false, 0x1d00ffff);
    // no SHA256d block at all, and a single one: the pow limit
    BOOST_CHECK_EQUAL(LwmaRetarget(&chain[0], consensus, CBlockHeader::SHA256D_BLOCK, 0), nLimit);
    BOOST_CHECK_EQUAL(LwmaRetarget(&chain[2], consensus, CBlockHeader::SHA256D_BLOCK, 0), nLimit);
}

BOOST_AUTO_TEST_CASE(lwma_sha256d_steady_and_decay)
{
    const Consensus::Params& consensus = Params().GetConsensus();
    const int64_t nSpacing = consensus.nSha256DTargetSpacing;
    const uint32_t nBits = 0x1b04ae5f; // difficulty 14000
    std::vector<CBlockIndex> chain(200);
    int n = LwmaSteadyChain(chain, 80, nSpacing, nBits);
    const int64_t nLastSha = chain[n - 1].nTime;

    // blocks exactly on schedule: the requirement stays where the blocks are
    CBlockIndex& tip = chain[n];
    LwmaSetBlock(tip, n, &chain[n - 1], nLastSha + nSpacing / 2, false, 0x1d00ffff);
    unsigned int nLevel = LwmaRetarget(&tip, consensus, CBlockHeader::SHA256D_BLOCK, 0);
    BOOST_CHECK_CLOSE(LwmaTargetRatio(nLevel, nBits), 1.0, 0.1);

    // flat until one spacing has passed, then the target grows with the time since the last block
    tip.nTime = nLastSha + nSpacing;
    BOOST_CHECK_EQUAL(LwmaRetarget(&tip, consensus, CBlockHeader::SHA256D_BLOCK, 0), nLevel);
    tip.nTime = nLastSha + 2 * nSpacing;
    BOOST_CHECK_CLOSE(LwmaTargetRatio(LwmaRetarget(&tip, consensus, CBlockHeader::SHA256D_BLOCK, 0), nLevel), 2.0, 0.1);
    tip.nTime = nLastSha + 10 * nSpacing;
    BOOST_CHECK_CLOSE(LwmaTargetRatio(LwmaRetarget(&tip, consensus, CBlockHeader::SHA256D_BLOCK, 0), nLevel), 10.0, 0.1);

    // far past the window bound only the newest two blocks are left; the rule still answers,
    // the requirement keeps easing and never passes the pow limit
    tip.nTime = nLastSha + 3 * consensus.nLwmaWindowMultiplier * consensus.nLwmaPastBlocks * nSpacing;
    unsigned int nFar = LwmaRetarget(&tip, consensus, CBlockHeader::SHA256D_BLOCK, 0);
    BOOST_CHECK(LwmaTargetRatio(nFar, nLevel) > 10.0);
    BOOST_CHECK(UintToArith256(consensus.powLimitSha256) >= arith_uint256().SetCompact(nFar));
    // the pow limit is difficulty 1/65536 on the usual scale, out of reach from 14000 within a
    // 32 bit block time; from difficulty 0.01 twenty days of silence get there
    std::vector<CBlockIndex> low(200);
    int m = LwmaSteadyChain(low, 80, nSpacing, 0x1d63ff9c);
    CBlockIndex& lowTip = low[m];
    LwmaSetBlock(lowTip, m, &low[m - 1], low[m - 1].nTime + 20 * 86400, false, 0x1d00ffff);
    BOOST_CHECK_EQUAL(LwmaRetarget(&lowTip, consensus, CBlockHeader::SHA256D_BLOCK, 0),
                      UintToArith256(consensus.powLimitSha256).GetCompact());
}

BOOST_AUTO_TEST_CASE(lwma_sha256d_brake)
{
    const Consensus::Params& consensus = Params().GetConsensus();
    const int64_t nSpacing = consensus.nSha256DTargetSpacing;
    const uint32_t nBits = 0x1b04ae5f;
    std::vector<CBlockIndex> chain(200);
    int n = LwmaSteadyChain(chain, 70, nSpacing, nBits);
    int64_t t = chain[n - 1].nTime;
    // a burst: eleven more blocks one second apart at the same bits
    for (int i = 0; i < 11; i++) {
        t += 1;
        LwmaSetBlock(chain[n], n, &chain[n - 1], t, true, nBits);
        n++;
    }
    CBlockIndex& tip = chain[n];
    LwmaSetBlock(tip, n, &chain[n - 1], t + 1, false, 0x1d00ffff);
    unsigned int nBurst = LwmaRetarget(&tip, consensus, CBlockHeader::SHA256D_BLOCK, 0);
    // the long window alone would only have moved a little; the short window says blocks are
    // coming 1200 times too fast, so the brake makes the requirement about 300 times harder
    double ratio = LwmaTargetRatio(nBits, nBurst);
    BOOST_CHECK(ratio > 100.0);
    BOOST_CHECK(ratio < 1000.0);
}

BOOST_AUTO_TEST_CASE(lwma_sha256d_activation_gate)
{
    Consensus::Params consensus = Params().GetConsensus();
    const int64_t nSpacing = consensus.nSha256DTargetSpacing;
    std::vector<CBlockIndex> chain(200);
    int n = LwmaSteadyChain(chain, 70, nSpacing, 0x1b04ae5f);
    const CBlockIndex* pindexLast = &chain[n - 1];
    const int nNext = pindexLast->nHeight + 1;

    consensus.nSha256dLwmaHeight = nNext + 1; // not yet
    BOOST_CHECK_EQUAL(GetNextWorkRequired(pindexLast, nullptr, consensus, false, CBlockHeader::SHA256D_BLOCK),
                      DarkGravityWave(pindexLast, consensus, false, CBlockHeader::SHA256D_BLOCK));
    consensus.nSha256dLwmaHeight = nNext; // this block
    BOOST_CHECK_EQUAL(GetNextWorkRequired(pindexLast, nullptr, consensus, false, CBlockHeader::SHA256D_BLOCK),
                      LwmaRetarget(pindexLast, consensus, CBlockHeader::SHA256D_BLOCK, nNext));
    // other algos and PoS are untouched by the gate
    BOOST_CHECK_EQUAL(GetNextWorkRequired(pindexLast, nullptr, consensus, false, CBlockHeader::PROGPOW_BLOCK),
                      DarkGravityWave(pindexLast, consensus, false, CBlockHeader::PROGPOW_BLOCK));
    BOOST_CHECK_EQUAL(GetNextWorkRequired(pindexLast, nullptr, consensus, true, 0),
                      DarkGravityWave(pindexLast, consensus, true, 0));
}


BOOST_AUTO_TEST_SUITE_END()
