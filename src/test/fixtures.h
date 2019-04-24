#include "primitives/transaction.h"
#include "test/test_bitcoin.h"
#include "zerocoin.h"
#include "test/testutil.h"

#include <boost/test/unit_test.hpp>

inline bool no_check( std::runtime_error const& ex ) { return true; }

struct ZerocoinTestingSetupBase : public TestingSetup {
    ZerocoinTestingSetupBase();

    CScript scriptPubKey;

    CBlock CreateBlock(
        const vector<uint256>& tx_ids,
        const CScript&);

    bool ProcessBlock(CBlock&);

    // Create a new block with just given transactions, coinbase paying to
    // scriptPubKey, and try to add it to the current chain.
    CBlock CreateAndProcessBlock(
        const vector<uint256>& tx_ids,
        const CScript&);

    void CreateAndProcessEmptyBlocks(size_t block_numbers, const CScript& script);

    std::vector<CTransaction> coinbaseTxns; // For convenience, coinbase transactionsl
    CKey coinbaseKey; // private/public key needed to spend coinbase transactions
};

struct ZerocoinTestingSetup200 : public ZerocoinTestingSetupBase {
        ZerocoinTestingSetup200();
};

struct ZerocoinTestingSetup109 : public ZerocoinTestingSetupBase {
        ZerocoinTestingSetup109();
};

struct MtpMalformedTestingSetup : public ZerocoinTestingSetupBase {
        MtpMalformedTestingSetup();

    CBlock CreateBlock(
            const vector<uint256>& tx_ids,
            const CScript&, bool);

    CBlock CreateAndProcessBlock(
        const vector<uint256>& tx_ids,
        const CScript&, bool);
};
