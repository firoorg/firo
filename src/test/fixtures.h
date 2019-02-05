#include "primitives/transaction.h"
#include "test/test_bitcoin.h"
#include "zerocoin.h"
#include "test/testutil.h"

#include <boost/test/unit_test.hpp>

static CScript scriptPubKey;

struct ZerocoinTestingSetup200 : public TestingSetup {
    ZerocoinTestingSetup200();
    
    CBlock CreateBlock(const std::vector<CMutableTransaction>&,
                       const CScript&);

    bool ProcessBlock(CBlock&);

    // Create a new block with just given transactions, coinbase paying to
    // scriptPubKey, and try to add it to the current chain.
    CBlock CreateAndProcessBlock(const std::vector<CMutableTransaction>&,
                                 const CScript&);

    std::vector<CTransaction> coinbaseTxns; // For convenience, coinbase transactions
    CKey coinbaseKey; // private/public key needed to spend coinbase transactions
};


struct ZerocoinTestingSetup109 : public TestingSetup {
    ZerocoinTestingSetup109();

    CBlock CreateBlock(const std::vector<CMutableTransaction>&,
                       const CScript&);

    bool ProcessBlock(CBlock&);

    // Create a new block with just given transactions, coinbase paying to
    // scriptPubKey, and try to add it to the current chain.
    CBlock CreateAndProcessBlock(const std::vector<CMutableTransaction>&,
                                 const CScript&);

    std::vector<CTransaction> coinbaseTxns; // For convenience, coinbase transactions
    CKey coinbaseKey; // private/public key needed to spend coinbase transactions
};
