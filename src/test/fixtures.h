#include "primitives/transaction.h"
#include "test/test_bitcoin.h"
#include "zerocoin.h"
#include "test/testutil.h"

#include <boost/test/unit_test.hpp>

static CScript scriptPubKey;


struct ZerocoinTestingSetupBase : public TestingSetup {
    ZerocoinTestingSetupBase();
    
    CBlock CreateBlock(const std::vector<CMutableTransaction>&,
                       const CScript&);

    bool ProcessBlock(CBlock&);

    // Create a new block with just given transactions, coinbase paying to
    // scriptPubKey, and try to add it to the current chain.
    CBlock CreateAndProcessBlock(const std::vector<CMutableTransaction>&,
                                 const CScript&);

    std::vector<CTransaction> coinbaseTxns; // For convenience, coinbase transactionsl
    CKey coinbaseKey; // private/public key needed to spend coinbase transactions
};

struct ZerocoinTestingSetup200 : public ZerocoinTestingSetupBase {
        ZerocoinTestingSetup200();

        using ZerocoinTestingSetupBase::CreateBlock;
        using ZerocoinTestingSetupBase::ProcessBlock;
        using ZerocoinTestingSetupBase::CreateAndProcessBlock;
        using ZerocoinTestingSetupBase::coinbaseTxns;
        using ZerocoinTestingSetupBase::coinbaseKey;
};


struct ZerocoinTestingSetup109 : public ZerocoinTestingSetupBase {
        ZerocoinTestingSetup109();

        using ZerocoinTestingSetupBase::CreateBlock;
        using ZerocoinTestingSetupBase::ProcessBlock;
        using ZerocoinTestingSetupBase::CreateAndProcessBlock;
        using ZerocoinTestingSetupBase::coinbaseTxns;
        using ZerocoinTestingSetupBase::coinbaseKey;
};
