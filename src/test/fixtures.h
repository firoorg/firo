#include "util.h"

#include "clientversion.h"
#include "primitives/transaction.h"
#include "random.h"
#include "sync.h"
#include "utilstrencodings.h"
#include "utilmoneystr.h"
#include "test/test_bitcoin.h"

#include "chainparams.h"
#include "consensus/consensus.h"
#include "consensus/validation.h"
#include "key.h"
#include "main.h"
#include "miner.h"
#include "pubkey.h"
#include "random.h"
#include "txdb.h"
#include "txmempool.h"
#include "ui_interface.h"
#include "zerocoin.h"

#include "test/testutil.h"

#include "wallet/db.h"

#include <boost/filesystem.hpp>
#include <boost/test/unit_test.hpp>
#include <boost/thread.hpp>

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