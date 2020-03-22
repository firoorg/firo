#include "validation.h"
#include "lelantus.h"
#include "zerocoin.h" // Mostly for reusing class libzerocoin::SpendMetaData
#include "timedata.h"
#include "chainparams.h"
#include "util.h"
#include "base58.h"
#include "definition.h"
#include "txmempool.h"
#include "wallet/wallet.h"
#include "wallet/walletdb.h"
#include "crypto/sha256.h"
#include "liblelantus/coin.h"
#include "liblelantus/schnorr_prover.h"
#include "znode-payments.h"
#include "znode-sync.h"
#include "primitives/zerocoin.h"

#include <atomic>
#include <sstream>
#include <chrono>

#include <boost/foreach.hpp>
#include <boost/scope_exit.hpp>

#include <ios>

namespace lelantus {

bool IsLelantusAllowed()
{
    LOCK(cs_main);
    return IsLelantusAllowed(chainActive.Height());
}

bool IsLelantusAllowed(int height)
{
	return height >= ::Params().GetConsensus().nLelantusStartBlock;
}

bool IsAvailableToMint(const CAmount& amount)
{
    return amount >= 5 * CENT;
}

void GenerateMintSchnorrProof(const lelantus::PrivateCoin& coin, std::vector<unsigned char>&  serializedSchnorrProof) {
    auto params = lelantus::Params::get_default();

    SchnorrProof<Scalar, GroupElement> schnorrProof;
    SchnorrProver<Scalar, GroupElement> schnorrProver(params->get_g(), params->get_h0());
    schnorrProver.proof(coin.getSerialNumber(), coin.getRandomness(), schnorrProof);

    serializedSchnorrProof.resize(schnorrProof.memoryRequired());
    schnorrProof.serialize(serializedSchnorrProof.data());
}

} // end of namespace lelantus.
