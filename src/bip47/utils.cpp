#include "bip47/utils.h"
#include "bip47/paymentcode.h"
#include "secretpoint.h"
#include "primitives/transaction.h"
#include "uint256.h"
#include "streams.h"
#include "utilstrencodings.h"

using namespace std;

namespace bip47 {
namespace utils {

bool pcodeFromMaskedPayload(std::vector<unsigned char> payload, COutPoint const & outpoint, CKey const & myPrivkey, CPubKey const & outPubkey, CPaymentCode & pcode)
{
    if(payload[0] != 1 || payload[1] != 0) {
        return false;
    }
    if(payload[2] != 2 && payload[2] != 3) {
        return false;
    }
    using vector = std::vector<unsigned char>;
    vector const secretPointData = CSecretPoint(myPrivkey, outPubkey).getEcdhSecret();
    vector maskData(CHMAC_SHA512::OUTPUT_SIZE);

    CDataStream ds(SER_NETWORK, 0);
    ds << outpoint;

    CHMAC_SHA512((const unsigned char*)(ds.vch.data()), ds.vch.size())
        .Write(secretPointData.data(), secretPointData.size())
        .Finalize(maskData.data());

    vector::iterator plIter = payload.begin()+3;
    for(vector::iterator iter = maskData.begin(); iter != maskData.end(); ++iter) {
        *plIter++ ^= *iter;
    }

    CPubKey pubkey(payload.begin() + 2, payload.begin() + 2 + 33); // pubkey starts at 2, its length is 33
    ChainCode chaincode({payload.begin() + 2 + 33, payload.begin() + 2 + 33 + 32}); // chain code starts at pubkey end, its length is 32
    pcode = CPaymentCode(pubkey, chaincode);
    return true;
}

CExtKey derive(CExtKey const & source, std::vector<uint32_t> const & path)
{
    CExtKey key1, key2, *currentKey = &key1, *nextKey = &key2;

    if(!source.Derive(key1, path[0])) {
        throw std::runtime_error("Cannot derive the key on path: " + std::string(path.begin(), path.end()));
    }

    for(std::vector<uint32_t>::const_iterator i = path.begin() + 1; i < path.end(); ++i) {
        if(!currentKey->Derive(*nextKey, *i)){
            throw std::runtime_error("Cannot derive the key on path: " + std::string(path.begin(), path.end()));
        }
        std::swap(currentKey, nextKey);
    }

    return *currentKey;
}

GroupElement GeFromPubkey(CPubKey const & pubKey) {
    GroupElement result;
    std::vector<unsigned char> serializedGe; serializedGe.reserve(std::distance(pubKey.begin(), pubKey.end()) + 1);
    std::copy(pubKey.begin()+ 1, pubKey.end(), std::back_inserter(serializedGe));
    serializedGe.push_back(*pubKey.begin() == 0x02 ? 0 : 1);
    serializedGe.push_back(0x0);
    result.deserialize(&serializedGe[0]);
    return result;
}

CPubKey PubkeyFromGe(GroupElement const & ge) {
    vector<unsigned char> pubkey_vch = ge.getvch();
    pubkey_vch.pop_back();
    unsigned char header_char = pubkey_vch[pubkey_vch.size()-1] == 0 ? 0x02 : 0x03;
    pubkey_vch.pop_back();
    pubkey_vch.insert(pubkey_vch.begin(), header_char);
    CPubKey result;
    result.Set(pubkey_vch.begin(), pubkey_vch.end());
    return result;
}

} }
