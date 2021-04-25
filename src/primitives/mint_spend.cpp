#include "mint_spend.h"
#include "../liblelantus/coin.h"

GroupElement const & MintMeta::GetPubCoinValue() const {
    return pubCoinValue;
}


void MintMeta::SetPubCoinValue(GroupElement const & other) {
    if (other == pubCoinValue)
        return;
    pubCoinValueHash.reset();
    pubCoinValue = other;
}


uint256 MintMeta::GetPubCoinValueHash() const {
    if(!pubCoinValueHash)
        pubCoinValueHash.reset(primitives::GetPubCoinValueHash(pubCoinValue));
    return *pubCoinValueHash;
}

namespace primitives {

uint256 GetSerialHash(const secp_primitives::Scalar& bnSerial) {
    CDataStream ss(SER_GETHASH, 0);
    ss << bnSerial;
    return Hash(ss.begin(), ss.end());
}

uint256 GetPubCoinValueHash(const secp_primitives::GroupElement& bnValue) {
    CDataStream ss(SER_GETHASH, 0);
    ss << bnValue;
    return Hash(ss.begin(), ss.end());
}

}
