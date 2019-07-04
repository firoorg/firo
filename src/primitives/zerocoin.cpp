#include "zerocoin.h"
#include <zerocoin_v3.h>


GroupElement const & CMintMeta::GetPubCoinValue() const {
    return pubCoinValue;
}


void CMintMeta::SetPubCoinValue(GroupElement const & other) {
    if (other == pubCoinValue)
        return;
    pubCoinValueHash.reset();
    pubCoinValue = other;
}


uint256 CMintMeta::GetPubCoinValueHash() const {
    if(!pubCoinValueHash)
        pubCoinValueHash.reset(sigma::GetPubCoinValueHash(pubCoinValue));
    return *pubCoinValueHash;
}
