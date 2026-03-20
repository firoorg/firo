#include "mint_spend.h"

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
