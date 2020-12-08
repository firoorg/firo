#include "bip47/paymentchannel.h"
#include "bip47/utils.h"
#include "bip47/address.h"
#include "bip47/utils.h"
#include "bip47/secretpoint.h"
#include "wallet/wallet.h"

namespace bip47 {

CPaymentChannel::CPaymentChannel(CPaymentCode const & theirPcode, CExtKey const & myChannelKey)
: myChannelKey(myChannelKey), theirPcode(theirPcode), usedAddressCount(0)
{}

std::vector<CBitcoinAddress> CPaymentChannel::generateTheirAddresses(size_t fromAddr, size_t uptoAddr) const
{
    static GroupElement const G(GroupElement().set_base_g());
    std::vector<CBitcoinAddress>  result;
    for(size_t i = fromAddr; i < uptoAddr; ++i) {
        CPubKey const theirPubkey = theirPcode.getNthPubkey(i).pubkey;
        CSecretPoint sp(myChannelKey.key, theirPubkey);
        std::vector<unsigned char> spBytes = sp.getEcdhSecret();

        std::vector<unsigned char> spHash(32);
        CSHA256().Write(spBytes.data(), spBytes.size()).Finalize(spHash.data());

        secp_primitives::GroupElement B = utils::GeFromPubkey(theirPubkey);
        secp_primitives::GroupElement Bprime = B + G *  secp_primitives::Scalar(spHash.data());
        CPubKey pubKeyN = utils::PubkeyFromGe(Bprime);

        result.emplace_back(pubKeyN.GetID());
    }

    return result;
}

CPaymentCode const & CPaymentChannel::getTheirPcode() const
{
    return theirPcode;
}

std::vector<unsigned char> CPaymentChannel::getMaskedPayload(COutPoint const & outpoint, CKey const & outpointSecret) const
{
    using vector = std::vector<unsigned char>;
    using iterator = vector::iterator;

    vector maskData(CHMAC_SHA512::OUTPUT_SIZE);

    CPubKey const theirPubkey = theirPcode.getNthPubkey(0).pubkey;
    vector const secretPointData = CSecretPoint(outpointSecret, theirPubkey).getEcdhSecret();

    CDataStream ds(SER_NETWORK, 0);
    ds << outpoint;

    CHMAC_SHA512((const unsigned char*)(ds.vch.data()), ds.vch.size())
            .Write(secretPointData.data(), secretPointData.size())
            .Finalize(maskData.data());

    vector payload = CPaymentCode(myChannelKey.key.GetPubKey(), myChannelKey.chaincode).getPayload();

    iterator plIter = payload.begin()+3;
    for(iterator iter = maskData.begin(); iter != maskData.end(); ++iter) {
        *plIter++ ^= *iter;
    }

    return payload;
}

CPaymentCode const & CPaymentChannel::getMyPcode() const
{
    if(!myPcode) {
        CExtPubKey myChannelPubkey = myChannelKey.Neuter();
        myPcode.emplace(myChannelPubkey.pubkey, myChannelPubkey.chaincode);
    }
    return *myPcode;
}


CPaymentChannel::AddrContT const & CPaymentChannel::generateMyUsedAddresses()
{
    for(size_t i = usedAddresses.size(); i < usedAddressCount; ++i) {
        usedAddresses.push_back(getMyPcode().getNthAddress(i));
    }
    return usedAddresses;
}

CPaymentChannel::AddrContT const & CPaymentChannel::generateMyNextAddresses()
{
    for(size_t i = nextAddresses.size(); i < 10; ++i) {
        nextAddresses.push_back(getMyPcode().getNthAddress(usedAddressCount + i));
    }
    return nextAddresses;
}

bool CPaymentChannel::markAddressUsed(CBitcoinAddress const & address)
{
    if(address == getMyPcode().getNotificationAddress()) {
        return true;
    }
    AddrContT::iterator begin = nextAddresses.begin() + 1;
    AddrContT::iterator iter = std::find(begin, nextAddresses.end(), address);
    if(iter == nextAddresses.end()) {
        return false;
    }
    iter += 1;
    usedAddressCount += std::distance(begin, iter);
    std::copy(begin, iter, std::back_inserter(usedAddresses));
    nextAddresses.erase(begin, iter);
    generateMyNextAddresses();

    return true;
}


}
