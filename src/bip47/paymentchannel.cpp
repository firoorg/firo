#include "bip47/paymentchannel.h"
#include "bip47/utils.h"
#include "bip47/address.h"
#include "bip47/utils.h"
#include "bip47/secretpoint.h"
#include "wallet/wallet.h"

namespace bip47 {

CPaymentChannel::CPaymentChannel(CPaymentCode const & theirPcode, CExtKey const & myChannelKey, Side side)
: myChannelKey(myChannelKey), theirPcode(theirPcode), usedAddressCount(0), theirUsedAddressCount(0), side(side)
{}

CPaymentCode const & CPaymentChannel::getTheirPcode() const
{
    return theirPcode;
}

namespace {
CBitcoinAddress generate(CKey const & privkey, CPubKey const & sharedSecretPubkey, CPubKey const & addressPubkey)
{
    static GroupElement const G(GroupElement().set_base_g());
    CSecretPoint sp(privkey, sharedSecretPubkey);
    std::vector<unsigned char> spBytes = sp.getEcdhSecret();

    std::vector<unsigned char> spHash(32);
    CSHA256().Write(spBytes.data(), spBytes.size()).Finalize(spHash.data());

    secp_primitives::GroupElement B = utils::GeFromPubkey(addressPubkey);
    secp_primitives::GroupElement Bprime = B + G *  secp_primitives::Scalar(spHash.data());
    CPubKey pubKeyN = utils::PubkeyFromGe(Bprime);

    return CBitcoinAddress(pubKeyN.GetID());
}
}

CBitcoinAddress CPaymentChannel::generateTheirNextSecretAddress()
{
    TheirAddrContT addr = generateTheirSecretAddresses(theirUsedAddressCount, theirUsedAddressCount + 1);
    theirUsedAddressCount += 1;
    return addr.front();
}

TheirAddrContT CPaymentChannel::generateTheirSecretAddresses(size_t fromAddr, size_t uptoAddr) const
{
    static GroupElement const G(GroupElement().set_base_g());
    std::vector<CBitcoinAddress>  result;
    for(size_t i = fromAddr; i < uptoAddr; ++i) {
        CPubKey const theirPubkey = theirPcode.getNthPubkey(i).pubkey;
        result.push_back(generate(myChannelKey.key, theirPubkey, theirPubkey));
    }
    return result;
}

CPaymentCode const & CPaymentChannel::getMyPcode() const
{
    if(!myPcode) {
        CExtPubKey myChannelPubkey = myChannelKey.Neuter();
        myPcode.emplace(myChannelPubkey.pubkey, myChannelPubkey.chaincode);
    }
    return *myPcode;
}

MyAddrContT CPaymentChannel::generateMySecretAddresses(size_t fromAddr, size_t uptoAddr) const
{
    static GroupElement const G(GroupElement().set_base_g());
    CExtPubKey theirPubkey = theirPcode.getNthPubkey(0);
    MyAddrContT  result;
    for(size_t i = fromAddr; i < uptoAddr; ++i) {
        CExtKey privkey = bip47::utils::derive(myChannelKey, {uint32_t(i)});
        result.emplace_back(generate(privkey.key, theirPubkey.pubkey, privkey.key.GetPubKey()), privkey.key);
    }
    return result;
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

MyAddrContT const & CPaymentChannel::generateMyUsedAddresses()
{
    if(side == Side::receiver && usedAddresses.size() < usedAddressCount) {
        MyAddrContT addrs = generateMySecretAddresses(usedAddresses.size(), usedAddressCount);
        std::copy(addrs.begin(), addrs.end(), std::back_inserter(usedAddresses));
    }
    return usedAddresses;
}

MyAddrContT const & CPaymentChannel::generateMyNextAddresses()
{
    if(side == Side::receiver && nextAddresses.size() < AddressLookaheadNumber) {
        MyAddrContT addrs = generateMySecretAddresses(usedAddressCount + nextAddresses.size(), usedAddressCount + AddressLookaheadNumber);
        std::copy(addrs.begin(), addrs.end(), std::back_inserter(nextAddresses));
    }
    return nextAddresses;
}

bool CPaymentChannel::markAddressUsed(CBitcoinAddress const & address)
{
    if(address == getMyPcode().getNotificationAddress())
        return true;
    if(side == Side::receiver) {
        MyAddrContT::iterator const begin = nextAddresses.begin();
        MyAddrContT::iterator iter = std::find_if(begin, nextAddresses.end(), FindByAddress(address));
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
    return false;
}


}
