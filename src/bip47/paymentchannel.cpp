#include "bip47/paymentchannel.h"
#include "bip47/bip47utils.h"
#include "bip47/bip47utils.h"
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
CBitcoinAddress generate(CKey const & privkey, CPubKey const & sharedSecretPubkey, CPubKey const & addressPubkey, CKey * privkeyOut = nullptr)
{
    static GroupElement const G(GroupElement().set_base_g());
    CSecretPoint sp(privkey, sharedSecretPubkey);
    std::vector<unsigned char> spBytes = sp.getEcdhSecret();

    std::vector<unsigned char> spHash(32);
    CSHA256().Write(spBytes.data(), spBytes.size()).Finalize(spHash.data());

    if (privkeyOut) {
        Scalar a = Scalar(privkey.begin()) + Scalar(spHash.data());

        vector<unsigned char> ppkeybytes = ParseHex(a.GetHex());
        privkeyOut->Set(ppkeybytes.begin(), ppkeybytes.end(), true);
        assert(privkeyOut->IsValid());
    }


    secp_primitives::GroupElement B = utils::GeFromPubkey(addressPubkey);
    secp_primitives::GroupElement Bprime = B + G *  secp_primitives::Scalar(spHash.data());
    CPubKey pubKeyN = utils::PubkeyFromGe(Bprime);

    return CBitcoinAddress(pubKeyN.GetID());
}
}

CBitcoinAddress CPaymentChannel::generateTheirNextSecretAddress()
{
    CBitcoinAddress addr = getTheirNextSecretAddress();
    ++theirUsedAddressCount;
    return addr;
}

TheirAddrContT CPaymentChannel::generateTheirSecretAddresses(uint32_t fromAddr, uint32_t uptoAddr) const
{
    static GroupElement const G(GroupElement().set_base_g());
    std::vector<CBitcoinAddress>  result;
    for (uint32_t i = fromAddr; i < uptoAddr; ++i) {
        CPubKey const theirPubkey = theirPcode.getNthPubkey(i).pubkey;
        result.push_back(generate(utils::Derive(myChannelKey, {0}).key, theirPubkey, theirPubkey));
    }
    return result;
}

CBitcoinAddress CPaymentChannel::getTheirNextSecretAddress() const
{
    TheirAddrContT addr = generateTheirSecretAddresses(theirUsedAddressCount, theirUsedAddressCount + 1);
    return addr.front();
}

TheirAddrContT CPaymentChannel::getTheirUsedSecretAddresses() const
{
    TheirAddrContT addition = generateTheirSecretAddresses(theirUsedAddresses.size(), theirUsedAddressCount);
    theirUsedAddresses.insert(theirUsedAddresses.end(), addition.begin(), addition.end());
    return theirUsedAddresses;
}

size_t CPaymentChannel::setTheirUsedAddressNumber(size_t number)
{
    if(theirUsedAddressCount < number)
        theirUsedAddressCount = number;
    return theirUsedAddressCount;
}

CPaymentCode const & CPaymentChannel::getMyPcode() const
{
    if (!myPcode) {
        CExtPubKey myChannelPubkey = myChannelKey.Neuter();
        myPcode.emplace(myChannelPubkey.pubkey, myChannelPubkey.chaincode);
    }
    return *myPcode;
}

MyAddrContT CPaymentChannel::generateMySecretAddresses(uint32_t fromAddr, uint32_t uptoAddr) const
{
    static GroupElement const G(GroupElement().set_base_g());
    CExtPubKey theirPubkey = theirPcode.getNthPubkey(0);
    MyAddrContT  result;
    for (uint32_t i = fromAddr; i < uptoAddr; ++i) {
        CExtKey privkey = bip47::utils::Derive(myChannelKey, {uint32_t(i)});
        CKey privkeyOut;
        result.emplace_back(generate(privkey.key, theirPubkey.pubkey, privkey.key.GetPubKey(), &privkeyOut), privkeyOut);
    }
    return result;
}

std::vector<unsigned char> CPaymentChannel::getMaskedPayload(unsigned char const * sha512Key, size_t sha512KeySize, CKey const & outpointSecret) const
{
    using vector = std::vector<unsigned char>;
    using iterator = vector::iterator;

    vector maskData(CHMAC_SHA512::OUTPUT_SIZE);

    CPubKey const theirPubkey = theirPcode.getNthPubkey(0).pubkey;
    vector const secretPointData = CSecretPoint(outpointSecret, theirPubkey).getEcdhSecret();

    CHMAC_SHA512(sha512Key, sha512KeySize)
            .Write(secretPointData.data(), secretPointData.size())
            .Finalize(maskData.data());

    vector payload = CPaymentCode(myChannelKey.key.GetPubKey(), myChannelKey.chaincode).getPayload();

    iterator plIter = payload.begin()+3;
    for (iterator iter = maskData.begin(); iter != maskData.end(); ++iter) {
        *plIter++ ^= *iter;
    }

    return payload;
}

std::vector<unsigned char> CPaymentChannel::getMaskedPayload(COutPoint const & outpoint, CKey const & outpointSecret) const
{
    CDataStream ds(SER_NETWORK, 0);
    ds << outpoint;

    return getMaskedPayload((const unsigned char *)ds.vch.data(), ds.vch.size(), outpointSecret);
}

MyAddrContT const & CPaymentChannel::generateMyUsedAddresses() const
{
    if (side == Side::receiver && usedAddresses.size() < usedAddressCount) {
        MyAddrContT addrs = generateMySecretAddresses(usedAddresses.size(), usedAddressCount);
        std::copy(addrs.begin(), addrs.end(), std::back_inserter(usedAddresses));
    }
    return usedAddresses;
}

MyAddrContT const & CPaymentChannel::generateMyNextAddresses() const
{
    if (side == Side::receiver && nextAddresses.size() < AddressLookaheadNumber) {
        MyAddrContT addrs = generateMySecretAddresses(usedAddressCount + nextAddresses.size(), usedAddressCount + AddressLookaheadNumber);
        std::copy(addrs.begin(), addrs.end(), std::back_inserter(nextAddresses));
    }
    return nextAddresses;
}

bool CPaymentChannel::markAddressUsed(CBitcoinAddress const & address)
{
    if (address == getMyPcode().getNotificationAddress())
        return true;
    if (side == Side::receiver) {
        MyAddrContT::iterator const begin = nextAddresses.begin();
        MyAddrContT::iterator iter = std::find_if (begin, nextAddresses.end(), FindByAddress(address));
        if (iter == nextAddresses.end()) {
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

size_t CPaymentChannel::setMyUsedAddressNumber(size_t number)
{
    if(usedAddressCount < number)
        usedAddressCount = number;
    return usedAddressCount;
}

bool CPaymentChannel::operator==(CPaymentChannel const & other) const
{
    if (!(myChannelKey.key == other.myChannelKey.key)
            || myChannelKey.chaincode != other.myChannelKey.chaincode
            || !(theirPcode == other.theirPcode)
            || usedAddressCount != other.usedAddressCount
            || theirUsedAddressCount != other.theirUsedAddressCount
            || side != other.side
        )
        return false;
    return true;
}


}
