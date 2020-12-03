#include "bip47/paymentchannel.h"
#include "bip47/utils.h"
#include "bip47/address.h"
#include "bip47/utils.h"
#include "bip47/secretpoint.h"
#include "wallet/wallet.h"

namespace bip47 {

CPaymentChannel::CPaymentChannel()
: idxSend(0), idxRecv(0), state(State::created)
{}

CPaymentChannel::CPaymentChannel(CPaymentCode const & theirPcode, CExtKey const & myChannelKey)
: theirPcode(theirPcode), idxSend(0), idxRecv(0), state(State::created), myChannelKey(myChannelKey)
{}

std::vector<CBitcoinAddress> CPaymentChannel::generateTheirAddresses(size_t number) const
{
    static GroupElement const G(GroupElement().set_base_g());
    std::vector<CBitcoinAddress> result;
    for(size_t i = 0; i < number; ++i) {
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

CPaymentCode const & CPaymentChannel::getMyPcode() const
{
    return payeePcode;
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

std::vector<CAddress> CPaymentChannel::getIncomingAddresses() const
{
    return incomingAddresses;
}

int CPaymentChannel::getIdxRecv() const
{
    return idxRecv;
}

void CPaymentChannel::addTransaction(uint256 hash)
{
    if (hash.IsNull()) return;
    if (std::find(transactions.begin(), transactions.end(), hash) != transactions.end()) return;
    transactions.push_back(hash);
}
void CPaymentChannel::getTransactions(std::vector<uint256>& hashes) const
{
    hashes.insert(hashes.end(), transactions.begin(), transactions.end());
}

void CPaymentChannel::addNewIncomingAddress(string newAddress, int nextIndex)
{
    incomingAddresses.push_back(CAddress(newAddress, nextIndex));      
    idxRecv = nextIndex;
}

std::string const & CPaymentChannel::getLabel() const
{
    return label;
}

void CPaymentChannel::setLabel(std::string const & l)
{
    label = l;
}

std::vector<string> CPaymentChannel::getOutgoingAddresses() const
{
    return outgoingAddresses;
}

int CPaymentChannel::getIdxSend() const
{
    return idxSend;
}

void CPaymentChannel::incrementOutgoingIndex()
{
    idxSend++;
}

void CPaymentChannel::addAddressToOutgoingAddresses(string address)
{
    outgoingAddresses.push_back(address);
}

bool CPaymentChannel::isNotificationTransactionSent() const
{
    return false;
}

}
