#include <vector>

#include "bip47/utils.h"
#include "bip47/paymentcode.h"
#include "secretpoint.h"
#include "primitives/transaction.h"
#include "uint256.h"
#include "streams.h"
#include "utilstrencodings.h"
#include "validation.h"
#include "wallet/wallet.h"
#include "wallet/walletexcept.h"

using namespace std;

namespace bip47 {
namespace utils {

std::unique_ptr<CPaymentCode> PcodeFromMaskedPayload(Bytes payload, COutPoint const & outpoint, CKey const & myPrivkey, CPubKey const & outPubkey)
{
    CDataStream ds(SER_NETWORK, 0);
    ds << outpoint;

    return PcodeFromMaskedPayload(payload, (unsigned char const *)ds.vch.data(), ds.vch.size(), myPrivkey, outPubkey);
}

std::unique_ptr<CPaymentCode> PcodeFromMaskedPayload(Bytes payload, unsigned char const * data, size_t dataSize, CKey const & myPrivkey, CPubKey const & outPubkey)
{
    if (payload[0] != 1 || payload[1] != 0) {
        return nullptr;
    }
    if (payload[2] != 2 && payload[2] != 3) {
        return nullptr;
    }
    Bytes const secretPointData = CSecretPoint(myPrivkey, outPubkey).getEcdhSecret();
    Bytes maskData(CHMAC_SHA512::OUTPUT_SIZE);

    CHMAC_SHA512(data, dataSize)
        .Write(secretPointData.data(), secretPointData.size())
        .Finalize(maskData.data());

    Bytes::iterator plIter = payload.begin()+3;
    for (Bytes::const_iterator iter = maskData.begin(); iter != maskData.end(); ++iter) {
        *plIter++ ^= *iter;
    }

    CPubKey pubkey(payload.begin() + 2, payload.begin() + 2 + 33); // pubkey starts at 2, its length is 33
    ChainCode chaincode({payload.begin() + 2 + 33, payload.begin() + 2 + 33 + 32}); // chain code starts at pubkey end, its length is 32
    return std::unique_ptr<CPaymentCode>(new CPaymentCode(pubkey, chaincode));
}

namespace {
std::pair<CScript::const_iterator, CScript::const_iterator> FindOpreturnData(CScript const & script)
{
    if (script.size() < 2 && script[0] != OP_RETURN)
        return {script.end(), script.end()};
    CScript::const_iterator iter = script.begin() + 1;
    if (*iter < OP_PUSHDATA1) {
        uint8_t sz = *iter;
        return {iter + 1, iter + 1 + sz};
    }
    if (*iter == OP_PUSHDATA1) {
        uint8_t sz = *(iter + 1);
        return {iter + 1 + sizeof(sz), iter +  1 + sizeof(sz) + sz};
    }
    if (*iter == OP_PUSHDATA2) {
        uint16_t sz = ReadLE16(&*(iter + 1));
        return {iter + 1 + sizeof(sz), iter +  1 + sizeof(sz) + sz};
    }
    if (*iter == OP_PUSHDATA4) {
        uint32_t sz = ReadLE32(&*(iter + 1));
        return {iter + 1 + sizeof(sz), iter +  1 + sizeof(sz) + sz};
    }
    return {script.end(), script.end()};
}
}

Bytes GetMaskedPcode(CTransactionRef const & tx)
{
    for (CTxOut const & out : tx->vout) {
        std::pair<CScript::const_iterator, CScript::const_iterator> opRetData = FindOpreturnData(out.scriptPubKey);
        if (opRetData.first == out.scriptPubKey.end())
            continue;

        if (*opRetData.first == 0x01 && *(opRetData.first + 1) == 0x00)
            return Bytes(opRetData.first, opRetData.second);
    }
    return Bytes();
}


bool GetScriptSigPubkey(CTxIn const & txin, CPubKey& pubkey)
{
    CScript::const_iterator pc = txin.scriptSig.begin();
    vector<unsigned char> chunk0data;
    vector<unsigned char> chunk1data;

    opcodetype opcode0, opcode1;
    if (!txin.scriptSig.GetOp(pc, opcode0, chunk0data))
    {
        return false;
    }
    if (!txin.scriptSig.GetOp(pc, opcode1, chunk1data))
    {
        //check whether this is a P2PK redeem script
        CTransactionRef tx;
        uint256 hashBlock = uint256();
        if (!GetTransaction(txin.prevout.hash, tx, Params().GetConsensus(), hashBlock, true))
            return false;

        CScript dest = tx->vout[txin.prevout.n].scriptPubKey;
        CScript::const_iterator pc = dest.begin();
        opcodetype opcode;
        std::vector<unsigned char> vch;
        if (!dest.GetOp(pc, opcode, vch) || vch.size() < 33 || vch.size() > 65)
            return false;
        CPubKey pubKeyOut = CPubKey(vch);
        if (!pubKeyOut.IsFullyValid())
            return false;
        if (!dest.GetOp(pc, opcode, vch) || opcode != OP_CHECKSIG || dest.GetOp(pc, opcode, vch))
            return false;
        pubkey = pubKeyOut;
        return true;
    }

    if (!chunk0data.empty() && chunk0data.size() > 2 && !chunk1data.empty() && chunk1data.size() > 2)
    {
        pubkey = CPubKey(chunk1data);
        return true;
    }
    else if (opcode0 == OP_CHECKSIG && !chunk0data.empty() && chunk0data.size() > 2)
    {
        pubkey = CPubKey(chunk0data);
        return true;
    }
    return false;
}

CExtKey Derive(CExtKey const & source, std::vector<uint32_t> const & path)
{
    CExtKey key1, key2, *currentKey = &key1, *nextKey = &key2;

    if (!source.Derive(key1, path[0])) {
        throw std::runtime_error("Cannot derive the key on path: " + std::string(path.begin(), path.end()));
    }

    for (std::vector<uint32_t>::const_iterator i = path.begin() + 1; i < path.end(); ++i) {
        if (!currentKey->Derive(*nextKey, *i)){
            throw std::runtime_error("Cannot derive the key on path: " + std::string(path.begin(), path.end()));
        }
        std::swap(currentKey, nextKey);
    }

    return *currentKey;
}

GroupElement GeFromPubkey(CPubKey const & pubKey)
{
    GroupElement result;
    std::vector<unsigned char> serializedGe; serializedGe.reserve(std::distance(pubKey.begin(), pubKey.end()) + 1);
    std::copy(pubKey.begin()+ 1, pubKey.end(), std::back_inserter(serializedGe));
    serializedGe.push_back(*pubKey.begin() == 0x02 ? 0 : 1);
    serializedGe.push_back(0x0);
    result.deserialize(&serializedGe[0]);
    return result;
}

CPubKey PubkeyFromGe(GroupElement const & ge)
{
    vector<unsigned char> pubkey_vch = ge.getvch();
    pubkey_vch.pop_back();
    unsigned char header_char = pubkey_vch[pubkey_vch.size()-1] == 0 ? 0x02 : 0x03;
    pubkey_vch.pop_back();
    pubkey_vch.insert(pubkey_vch.begin(), header_char);
    CPubKey result;
    result.Set(pubkey_vch.begin(), pubkey_vch.end());
    return result;
}

std::string ShortenPcode(CPaymentCode const & pcode)
{
    std::ostringstream ostr;
    std::string pcodeStr = pcode.toString();
    ostr << pcodeStr.substr(0, 6);
    ostr << "...";
    ostr << pcodeStr.substr(pcodeStr.size() - 6, 6);
    return ostr.str();
}


void AddReceiverSecretAddresses(CAccountReceiver const & receiver, ::CWallet & wallet)
{
    bip47::MyAddrContT addrs = receiver.getMyNextAddresses();
    LOCK(wallet.cs_wallet);
    for (bip47::MyAddrContT::value_type const & addr : addrs) {
        CPubKey pubkey = addr.second.GetPubKey();
        CKeyID vchAddress = pubkey.GetID();
        wallet.MarkDirty();
        wallet.SetAddressBook(vchAddress, "", "receive");
        if (wallet.HaveKey(vchAddress)) {
            continue;
        }
        if (!wallet.AddKeyPubKey(addr.second, pubkey)) {
            throw WalletError("Error adding key to wallet");
        }
    }
}

} }
