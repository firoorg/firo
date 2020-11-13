#include "bip47/utils.h"
#include "bip47/paymentcode.h"
#include "secretpoint.h"
#include "primitives/transaction.h"
#include "bip47/paymentaddress.h"
#include <vector>
#include "uint256.h"
#include "wallet/wallet.h"
#include "validation.h"

using namespace std;

namespace bip47 {
namespace utils {

void arraycopy(const std::vector<unsigned char> &source_arr, size_t sourcePos, unsigned char* dest_arr, size_t destPos, size_t len){
    if(source_arr.size() < sourcePos + len)
    {
        throw std::runtime_error("arraycopy error, source_arr has invalid size");
    }
    memcpy(dest_arr + destPos,source_arr.data() + sourcePos , len);
}
void arraycopy(const unsigned char *source_arr,size_t sourcePos,std::vector<unsigned char> &dest_arr, size_t destPos, size_t len){
    if(dest_arr.size() < destPos + len)
    {
        throw std::runtime_error("arraycopy error, dest_arr has invalid size");
    }
    memcpy(dest_arr.data() + destPos, source_arr + sourcePos , len);
}
void arraycopy(const std::vector<unsigned char> &source_arr,size_t sourcePos,std::vector<unsigned char> &dest_arr, size_t destPos, size_t len){
    if(dest_arr.size() < destPos + len)
    {
        throw std::runtime_error("arraycopy error, dest_arr has invalid size");
    }
    if(source_arr.size() < sourcePos + len)
    {
        throw std::runtime_error("arraycopy error, source_arr has invalid size");
    }
    memcpy(dest_arr.data() + destPos, source_arr.data() + sourcePos , len);
}
void copyOfRange(const std::vector<unsigned char> &original, size_t from, size_t to,std::vector<unsigned char> &result) {
    int newLength = to - from;
    if (newLength < 0)
        throw std::runtime_error(from + " > " + to);
    result = std::vector<unsigned char>(newLength);
    int len = original.size() - from;
    if(len > newLength) len = newLength;
    arraycopy(original, from, result, 0, len);
}
bool doublehash(const std::vector<unsigned char> &input,std::vector<unsigned char> &result)
{
    try{
        SHA256_CTX shaCtx;
        SHA256_Init(&shaCtx);
        SHA256_Update(&shaCtx, input.data(), input.size());
        uint256 hash1;
        SHA256_Final((unsigned char*)&hash1, &shaCtx);
        uint256 hash2;
        SHA256((unsigned char*)&hash1, sizeof(hash1), (unsigned char*)&hash2);
        result = std::vector<unsigned char>(hash2.begin(),hash2.end());
        return true;
    }
    catch(std::exception &e)
    {
        printf("bool util::doublehash is failed ...\n");
        return false;
    }
    
}

bool getOpCodeOutput(const CTransaction& tx, CTxOut& txout) {
    for(size_t i = 0; i < tx.vout.size(); i++) {
        if (tx.vout[i].scriptPubKey[0] == OP_RETURN) {
            txout = tx.vout[i];
            return true;
        }
    }
    return false;
}


bool isValidNotificationTransactionOpReturn(CTxOut txout) {
    vector<unsigned char> op_date;
    return getOpCodeData(txout, op_date);
}

bool getOpCodeData(CTxOut const & txout, vector<unsigned char>& op_data) {
    CScript::const_iterator pc = txout.scriptPubKey.begin();
    vector<unsigned char> data;
    
    while (pc < txout.scriptPubKey.end())
    {
        opcodetype opcode;
        if (!txout.scriptPubKey.GetOp(pc, opcode, data))
        {
            LogPrintf("GetOp false in getOpCodeData\n");
            return false;
        }
        LogPrintf("Data.size() = %d,  opcode = 0x%x\n", data.size(), opcode);
        if (data.size() > 0 && opcode < OP_PUSHDATA4  )
        {
            op_data = data;
            return true;
        } 
        
    }
    return false;
}

bool getPaymentCodeInNotificationTransaction(vector<unsigned char> const & privKeyBytes, CTransaction const & tx, CPaymentCode &paymentCode) {
    // tx.vin[0].scriptSig
//     CWalletTx wtx(pwalletMain, tx);

    CTxOut txout;
    if(!getOpCodeOutput(tx, txout)) {
        LogPrintf("Cannot Get OpCodeOutput\n");
        return false;
    }

    if(!isValidNotificationTransactionOpReturn(txout))
    {
        LogPrintf("Error isValidNotificationTransactionOpReturn txout\n");
        return false;
    }

    vector<unsigned char> op_data;
    if(!getOpCodeData(txout, op_data)) {
        LogPrintf("Cannot Get OpCodeData\n");
        return false;
    }

    /**
     * @Todo Get PubKeyBytes from tx script Sig
     * */
    vector<unsigned char> pubKeyBytes;

    if (!getScriptSigPubkey(tx.vin[0], pubKeyBytes))
    {
        LogPrintf("Bip47Utiles CPaymentCode ScriptSig GetPubkey error\n");
        return false;
    }
    
    LogPrintf("pubkeyBytes size = %d\n", pubKeyBytes.size());


    vector<unsigned char> outpoint(tx.vin[0].prevout.hash.begin(), tx.vin[0].prevout.hash.end());
    CKey key; key.Set(privKeyBytes.begin(), privKeyBytes.end(), false);
    CSecretPoint secretPoint(key, CPubKey(pubKeyBytes));
    
    LogPrintf("Generating Secret Point for Decode with \n privekey: %s\n pubkey: %s\n", HexStr(privKeyBytes), HexStr(pubKeyBytes));
    
    LogPrintf("output: %s\n", tx.vin[0].prevout.hash.GetHex());
    uint256 secretPBytes(secretPoint.getEcdhSecret());
    LogPrintf("secretPoint: %s\n", secretPBytes.GetHex());

    vector<unsigned char> mask = CPaymentCode::getMask(secretPoint.getEcdhSecret(), outpoint);
    vector<unsigned char> payload = CPaymentCode::blind(op_data, mask);
//bip47
//    CPaymentCode pcode(payload.data(), payload.size());
//    paymentCode = pcode;
    return true;
}

bool getScriptSigPubkey(CTxIn const & txin, vector<unsigned char>& pubkeyBytes)
{
    LogPrintf("ScriptSig size = %d\n", txin.scriptSig.size());
    CScript::const_iterator pc = txin.scriptSig.begin();
    vector<unsigned char> chunk0data;
    vector<unsigned char> chunk1data;
    
    opcodetype opcode0, opcode1;
    if (!txin.scriptSig.GetOp(pc, opcode0, chunk0data))
    {
        LogPrintf("Bip47Utiles ScriptSig Chunk0 error != 2\n");
        return false;
    }
    LogPrintf("opcode0 = %x, chunk0data.size = %d\n", opcode0, chunk0data.size());

    if (!txin.scriptSig.GetOp(pc, opcode1, chunk1data))
    {
        //check whether this is a P2PK redeems cript
        LogPrintf("A\n");
        CTransactionRef tx;
        uint256 hashBlock = uint256();
        if (!GetTransaction(txin.prevout.hash, tx, Params().GetConsensus(), hashBlock, true))
            return false;
        
        CScript dest = tx->vout[txin.prevout.n].scriptPubKey;
        LogPrintf("B\n");
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

        pubkeyBytes.clear();
        std::copy(pubKeyOut.begin(), pubKeyOut.end(), std::back_inserter(pubkeyBytes));
        return true;
    } 
    LogPrintf("opcode1 = %x, chunk1data.size = %d\n", opcode1, chunk1data.size());
    
    if(!chunk0data.empty() && chunk0data.size() > 2 && !chunk1data.empty() && chunk1data.size() > 2)
    {
        pubkeyBytes = chunk1data;
        return true;
    }
    else if(opcode0 == OP_CHECKSIG && !chunk0data.empty() && chunk0data.size() > 2)
    {
        pubkeyBytes = chunk0data;
        return true;
    }

    LogPrintf("Script did not match expected form: \n");
    return false;
}

CPaymentAddress getPaymentAddress(CPaymentCode const & pcode, int idx, CExtKey const & extkey) {
    vector<unsigned char> ppkeybytes(extkey.key.begin(), extkey.key.end());

    CPaymentAddress paddr(pcode, idx, ppkeybytes);
    return paddr;

}

CPaymentAddress getReceiveAddress(CAccount *v_bip47Account, CWallet* pbip47Wallet, CPaymentCode const & pcode_from, int idx)
{
    CPaymentAddress pm_address;
    //loook for bip47 account that has payment address as in the chanel
    CExtKey accEkey = v_bip47Account->keyPrivAt(idx);
    if(accEkey.key.IsValid()){ //Keep Empty
    }
    pm_address = getPaymentAddress(pcode_from, 0, accEkey);

    return pm_address;
}

CPaymentAddress getSendAddress(CWallet* pbip47Wallet, CPaymentCode const & pcode_to, int idx)
{
    CPaymentAddress pm_address;
    CExtKey accEkey = pbip47Wallet->getBIP47Account(0).keyPrivAt(0);
    if(accEkey.key.IsValid()){ //Keep Empty
    }
    pm_address = getPaymentAddress(pcode_to, idx, accEkey);

    return pm_address;

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
