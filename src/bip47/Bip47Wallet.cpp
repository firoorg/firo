#include "Bip47Wallet.h"
#include "Bip47Account.h"
#include "SecretPoint.h"

void Bip47Wallet::makeNotificationTransaction(String paymentCode) 
{
    Bip47Account toBip47Account(0, paymentCode);
    CAmount ntValue = CENT;
    CBitcoinAddress ntAddress = toBip47Account.getNotificationAddress();

    // Wallet comments
    CWalletTx wtx;

    wtx.mapValue["comment"] = "notification_transaction";


    CScript scriptPubKey = GetScriptForDestination(ntAddress.Get());
        // Create and send the transaction
    CReserveKey reservekey(pwalletMain);
    CAmount nFeeRequired;
    std::string strError;
    vector<CRecipient> vecSend;
    int nChangePosRet = -1;
    CRecipient recipient = {scriptPubKey, ntValue, true};
    vecSend.push_back(recipient);
    if(!pwalletMain->CreateTransaction(vecSend, wtx, reservekey, nFeeRequired, nChangePosRet, strError)) {
        
    }

    if ( wtx.vin.size() > 0 ) {
        
    }

    /* @todo
        Alice selects the private key corresponding to the designated pubkey

    */
    CPubKey designatedPubKey;
    reservekey.GetReservedKey(designatedPubKey);
    CKey privKey;
    pwalletMain->GetKey(designatedPubKey.GetID(), privKey);
    
    CPubKey pubkey = toBip47Account.getNotificationKey().pubkey;
    vector<unsigned char> dataPriv(privKey.size());
    vector<unsigned char> dataPub(pubkey.size());

    Bip47_common::arraycopy(privKey.begin(), 0, dataPriv, 0, privKey.size());
    Bip47_common::arraycopy(pubkey.begin(), 0, dataPub, 0, pubkey.size());
    
    SecretPoint secretPoint(dataPriv, dataPub);

    /*
    
    */
    vector<unsigned char> outpoint = ParseHex(wtx.vin[0].prevout.ToString());;
    vector<unsigned char> mask = PaymentCode::getMask(secretPoint.ECDHSecretAsBytes(), outpoint);

    vector<unsigned char> op_return = PaymentCode::blind(mBip47Accounts[0].getPaymentCode().getPayload(), mask);

    CScript op_returnScriptPubKey = CScript() << OP_RETURN << op_return;
    CTxOut txOut(0, op_returnScriptPubKey);
    wtx.vout.push_back(txOut);
    // vecSend.push_back(recipient);

    if(!pwalletMain->CreateTransaction(vecSend, wtx, reservekey, nFeeRequired, nChangePosRet, strError)) {
        
    }

    if(!pwalletMain->CommitTransaction(wtx, reservekey)) {

    }
}

void Bip47Wallet::deriveAccount(vector<unsigned char> hd_seed) 
{
    CExtKey masterKey;             //bip47 master key
    CExtKey purposeKey;            //key at m/47'
    CExtKey coinTypeKey;           //key at m/47'/<1/136>' (Testnet or Zcoin Coin Type respectively, according to SLIP-0047)
    // CExtKey identityKey;           //key identity
    // CExtKey childKey;              // index

    masterKey.SetMaster(&hd_seed[0], hd_seed.size());
    masterKey.Derive(purposeKey, BIP47_INDEX | BIP32_HARDENED_KEY_LIMIT);
    purposeKey.Derive(coinTypeKey, 0 | BIP32_HARDENED_KEY_LIMIT);
    // coinTypeKey.Derive(identityKey, 0 | BIP32_HARDENED_KEY_LIMIT);
    Bip47Account bip47Account(0, coinTypeKey, 0);

    mBip47Accounts.clear();
    mBip47Accounts.push_back(bip47Account);
}

