#include "Bip47Util.h"
#include "wallet/wallet.h"
#include "PaymentCode.h"
#include "SecretPoint.h"
#include "primitives/transaction.h"
#include "PaymentAddress.h"
#include <vector>

using namespace std;

bool BIP47Util::getOpCodeOutput(const CTransaction& tx, CTxOut& txout) {
    for(int i = 0; i < tx.vout.size(); i++) {
        if (tx.vout[i].scriptPubKey[0] == OP_RETURN) {
            txout = tx.vout[i];
            return true;
        }
    }
    return false;
}

/**
 *  @todo Implement the validate code
 *
 * */
bool BIP47Util::isValidNotificationTransactionOpReturn(CTxOut txout) {
    vector<unsigned char> op_date;
    return getOpCodeData(txout, op_date);
}

bool BIP47Util::getOpCodeData(CTxOut txout, vector<unsigned char>& op_data) {
    CScript::const_iterator pc = txout.scriptPubKey.begin();
        vector<unsigned char> data;
        while (pc < txout.scriptPubKey.end())
        {
            opcodetype opcode;
            if (!txout.scriptPubKey.GetOp(pc, opcode, data))
                break;
            if (data.size() != 0 && opcode == OP_RETURN)
            {
                op_data = data;
                return true;
            }
        }
    return false;
}

bool BIP47Util::getPaymentCodeInNotificationTransaction(vector<unsigned char> privKeyBytes, CTransaction tx, PaymentCode &paymentCode) {
    // tx.vin[0].scriptSig
    CWalletTx wtx(pwalletMain, tx);

    CTxOut txout;
    if(!getOpCodeOutput(tx, txout)) {
        return false;
    }

    vector<unsigned char> op_data;
    if(!getOpCodeData(txout, op_data)) {
        return false;
    }

    /**
     * @Todo Get PubKeyBytes from tx script Sig
     * */
    vector<unsigned char> pubKeyBytes;

    vector<unsigned char> outpoint = ParseHex(wtx.vin[0].prevout.ToString());
    SecretPoint secretPoint(privKeyBytes, pubKeyBytes);
    vector<unsigned char> mask = PaymentCode::getMask(secretPoint.ECDHSecretAsBytes(), outpoint);
    vector<unsigned char> payload = PaymentCode::blind(op_data, mask);
    PaymentCode pcode(payload.data(), payload.size());
    paymentCode = pcode;
    return true;
}

PaymentAddress BIP47Util::getPaymentAddress(PaymentCode &pcode, int idx, CExtKey extkey) {
    vector<unsigned char> privKey(extkey.key.GetPrivKey().begin(), extkey.key.GetPrivKey().end());
    return PaymentAddress(0, pcode, idx, privKey);
}
