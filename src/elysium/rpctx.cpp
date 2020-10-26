#include "rpctx.h"

#include "createpayload.h"
#include "dex.h"
#include "errors.h"
#include "elysium.h"
#include "pending.h"
#include "rpcrequirements.h"
#include "rpcvalues.h"
#include "rules.h"
#include "signaturebuilder.h"
#include "sp.h"
#include "tx.h"
#include "utilsbitcoin.h"
#include "wallet.h"

#include "../init.h"
#include "../validation.h"
#include "../rpc/server.h"
#include "../sync.h"
#include "../wallet/wallet.h"
#include "../wallet/walletexcept.h"

#include <univalue.h>

#include <boost/function_output_iterator.hpp>
#include <boost/optional.hpp>

#include <stdexcept>
#include <string>

#include <inttypes.h>

using std::runtime_error;
using namespace elysium;


UniValue elysium_sendrawtx(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 2 || request.params.size() > 5)
        throw runtime_error(
            "elysium_sendrawtx \"fromaddress\" \"rawtransaction\" ( \"referenceaddress\" \"redeemaddress\" \"referenceamount\" )\n"
            "\nBroadcasts a raw Elysium Layer transaction.\n"
            "\nArguments:\n"
            "1. fromaddress          (string, required) the address to send from\n"
            "2. rawtransaction       (string, required) the hex-encoded raw transaction\n"
            "3. referenceaddress     (string, optional) a reference address (none by default)\n"
            "4. redeemaddress        (string, optional) an address that can spent the transaction dust (sender by default)\n"
            "5. referenceamount      (string, optional) a zcoin amount that is sent to the receiver (minimal by default)\n"
            "\nResult:\n"
            "\"hash\"                  (string) the hex-encoded transaction hash\n"
            "\nExamples:\n"
            + HelpExampleCli("elysium_sendrawtx", "\"1MCHESTptvd2LnNp7wmr2sGTpRomteAkq8\" \"000000000000000100000000017d7840\" \"1EqTta1Rt8ixAA32DuC29oukbsSWU62qAV\"")
            + HelpExampleRpc("elysium_sendrawtx", "\"1MCHESTptvd2LnNp7wmr2sGTpRomteAkq8\", \"000000000000000100000000017d7840\", \"1EqTta1Rt8ixAA32DuC29oukbsSWU62qAV\"")
        );

    std::string fromAddress = ParseAddress(request.params[0]);
    std::vector<unsigned char> data = ParseHexV(request.params[1], "raw transaction");
    std::string toAddress = (request.params.size() > 2) ? ParseAddressOrEmpty(request.params[2]): "";
    std::string redeemAddress = (request.params.size() > 3) ? ParseAddressOrEmpty(request.params[3]): "";
    int64_t referenceAmount = (request.params.size() > 4) ? ParseAmount(request.params[4], true): 0;

    //some sanity checking of the data supplied?
    uint256 newTX;
    std::string rawHex;
    int result = WalletTxBuilder(fromAddress, toAddress, redeemAddress, referenceAmount, data, newTX, rawHex, autoCommit);

    // check error and return the txid (or raw hex depending on autocommit)
    if (result != 0) {
        throw JSONRPCError(result, error_str(result));
    } else {
        if (!autoCommit) {
            return rawHex;
        } else {
            return newTX.GetHex();
        }
    }
}


UniValue elysium_send(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 4 || request.params.size() > 6)
        throw runtime_error(
            "elysium_send \"fromaddress\" \"toaddress\" propertyid \"amount\" ( \"redeemaddress\" \"referenceamount\" )\n"

            "\nCreate and broadcast a simple send transaction.\n"

            "\nArguments:\n"
            "1. fromaddress          (string, required) the address to send from\n"
            "2. toaddress            (string, required) the address of the receiver\n"
            "3. propertyid           (number, required) the identifier of the tokens to send\n"
            "4. amount               (string, required) the amount to send\n"
            "5. redeemaddress        (string, optional) an address that can spend the transaction dust (sender by default)\n"
            "6. referenceamount      (string, optional) a zcoin amount that is sent to the receiver (minimal by default)\n"

            "\nResult:\n"
            "\"hash\"                  (string) the hex-encoded transaction hash\n"

            "\nExamples:\n"
            + HelpExampleCli("elysium_send", "\"3M9qvHKtgARhqcMtM5cRT9VaiDJ5PSfQGY\" \"37FaKponF7zqoMLUjEiko25pDiuVH5YLEa\" 1 \"100.0\"")
            + HelpExampleRpc("elysium_send", "\"3M9qvHKtgARhqcMtM5cRT9VaiDJ5PSfQGY\", \"37FaKponF7zqoMLUjEiko25pDiuVH5YLEa\", 1, \"100.0\"")
        );

    // obtain parameters & info
    std::string fromAddress = ParseAddress(request.params[0]);
    std::string toAddress = ParseAddress(request.params[1]);
    uint32_t propertyId = ParsePropertyId(request.params[2]);
    int64_t amount = ParseAmount(request.params[3], isPropertyDivisible(propertyId));
    std::string redeemAddress = (request.params.size() > 4 && !ParseText(request.params[4]).empty()) ? ParseAddress(request.params[4]): "";
    int64_t referenceAmount = (request.params.size() > 5) ? ParseAmount(request.params[5], true): 0;

    // perform checks
    RequireExistingProperty(propertyId);
    RequireBalance(fromAddress, propertyId, amount);
    RequireSaneReferenceAmount(referenceAmount);

    // create a payload for the transaction
    std::vector<unsigned char> payload = CreatePayload_SimpleSend(propertyId, amount);

    // request the wallet build the transaction (and if needed commit it)
    uint256 txid;
    std::string rawHex;
    int result = WalletTxBuilder(fromAddress, toAddress, redeemAddress, referenceAmount, payload, txid, rawHex, autoCommit);

    // check error and return the txid (or raw hex depending on autocommit)
    if (result != 0) {
        throw JSONRPCError(result, error_str(result));
    } else {
        if (!autoCommit) {
            return rawHex;
        } else {
            PendingAdd(txid, fromAddress, ELYSIUM_TYPE_SIMPLE_SEND, propertyId, amount);
            return txid.GetHex();
        }
    }
}


UniValue elysium_sendall(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 3 || request.params.size() > 5)
        throw runtime_error(
            "elysium_sendall \"fromaddress\" \"toaddress\" ecosystem ( \"redeemaddress\" \"referenceamount\" )\n"

            "\nTransfers all available tokens in the given ecosystem to the recipient.\n"

            "\nArguments:\n"
            "1. fromaddress          (string, required) the address to send from\n"
            "2. toaddress            (string, required) the address of the receiver\n"
            "3. ecosystem            (number, required) the ecosystem of the tokens to send (1 for main ecosystem, 2 for test ecosystem)\n"
            "4. redeemaddress        (string, optional) an address that can spend the transaction dust (sender by default)\n"
            "5. referenceamount      (string, optional) a zcoin amount that is sent to the receiver (minimal by default)\n"

            "\nResult:\n"
            "\"hash\"                  (string) the hex-encoded transaction hash\n"

            "\nExamples:\n"
            + HelpExampleCli("elysium_sendall", "\"3M9qvHKtgARhqcMtM5cRT9VaiDJ5PSfQGY\" \"37FaKponF7zqoMLUjEiko25pDiuVH5YLEa\" 2")
            + HelpExampleRpc("elysium_sendall", "\"3M9qvHKtgARhqcMtM5cRT9VaiDJ5PSfQGY\", \"37FaKponF7zqoMLUjEiko25pDiuVH5YLEa\" 2")
        );

    // obtain parameters & info
    std::string fromAddress = ParseAddress(request.params[0]);
    std::string toAddress = ParseAddress(request.params[1]);
    uint8_t ecosystem = ParseEcosystem(request.params[2]);
    std::string redeemAddress = (request.params.size() > 3 && !ParseText(request.params[3]).empty()) ? ParseAddress(request.params[3]): "";
    int64_t referenceAmount = (request.params.size() > 4) ? ParseAmount(request.params[4], true): 0;

    // perform checks
    RequireSaneReferenceAmount(referenceAmount);

    // create a payload for the transaction
    std::vector<unsigned char> payload = CreatePayload_SendAll(ecosystem);

    // request the wallet build the transaction (and if needed commit it)
    uint256 txid;
    std::string rawHex;
    int result = WalletTxBuilder(fromAddress, toAddress, redeemAddress, referenceAmount, payload, txid, rawHex, autoCommit);

    // check error and return the txid (or raw hex depending on autocommit)
    if (result != 0) {
        throw JSONRPCError(result, error_str(result));
    } else {
        if (!autoCommit) {
            return rawHex;
        } else {
            // TODO: pending
            return txid.GetHex();
        }
    }
}


UniValue elysium_senddexsell(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 7)
        throw runtime_error(
            "elysium_senddexsell \"fromaddress\" propertyidforsale \"amountforsale\" \"amountdesired\" paymentwindow minacceptfee action\n"

            "\nPlace, update or cancel a sell offer on the traditional distributed ELYSIUM/BTC exchange.\n"

            "\nArguments:\n"

            "1. fromaddress          (string, required) the address to send from\n"
            "2. propertyidforsale    (number, required) the identifier of the tokens to list for sale (must be 1 for ELYSIUM or 2 for TELYSIUM)\n"
            "3. amountforsale        (string, required) the amount of tokens to list for sale\n"
            "4. amountdesired        (string, required) the amount of zcoins desired\n"
            "5. paymentwindow        (number, required) a time limit in blocks a buyer has to pay following a successful accepting order\n"
            "6. minacceptfee         (string, required) a minimum mining fee a buyer has to pay to accept the offer\n"
            "7. action               (number, required) the action to take (1 for new offers, 2 to update\", 3 to cancel)\n"

            "\nResult:\n"
            "\"hash\"                  (string) the hex-encoded transaction hash\n"

            "\nExamples:\n"
            + HelpExampleCli("elysium_senddexsell", "\"37FaKponF7zqoMLUjEiko25pDiuVH5YLEa\" 1 \"1.5\" \"0.75\" 25 \"0.0005\" 1")
            + HelpExampleRpc("elysium_senddexsell", "\"37FaKponF7zqoMLUjEiko25pDiuVH5YLEa\", 1, \"1.5\", \"0.75\", 25, \"0.0005\", 1")
        );

    // obtain parameters & info
    std::string fromAddress = ParseAddress(request.params[0]);
    uint32_t propertyIdForSale = ParsePropertyId(request.params[1]);
    int64_t amountForSale = 0; // depending on action
    int64_t amountDesired = 0; // depending on action
    uint8_t paymentWindow = 0; // depending on action
    int64_t minAcceptFee = 0;  // depending on action
    uint8_t action = ParseDExAction(request.params[6]);

    // perform conversions
    if (action <= CMPTransaction::UPDATE) { // actions 3 permit zero values, skip check
        amountForSale = ParseAmount(request.params[2], true); // TMSC/MSC is divisible
        amountDesired = ParseAmount(request.params[3], true); // BTC is divisible
        paymentWindow = ParseDExPaymentWindow(request.params[4]);
        minAcceptFee = ParseDExFee(request.params[5]);
    }

    // perform checks
    switch (action) {
        case CMPTransaction::NEW:
        {
            RequirePrimaryToken(propertyIdForSale);
            RequireBalance(fromAddress, propertyIdForSale, amountForSale);
            RequireNoOtherDExOffer(fromAddress, propertyIdForSale);
            break;
        }
        case CMPTransaction::UPDATE:
        {
            RequirePrimaryToken(propertyIdForSale);
            RequireBalance(fromAddress, propertyIdForSale, amountForSale);
            RequireMatchingDExOffer(fromAddress, propertyIdForSale);
            break;
        }
        case CMPTransaction::CANCEL:
        {
            RequirePrimaryToken(propertyIdForSale);
            RequireMatchingDExOffer(fromAddress, propertyIdForSale);
            break;
        }
    }

    // create a payload for the transaction
    std::vector<unsigned char> payload = CreatePayload_DExSell(propertyIdForSale, amountForSale, amountDesired, paymentWindow, minAcceptFee, action);

    // request the wallet build the transaction (and if needed commit it)
    uint256 txid;
    std::string rawHex;
    int result = WalletTxBuilder(fromAddress, "", "", 0, payload, txid, rawHex, autoCommit);

    // check error and return the txid (or raw hex depending on autocommit)
    if (result != 0) {
        throw JSONRPCError(result, error_str(result));
    } else {
        if (!autoCommit) {
            return rawHex;
        } else {
            bool fSubtract = (action <= CMPTransaction::UPDATE); // no pending balances for cancels
            PendingAdd(txid, fromAddress, ELYSIUM_TYPE_TRADE_OFFER, propertyIdForSale, amountForSale, fSubtract);
            return txid.GetHex();
        }
    }
}


UniValue elysium_senddexaccept(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 4 || request.params.size() > 5)
        throw runtime_error(
            "elysium_senddexaccept \"fromaddress\" \"toaddress\" propertyid \"amount\" ( override )\n"

            "\nCreate and broadcast an accept offer for the specified token and amount.\n"

            "\nArguments:\n"
            "1. fromaddress          (string, required) the address to send from\n"
            "2. toaddress            (string, required) the address of the seller\n"
            "3. propertyid           (number, required) the identifier of the token to purchase\n"
            "4. amount               (string, required) the amount to accept\n"
            "5. override             (boolean, optional) override minimum accept fee and payment window checks (use with caution!)\n"

            "\nResult:\n"
            "\"hash\"                  (string) the hex-encoded transaction hash\n"

            "\nExamples:\n"
            + HelpExampleCli("elysium_senddexaccept", "\"35URq1NN3xL6GeRKUP6vzaQVcxoJiiJKd8\" \"37FaKponF7zqoMLUjEiko25pDiuVH5YLEa\" 1 \"15.0\"")
            + HelpExampleRpc("elysium_senddexaccept", "\"35URq1NN3xL6GeRKUP6vzaQVcxoJiiJKd8\", \"37FaKponF7zqoMLUjEiko25pDiuVH5YLEa\", 1, \"15.0\"")
        );

    // obtain parameters & info
    std::string fromAddress = ParseAddress(request.params[0]);
    std::string toAddress = ParseAddress(request.params[1]);
    uint32_t propertyId = ParsePropertyId(request.params[2]);
    int64_t amount = ParseAmount(request.params[3], true); // MSC/TMSC is divisible
    bool override = (request.params.size() > 4) ? request.params[4].get_bool(): false;

    // perform checks
    RequirePrimaryToken(propertyId);
    RequireMatchingDExOffer(toAddress, propertyId);

    if (!override) { // reject unsafe accepts - note client maximum tx fee will always be respected regardless of override here
        RequireSaneDExFee(toAddress, propertyId);
        RequireSaneDExPaymentWindow(toAddress, propertyId);
    }


    // use new 0.10 custom fee to set the accept minimum fee appropriately
    int64_t nMinimumAcceptFee = 0;
    {
        LOCK(cs_main);
        const CMPOffer* sellOffer = DEx_getOffer(toAddress, propertyId);
        if (sellOffer == NULL) throw JSONRPCError(RPC_TYPE_ERROR, "Unable to load sell offer from the distributed exchange");
        nMinimumAcceptFee = sellOffer->getMinFee();
    }

    LOCK2(cs_main, pwalletMain->cs_wallet);

    // temporarily update the global transaction fee to pay enough for the accept fee
    CFeeRate payTxFeeOriginal = payTxFee;
    payTxFee = CFeeRate(nMinimumAcceptFee, 225); // TODO: refine!
    // fPayAtLeastCustomFee = true;

    // create a payload for the transaction
    std::vector<unsigned char> payload = CreatePayload_DExAccept(propertyId, amount);

    // request the wallet build the transaction (and if needed commit it)
    uint256 txid;
    std::string rawHex;
    int result = WalletTxBuilder(fromAddress, toAddress, "", 0, payload, txid, rawHex, autoCommit);

    // set the custom fee back to original
    payTxFee = payTxFeeOriginal;

    // check error and return the txid (or raw hex depending on autocommit)
    if (result != 0) {
        throw JSONRPCError(result, error_str(result));
    } else {
        if (!autoCommit) {
            return rawHex;
        } else {
            return txid.GetHex();
        }
    }
}


UniValue elysium_sendissuancecrowdsale(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 14)
        throw runtime_error(
            "elysium_sendissuancecrowdsale \"fromaddress\" ecosystem type previousid \"category\" \"subcategory\" \"name\" \"url\" \"data\" propertyiddesired tokensperunit deadline ( earlybonus issuerpercentage )\n"

            "Create new tokens as crowdsale."

            "\nArguments:\n"
            "1. fromaddress          (string, required) the address to send from\n"
            "2. ecosystem            (string, required) the ecosystem to create the tokens in (1 for main ecosystem, 2 for test ecosystem)\n"
            "3. type                 (number, required) the type of the tokens to create: (1 for indivisible tokens, 2 for divisible tokens)\n"
            "4. previousid           (number, required) an identifier of a predecessor token (0 for new crowdsales)\n"
            "5. category             (string, required) a category for the new tokens (can be \"\")\n"
            "6. subcategory          (string, required) a subcategory for the new tokens  (can be \"\")\n"
            "7. name                 (string, required) the name of the new tokens to create\n"
            "8. url                  (string, required) an URL for further information about the new tokens (can be \"\")\n"
            "9. data                 (string, required) a description for the new tokens (can be \"\")\n"
            "10. propertyiddesired   (number, required) the identifier of a token eligible to participate in the crowdsale\n"
            "11. tokensperunit       (string, required) the amount of tokens granted per unit invested in the crowdsale\n"
            "12. deadline            (number, required) the deadline of the crowdsale as Unix timestamp\n"
            "13. earlybonus          (number, required) an early bird bonus for participants in percent per week\n"
            "14. issuerpercentage    (number, required) a percentage of tokens that will be granted to the issuer\n"

            "\nResult:\n"
            "\"hash\"                  (string) the hex-encoded transaction hash\n"

            "\nExamples:\n"
            + HelpExampleCli("elysium_sendissuancecrowdsale", "\"aGoK6MF87K2SgT7cnJFhSWt7u2cAS5m18p\" 2 1 0 \"Companies\" \"Zcoin Mining\" \"Quantum Miner\" \"\" \"\" 2 \"100\" 1483228800 30 2")
            + HelpExampleRpc("elysium_sendissuancecrowdsale", "\"aGoK6MF87K2SgT7cnJFhSWt7u2cAS5m18p\", 2, 1, 0, \"Companies\", \"Zcoin Mining\", \"Quantum Miner\", \"\", \"\", 2, \"100\", 1483228800, 30, 2")
        );

    // obtain parameters & info
    std::string fromAddress = ParseAddress(request.params[0]);
    uint8_t ecosystem = ParseEcosystem(request.params[1]);
    uint16_t type = ParsePropertyType(request.params[2]);
    uint32_t previousId = ParsePreviousPropertyId(request.params[3]);
    std::string category = ParseText(request.params[4]);
    std::string subcategory = ParseText(request.params[5]);
    std::string name = ParseText(request.params[6]);
    std::string url = ParseText(request.params[7]);
    std::string data = ParseText(request.params[8]);
    uint32_t propertyIdDesired = ParsePropertyId(request.params[9]);
    int64_t numTokens = ParseAmount(request.params[10], type);
    int64_t deadline = ParseDeadline(request.params[11]);
    uint8_t earlyBonus = ParseEarlyBirdBonus(request.params[12]);
    uint8_t issuerPercentage = ParseIssuerBonus(request.params[13]);

    // perform checks
    RequirePropertyName(name);
    RequireExistingProperty(propertyIdDesired);
    RequireSameEcosystem(ecosystem, propertyIdDesired);

    // create a payload for the transaction
    std::vector<unsigned char> payload = CreatePayload_IssuanceVariable(ecosystem, type, previousId, category, subcategory, name, url, data, propertyIdDesired, numTokens, deadline, earlyBonus, issuerPercentage);

    // request the wallet build the transaction (and if needed commit it)
    uint256 txid;
    std::string rawHex;
    int result = WalletTxBuilder(fromAddress, "", "", 0, payload, txid, rawHex, autoCommit);

    // check error and return the txid (or raw hex depending on autocommit)
    if (result != 0) {
        throw JSONRPCError(result, error_str(result));
    } else {
        if (!autoCommit) {
            return rawHex;
        } else {
            return txid.GetHex();
        }
    }
}


UniValue elysium_sendissuancefixed(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 10 || request.params.size() > 11)
        throw runtime_error(
            "elysium_sendissuancefixed \"fromaddress\" ecosystem type previousid \"category\" \"subcategory\" \"name\" \"url\" \"data\" \"amount\" ( sigma )\n"

            "\nCreate new tokens with fixed supply.\n"

            "\nArguments:\n"
            "1. fromaddress          (string, required) the address to send from\n"
            "2. ecosystem            (string, required) the ecosystem to create the tokens in (1 for main ecosystem, 2 for test ecosystem)\n"
            "3. type                 (number, required) the type of the tokens to create: (1 for indivisible tokens, 2 for divisible tokens)\n"
            "4. previousid           (number, required) an identifier of a predecessor token (use 0 for new tokens)\n"
            "5. category             (string, required) a category for the new tokens (can be \"\")\n"
            "6. subcategory          (string, required) a subcategory for the new tokens  (can be \"\")\n"
            "7. name                 (string, required) the name of the new tokens to create\n"
            "8. url                  (string, required) an URL for further information about the new tokens (can be \"\")\n"
            "9. data                 (string, required) a description for the new tokens (can be \"\")\n"
            "10. amount              (string, required) the number of tokens to create\n"
            "11. sigma               (number, optional, default=0) flag to control sigma feature for the new tokens: (0 for soft disabled, 1 for soft enabled, 2 for hard disabled, 3 for hard enabled)\n"

            "\nResult:\n"
            "\"hash\"                  (string) the hex-encoded transaction hash\n"

            "\nExamples:\n"
            + HelpExampleCli("elysium_sendissuancefixed", "\"aGoK6MF87K2SgT7cnJFhSWt7u2cAS5m18p\" 2 1 0 \"Companies\" \"Zcoin Mining\" \"Quantum Miner\" \"\" \"\" \"1000000\"")
            + HelpExampleRpc("elysium_sendissuancefixed", "\"aGoK6MF87K2SgT7cnJFhSWt7u2cAS5m18p\", 2, 1, 0, \"Companies\", \"Zcoin Mining\", \"Quantum Miner\", \"\", \"\", \"1000000\"")
        );

    // obtain parameters & info
    std::string fromAddress = ParseAddress(request.params[0]);
    uint8_t ecosystem = ParseEcosystem(request.params[1]);
    uint16_t type = ParsePropertyType(request.params[2]);
    uint32_t previousId = ParsePreviousPropertyId(request.params[3]);
    std::string category = ParseText(request.params[4]);
    std::string subcategory = ParseText(request.params[5]);
    std::string name = ParseText(request.params[6]);
    std::string url = ParseText(request.params[7]);
    std::string data = ParseText(request.params[8]);
    int64_t amount = ParseAmount(request.params[9], type);
    boost::optional<SigmaStatus> sigma;

    if (request.params.size() > 10) {
        sigma = static_cast<SigmaStatus>(request.params[10].get_int());
    }

    // perform checks
    RequirePropertyName(name);

    if (sigma) {
        RequireSigmaStatus(sigma.get());
    }

    // create a payload for the transaction
    std::vector<unsigned char> payload = CreatePayload_IssuanceFixed(
        ecosystem,
        type,
        previousId,
        category,
        subcategory,
        name,
        url,
        data,
        amount,
        sigma
    );

    // request the wallet build the transaction (and if needed commit it)
    auto& consensus = ConsensusParams();
    uint256 txid;
    std::string rawHex;
    std::string receiver;
    CAmount fee = 0;

    if (IsRequireCreationFee(ecosystem)) {
        receiver = consensus.PROPERTY_CREATION_FEE_RECEIVER.ToString();
        fee = consensus.PROPERTY_CREATION_FEE;
    }

    int result = WalletTxBuilder(fromAddress, receiver, "", fee, payload, txid, rawHex, autoCommit);

    // check error and return the txid (or raw hex depending on autocommit)
    if (result != 0) {
        throw JSONRPCError(result, error_str(result));
    } else {
        if (!autoCommit) {
            return rawHex;
        } else {
            return txid.GetHex();
        }
    }
}


UniValue elysium_sendissuancemanaged(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 9 || request.params.size() > 10)
        throw runtime_error(
            "elysium_sendissuancemanaged \"fromaddress\" ecosystem type previousid \"category\" \"subcategory\" \"name\" \"url\" \"data\" ( sigma )\n"

            "\nCreate new tokens with manageable supply.\n"

            "\nArguments:\n"
            "1. fromaddress          (string, required) the address to send from\n"
            "2. ecosystem            (string, required) the ecosystem to create the tokens in (1 for main ecosystem, 2 for test ecosystem)\n"
            "3. type                 (number, required) the type of the tokens to create: (1 for indivisible tokens, 2 for divisible tokens)\n"
            "4. previousid           (number, required) an identifier of a predecessor token (use 0 for new tokens)\n"
            "5. category             (string, required) a category for the new tokens (can be \"\")\n"
            "6. subcategory          (string, required) a subcategory for the new tokens  (can be \"\")\n"
            "7. name                 (string, required) the name of the new tokens to create\n"
            "8. url                  (string, required) an URL for further information about the new tokens (can be \"\")\n"
            "9. data                 (string, required) a description for the new tokens (can be \"\")\n"
            "10. sigma               (number, optional, default=0) flag to control sigma feature for the new tokens: (0 for soft disabled, 1 for soft enabled, 2 for hard disabled, 3 for hard enabled)\n"

            "\nResult:\n"
            "\"hash\"                  (string) the hex-encoded transaction hash\n"

            "\nExamples:\n"
            + HelpExampleCli("elysium_sendissuancemanaged", "\"aGoK6MF87K2SgT7cnJFhSWt7u2cAS5m18p\" 2 1 0 \"Companies\" \"Zcoin Mining\" \"Quantum Miner\" \"\" \"\"")
            + HelpExampleRpc("elysium_sendissuancemanaged", "\"aGoK6MF87K2SgT7cnJFhSWt7u2cAS5m18p\", 2, 1, 0, \"Companies\", \"Zcoin Mining\", \"Quantum Miner\", \"\", \"\"")
        );

    // obtain parameters & info
    std::string fromAddress = ParseAddress(request.params[0]);
    uint8_t ecosystem = ParseEcosystem(request.params[1]);
    uint16_t type = ParsePropertyType(request.params[2]);
    uint32_t previousId = ParsePreviousPropertyId(request.params[3]);
    std::string category = ParseText(request.params[4]);
    std::string subcategory = ParseText(request.params[5]);
    std::string name = ParseText(request.params[6]);
    std::string url = ParseText(request.params[7]);
    std::string data = ParseText(request.params[8]);
    boost::optional<SigmaStatus> sigma;

    if (request.params.size() > 9) {
        sigma = static_cast<SigmaStatus>(request.params[9].get_int());
    }

    // perform checks
    RequirePropertyName(name);

    if (sigma) {
        RequireSigmaStatus(sigma.get());
    }

    // create a payload for the transaction
    std::vector<unsigned char> payload = CreatePayload_IssuanceManaged(
        ecosystem,
        type,
        previousId,
        category,
        subcategory,
        name,
        url,
        data,
        sigma
    );

    // request the wallet build the transaction (and if needed commit it)
    auto& consensus = ConsensusParams();
    uint256 txid;
    std::string rawHex;
    std::string receiver;
    CAmount fee = 0;

    if (IsRequireCreationFee(ecosystem)) {
        receiver = consensus.PROPERTY_CREATION_FEE_RECEIVER.ToString();
        fee = consensus.PROPERTY_CREATION_FEE;
    }

    int result = WalletTxBuilder(fromAddress, receiver, "", fee, payload, txid, rawHex, autoCommit);

    // check error and return the txid (or raw hex depending on autocommit)
    if (result != 0) {
        throw JSONRPCError(result, error_str(result));
    } else {
        if (!autoCommit) {
            return rawHex;
        } else {
            return txid.GetHex();
        }
    }
}


UniValue elysium_sendsto(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 3 || request.params.size() > 5)
        throw runtime_error(
            "elysium_sendsto \"fromaddress\" propertyid \"amount\" ( \"redeemaddress\" distributionproperty )\n"

            "\nCreate and broadcast a send-to-owners transaction.\n"

            "\nArguments:\n"
            "1. fromaddress            (string, required) the address to send from\n"
            "2. propertyid             (number, required) the identifier of the tokens to distribute\n"
            "3. amount                 (string, required) the amount to distribute\n"
            "4. redeemaddress          (string, optional) an address that can spend the transaction dust (sender by default)\n"
            "5. distributionproperty   (number, optional) the identifier of the property holders to distribute to\n"

            "\nResult:\n"
            "\"hash\"                  (string) the hex-encoded transaction hash\n"

            "\nExamples:\n"
            + HelpExampleCli("elysium_sendsto", "\"32Z3tJccZuqQZ4PhJR2hxHC3tjgjA8cbqz\" \"37FaKponF7zqoMLUjEiko25pDiuVH5YLEa\" 3 \"5000\"")
            + HelpExampleRpc("elysium_sendsto", "\"32Z3tJccZuqQZ4PhJR2hxHC3tjgjA8cbqz\", \"37FaKponF7zqoMLUjEiko25pDiuVH5YLEa\", 3, \"5000\"")
        );

    // obtain parameters & info
    std::string fromAddress = ParseAddress(request.params[0]);
    uint32_t propertyId = ParsePropertyId(request.params[1]);
    int64_t amount = ParseAmount(request.params[2], isPropertyDivisible(propertyId));
    std::string redeemAddress = (request.params.size() > 3 && !ParseText(request.params[3]).empty()) ? ParseAddress(request.params[3]): "";
    uint32_t distributionPropertyId = (request.params.size() > 4) ? ParsePropertyId(request.params[4]) : propertyId;

    // perform checks
    RequireBalance(fromAddress, propertyId, amount);

    // create a payload for the transaction
    std::vector<unsigned char> payload = CreatePayload_SendToOwners(propertyId, amount, distributionPropertyId);

    // request the wallet build the transaction (and if needed commit it)
    uint256 txid;
    std::string rawHex;
    int result = WalletTxBuilder(fromAddress, "", redeemAddress, 0, payload, txid, rawHex, autoCommit);

    // check error and return the txid (or raw hex depending on autocommit)
    if (result != 0) {
        throw JSONRPCError(result, error_str(result));
    } else {
        if (!autoCommit) {
            return rawHex;
        } else {
            PendingAdd(txid, fromAddress, ELYSIUM_TYPE_SEND_TO_OWNERS, propertyId, amount);
            return txid.GetHex();
        }
    }
}


UniValue elysium_sendgrant(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 4 || request.params.size() > 5)
        throw runtime_error(
            "elysium_sendgrant \"fromaddress\" \"toaddress\" propertyid \"amount\" ( \"memo\" )\n"

            "\nIssue or grant new units of managed tokens.\n"

            "\nArguments:\n"
            "1. fromaddress          (string, required) the address to send from\n"
            "2. toaddress            (string, required) the receiver of the tokens (sender by default, can be \"\")\n"
            "3. propertyid           (number, required) the identifier of the tokens to grant\n"
            "4. amount               (string, required) the amount of tokens to create\n"
            "5. memo                 (string, optional) a text note attached to this transaction (none by default)\n"

            "\nResult:\n"
            "\"hash\"                  (string) the hex-encoded transaction hash\n"

            "\nExamples:\n"
            + HelpExampleCli("elysium_sendgrant", "\"3HsJvhr9qzgRe3ss97b1QHs38rmaLExLcH\" \"\" 51 \"7000\"")
            + HelpExampleRpc("elysium_sendgrant", "\"3HsJvhr9qzgRe3ss97b1QHs38rmaLExLcH\", \"\", 51, \"7000\"")
        );

    // obtain parameters & info
    std::string fromAddress = ParseAddress(request.params[0]);
    std::string toAddress = !ParseText(request.params[1]).empty() ? ParseAddress(request.params[1]): "";
    uint32_t propertyId = ParsePropertyId(request.params[2]);
    int64_t amount = ParseAmount(request.params[3], isPropertyDivisible(propertyId));
    std::string memo = (request.params.size() > 4) ? ParseText(request.params[4]): "";

    // perform checks
    RequireExistingProperty(propertyId);
    RequireManagedProperty(propertyId);
    RequireTokenIssuer(fromAddress, propertyId);

    // create a payload for the transaction
    std::vector<unsigned char> payload = CreatePayload_Grant(propertyId, amount, memo);

    // request the wallet build the transaction (and if needed commit it)
    uint256 txid;
    std::string rawHex;
    int result = WalletTxBuilder(fromAddress, toAddress, "", 0, payload, txid, rawHex, autoCommit);

    // check error and return the txid (or raw hex depending on autocommit)
    if (result != 0) {
        throw JSONRPCError(result, error_str(result));
    } else {
        if (!autoCommit) {
            return rawHex;
        } else {
            return txid.GetHex();
        }
    }
}


UniValue elysium_sendrevoke(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 3 || request.params.size() > 4)
        throw runtime_error(
            "elysium_sendrevoke \"fromaddress\" propertyid \"amount\" ( \"memo\" )\n"

            "\nRevoke units of managed tokens.\n"

            "\nArguments:\n"
            "1. fromaddress          (string, required) the address to revoke the tokens from\n"
            "2. propertyid           (number, required) the identifier of the tokens to revoke\n"
            "3. amount               (string, required) the amount of tokens to revoke\n"
            "4. memo                 (string, optional) a text note attached to this transaction (none by default)\n"

            "\nResult:\n"
            "\"hash\"                  (string) the hex-encoded transaction hash\n"

            "\nExamples:\n"
            + HelpExampleCli("elysium_sendrevoke", "\"3HsJvhr9qzgRe3ss97b1QHs38rmaLExLcH\" \"\" 51 \"100\"")
            + HelpExampleRpc("elysium_sendrevoke", "\"3HsJvhr9qzgRe3ss97b1QHs38rmaLExLcH\", \"\", 51, \"100\"")
        );

    // obtain parameters & info
    std::string fromAddress = ParseAddress(request.params[0]);
    uint32_t propertyId = ParsePropertyId(request.params[1]);
    int64_t amount = ParseAmount(request.params[2], isPropertyDivisible(propertyId));
    std::string memo = (request.params.size() > 3) ? ParseText(request.params[3]): "";

    // perform checks
    RequireExistingProperty(propertyId);
    RequireManagedProperty(propertyId);
    RequireTokenIssuer(fromAddress, propertyId);
    RequireBalance(fromAddress, propertyId, amount);

    // create a payload for the transaction
    std::vector<unsigned char> payload = CreatePayload_Revoke(propertyId, amount, memo);

    // request the wallet build the transaction (and if needed commit it)
    uint256 txid;
    std::string rawHex;
    int result = WalletTxBuilder(fromAddress, "", "", 0, payload, txid, rawHex, autoCommit);

    // check error and return the txid (or raw hex depending on autocommit)
    if (result != 0) {
        throw JSONRPCError(result, error_str(result));
    } else {
        if (!autoCommit) {
            return rawHex;
        } else {
            return txid.GetHex();
        }
    }
}


UniValue elysium_sendclosecrowdsale(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2)
        throw runtime_error(
            "elysium_sendclosecrowdsale \"fromaddress\" propertyid\n"

            "\nManually close a crowdsale.\n"

            "\nArguments:\n"
            "1. fromaddress          (string, required) the address associated with the crowdsale to close\n"
            "2. propertyid           (number, required) the identifier of the crowdsale to close\n"

            "\nResult:\n"
            "\"hash\"                  (string) the hex-encoded transaction hash\n"

            "\nExamples:\n"
            + HelpExampleCli("elysium_sendclosecrowdsale", "\"3JYd75REX3HXn1vAU83YuGfmiPXW7BpYXo\" 70")
            + HelpExampleRpc("elysium_sendclosecrowdsale", "\"3JYd75REX3HXn1vAU83YuGfmiPXW7BpYXo\", 70")
        );

    // obtain parameters & info
    std::string fromAddress = ParseAddress(request.params[0]);
    uint32_t propertyId = ParsePropertyId(request.params[1]);

    // perform checks
    RequireExistingProperty(propertyId);
    RequireCrowdsale(propertyId);
    RequireActiveCrowdsale(propertyId);
    RequireTokenIssuer(fromAddress, propertyId);

    // create a payload for the transaction
    std::vector<unsigned char> payload = CreatePayload_CloseCrowdsale(propertyId);

    // request the wallet build the transaction (and if needed commit it)
    uint256 txid;
    std::string rawHex;
    int result = WalletTxBuilder(fromAddress, "", "", 0, payload, txid, rawHex, autoCommit);

    // check error and return the txid (or raw hex depending on autocommit)
    if (result != 0) {
        throw JSONRPCError(result, error_str(result));
    } else {
        if (!autoCommit) {
            return rawHex;
        } else {
            return txid.GetHex();
        }
    }
}

UniValue trade_MP(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 6)
        throw runtime_error(
            "trade_MP \"fromaddress\" propertyidforsale \"amountforsale\" propertiddesired \"amountdesired\" action\n"
            "\nNote: this command is depreciated, and was replaced by:\n"
            " - sendtrade_ELYSIUM\n"
            " - sendcanceltradebyprice_ELYSIUM\n"
            " - sendcanceltradebypair_ELYSIUM\n"
            " - sendcanceltradebypair_ELYSIUM\n"
        );

    JSONRPCRequest newRequest;
    newRequest.params = UniValue(UniValue::VARR);
    UniValue &values = newRequest.params;
    uint8_t action = ParseMetaDExAction(request.params[5]);

    // Forward to the new commands, based on action value
    switch (action) {
        case CMPTransaction::ADD:
        {
            values.push_back(request.params[0]); // fromAddress
            values.push_back(request.params[1]); // propertyIdForSale
            values.push_back(request.params[2]); // amountForSale
            values.push_back(request.params[3]); // propertyIdDesired
            values.push_back(request.params[4]); // amountDesired
            return elysium_sendtrade(newRequest);
        }
        case CMPTransaction::CANCEL_AT_PRICE:
        {
            values.push_back(request.params[0]); // fromAddress
            values.push_back(request.params[1]); // propertyIdForSale
            values.push_back(request.params[2]); // amountForSale
            values.push_back(request.params[3]); // propertyIdDesired
            values.push_back(request.params[4]); // amountDesired
            return elysium_sendcanceltradesbyprice(newRequest);
        }
        case CMPTransaction::CANCEL_ALL_FOR_PAIR:
        {
            values.push_back(request.params[0]); // fromAddress
            values.push_back(request.params[1]); // propertyIdForSale
            values.push_back(request.params[3]); // propertyIdDesired
            return elysium_sendcanceltradesbypair(newRequest);
        }
        case CMPTransaction::CANCEL_EVERYTHING:
        {
            uint8_t ecosystem = 0;
            if (isMainEcosystemProperty(request.params[1].get_int64())
                    && isMainEcosystemProperty(request.params[3].get_int64())) {
                ecosystem = ELYSIUM_PROPERTY_ELYSIUM;
            }
            if (isTestEcosystemProperty(request.params[1].get_int64())
                    && isTestEcosystemProperty(request.params[3].get_int64())) {
                ecosystem = ELYSIUM_PROPERTY_TELYSIUM;
            }
            values.push_back(request.params[0]); // fromAddress
            values.push_back(ecosystem);
            return elysium_sendcancelalltrades(newRequest);
        }
    }

    throw JSONRPCError(RPC_TYPE_ERROR, "Invalid action (1,2,3,4 only)");
}


UniValue elysium_sendtrade(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 5)
        throw runtime_error(
            "elysium_sendtrade \"fromaddress\" propertyidforsale \"amountforsale\" propertiddesired \"amountdesired\"\n"

            "\nPlace a trade offer on the distributed token exchange.\n"

            "\nArguments:\n"
            "1. fromaddress          (string, required) the address to trade with\n"
            "2. propertyidforsale    (number, required) the identifier of the tokens to list for sale\n"
            "3. amountforsale        (string, required) the amount of tokens to list for sale\n"
            "4. propertiddesired     (number, required) the identifier of the tokens desired in exchange\n"
            "5. amountdesired        (string, required) the amount of tokens desired in exchange\n"

            "\nResult:\n"
            "\"hash\"                  (string) the hex-encoded transaction hash\n"

            "\nExamples:\n"
            + HelpExampleCli("elysium_sendtrade", "\"3BydPiSLPP3DR5cf726hDQ89fpqWLxPKLR\" 31 \"250.0\" 1 \"10.0\"")
            + HelpExampleRpc("elysium_sendtrade", "\"3BydPiSLPP3DR5cf726hDQ89fpqWLxPKLR\", 31, \"250.0\", 1, \"10.0\"")
        );

    // obtain parameters & info
    std::string fromAddress = ParseAddress(request.params[0]);
    uint32_t propertyIdForSale = ParsePropertyId(request.params[1]);
    int64_t amountForSale = ParseAmount(request.params[2], isPropertyDivisible(propertyIdForSale));
    uint32_t propertyIdDesired = ParsePropertyId(request.params[3]);
    int64_t amountDesired = ParseAmount(request.params[4], isPropertyDivisible(propertyIdDesired));

    // perform checks
    RequireExistingProperty(propertyIdForSale);
    RequireExistingProperty(propertyIdDesired);
    RequireBalance(fromAddress, propertyIdForSale, amountForSale);
    RequireSameEcosystem(propertyIdForSale, propertyIdDesired);
    RequireDifferentIds(propertyIdForSale, propertyIdDesired);

    // create a payload for the transaction
    std::vector<unsigned char> payload = CreatePayload_MetaDExTrade(propertyIdForSale, amountForSale, propertyIdDesired, amountDesired);

    // request the wallet build the transaction (and if needed commit it)
    uint256 txid;
    std::string rawHex;
    int result = WalletTxBuilder(fromAddress, "", "", 0, payload, txid, rawHex, autoCommit);

    // check error and return the txid (or raw hex depending on autocommit)
    if (result != 0) {
        throw JSONRPCError(result, error_str(result));
    } else {
        if (!autoCommit) {
            return rawHex;
        } else {
            PendingAdd(txid, fromAddress, ELYSIUM_TYPE_METADEX_TRADE, propertyIdForSale, amountForSale);
            return txid.GetHex();
        }
    }
}


UniValue elysium_sendcanceltradesbyprice(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 5)
        throw runtime_error(
            "elysium_sendcanceltradesbyprice \"fromaddress\" propertyidforsale \"amountforsale\" propertiddesired \"amountdesired\"\n"

            "\nCancel offers on the distributed token exchange with the specified price.\n"

            "\nArguments:\n"
            "1. fromaddress          (string, required) the address to trade with\n"
            "2. propertyidforsale    (number, required) the identifier of the tokens listed for sale\n"
            "3. amountforsale        (string, required) the amount of tokens to listed for sale\n"
            "4. propertiddesired     (number, required) the identifier of the tokens desired in exchange\n"
            "5. amountdesired        (string, required) the amount of tokens desired in exchange\n"

            "\nResult:\n"
            "\"hash\"                  (string) the hex-encoded transaction hash\n"

            "\nExamples:\n"
            + HelpExampleCli("elysium_sendcanceltradesbyprice", "\"3BydPiSLPP3DR5cf726hDQ89fpqWLxPKLR\" 31 \"100.0\" 1 \"5.0\"")
            + HelpExampleRpc("elysium_sendcanceltradesbyprice", "\"3BydPiSLPP3DR5cf726hDQ89fpqWLxPKLR\", 31, \"100.0\", 1, \"5.0\"")
        );

    // obtain parameters & info
    std::string fromAddress = ParseAddress(request.params[0]);
    uint32_t propertyIdForSale = ParsePropertyId(request.params[1]);
    int64_t amountForSale = ParseAmount(request.params[2], isPropertyDivisible(propertyIdForSale));
    uint32_t propertyIdDesired = ParsePropertyId(request.params[3]);
    int64_t amountDesired = ParseAmount(request.params[4], isPropertyDivisible(propertyIdDesired));

    // perform checks
    RequireExistingProperty(propertyIdForSale);
    RequireExistingProperty(propertyIdDesired);
    RequireSameEcosystem(propertyIdForSale, propertyIdDesired);
    RequireDifferentIds(propertyIdForSale, propertyIdDesired);
    // TODO: check, if there are matching offers to cancel

    // create a payload for the transaction
    std::vector<unsigned char> payload = CreatePayload_MetaDExCancelPrice(propertyIdForSale, amountForSale, propertyIdDesired, amountDesired);

    // request the wallet build the transaction (and if needed commit it)
    uint256 txid;
    std::string rawHex;
    int result = WalletTxBuilder(fromAddress, "", "", 0, payload, txid, rawHex, autoCommit);

    // check error and return the txid (or raw hex depending on autocommit)
    if (result != 0) {
        throw JSONRPCError(result, error_str(result));
    } else {
        if (!autoCommit) {
            return rawHex;
        } else {
            PendingAdd(txid, fromAddress, ELYSIUM_TYPE_METADEX_CANCEL_PRICE, propertyIdForSale, amountForSale, false);
            return txid.GetHex();
        }
    }
}


UniValue elysium_sendcanceltradesbypair(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 3)
        throw runtime_error(
            "elysium_sendcanceltradesbypair \"fromaddress\" propertyidforsale propertiddesired\n"

            "\nCancel all offers on the distributed token exchange with the given currency pair.\n"

            "\nArguments:\n"
            "1. fromaddress          (string, required) the address to trade with\n"
            "2. propertyidforsale    (number, required) the identifier of the tokens listed for sale\n"
            "3. propertiddesired     (number, required) the identifier of the tokens desired in exchange\n"

            "\nResult:\n"
            "\"hash\"                  (string) the hex-encoded transaction hash\n"

            "\nExamples:\n"
            + HelpExampleCli("elysium_sendcanceltradesbypair", "\"3BydPiSLPP3DR5cf726hDQ89fpqWLxPKLR\" 1 31")
            + HelpExampleRpc("elysium_sendcanceltradesbypair", "\"3BydPiSLPP3DR5cf726hDQ89fpqWLxPKLR\", 1, 31")
        );

    // obtain parameters & info
    std::string fromAddress = ParseAddress(request.params[0]);
    uint32_t propertyIdForSale = ParsePropertyId(request.params[1]);
    uint32_t propertyIdDesired = ParsePropertyId(request.params[2]);

    // perform checks
    RequireExistingProperty(propertyIdForSale);
    RequireExistingProperty(propertyIdDesired);
    RequireSameEcosystem(propertyIdForSale, propertyIdDesired);
    RequireDifferentIds(propertyIdForSale, propertyIdDesired);
    // TODO: check, if there are matching offers to cancel

    // create a payload for the transaction
    std::vector<unsigned char> payload = CreatePayload_MetaDExCancelPair(propertyIdForSale, propertyIdDesired);

    // request the wallet build the transaction (and if needed commit it)
    uint256 txid;
    std::string rawHex;
    int result = WalletTxBuilder(fromAddress, "", "", 0, payload, txid, rawHex, autoCommit);

    // check error and return the txid (or raw hex depending on autocommit)
    if (result != 0) {
        throw JSONRPCError(result, error_str(result));
    } else {
        if (!autoCommit) {
            return rawHex;
        } else {
            PendingAdd(txid, fromAddress, ELYSIUM_TYPE_METADEX_CANCEL_PAIR, propertyIdForSale, 0, false);
            return txid.GetHex();
        }
    }
}


UniValue elysium_sendcancelalltrades(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2)
        throw runtime_error(
            "elysium_sendcancelalltrades \"fromaddress\" ecosystem\n"

            "\nCancel all offers on the distributed token exchange.\n"

            "\nArguments:\n"
            "1. fromaddress          (string, required) the address to trade with\n"
            "2. ecosystem            (number, required) the ecosystem of the offers to cancel (1 for main ecosystem, 2 for test ecosystem)\n"

            "\nResult:\n"
            "\"hash\"                  (string) the hex-encoded transaction hash\n"

            "\nExamples:\n"
            + HelpExampleCli("elysium_sendcancelalltrades", "\"3BydPiSLPP3DR5cf726hDQ89fpqWLxPKLR\" 1")
            + HelpExampleRpc("elysium_sendcancelalltrades", "\"3BydPiSLPP3DR5cf726hDQ89fpqWLxPKLR\", 1")
        );

    // obtain parameters & info
    std::string fromAddress = ParseAddress(request.params[0]);
    uint8_t ecosystem = ParseEcosystem(request.params[1]);

    // perform checks
    // TODO: check, if there are matching offers to cancel

    // create a payload for the transaction
    std::vector<unsigned char> payload = CreatePayload_MetaDExCancelEcosystem(ecosystem);

    // request the wallet build the transaction (and if needed commit it)
    uint256 txid;
    std::string rawHex;
    int result = WalletTxBuilder(fromAddress, "", "", 0, payload, txid, rawHex, autoCommit);

    // check error and return the txid (or raw hex depending on autocommit)
    if (result != 0) {
        throw JSONRPCError(result, error_str(result));
    } else {
        if (!autoCommit) {
            return rawHex;
        } else {
            PendingAdd(txid, fromAddress, ELYSIUM_TYPE_METADEX_CANCEL_ECOSYSTEM, ecosystem, 0, false);
            return txid.GetHex();
        }
    }
}


UniValue elysium_sendchangeissuer(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 3)
        throw runtime_error(
            "elysium_sendchangeissuer \"fromaddress\" \"toaddress\" propertyid\n"

            "\nChange the issuer on record of the given tokens.\n"

            "\nArguments:\n"
            "1. fromaddress          (string, required) the address associated with the tokens\n"
            "2. toaddress            (string, required) the address to transfer administrative control to\n"
            "3. propertyid           (number, required) the identifier of the tokens\n"

            "\nResult:\n"
            "\"hash\"                  (string) the hex-encoded transaction hash\n"

            "\nExamples:\n"
            + HelpExampleCli("elysium_sendchangeissuer", "\"1ARjWDkZ7kT9fwjPrjcQyvbXDkEySzKHwu\" \"3HTHRxu3aSDV4deakjC7VmsiUp7c6dfbvs\" 3")
            + HelpExampleRpc("elysium_sendchangeissuer", "\"1ARjWDkZ7kT9fwjPrjcQyvbXDkEySzKHwu\", \"3HTHRxu3aSDV4deakjC7VmsiUp7c6dfbvs\", 3")
        );

    // obtain parameters & info
    std::string fromAddress = ParseAddress(request.params[0]);
    std::string toAddress = ParseAddress(request.params[1]);
    uint32_t propertyId = ParsePropertyId(request.params[2]);

    // perform checks
    RequireExistingProperty(propertyId);
    RequireTokenIssuer(fromAddress, propertyId);

    // create a payload for the transaction
    std::vector<unsigned char> payload = CreatePayload_ChangeIssuer(propertyId);

    // request the wallet build the transaction (and if needed commit it)
    uint256 txid;
    std::string rawHex;
    int result = WalletTxBuilder(fromAddress, toAddress, "", 0, payload, txid, rawHex, autoCommit);

    // check error and return the txid (or raw hex depending on autocommit)
    if (result != 0) {
        throw JSONRPCError(result, error_str(result));
    } else {
        if (!autoCommit) {
            return rawHex;
        } else {
            return txid.GetHex();
        }
    }
}


UniValue elysium_sendenablefreezing(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2)
        throw runtime_error(
            "elysium_sendenablefreezing \"fromaddress\" propertyid\n"

            "\nEnables address freezing for a centrally managed property.\n"

            "\nArguments:\n"
            "1. fromaddress          (string,  required) the issuer of the tokens\n"
            "2. propertyid           (number,  required) the identifier of the tokens\n"

            "\nResult:\n"
            "\"hash\"                  (string) the hex-encoded transaction hash\n"

            "\nExamples:\n"
            + HelpExampleCli("elysium_sendenablefreezing", "\"3HTHRxu3aSDV4deakjC7VmsiUp7c6dfbvs\" 3")
            + HelpExampleRpc("elysium_sendenablefreezing", "\"3HTHRxu3aSDV4deakjC7VmsiUp7c6dfbvs\", 3")
        );

    // obtain parameters & info
    std::string fromAddress = ParseAddress(request.params[0]);
    uint32_t propertyId = ParsePropertyId(request.params[1]);

    // perform checks
    RequireExistingProperty(propertyId);
    RequireManagedProperty(propertyId);
    RequireTokenIssuer(fromAddress, propertyId);

    // create a payload for the transaction
    std::vector<unsigned char> payload = CreatePayload_EnableFreezing(propertyId);

    // request the wallet build the transaction (and if needed commit it)
    uint256 txid;
    std::string rawHex;
    int result = WalletTxBuilder(fromAddress, "", "", 0, payload, txid, rawHex, autoCommit);

    // check error and return the txid (or raw hex depending on autocommit)
    if (result != 0) {
        throw JSONRPCError(result, error_str(result));
    } else {
        if (!autoCommit) {
            return rawHex;
        } else {
            return txid.GetHex();
        }
    }
}


UniValue elysium_senddisablefreezing(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2)
        throw runtime_error(
            "elysium_senddisablefreezing \"fromaddress\" propertyid\n"

            "\nDisables address freezing for a centrally managed property.\n"
            "\nIMPORTANT NOTE:  Disabling freezing for a property will UNFREEZE all frozen addresses for that property!"

            "\nArguments:\n"
            "1. fromaddress          (string,  required) the issuer of the tokens\n"
            "2. propertyid           (number,  required) the identifier of the tokens\n"

            "\nResult:\n"
            "\"hash\"                  (string) the hex-encoded transaction hash\n"

            "\nExamples:\n"
            + HelpExampleCli("elysium_senddisablefreezing", "\"3HTHRxu3aSDV4deakjC7VmsiUp7c6dfbvs\" 3")
            + HelpExampleRpc("elysium_senddisablefreezing", "\"3HTHRxu3aSDV4deakjC7VmsiUp7c6dfbvs\", 3")
        );

    // obtain parameters & info
    std::string fromAddress = ParseAddress(request.params[0]);
    uint32_t propertyId = ParsePropertyId(request.params[1]);

    // perform checks
    RequireExistingProperty(propertyId);
    RequireManagedProperty(propertyId);
    RequireTokenIssuer(fromAddress, propertyId);

    // create a payload for the transaction
    std::vector<unsigned char> payload = CreatePayload_DisableFreezing(propertyId);

    // request the wallet build the transaction (and if needed commit it)
    uint256 txid;
    std::string rawHex;
    int result = WalletTxBuilder(fromAddress, "", "", 0, payload, txid, rawHex, autoCommit);

    // check error and return the txid (or raw hex depending on autocommit)
    if (result != 0) {
        throw JSONRPCError(result, error_str(result));
    } else {
        if (!autoCommit) {
            return rawHex;
        } else {
            return txid.GetHex();
        }
    }
}


UniValue elysium_sendfreeze(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 4)
        throw runtime_error(
            "elysium_sendfreeze \"fromaddress\" \"toaddress\" propertyid amount \n"
            "\nFreeze an address for a centrally managed token.\n"
            "\nNote: Only the issuer may freeze tokens, and only if the token is of the managed type with the freezing option enabled.\n"
            "\nArguments:\n"
            "1. fromaddress          (string, required) the address to send from (must be the issuer of the property)\n"
            "2. toaddress            (string, required) the address to freeze tokens for\n"
            "3. propertyid           (number, required) the property to freeze tokens for (must be managed type and have freezing option enabled)\n"
            "4. amount               (number, required) the amount of tokens to freeze (note: this is unused - once frozen an address cannot send any transactions for the property)\n"
            "\nResult:\n"
            "\"hash\"                  (string) the hex-encoded transaction hash\n"
            "\nExamples:\n"
            + HelpExampleCli("elysium_sendfreeze", "\"1EXoDusjGwvnjZUyKkxZ4UHEf77z6A5S4P\" \"3HTHRxu3aSDV4deakjC7VmsiUp7c6dfbvs\" 1 0")
            + HelpExampleRpc("elysium_sendfreeze", "\"1EXoDusjGwvnjZUyKkxZ4UHEf77z6A5S4P\", \"3HTHRxu3aSDV4deakjC7VmsiUp7c6dfbvs\", 1, 0")
        );

    // obtain parameters & info
    std::string fromAddress = ParseAddress(request.params[0]);
    std::string refAddress = ParseAddress(request.params[1]);
    uint32_t propertyId = ParsePropertyId(request.params[2]);
    int64_t amount = ParseAmount(request.params[3], isPropertyDivisible(propertyId));

    // perform checks
    RequireExistingProperty(propertyId);
    RequireManagedProperty(propertyId);
    RequireTokenIssuer(fromAddress, propertyId);

    // create a payload for the transaction
    std::vector<unsigned char> payload = CreatePayload_FreezeTokens(propertyId, amount, refAddress);

    // request the wallet build the transaction (and if needed commit it)
    // Note: no ref address is sent to WalletTxBuilder as the ref address is contained within the payload
    uint256 txid;
    std::string rawHex;
    int result = WalletTxBuilder(fromAddress, "", "", 0, payload, txid, rawHex, autoCommit);

    // check error and return the txid (or raw hex depending on autocommit)
    if (result != 0) {
        throw JSONRPCError(result, error_str(result));
    } else {
        if (!autoCommit) {
            return rawHex;
        } else {
            return txid.GetHex();
        }
    }
}


UniValue elysium_sendunfreeze(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 4)
        throw runtime_error(
            "elysium_sendunfreeze \"fromaddress\" \"toaddress\" propertyid amount \n"
            "\nUnfreezes an address for a centrally managed token.\n"
            "\nNote: Only the issuer may unfreeze tokens.\n"
            "\nArguments:\n"
            "1. fromaddress          (string, required) the address to send from (must be the issuer of the property)\n"
            "2. toaddress            (string, required) the address to unfreeze tokens for\n"
            "3. propertyid           (number, required) the property to unfreeze tokens for (must be managed type and have freezing option enabled)\n"
            "4. amount               (number, required) the amount of tokens to unfreeze (note: this is unused - once frozen an address cannot send any transactions for the property)\n"
            "\nResult:\n"
            "\"hash\"                  (string) the hex-encoded transaction hash\n"
            "\nExamples:\n"
            + HelpExampleCli("elysium_sendunfreeze", "\"1EXoDusjGwvnjZUyKkxZ4UHEf77z6A5S4P\" \"3HTHRxu3aSDV4deakjC7VmsiUp7c6dfbvs\" 1 0")
            + HelpExampleRpc("elysium_sendunfreeze", "\"1EXoDusjGwvnjZUyKkxZ4UHEf77z6A5S4P\", \"3HTHRxu3aSDV4deakjC7VmsiUp7c6dfbvs\", 1, 0")
        );

    // obtain parameters & info
    std::string fromAddress = ParseAddress(request.params[0]);
    std::string refAddress = ParseAddress(request.params[1]);
    uint32_t propertyId = ParsePropertyId(request.params[2]);
    int64_t amount = ParseAmount(request.params[3], isPropertyDivisible(propertyId));

    // perform checks
    RequireExistingProperty(propertyId);
    RequireManagedProperty(propertyId);
    RequireTokenIssuer(fromAddress, propertyId);

    // create a payload for the transaction
    std::vector<unsigned char> payload = CreatePayload_UnfreezeTokens(propertyId, amount, refAddress);

    // request the wallet build the transaction (and if needed commit it)
    // Note: no ref address is sent to WalletTxBuilder as the ref address is contained within the payload
    uint256 txid;
    std::string rawHex;
    int result = WalletTxBuilder(fromAddress, "", "", 0, payload, txid, rawHex, autoCommit);

    // check error and return the txid (or raw hex depending on autocommit)
    if (result != 0) {
        throw JSONRPCError(result, error_str(result));
    } else {
        if (!autoCommit) {
            return rawHex;
        } else {
            return txid.GetHex();
        }
    }
}


UniValue elysium_sendactivation(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 4)
        throw runtime_error(
            "elysium_sendactivation \"fromaddress\" featureid block minclientversion\n"
            "\nActivate a protocol feature.\n"
            "\nNote: Elysium Core ignores activations from unauthorized sources.\n"
            "\nArguments:\n"
            "1. fromaddress          (string, required) the address to send from\n"
            "2. featureid            (number, required) the identifier of the feature to activate\n"
            "3. block                (number, required) the activation block\n"
            "4. minclientversion     (number, required) the minimum supported client version\n"
            "\nResult:\n"
            "\"hash\"                  (string) the hex-encoded transaction hash\n"
            "\nExamples:\n"
            + HelpExampleCli("elysium_sendactivation", "\"1EXoDusjGwvnjZUyKkxZ4UHEf77z6A5S4P\" 1 370000 999")
            + HelpExampleRpc("elysium_sendactivation", "\"1EXoDusjGwvnjZUyKkxZ4UHEf77z6A5S4P\", 1, 370000, 999")
        );

    // obtain parameters & info
    std::string fromAddress = ParseAddress(request.params[0]);
    uint16_t featureId = request.params[1].get_int();
    uint32_t activationBlock = request.params[2].get_int();
    uint32_t minClientVersion = request.params[3].get_int();

    // create a payload for the transaction
    std::vector<unsigned char> payload = CreatePayload_ActivateFeature(featureId, activationBlock, minClientVersion);

    // request the wallet build the transaction (and if needed commit it)
    uint256 txid;
    std::string rawHex;
    int result = WalletTxBuilder(fromAddress, "", "", 0, payload, txid, rawHex, autoCommit);

    // check error and return the txid (or raw hex depending on autocommit)
    if (result != 0) {
        throw JSONRPCError(result, error_str(result));
    } else {
        if (!autoCommit) {
            return rawHex;
        } else {
            return txid.GetHex();
        }
    }
}


UniValue elysium_senddeactivation(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 2)
        throw runtime_error(
            "elysium_senddeactivation \"fromaddress\" featureid\n"
            "\nDeactivate a protocol feature.  For Emergency Use Only.\n"
            "\nNote: Elysium Core ignores deactivations from unauthorized sources.\n"
            "\nArguments:\n"
            "1. fromaddress          (string, required) the address to send from\n"
            "2. featureid            (number, required) the identifier of the feature to activate\n"
            "\nResult:\n"
            "\"hash\"                  (string) the hex-encoded transaction hash\n"
            "\nExamples:\n"
            + HelpExampleCli("elysium_senddeactivation", "\"1EXoDusjGwvnjZUyKkxZ4UHEf77z6A5S4P\" 1")
            + HelpExampleRpc("elysium_senddeactivation", "\"1EXoDusjGwvnjZUyKkxZ4UHEf77z6A5S4P\", 1")
        );

    // obtain parameters & info
    std::string fromAddress = ParseAddress(request.params[0]);
    uint16_t featureId = request.params[1].get_int64();

    // create a payload for the transaction
    std::vector<unsigned char> payload = CreatePayload_DeactivateFeature(featureId);

    // request the wallet build the transaction (and if needed commit it)
    uint256 txid;
    std::string rawHex;
    int result = WalletTxBuilder(fromAddress, "", "", 0, payload, txid, rawHex, autoCommit);

    // check error and return the txid (or raw hex depending on autocommit)
    if (result != 0) {
        throw JSONRPCError(result, error_str(result));
    } else {
        if (!autoCommit) {
            return rawHex;
        } else {
            return txid.GetHex();
        }
    }
}


UniValue elysium_sendalert(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 4)
        throw runtime_error(
            "elysium_sendalert \"fromaddress\" alerttype expiryvalue typecheck versioncheck \"message\"\n"
            "\nCreates and broadcasts an Elysium Core alert.\n"
            "\nNote: Elysium Core ignores alerts from unauthorized sources.\n"
            "\nArguments:\n"
            "1. fromaddress          (string, required) the address to send from\n"
            "2. alerttype            (number, required) the alert type\n"
            "3. expiryvalue          (number, required) the value when the alert expires (depends on alert type)\n"
            "4. message              (string, required) the user-faced alert message\n"
            "\nResult:\n"
            "\"hash\"                  (string) the hex-encoded transaction hash\n"
            "\nExamples:\n"
            + HelpExampleCli("elysium_sendalert", "")
            + HelpExampleRpc("elysium_sendalert", "")
        );

    // obtain parameters & info
    std::string fromAddress = ParseAddress(request.params[0]);
    int64_t tempAlertType = request.params[1].get_int64();
    if (tempAlertType < 1 || 65535 < tempAlertType) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Alert type is out of range");
    }
    uint16_t alertType = static_cast<uint16_t>(tempAlertType);
    int64_t tempExpiryValue = request.params[2].get_int64();
    if (tempExpiryValue < 1 || 4294967295LL < tempExpiryValue) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Expiry value is out of range");
    }
    uint32_t expiryValue = static_cast<uint32_t>(tempExpiryValue);
    std::string alertMessage = ParseText(request.params[3]);

    // create a payload for the transaction
    std::vector<unsigned char> payload = CreatePayload_ElysiumAlert(alertType, expiryValue, alertMessage);

    // request the wallet build the transaction (and if needed commit it)
    uint256 txid;
    std::string rawHex;
    int result = WalletTxBuilder(fromAddress, "", "", 0, payload, txid, rawHex, autoCommit);

    // check error and return the txid (or raw hex depending on autocommit)
    if (result != 0) {
        throw JSONRPCError(result, error_str(result));
    } else {
        if (!autoCommit) {
            return rawHex;
        } else {
            return txid.GetHex();
        }
    }
}


UniValue elysium_sendcreatedenomination(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() != 3) {
        throw std::runtime_error(
            "elysium_sendcreatedenomination \"fromaddress\" propertyid \"value\"\n"
            "\nCreate a new denomination for the given property.\n"
            "\nArguments:\n"
            "1. fromaddress          (string, required) the address to send from\n"
            "2. propertyid           (number, required) the property to create a new denomination\n"
            "3. value                (string, required) the value of denomination to create\n"
            "\nResult:\n"
            "\"hash\"                  (string) the hex-encoded transaction hash\n"
            "\nExamples:\n"
            + HelpExampleCli("elysium_sendcreatedenomination", "\"3M9qvHKtgARhqcMtM5cRT9VaiDJ5PSfQGY\" 1 \"100.0\"")
            + HelpExampleRpc("elysium_sendcreatedenomination", "\"3M9qvHKtgARhqcMtM5cRT9VaiDJ5PSfQGY\", 1, \"100.0\"")
        );
    }

    // obtain parameters & info
    std::string fromAddress = ParseAddress(request.params[0]);
    uint32_t propertyId = ParsePropertyId(request.params[1]);
    int64_t value = ParseAmount(request.params[2], isPropertyDivisible(propertyId));

    // perform checks
    RequireExistingProperty(propertyId);
    RequireTokenIssuer(fromAddress, propertyId);
    RequireSigma(propertyId);

    {
        LOCK(cs_main);

        CMPSPInfo::Entry info;
        assert(_my_sps->getSP(propertyId, info));

        if (info.denominations.size() >= MAX_DENOMINATIONS) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "No more room for new denomination");
        }

        if (std::find(info.denominations.begin(), info.denominations.end(), value) != info.denominations.end()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "Denomination with value " + FormatMP(propertyId, value) + " already exists");
        }
    }

    // create a payload for the transaction
    std::vector<unsigned char> payload = CreatePayload_CreateDenomination(propertyId, value);

    // request the wallet build the transaction (and if needed commit it)
    uint256 txid;
    std::string rawHex;
    int result = WalletTxBuilder(fromAddress, "", "", 0, payload, txid, rawHex, autoCommit);

    // check error and return the txid (or raw hex depending on autocommit)
    if (result != 0) {
        throw JSONRPCError(result, error_str(result));
    } else {
        if (!autoCommit) {
            return rawHex;
        } else {
            return txid.GetHex();
        }
    }
}


UniValue elysium_sendmint(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 3 || request.params.size() > 4) {
        throw std::runtime_error(
            "elysium_sendmint \"fromaddress\" propertyid {\"denomination\":amount,...} ( denomminconf )\n"
            "\nCreate mints.\n"
            "\nArguments:\n"
            "1. fromaddress                  (string, required) the address to send from\n"
            "2. propertyid                   (number, required) the property to create mints\n"
            "3. denominations                (string, required) A json object with denomination and amount\n"
            "    {\n"
            "      denomination:amount       (number) The denomination id, the amount of mints\n"
            "      ,...\n"
            "    }\n"
            "4. denomminconf                 (number, optional, default=6) Allow only denominations with at least this many confirmations\n"
            "\nResult:\n"
            "\"hash\"                          (string) the hex-encoded transaction hash\n"
            "\nExamples:\n"
            + HelpExampleCli("elysium_sendmint", "\"3M9qvHKtgARhqcMtM5cRT9VaiDJ5PSfQGY\" 1 \"{\"0\":1, \"1\":2}\"")
            + HelpExampleRpc("elysium_sendmint", "\"3M9qvHKtgARhqcMtM5cRT9VaiDJ5PSfQGY\", 1, \"{\"0\":1, \"1\":2}\"")
        );
    }

    // obtain parameters & info
    std::string fromAddress = ParseAddress(request.params[0]);
    uint32_t propertyId = ParsePropertyId(request.params[1]);
    UniValue denominations = request.params[2].get_obj();
    int minConfirms = 6;
    if (request.params.size() > 3) {
        minConfirms = request.params[3].get_int();
    }

    // perform checks
    RequireExistingProperty(propertyId);
    RequireSigma(propertyId);
    auto keys = denominations.getKeys();

    // collect all mints need to be created
    std::vector<SigmaDenomination> denoms;
    for (const auto& denom : keys) {
        auto denomId = std::stoul(denom);
        if (denomId > UINT8_MAX) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid denomination");
        }

        auto amount = denominations[denom].get_int();
        if (amount < 0 || amount > UINT8_MAX) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "invalid amount of mints");
        }

        denoms.insert(denoms.end(), static_cast<unsigned>(amount), static_cast<SigmaDenomination>(denomId));

        int remainingConfirms;
        try {
            LOCK(cs_main);
            remainingConfirms = _my_sps->getDenominationRemainingConfirmation(propertyId, denomId, minConfirms);
        } catch (std::invalid_argument const &e) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, e.what());
        }

        if (remainingConfirms) {
            throw JSONRPCError(RPC_INVALID_PARAMETER,
                "confirmations of the denomination is less than required");
        }
    }

    int64_t amount;
    try {
        amount = SumDenominationsValue(propertyId, denoms.begin(), denoms.end());
    } catch (std::invalid_argument const &e) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, e.what());
    } catch (std::overflow_error const &e) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, e.what());
    }

    RequireBalance(fromAddress, propertyId, amount);

    // Create mints.
    std::vector<SigmaMintId> ids;
    std::vector<std::pair<SigmaDenomination, SigmaPublicKey>> mints;
    uint256 txid;
    std::string rawHex;

    ids.reserve(denoms.size());
    mints.reserve(denoms.size());

    try {
        try {
            wallet->CreateSigmaMints(propertyId, denoms.begin(), denoms.end(), boost::make_function_output_iterator([&] (const SigmaMintId& m) {
                ids.push_back(m);
                mints.push_back(std::make_pair(m.denomination, m.pubKey));
            }));
        } catch (WalletLocked const &e) {
            throw JSONRPCError(RPC_WALLET_ERROR, e.what());
        }

        // Create transaction.
        auto payload = CreatePayload_SimpleMint(propertyId, mints);
        auto result = WalletTxBuilder(fromAddress, "", "", 0, payload, txid, rawHex, autoCommit);

        if (result != 0) {
            throw JSONRPCError(result, error_str(result));
        }
    } catch (...) {
        for (auto& id : ids) {
            wallet->DeleteUnconfirmedSigmaMint(id);
        }
        throw;
    }

    // Assign transaction ID.
    for (auto& id : ids) {
        wallet->SetSigmaMintCreatedTransaction(id, txid);
    }

    if (!autoCommit) {
        return rawHex;
    } else {
        PendingAdd(txid, fromAddress, ELYSIUM_TYPE_SIMPLE_MINT, propertyId, amount);
        return txid.GetHex();
    }
}


UniValue elysium_sendspend(const JSONRPCRequest& request)
{
    if (request.fHelp || request.params.size() < 3 || request.params.size() > 4) {
        throw std::runtime_error(
            "elysium_sendspend \"toaddress\" propertyid denomination ( \"referenceamount\" )\n"
            "\nCreate spend.\n"
            "\nArguments:\n"
            "1. toaddress                    (string, required) the address to spend to\n"
            "2. propertyid                   (number, required) the property to spend\n"
            "3. denomination                 (number, required) the id of the denomination need to spend\n"
            "4. referenceamount              (string, optional) a zcoin amount that is sent to the receiver (minimal by default)\n"
            "\nResult:\n"
            "\"hash\"                          (string) the hex-encoded transaction hash\n"
            "\nExamples:\n"
            + HelpExampleCli("elysium_sendspend", "\"3M9qvHKtgARhqcMtM5cRT9VaiDJ5PSfQGY\" 1 1")
            + HelpExampleRpc("elysium_sendspend", "\"3M9qvHKtgARhqcMtM5cRT9VaiDJ5PSfQGY\", 1, 1")
        );
    }

    // obtain parameters & info
    auto toAddress = ParseAddress(request.params[0]);
    auto propertyId = ParsePropertyId(request.params[1]);
    auto denomination = ParseSigmaDenomination(request.params[2]);
    auto referenceAmount = (request.params.size() > 3) ? ParseAmount(request.params[3], true): 0;

    // perform checks
    RequireExistingProperty(propertyId);
    RequireExistingDenomination(propertyId, denomination);
    RequireSaneReferenceAmount(referenceAmount);
    RequireSigmaSpendV1Feature();

    // create spend
    SigmaMintId mint;
    std::vector<unsigned char> payload;

    // calculate reference amount
    CBitcoinAddress address(toAddress);
    if (referenceAmount <= 0) {
        CScript scriptPubKey = GetScriptForDestination(CBitcoinAddress(address).Get());
        referenceAmount = GetDustThreshold(scriptPubKey);
    }

    try {

        bool fPadding = true;

        auto spend = wallet->CreateSigmaSpendV1(propertyId, denomination, fPadding);
        auto key = wallet->GetSigmaSignatureKey(spend.mint);
        auto pubkey = key.GetPubKey();

        SigmaV1SignatureBuilder sigBuilder(address, referenceAmount, spend.proof);
        auto signature = sigBuilder.Sign(key);

        if (!sigBuilder.Verify(pubkey, signature)) {
            throw JSONRPCError(RPC_WALLET_ERROR, "Fail to create valid signature to spend.");
        }

        mint = spend.mint;
        payload = CreatePayload_SimpleSpend(
            mint.property,
            mint.denomination,
            spend.group,
            spend.groupSize,
            spend.proof,
            signature,
            pubkey);

    } catch (InsufficientFunds& e) {
        throw JSONRPCError(RPC_WALLET_INSUFFICIENT_FUNDS, e.what());
    } catch (WalletError &e) {
        throw JSONRPCError(RPC_WALLET_ERROR, e.what());
    }

    // request the wallet build the transaction (and if needed commit it)
    uint256 txid;
    std::string rawHex;
    int result = WalletTxBuilder(
        "",
        toAddress,
        "",
        referenceAmount,
        payload,
        txid,
        rawHex,
        autoCommit,
        InputMode::SIGMA
    );

    // check error and return the txid (or raw hex depending on autocommit)
    if (result != 0) {
        throw JSONRPCError(result, error_str(result));
    } else {
        // mark the coin as used
        wallet->SetSigmaMintUsedTransaction(mint, txid);

        if (!autoCommit) {
            return rawHex;
        } else {
            PendingAdd(
                txid,
                "Spend",
                ELYSIUM_TYPE_SIMPLE_SPEND,
                propertyId,
                GetDenominationValue(mint.property, mint.denomination),
                false,
                toAddress);
            return txid.GetHex();
        }
    }
}

static const CRPCCommand commands[] =
{ //  category                             name                            actor (function)               okSafeMode
  //  ------------------------------------ ------------------------------- ------------------------------ ----------
    { "elysium (transaction creation)",  "elysium_sendrawtx",                 &elysium_sendrawtx,                  false },
    { "elysium (transaction creation)",  "elysium_send",                      &elysium_send,                       false },
    { "hidden",                          "elysium_senddexsell",               &elysium_senddexsell,                false },
    { "hidden",                          "elysium_senddexaccept",             &elysium_senddexaccept,              false },
    { "hidden",                          "elysium_sendissuancecrowdsale",     &elysium_sendissuancecrowdsale,      false },
    { "elysium (transaction creation)",  "elysium_sendissuancefixed",         &elysium_sendissuancefixed,          false },
    { "elysium (transaction creation)",  "elysium_sendissuancemanaged",       &elysium_sendissuancemanaged,        false },
    { "elysium (transaction creation)",  "elysium_sendtrade",                 &elysium_sendtrade,                  false },
    { "elysium (transaction creation)",  "elysium_sendcanceltradesbyprice",   &elysium_sendcanceltradesbyprice,    false },
    { "elysium (transaction creation)",  "elysium_sendcanceltradesbypair",    &elysium_sendcanceltradesbypair,     false },
    { "elysium (transaction creation)",  "elysium_sendcancelalltrades",       &elysium_sendcancelalltrades,        false },
    { "elysium (transaction creation)",  "elysium_sendsto",                   &elysium_sendsto,                    false },
    { "elysium (transaction creation)",  "elysium_sendgrant",                 &elysium_sendgrant,                  false },
    { "elysium (transaction creation)",  "elysium_sendrevoke",                &elysium_sendrevoke,                 false },
    { "hidden",                          "elysium_sendclosecrowdsale",        &elysium_sendclosecrowdsale,         false },
    { "elysium (transaction creation)",  "elysium_sendchangeissuer",          &elysium_sendchangeissuer,           false },
    { "hidden",                          "elysium_sendall",                   &elysium_sendall,                    false },
    { "hidden",                          "elysium_sendenablefreezing",        &elysium_sendenablefreezing,         false },
    { "hidden",                          "elysium_senddisablefreezing",       &elysium_senddisablefreezing,        false },
    { "hidden",                          "elysium_sendfreeze",                &elysium_sendfreeze,                 false },
    { "hidden",                          "elysium_sendunfreeze",              &elysium_sendunfreeze,               false },
    { "hidden",                          "elysium_senddeactivation",          &elysium_senddeactivation,           true  },
    { "hidden",                          "elysium_sendactivation",            &elysium_sendactivation,             false },
    { "hidden",                          "elysium_sendalert",                 &elysium_sendalert,                  true  },
    { "elysium (transaction creation)",  "elysium_sendcreatedenomination",    &elysium_sendcreatedenomination,     false },
    { "elysium (transaction creation)",  "elysium_sendmint",                  &elysium_sendmint,                   false },
    { "elysium (transaction creation)",  "elysium_sendspend",                 &elysium_sendspend,                  false },

    /* depreciated: */
    { "hidden",                          "sendrawtx_MP",                      &elysium_sendrawtx,                  false },
    { "hidden",                          "send_MP",                           &elysium_send,                       false },
    { "hidden",                          "sendtoowners_MP",                   &elysium_sendsto,                    false },
    { "hidden",                          "trade_MP",                          &trade_MP,                           false },
};

void RegisterElysiumTransactionCreationRPCCommands(CRPCTable &tableRPC)
{
    for (unsigned int vcidx = 0; vcidx < ARRAYLEN(commands); vcidx++)
        tableRPC.appendCommand(commands[vcidx].name, &commands[vcidx]);
}
