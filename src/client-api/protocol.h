// Copyright (c) 2010 Satoshi Nakamoto
// Copyright (c) 2009-2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef ZCOIN_APIPROTOCOL_H
#define ZCOIN_APIPROTOCOL_H
#include "univalue.h"

#include <list>
#include <map>
#include <stdint.h>
#include <string>
#include <boost/filesystem.hpp>

//! Zcoin client-API error codes
enum APIErrorCode
{
    //! Standard JSON-API 2.0 errors
    API_INVALID_REQUEST  = -32600,
    API_METHOD_NOT_FOUND = -32601,
    API_INVALID_PARAMS   = -32602,
    API_INTERNAL_ERROR   = -32603,
    API_PARSE_ERROR      = -32700,
    
    //! General application defined errors
    API_MISC_ERROR                  = -1,  //!< std::exception thrown in command handling
    API_FORBIDDEN_BY_SAFE_MODE      = -2,  //!< Server is in safe mode, and command is not allowed in safe mode
    API_TYPE_ERROR                  = -3,  //!< Unexpected type was passed as parameter
    API_INVALID_ADDRESS_OR_KEY      = -5,  //!< Invalid address or key
    API_OUT_OF_MEMORY               = -7,  //!< Ran out of memory during operation
    API_INVALID_PARAMETER           = -8,  //!< Invalid, missing or duplicate parameter
    API_DATABASE_ERROR              = -20, //!< Database error
    API_DESERIALIZATION_ERROR       = -22, //!< Error parsing or validating structure in raw format
    API_VERIFY_ERROR                = -25, //!< General error during transaction or block submission
    API_VERIFY_REJECTED             = -26, //!< Transaction or block was rejected by network rules
    API_VERIFY_ALREADY_IN_CHAIN     = -27, //!< Transaction already in chain
    API_IN_WARMUP                   = -28, //!< Client still warming up
    API_NOT_AUTHENTICATED           = -29, //!< Calling thread is not authenticated to request this method
    API_RESPONSE_ERROR              = -30, //!< ZMQ error in forming the response
    API_WRONG_TYPE_CALLED           = -31, //!< wrong type passed for method
    API_TYPE_NOT_IMPLEMENTED        = -32, //!< No implementation of this type for this method

    //! Aliases for backward compatibility
    API_TRANSACTION_ERROR           = API_VERIFY_ERROR,
    API_TRANSACTION_REJECTED        = API_VERIFY_REJECTED,
    API_TRANSACTION_ALREADY_IN_CHAIN= API_VERIFY_ALREADY_IN_CHAIN,

    //! P2P client errors
    API_CLIENT_NOT_CONNECTED        = -9,  //!< Bitcoin is not connected
    API_CLIENT_IN_INITIAL_DOWNLOAD  = -10, //!< Still downloading initial blocks
    API_CLIENT_NODE_ALREADY_ADDED   = -23, //!< Node is already added
    API_CLIENT_NODE_NOT_ADDED       = -24, //!< Node has not been added before
    API_CLIENT_NODE_NOT_CONNECTED   = -29, //!< Node to disconnect not found in connected nodes
    API_CLIENT_INVALID_IP_OR_SUBNET = -30, //!< Invalid IP/Subnet

    //! Wallet errors
    API_WALLET_ERROR                = -4,  //!< Unspecified problem with wallet (key not found etc.)
    API_WALLET_INSUFFICIENT_FUNDS   = -6,  //!< Not enough funds in wallet or account
    API_WALLET_INVALID_ACCOUNT_NAME = -11, //!< Invalid account name
    API_WALLET_KEYPOOL_RAN_OUT      = -12, //!< Keypool ran out, constall keypoolrefill first
    API_WALLET_UNLOCK_NEEDED        = -13, //!< Enter the wallet passphrase with walletpassphrase first
    API_WALLET_PASSPHRASE_INCORRECT = -14, //!< The wallet passphrase entered was incorrect
    API_WALLET_WRONG_ENC_STATE      = -15, //!< Command given in wrong wallet encryption state (encrypting an encrypted wallet etc.)
    API_WALLET_ENCRYPTION_FAILED    = -16, //!< Failed to encrypt the wallet
    API_WALLET_ALREADY_UNLOCKED     = -17, //!< Wallet is already unlocked
};

UniValue JSONAPIReplyObj(const UniValue& result, const UniValue& error);
std::string JSONAPIReply(const UniValue& result, const UniValue& error);
UniValue JSONAPIError(int code, const std::string& message);

#endif //ZCOIN_APIPROTOCOL_H
