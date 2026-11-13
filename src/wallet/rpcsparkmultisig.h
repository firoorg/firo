// Copyright (c) 2026 The Firo Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef FIRO_WALLET_RPCSPARKMULTISIG_H
#define FIRO_WALLET_RPCSPARKMULTISIG_H

#include "hash.h"
#include "libspark/multisig.h"
#include "primitives/transaction.h"

#include <univalue.h>

class CWallet;
class JSONRPCRequest;

// Spark threshold multisignature wallets (doc/spark-multisig-wallet.md)
UniValue addsparkmultisigaddress(const JSONRPCRequest& request);

/**
 * One pass of the Spark multisig setup: addsparkmultisigaddress without the stop of
 * the node, for the GUI, which shows its user the outcome before it restarts.
 * @param[in] args   The arguments of addsparkmultisigaddress.
 * @param[in] fStore Whether a pass that has everyone's data makes this the multisig
 *                   wallet. If not, the pass reports the address the wallet would get.
 * @return The result of addsparkmultisigaddress. After the pass that stored the keys,
 *         which is the first to return "complete", the caller has to stop the node.
 * @throws UniValue As the RPC does.
 */
UniValue SetupSparkMultisig(CWallet* pwallet, const UniValue& args, bool fStore);
UniValue createsparkmultisigspend(const JSONRPCRequest& request);
UniValue signsparkmultisigspend(const JSONRPCRequest& request);
UniValue combinesparkmultisigspend(const JSONRPCRequest& request);
UniValue decodesparkmultisigspend(const JSONRPCRequest& request);

// One private output of a spend, with the nonce that lets a cosigner rebuild the coin
// and so see that it pays what it claims to pay
struct CSparkMultisigOutput {
    std::string address;
    uint64_t amount = 0;
    std::string memo;
    Scalar nonce;

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        READWRITE(address);
        READWRITE(amount);
        READWRITE(memo);
        READWRITE(nonce);
    }
};

// A Spark spend on its way through its cosigners. It leaves the wallet sealed to the
// group (spark::MultisigKey::seal), because its content shows what is spent and the
// signing transcript would let an outsider link the transaction to the coins it consumes.
struct CSparkMultisigSpend {
    CMutableTransaction tx; //!< the spend, with a placeholder where the authorizing proof goes
    std::map<uint64_t, std::pair<uint64_t, std::vector<unsigned char>>> coverSets; //!< size and representation by id
    std::vector<CSparkMultisigOutput> outputs; //!< the private outputs, in transaction order
    std::vector<spark::MultisigCommitment> commitments; //!< nonce commitments, by signer
    std::vector<spark::MultisigShare> shares; //!< signature shares, by signer

    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action)
    {
        uint8_t version = 1;
        READWRITE(version);
        if (version != 1) {
            throw std::invalid_argument("unsupported version");
        }
        READWRITE(tx);
        READWRITE(coverSets);
        READWRITE(outputs);
        READWRITE(commitments);
        READWRITE(shares);
    }

    // Identifies the transaction, whoever has signed it so far
    uint256 GetBodyHash() const
    {
        CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
        ss << tx << coverSets << outputs;
        return ss.GetHash();
    }
};

#endif // FIRO_WALLET_RPCSPARKMULTISIG_H
