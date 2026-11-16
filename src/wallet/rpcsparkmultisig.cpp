// Copyright (c) 2026 The Firo Core Developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "rpcsparkmultisig.h"

#include "base58.h"
#include "core_io.h"
#include "init.h"
#include "libspark/multisig.h"
#include "rpc/server.h"
#include "spark/sparkwallet.h"
#include "spark/state.h"
#include "utilstrencodings.h"
#include "validation.h"
#include "wallet.h"
#include "walletdb.h"
#include "rpcwallet.h"

#include <algorithm>
#include <set>

// Spark multisig follows the shape of transparent multisig. The cosigners exchange
// public keys and each of them runs addsparkmultisigaddress, which here takes three
// passes because they generate the spend key together and each keeps a share of it.
// Unless one signer is enough, the key itself never exists in one place.
// A spend is created by anyone, passed among the signers, who each approve it with
// approvesparkmultisigspend and then sign it with signsparkmultisigspend, until it is
// complete, and sent with sendrawtransaction.

namespace {

// What a participant establishes about a spend from its own wallet
struct CSparkMultisigSpendInfo {
    spark::SpendTransaction spend{spark::Params::get_default()};
    std::vector<Scalar> serials; //!< of the coins it spends
    CAmount fee = 0;
    UniValue inputs{UniValue::VARR};
    UniValue outputs{UniValue::VARR};
    UniValue transparentOutputs{UniValue::VARR};
};

// A nonce a signer has committed to. Nonces are kept in memory only: one that came
// back after a restart or from a restored backup could sign again. Each signature
// share from the same nonce pair is one more linear equation in the pair and the
// key share, so a third one gives the key share away.
struct CSparkMultisigNonce {
    spark::MultisigNonce nonce;
    Scalar statement; //!< what it was issued for: all that the proof's challenge covers
};
// ponytail: the nonce of a spend that is never signed stays here until restart;
// evict the oldest if a signer ever abandons enough spends for that to matter.
CCriticalSection cs_multisigNonces;
std::map<uint256, CSparkMultisigNonce> mapMultisigNonces; // by hash of the commitment

const spark::MultisigKey& GetMultisigKey(CWallet* pwallet)
{
    EnsureSparkWalletIsAvailable();
    const spark::MultisigKey* key = pwallet->sparkWallet->getMultisigKey();
    if (!key) {
        throw JSONRPCError(RPC_WALLET_ERROR, "This is not a Spark multisig wallet. Set one up with addsparkmultisigaddress.");
    }
    return *key;
}

CPubKey GetParticipantPubKey(const GroupElement& participant)
{
    return CPubKey(spark::MultisigKey::serialize_participant(participant));
}

Scalar GetParticipantSecret(CWallet* pwallet, const CPubKey& pubkey)
{
    EnsureWalletIsUnlocked(pwallet);
    CKey key;
    if (!pwallet->GetKey(pubkey.GetID(), key)) {
        throw JSONRPCError(RPC_WALLET_ERROR, "The private key of this wallet's multisig participant key is not available");
    }
    Scalar secret;
    secret.deserialize(key.begin());
    return secret;
}

std::string EncodeSpend(const spark::MultisigKey& key, const CSparkMultisigSpend& spend)
{
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << spend;
    return HexStr(key.seal(spark::Params::get_default(), stream));
}

CSparkMultisigSpend DecodeSpend(const spark::MultisigKey& key, const UniValue& value)
{
    const std::string& hex = value.get_str();
    if (!IsHex(hex)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Spark multisig spend must be a hex string");
    }

    CSparkMultisigSpend spend;
    try {
        CDataStream stream = key.open(spark::Params::get_default(), ParseHex(hex));
        stream >> spend;
        if (!stream.empty()) {
            throw std::invalid_argument("trailing data");
        }
    } catch (const std::exception&) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Not a Spark multisig spend of this wallet's group");
    }

    // A spend has at most one nonce commitment and one signature share from each of
    // its signers. Anyone who can seal a spend can add entries, so they are counted
    // before anything works through them.
    const auto fSigners = [&key](const auto& entries) {
        std::set<uint32_t> seen;
        return entries.size() <= key.threshold && std::all_of(entries.begin(), entries.end(), [&](const auto& entry) {
            return entry.index >= 1 && entry.index <= key.participants.size() && seen.insert(entry.index).second;
        });
    };
    if (!fSigners(spend.commitments) || !fSigners(spend.shares)) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, "Invalid Spark multisig spend: more signers than the spend takes, or unknown ones");
    }
    return spend;
}

template <typename T>
void SortByIndex(std::vector<T>& entries)
{
    std::sort(entries.begin(), entries.end(), [](const T& left, const T& right) { return left.index < right.index; });
}

template <typename T>
bool HasIndex(const std::vector<T>& entries, uint32_t index)
{
    return std::any_of(entries.begin(), entries.end(), [index](const T& entry) { return entry.index == index; });
}

/**
 * Check a spend against this wallet and prepare it for signing: its inputs are coins
 * of the wallet, its private outputs are the ones it describes, and the amounts
 * balance. The signatures bind to the spend through its binding hash, which this
 * computes from the transaction itself. Only the cover set hash is taken as given: a
 * wrong one cannot redirect a signature, it can only yield an invalid transaction.
 */
CSparkMultisigSpendInfo CheckSpend(CWallet* pwallet, const spark::MultisigKey& key, const CSparkMultisigSpend& package)
{
    const spark::Params* params = spark::Params::get_default();
    const CTransaction tx(package.tx);
    CSparkMultisigSpendInfo info;

    try {
        if (!tx.IsSparkSpendV2()) {
            throw std::invalid_argument("not a Spark V2 spend");
        }
        // The input the wallet gives its own spends. The signatures cover these
        // fields, and nothing shows them to a signer: a sequence below the maximum
        // would make the lock time of the transaction a real time lock.
        if (tx.vin.size() != 1 || !tx.vin[0].prevout.IsNull() || tx.vin[0].nSequence != CTxIn::SEQUENCE_FINAL ||
            tx.vin[0].scriptSig != (CScript() << OP_SPARKSPEND) || tx.HasWitness()) {
            throw std::invalid_argument("unexpected input");
        }
        info.spend = spark::ParseSparkSpend(tx);
        if (!info.spend.getExtensionCommitment().IsNull()) {
            throw std::invalid_argument("unexpected extension");
        }
        if (info.spend.getFee() > static_cast<uint64_t>(MAX_MONEY)) {
            throw std::invalid_argument("fee out of range");
        }
        info.fee = info.spend.getFee();

        // Outputs
        std::vector<spark::Coin> coins;
        CAmount transparentValue = 0;
        for (const CTxOut& out : tx.vout) {
            const CScript& script = out.scriptPubKey;
            if (script.IsSparkSMint()) {
                coins.emplace_back(params);
                spark::ParseSparkMintCoin(script, coins.back());
            } else if (script.IsSparkMint() || script.IsLelantusMint() || script.IsLelantusJMint() || script.IsSigmaMint()) {
                throw std::invalid_argument("unexpected output type");
            } else {
                if (!MoneyRange(out.nValue) || !MoneyRange(transparentValue + out.nValue)) {
                    throw std::invalid_argument("output value out of range");
                }
                transparentValue += out.nValue;

                UniValue entry(UniValue::VOBJ);
                CTxDestination destination;
                if (ExtractDestination(script, destination)) {
                    entry.push_back(Pair("address", CBitcoinAddress(destination).ToString()));
                } else {
                    entry.push_back(Pair("script", HexStr(script.begin(), script.end())));
                }
                entry.push_back(Pair("amount", ValueFromAmount(out.nValue)));
                info.transparentOutputs.push_back(entry);
            }
        }

        if (coins.size() != package.outputs.size()) {
            throw std::invalid_argument("outputs are not all described");
        }
        const std::vector<unsigned char> serialContext = spark::getSerialContext(tx);
        CAmount privateValue = 0;
        std::set<std::vector<unsigned char>> serialCommitments;
        for (std::size_t j = 0; j < coins.size(); ++j) {
            // Whoever creates a spend chooses the nonces of its outputs. Two outputs
            // to one address with one nonce are different coins with the same serial
            // number: each matches its description, and only one can ever be spent.
            if (!serialCommitments.insert(coins[j].S.getvch()).second) {
                throw std::invalid_argument("two outputs share a serial number, so that only one of them could be spent");
            }
            const CSparkMultisigOutput& output = package.outputs[j];
            spark::Address address(params);
            if (address.decode(output.address) != spark::GetNetworkType()) {
                throw std::invalid_argument("output address of another network");
            }
            if (output.amount > static_cast<uint64_t>(MAX_MONEY) || !MoneyRange(privateValue + static_cast<CAmount>(output.amount))) {
                throw std::invalid_argument("output value out of range");
            }
            if (spark::Coin(params, spark::COIN_TYPE_SPEND, output.nonce, address, output.amount, output.memo, serialContext) != coins[j]) {
                throw std::invalid_argument("an output does not match its description");
            }
            privateValue += output.amount;

            UniValue entry(UniValue::VOBJ);
            entry.push_back(Pair("address", output.address));
            entry.push_back(Pair("amount", ValueFromAmount(output.amount)));
            entry.push_back(Pair("memo", output.memo));
            entry.push_back(Pair("ismine", pwallet->sparkWallet->isAddressMine(address)));
            info.outputs.push_back(entry);
        }

        // The binding hash covers the transparent part of the transaction through
        // this hash, which every cover set representation ends with
        CMutableTransaction metadata(tx);
        metadata.vExtraPayload.clear();
        metadata.vout.erase(
            std::remove_if(metadata.vout.begin(), metadata.vout.end(), [](const CTxOut& out) { return out.scriptPubKey.IsSparkSMint(); }),
            metadata.vout.end());
        const uint256 metadataHash = metadata.GetHash();

        const std::map<uint64_t, uint256>& blockHashes = info.spend.getBlockHashes();
        std::unordered_map<uint64_t, spark::CoverSetData> coverSets;
        for (const auto& entry : package.coverSets) {
            const std::vector<unsigned char>& representation = entry.second.second;
            if (!blockHashes.count(entry.first) ||
                representation.size() < metadataHash.size() ||
                !std::equal(metadataHash.begin(), metadataHash.end(), representation.end() - metadataHash.size())) {
                throw std::invalid_argument("cover set data of another transaction");
            }
            coverSets[entry.first] = {static_cast<std::size_t>(entry.second.first), representation};
        }
        if (coverSets.size() != blockHashes.size()) {
            throw std::invalid_argument("missing cover set data");
        }
        info.spend.setOutCoins(coins);
        info.spend.setCoverSets(coverSets);
        info.spend.setVout(transparentValue);

        // Inputs
        const spark::FullViewKey fullViewKey = key.get_full_view_key(params);
        const std::unordered_map<uint256, CSparkMintMeta> mints = pwallet->sparkWallet->getMintMap();
        const std::vector<GroupElement>& tags = info.spend.getUsedLTags();
        const std::vector<GroupElement>& offsets = info.spend.getS1();
        const GroupElement& D = fullViewKey.get_D();
        if (offsets.size() != tags.size()) {
            throw std::invalid_argument("bad input");
        }
        CAmount inputValue = 0;
        for (std::size_t u = 0; u < tags.size(); ++u) {
            const GroupElement& tag = tags[u];
            const uint256 tagHash = primitives::GetLTagHash(tag);
            const auto mint = mints.find(tagHash);
            if (mint == mints.end()) {
                throw std::invalid_argument("an input is not a coin this wallet knows; make sure the wallet is synchronized");
            }
            const CSparkMintMeta& meta = mint->second;
            spark::Coin coin = meta.coin;
            const spark::RecoveredCoinData recovered = coin.recover(fullViewKey, {meta.i, meta.d, meta.v, meta.k, meta.memo});
            // The serial commitment offset is the one the wallet derives for this coin.
            // With another mask the proof could still be completed, and the
            // transaction would show which coin it spends.
            if (recovered.T != tag || !MoneyRange(inputValue + static_cast<CAmount>(meta.v)) ||
                params->get_F()*recovered.s + params->get_H().inverse()*spark::SparkUtils::hash_ser1(recovered.s, D) + D != offsets[u]) {
                throw std::invalid_argument("bad input");
            }
            info.serials.emplace_back(recovered.s);
            inputValue += meta.v;

            UniValue entry(UniValue::VOBJ);
            entry.push_back(Pair("lTagHash", tagHash.GetHex()));
            entry.push_back(Pair("amount", ValueFromAmount(meta.v)));
            info.inputs.push_back(entry);
        }

        if (inputValue != privateValue + transparentValue + info.fee) {
            throw std::invalid_argument("amounts do not balance");
        }

        // A signature share exists only once all signers are known, and can then be
        // checked. One that does not verify could never complete the spend, and would
        // be reported as a signature until then.
        if (!package.shares.empty()) {
            const spark::MultisigSession session(params, key, info.spend.getBindingHash(), info.spend.getChaumContext(), offsets, tags, package.commitments);
            for (const spark::MultisigShare& share : package.shares) {
                if (!session.verify(share)) {
                    throw std::invalid_argument("bad signature share from participant " + std::to_string(share.index));
                }
            }
        }
    } catch (const std::exception& e) {
        throw JSONRPCError(RPC_DESERIALIZATION_ERROR, std::string("Invalid Spark multisig spend: ") + e.what());
    }
    return info;
}

// What a call asks this wallet to do with a spend. A signer approves a spend and later
// signs it, and says which of the two it means. What a spend already carries never
// decides it: a signer handed another transaction in place of the one it approved
// would otherwise approve and sign that one in a single call.
enum class SpendAction {
    Combine, //!< nothing that takes the wallet's key
    Approve, //!< commit to nonces for the spend
    Sign,    //!< add the signature share to a spend this wallet approved
};

/**
 * Take a spend one step further: add this wallet's nonce commitment or its signature
 * share if asked to, and complete the transaction once every signer has signed.
 * @return hex of the complete transaction, or of the spend to pass on
 */
UniValue AdvanceSpend(CWallet* pwallet, const spark::MultisigKey& key, CSparkMultisigSpend& package, SpendAction action)
{
    const spark::Params* params = spark::Params::get_default();
    if (package.commitments.size() > key.threshold) {
        throw JSONRPCError(RPC_WALLET_ERROR, strprintf("More participants approved this spend than the %u it takes. Combine the spends of exactly that many signers.", key.threshold));
    }
    CSparkMultisigSpendInfo info = CheckSpend(pwallet, key, package);

    // Record where the outputs go, as the wallet does for its own spends. Only the
    // spend tells: the chain shows the wallet neither the recipient nor the amount
    // of an output to someone else. It comes first, and all of it or nothing, so that
    // the wallet does not sign or complete a spend whose recipients it failed to keep.
    // ponytail: the record of a spend that is never sent stays in the wallet file;
    // erase it with the abandoned spend if such records ever add up.
    std::vector<std::pair<CScript, CSparkOutputTx>> records;
    for (const CTxOut& out : package.tx.vout) {
        if (out.scriptPubKey.IsSparkSMint()) {
            const CSparkMultisigOutput& output = package.outputs.at(records.size());
            CSparkOutputTx record;
            record.address = output.address;
            record.amount = output.amount;
            record.memo = output.memo;
            records.emplace_back(out.scriptPubKey, record);
        }
    }
    if (!pwallet->WriteSparkOutputTxs(records)) {
        throw JSONRPCError(RPC_DATABASE_ERROR, "Unable to save the recipients of this spend");
    }

    const Scalar mu = info.spend.getBindingHash();
    const spark::ChaumV2Context context = info.spend.getChaumContext();
    const std::vector<GroupElement>& S = info.spend.getS1();
    const std::vector<GroupElement>& T = info.spend.getUsedLTags();
    const Scalar statement = spark::MultisigSession::statement_hash(params, mu, context, S, T);

    bool fComplete = false;
    CTransactionRef signedTx;
    try {
        if (action != SpendAction::Combine) {
            if (info.fee > maxTxFee) {
                throw JSONRPCError(RPC_WALLET_ERROR, "The fee of this spend exceeds the maximum set with -maxtxfee");
            }
            const Scalar secret = GetParticipantSecret(pwallet, GetParticipantPubKey(key.participants.at(key.index - 1)));
            const auto commitment = std::find_if(package.commitments.begin(), package.commitments.end(), [&key](const spark::MultisigCommitment& entry) {
                return entry.index == key.index;
            });

            if (action == SpendAction::Approve) {
                // Commit to a fresh nonce for each input
                if (commitment != package.commitments.end()) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "This wallet has approved this spend already");
                }
                if (package.commitments.size() == key.threshold) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "This spend already has its signers and this wallet is not among them");
                }
                CSparkMultisigNonce entry;
                entry.statement = statement;
                package.commitments.emplace_back(spark::MultisigSession::commit(params, key.index, S.size(), secret, entry.nonce));
                {
                    LOCK(cs_multisigNonces);
                    mapMultisigNonces[SerializeHash(package.commitments.back())] = entry;
                }
                SortByIndex(package.commitments);
            } else {
                // Sign, once the signers are known, what this wallet approved
                if (commitment == package.commitments.end()) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "This wallet has not approved this spend. Check what it pays with decodesparkmultisigspend, then approve it with approvesparkmultisigspend.");
                }
                if (package.commitments.size() < key.threshold) {
                    throw JSONRPCError(RPC_WALLET_ERROR, strprintf("This spend needs %u more to approve it before it can be signed", key.threshold - static_cast<uint32_t>(package.commitments.size())));
                }
                if (HasIndex(package.shares, key.index)) {
                    throw JSONRPCError(RPC_WALLET_ERROR, "This wallet has signed this spend already");
                }
                const spark::MultisigSession session(params, key, mu, context, S, T, package.commitments);

                // The nonce leaves memory before a signature share exists, so that
                // nothing that goes wrong from here on can make it sign twice. Handed
                // back with another transaction it stays, for the one it was made for:
                // no signature came of it, and whoever can seal a spend would
                // otherwise be able to end the signing of any other.
                CSparkMultisigNonce entry;
                {
                    LOCK(cs_multisigNonces);
                    const auto nonce = mapMultisigNonces.find(SerializeHash(*commitment));
                    if (nonce == mapMultisigNonces.end()) {
                        throw JSONRPCError(RPC_WALLET_ERROR, "This wallet no longer holds the nonce it committed to for this spend: it has signed already or was restarted. Start over with a new spend.");
                    }
                    if (nonce->second.statement != statement) {
                        throw JSONRPCError(RPC_WALLET_ERROR, "The transaction changed after this wallet approved it");
                    }
                    entry = nonce->second;
                    mapMultisigNonces.erase(nonce);
                }
                package.shares.emplace_back(session.sign(secret, entry.nonce));
                SortByIndex(package.shares);
            }
        }

        if (package.commitments.size() == key.threshold && package.shares.size() == key.threshold) {
            const spark::MultisigSession session(params, key, mu, context, S, T, package.commitments);
            info.spend.setChaumProof(session.combine(info.serials, package.shares));

            CDataStream serialized(SER_NETWORK, PROTOCOL_VERSION);
            serialized << info.spend;
            CMutableTransaction tx(package.tx);
            tx.vExtraPayload.assign(serialized.begin(), serialized.end());
            signedTx = MakeTransactionRef(std::move(tx));
            fComplete = true;
        }
    } catch (const std::exception& e) {
        throw JSONRPCError(RPC_WALLET_ERROR, e.what());
    }

    if (fComplete) {
        // The check of the Spark proofs that the mempool makes, so that complete
        // means authorized. Whether its coins are still unspent, the mempool decides.
        LOCK(cs_main);
        CValidationState state;
        if (!spark::CheckSparkTransaction(*signedTx, state, signedTx->GetHash(), false, INT_MAX, false, true, nullptr)) {
            throw JSONRPCError(RPC_VERIFY_REJECTED, "The signed transaction is not valid: " + state.GetRejectReason());
        }
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("hex", fComplete ? EncodeHexTx(*signedTx) : EncodeSpend(key, package)));
    result.push_back(Pair("complete", fComplete));
    result.push_back(Pair("id", package.GetBodyHash().GetHex()));
    return result;
}

} // namespace

UniValue addsparkmultisigaddress(const JSONRPCRequest& request)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() < 2 || request.params.size() > 3) {
        throw std::runtime_error(
            "addsparkmultisigaddress nrequired [\"key\",...] ( [\"data\",...] )\n"
            "\nTurn this wallet into a Spark multisig wallet that it shares with the holders of the other keys.\n"
            "All Spark addresses of the wallet then belong to the group: every participant sees their coins,\n"
            "and spending takes nrequired participants (see createsparkmultisigspend).\n"
            "\nEvery participant makes the same call three times, each time passing on the data of its result:\n"
            "  1. Without data. The result is the participant's data for round one.\n"
            "  2. With the round one data of every other participant. The result is its data for round two.\n"
            "  3. With the round two data of every other participant. The result is the group's address.\n"
            "The calls keep no state and can be repeated, also after the setup: a participant that lost its\n"
            "wallet but still has its key can go through the three calls again with the others' data. The\n"
            "data is safe to send over any channel: what it holds in secret is encrypted to the participant\n"
            "keys. The keys themselves must be authentic, so exchange them the way you would for any\n"
            "multisig address.\n"
            "\nBefore the address receives funds, the participants confirm that all of them completed the\n"
            "third call and obtained the same address. The address depends on all the data they exchanged,\n"
            "so participants with the same address hold shares of the same key.\n"
            "\nThe wallet must not hold Spark coins yet. Its transparent keys and funds are not affected. The\n"
            "third call stops the server; restart it to use the multisig wallet.\n"
            + HelpRequiringPassphrase(pwallet) + "\n"
            "\nArguments:\n"
            "1. nrequired        (numeric, required) The number of participants needed to spend. With 1, every\n"
            "                    participant holds the whole spend key.\n"
            "2. \"keys\"           (string, required) A json array of the hex-encoded compressed public keys of all\n"
            "                    participants, in any order. Exactly one must belong to this wallet: take it from\n"
            "                    getnewaddress and validateaddress.\n"
            "     [\n"
            "       \"key\"        (string) public key\n"
            "       ,...\n"
            "     ]\n"
            "3. \"data\"           (string, optional) A json array with the latest data of the other participants.\n"
            "                    The wallet's own data may be included and is ignored.\n"
            "     [\n"
            "       \"hex\"        (string) data from another participant's call\n"
            "       ,...\n"
            "     ]\n"
            "\nResult:\n"
            "{\n"
            "  \"complete\" : true|false, (boolean) Whether the wallet is the multisig wallet\n"
            "  \"hex\" : \"value\",         (string) This participant's data, for all other participants. Not given\n"
            "                             by the call that completes the setup, nor by a locked wallet.\n"
            "  \"address\" : \"value\",     (string) Once complete: the group's default Spark address\n"
            "  \"warning\" : \"value\"      (string) From the call that completes the setup: what to do next\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("addsparkmultisigaddress", "2 \"[\\\"02c6...\\\",\\\"03a1...\\\",\\\"02f9...\\\"]\"")
            + HelpExampleCli("addsparkmultisigaddress", "2 \"[\\\"02c6...\\\",\\\"03a1...\\\",\\\"02f9...\\\"]\" \"[\\\"01...\\\",\\\"01...\\\"]\"")
            + HelpExampleRpc("addsparkmultisigaddress", "2, [\"02c6...\",\"03a1...\",\"02f9...\"]"));
    }

    EnsureSparkWalletIsAvailable();
    const spark::Params* params = spark::Params::get_default();

    const int nRequired = request.params[0].get_int();
    const UniValue& keys = request.params[1].get_array();
    std::vector<GroupElement> participants;
    std::vector<CPubKey> own;
    for (std::size_t i = 0; i < keys.size(); ++i) {
        const std::string& hex = keys[i].get_str();
        const CPubKey pubkey(ParseHex(hex));
        if (!IsHex(hex) || !pubkey.IsFullyValid() || !pubkey.IsCompressed()) {
            throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Invalid compressed public key: " + hex);
        }
        participants.emplace_back(spark::MultisigKey::parse_participant(std::vector<unsigned char>(pubkey.begin(), pubkey.end())));
        if (pwallet->HaveKey(pubkey.GetID())) {
            own.emplace_back(pubkey);
        }
    }
    if (own.size() != 1) {
        throw JSONRPCError(RPC_INVALID_ADDRESS_OR_KEY, "Exactly one of the keys must belong to this wallet");
    }
    if (nRequired < 1 || static_cast<std::size_t>(nRequired) > participants.size()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "nrequired must be between 1 and the number of keys");
    }

    UniValue result(UniValue::VOBJ);

    // Once set up, the call answers with the address. It keeps producing this
    // participant's data too, which another participant needs to repeat the setup
    // after losing its wallet.
    const spark::MultisigKey* existing = pwallet->sparkWallet->getMultisigKey();
    if (existing) {
        bool fSame = existing->threshold == static_cast<uint32_t>(nRequired) && existing->participants.size() == participants.size();
        for (const GroupElement& participant : participants) {
            fSame = fSame && std::find(existing->participants.begin(), existing->participants.end(), participant) != existing->participants.end();
        }
        if (!fSame) {
            throw JSONRPCError(RPC_WALLET_ERROR, "This wallet already is a Spark multisig wallet, with other parameters");
        }
        result.push_back(Pair("complete", true));
        result.push_back(Pair("address", pwallet->sparkWallet->getDefaultAddress().encode(spark::GetNetworkType())));
        if (pwallet->IsLocked()) {
            return result;
        }
    } else if (!pwallet->sparkWallet->getMintMap().empty()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "This wallet holds Spark coins, which it would lose sight of. Set up Spark multisig in a new wallet.");
    }

    const Scalar secret = GetParticipantSecret(pwallet, own[0]);
    std::optional<spark::MultisigKey> key;
    try {
        const spark::MultisigKeygen keygen(params, nRequired, participants, secret);

        // The latest message of every other participant
        std::vector<spark::MultisigKeygenMessage> messages;
        if (request.params.size() > 2) {
            const UniValue& data = request.params[2].get_array();
            for (std::size_t i = 0; i < data.size(); ++i) {
                const std::string& hex = data[i].get_str();
                if (!IsHex(hex)) {
                    throw std::invalid_argument("Data must be hex strings");
                }
                CDataStream stream(ParseHex(hex), SER_NETWORK, PROTOCOL_VERSION);
                spark::MultisigKeygenMessage message;
                stream >> message;
                if (!stream.empty()) {
                    throw std::invalid_argument("Trailing bytes in data");
                }
                if (message.key == keygen.get_participants()[keygen.get_index() - 1]) {
                    continue; // this wallet makes its own
                }
                const auto known = std::find_if(messages.begin(), messages.end(), [&message](const spark::MultisigKeygenMessage& other) {
                    return other.key == message.key;
                });
                if (known == messages.end()) {
                    messages.emplace_back(message);
                } else if (known->shares.empty()) {
                    *known = message;
                }
            }
        }

        spark::MultisigKeygenMessage message = keygen.round1();
        if (messages.size() + 1 == participants.size()) {
            messages.emplace_back(message);
            message = keygen.round2(messages);
            messages.back() = message;
            if (existing) {
                // Whoever repeats the setup has to arrive at the key this wallet
                // holds a share of. Round one data that adds up to other commitments
                // would leave it with a share of another key.
                std::vector<GroupElement> commitments(existing->commitments.size());
                for (const spark::MultisigKeygenMessage& other : messages) {
                    for (std::size_t j = 0; j < commitments.size(); ++j) {
                        commitments[j] += other.C.at(j);
                    }
                }
                if (commitments != existing->commitments) {
                    throw std::invalid_argument("This is not the round one data the wallet's group was set up with");
                }
            }
            if (!existing && std::none_of(messages.begin(), messages.end(), [](const spark::MultisigKeygenMessage& other) { return other.shares.empty(); })) {
                key = keygen.finalize(messages);
            }
        } else if (!messages.empty()) {
            throw std::invalid_argument("Expected data from every other participant");
        }

        if (!key) {
            CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
            stream << message;
            if (!existing) {
                result.push_back(Pair("complete", false));
            }
            result.push_back(Pair("hex", HexStr(stream.begin(), stream.end())));
            return result;
        }
    } catch (const std::exception& e) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, e.what());
    }

    // The Spark wallet uses one immutable key set until restart. Drain earlier
    // scans, then check under cs_main that no new scans were queued while waiting.
    // A second final setup call in the same RPC batch must also see the saved key.
    // Once the keys are saved the running wallet stops using the ones it has: the
    // node stops, but not before another call or the next block can arrive.
    bool fSaved = false;
    for (int attempt = 0; attempt < 3 && !fSaved; ++attempt) {
        uint64_t generation;
        {
            LOCK(cs_main);
            generation = pwallet->sparkWallet->GetMintWorkGeneration();
        }
        pwallet->sparkWallet->WaitForPendingTasks();
        {
            LOCK2(cs_main, pwallet->cs_wallet);
            if (pwallet->sparkWallet->GetMintWorkGeneration() != generation)
                continue;

            CWalletDB walletdb(pwallet->strWalletFile);
            spark::MultisigKey savedKey;
            if (walletdb.ReadSparkMultisigKey(savedKey))
                throw JSONRPCError(RPC_WALLET_ERROR, "This wallet already completed Spark multisig setup. Restart it to use the saved group.");
            if (!pwallet->sparkWallet->getMintMap().empty())
                throw JSONRPCError(RPC_WALLET_ERROR, "This wallet holds Spark coins, which it would lose sight of. Set up Spark multisig in a new wallet.");

            fSaved = walletdb.TxnBegin();
            if (fSaved) {
                fSaved = walletdb.WriteSparkMultisigKey(*key) &&
                    walletdb.writeFullViewKey(key->get_full_view_key(params)) &&
                    walletdb.writeDiversifier(0);
                // Old single-signer receive addresses must not remain in the GUI
                // or its saved receive requests after this wallet changes keys.
                for (const auto& address : pwallet->mapSparkAddressBook) {
                    if (!fSaved)
                        break;
                    if (!pwallet->sparkWallet->isAddressMine(address.first))
                        continue;
                    fSaved = walletdb.WritePurpose(address.first, "retired");
                    for (const auto& item : address.second.destdata) {
                        if (fSaved && item.first.rfind("rr", 0) == 0)
                            fSaved = walletdb.EraseDestData(address.first, item.first);
                    }
                }
                if (fSaved)
                    fSaved = walletdb.TxnCommit();
                else
                    walletdb.TxnAbort();
            }
            if (!fSaved)
                throw JSONRPCError(RPC_DATABASE_ERROR, "Unable to save the Spark multisig key");
            pwallet->sparkWallet->SetKeysReplaced();
            StartShutdown();
        }
    }
    if (!fSaved)
        throw JSONRPCError(RPC_WALLET_ERROR, "Spark wallet received new coins during setup. Retry after it finishes scanning.");

    result.push_back(Pair("complete", true));
    result.push_back(Pair("address", spark::Address(spark::IncomingViewKey(key->get_full_view_key(params)), 0).encode(spark::GetNetworkType())));
    result.push_back(Pair("warning", "Firo server stopping. Restart it to use the Spark multisig wallet. Before the address receives funds, confirm that every participant completed the setup and obtained this address."));
    return result;
}

UniValue createsparkmultisigspend(const JSONRPCRequest& request)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            "createsparkmultisigspend {\"address\":{amount,subtractfee...}, \"address\":{amount,memo,subtractfee...}}\n"
            "\nCreate a spend from this Spark multisig wallet for its participants to sign.\n"
            "The recipients are given as for spendspark. Any participant can create a spend; it takes\n"
            "no key, so the wallet may stay locked. The result goes to approvesparkmultisigspend.\n"
            "\nArguments:\n"
            "1. recipients       (string, required) A json object with addresses and amounts\n"
            "{\n"
            "  \"address\":amount (numeric or string), memo (string,only for private, not required), subtractfee (bool) The Firo or Spark address is the key, the numeric amount (can be string) in " + CURRENCY_UNIT + " is the value\n"
            "  ,...\n"
            "}\n"
            "\nResult:\n"
            "{\n"
            "  \"hex\" : \"value\",   (string) The unsigned spend, encrypted to the participants of the wallet\n"
            "  \"fee\" : n,         (numeric) The fee the transaction pays, in " + CURRENCY_UNIT + "\n"
            "  \"id\" : \"hex\"       (string) Names this spend in the results of all the calls it goes through\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("createsparkmultisigspend", "\"{\\\"TR1FW48J6ozpRu25U8giSDdTrdXXUYau7U\\\":{\\\"amount\\\":0.01, \\\"subtractFee\\\": false}}\"")
            + HelpExampleRpc("createsparkmultisigspend", "{\"TR1FW48J6ozpRu25U8giSDdTrdXXUYau7U\":{\"amount\":0.01, \"subtractFee\": false}}"));
    }

    const spark::MultisigKey& key = GetMultisigKey(pwallet);
    if (!spark::IsSparkAllowed()) {
        throw JSONRPCError(RPC_WALLET_ERROR, "Spark is not activated yet");
    }

    std::vector<CRecipient> recipients;
    std::vector<std::pair<spark::OutputCoinData, bool>> privateRecipients;
    ParseSparkSpendRecipients(request.params[0], recipients, privateRecipients);

    CAmount fee = 0;
    CSparkMultisigDraft draft;
    CSparkMultisigSpend spend;
    try {
        const CWalletTx wtx = pwallet->sparkWallet->CreateSparkSpendTransaction(
            recipients, privateRecipients, fee, nullptr, 0, uint256(), -1, nullptr, &draft);
        spend.tx = CMutableTransaction(*wtx.tx);
    } catch (const std::exception& e) {
        throw JSONRPCError(RPC_WALLET_ERROR, e.what());
    }

    for (const auto& entry : draft.coverSets) {
        spend.coverSets[entry.first] = {entry.second.cover_set_size, entry.second.cover_set_representation};
    }
    for (std::size_t j = 0; j < draft.outputs.size(); ++j) {
        CSparkMultisigOutput output;
        output.address = draft.outputs[j].address.encode(spark::GetNetworkType());
        output.amount = draft.outputs[j].v;
        output.memo = draft.outputs[j].memo;
        output.nonce = draft.outputNonces.at(j);
        spend.outputs.emplace_back(output);
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("hex", EncodeSpend(key, spend)));
    result.push_back(Pair("fee", ValueFromAmount(fee)));
    result.push_back(Pair("id", spend.GetBodyHash().GetHex()));
    return result;
}

UniValue approvesparkmultisigspend(const JSONRPCRequest& request)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            "approvesparkmultisigspend \"hexstring\"\n"
            "\nApprove a spend of this Spark multisig wallet: commit the wallet to signing it. Check what the\n"
            "spend pays first, with decodesparkmultisigspend. The first nrequired participants to approve a\n"
            "spend are its signers.\n"
            "\nApproving does not sign. Once the spend has its signers, each of them adds its signature with\n"
            "signsparkmultisigspend, which signs nothing but what this call approved. A wallet that is\n"
            "restarted after approving cannot sign that spend any more; create the spend again in that case,\n"
            "and also to replace a signer.\n"
            + HelpRequiringPassphrase(pwallet) + "\n"
            "\nArguments:\n"
            "1. \"hexstring\"      (string, required) The spend, from createsparkmultisigspend or another signer\n"
            "\nResult:\n"
            "{\n"
            "  \"hex\" : \"value\",          (string) The spend to pass on\n"
            "  \"complete\" : false,       (boolean) Approving never completes a spend\n"
            "  \"id\" : \"hex\"              (string) Names the spend, as in the result of createsparkmultisigspend\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("approvesparkmultisigspend", "\"hexstring\"")
            + HelpExampleRpc("approvesparkmultisigspend", "\"hexstring\""));
    }

    const spark::MultisigKey& key = GetMultisigKey(pwallet);
    CSparkMultisigSpend spend = DecodeSpend(key, request.params[0]);
    return AdvanceSpend(pwallet, key, spend, SpendAction::Approve);
}

UniValue signsparkmultisigspend(const JSONRPCRequest& request)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            "signsparkmultisigspend \"hexstring\"\n"
            "\nSign a spend of this Spark multisig wallet and return it, as signrawtransaction does for a\n"
            "transparent multisig transaction. Pass the result to the next signer until it is complete, then\n"
            "send the transaction with sendrawtransaction.\n"
            "\nA spend takes exactly nrequired signers, and each of them takes two steps:\n"
            "  1. approvesparkmultisigspend commits the wallet to the spend. The first nrequired\n"
            "     participants to do so are its signers.\n"
            "  2. signsparkmultisigspend, once all signers have approved, adds the wallet's signature share.\n"
            "With 2 signers the spend goes A (approve), B (approve, then sign), A (sign). Signers working in\n"
            "parallel merge their results with combinesparkmultisigspend between the steps.\n"
            "\nThe call signs only a spend that this wallet approved, and fails for any other and for one that\n"
            "changed since: a signer that is handed another transaction in place of the one it approved does\n"
            "not sign it. The id in the results tells the spends apart.\n"
            + HelpRequiringPassphrase(pwallet) + "\n"
            "\nArguments:\n"
            "1. \"hexstring\"      (string, required) The spend, from approvesparkmultisigspend or another signer\n"
            "\nResult:\n"
            "{\n"
            "  \"hex\" : \"value\",          (string) The spend to pass on, or once complete the hex-encoded transaction\n"
            "  \"complete\" : true|false,  (boolean) Whether the transaction is fully signed and ready to send\n"
            "  \"id\" : \"hex\"              (string) Names the spend, as in the result of createsparkmultisigspend\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("signsparkmultisigspend", "\"hexstring\"")
            + HelpExampleRpc("signsparkmultisigspend", "\"hexstring\""));
    }

    const spark::MultisigKey& key = GetMultisigKey(pwallet);
    CSparkMultisigSpend spend = DecodeSpend(key, request.params[0]);
    return AdvanceSpend(pwallet, key, spend, SpendAction::Sign);
}

UniValue combinesparkmultisigspend(const JSONRPCRequest& request)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            "combinesparkmultisigspend [\"hexstring\",...]\n"
            "\nMerge copies of one Spark multisig spend that different participants have approved or signed.\n"
            "Signers who work in parallel use this after approvesparkmultisigspend and again after\n"
            "signsparkmultisigspend. Any participant can combine; it takes no key.\n"
            "\nLike those two, the call records in the wallet where the outputs of the spend go. A participant\n"
            "that does not sign a spend passes its copy here, at any stage, for the wallet's transaction\n"
            "history to show the recipients. The chain alone does not tell them.\n"
            "\nArguments:\n"
            "1. \"txs\"            (string, required) A json array of results of approvesparkmultisigspend or\n"
            "                    signsparkmultisigspend\n"
            "     [\n"
            "       \"hexstring\"  (string) A spend\n"
            "       ,...\n"
            "     ]\n"
            "\nResult:\n"
            "{\n"
            "  \"hex\" : \"value\",          (string) The merged spend, or once complete the hex-encoded transaction\n"
            "  \"complete\" : true|false,  (boolean) Whether the transaction is fully signed and ready to send\n"
            "  \"id\" : \"hex\"              (string) Names the spend, as in the result of createsparkmultisigspend\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("combinesparkmultisigspend", "\"[\\\"hexstring\\\",\\\"hexstring\\\"]\"")
            + HelpExampleRpc("combinesparkmultisigspend", "[\"hexstring\",\"hexstring\"]"));
    }

    const spark::MultisigKey& key = GetMultisigKey(pwallet);
    const UniValue& txs = request.params[0].get_array();
    if (txs.empty()) {
        throw JSONRPCError(RPC_INVALID_PARAMETER, "Expected at least one spend");
    }

    CSparkMultisigSpend spend = DecodeSpend(key, txs[0]);
    for (std::size_t i = 1; i < txs.size(); ++i) {
        const CSparkMultisigSpend other = DecodeSpend(key, txs[i]);
        if (other.GetBodyHash() != spend.GetBodyHash()) {
            throw JSONRPCError(RPC_INVALID_PARAMETER, "The spends are not copies of one transaction");
        }
        for (const spark::MultisigCommitment& commitment : other.commitments) {
            const auto known = std::find_if(spend.commitments.begin(), spend.commitments.end(), [&commitment](const spark::MultisigCommitment& entry) {
                return entry.index == commitment.index;
            });
            if (known == spend.commitments.end()) {
                spend.commitments.emplace_back(commitment);
            } else if (SerializeHash(*known) != SerializeHash(commitment)) {
                throw JSONRPCError(RPC_INVALID_PARAMETER, strprintf("Participant %u committed differently in two of the spends", commitment.index));
            }
        }
        for (const spark::MultisigShare& share : other.shares) {
            if (!HasIndex(spend.shares, share.index)) {
                spend.shares.emplace_back(share);
            }
        }
    }
    SortByIndex(spend.commitments);
    SortByIndex(spend.shares);

    return AdvanceSpend(pwallet, key, spend, SpendAction::Combine);
}

UniValue decodesparkmultisigspend(const JSONRPCRequest& request)
{
    CWallet* const pwallet = GetWalletForJSONRPCRequest(request);
    if (!EnsureWalletIsAvailable(pwallet, request.fHelp)) {
        return NullUniValue;
    }

    if (request.fHelp || request.params.size() != 1) {
        throw std::runtime_error(
            "decodesparkmultisigspend \"hexstring\"\n"
            "\nShow what a spend of this Spark multisig wallet does, for a signer to review before approving.\n"
            "Everything shown is checked against the transaction and this wallet's own records: the inputs\n"
            "are coins of the wallet, the outputs pay exactly what is listed, and the signatures are those\n"
            "of the signers they are listed for.\n"
            "\nArguments:\n"
            "1. \"hexstring\"      (string, required) The spend, from createsparkmultisigspend or a signer\n"
            "\nResult:\n"
            "{\n"
            "  \"id\" : \"hex\",               (string) Names the spend. It is the same for every copy of a spend,\n"
            "                              whoever has approved or signed it, and differs for any other spend.\n"
            "  \"fee\" : n,                  (numeric) The fee in " + CURRENCY_UNIT + "\n"
            "  \"inputs\" : [                (array) The coins of the wallet that are spent\n"
            "    { \"lTagHash\" : \"hex\", \"amount\" : n }, ...\n"
            "  ],\n"
            "  \"outputs\" : [               (array) The Spark outputs. Change returns to an address of the wallet.\n"
            "    { \"address\" : \"value\", \"amount\" : n, \"memo\" : \"value\", \"ismine\" : true|false }, ...\n"
            "  ],\n"
            "  \"transparent_outputs\" : [   (array) The transparent outputs\n"
            "    { \"address\" : \"value\", \"amount\" : n }, ...\n"
            "  ],\n"
            "  \"nrequired\" : n,            (numeric) The number of signers the spend takes\n"
            "  \"signers\" : [               (array) The participants that approved the spend so far\n"
            "    { \"key\" : \"hex\", \"signed\" : true|false }, ...\n"
            "  ]\n"
            "}\n"
            "\nExamples:\n"
            + HelpExampleCli("decodesparkmultisigspend", "\"hexstring\"")
            + HelpExampleRpc("decodesparkmultisigspend", "\"hexstring\""));
    }

    const spark::MultisigKey& key = GetMultisigKey(pwallet);
    const CSparkMultisigSpend spend = DecodeSpend(key, request.params[0]);
    const CSparkMultisigSpendInfo info = CheckSpend(pwallet, key, spend);

    UniValue signers(UniValue::VARR);
    for (const spark::MultisigCommitment& commitment : spend.commitments) {
        UniValue signer(UniValue::VOBJ);
        signer.push_back(Pair("key", HexStr(GetParticipantPubKey(key.participants[commitment.index - 1]))));
        signer.push_back(Pair("signed", HasIndex(spend.shares, commitment.index)));
        signers.push_back(signer);
    }

    UniValue result(UniValue::VOBJ);
    result.push_back(Pair("id", spend.GetBodyHash().GetHex()));
    result.push_back(Pair("fee", ValueFromAmount(info.fee)));
    result.push_back(Pair("inputs", info.inputs));
    result.push_back(Pair("outputs", info.outputs));
    result.push_back(Pair("transparent_outputs", info.transparentOutputs));
    result.push_back(Pair("nrequired", static_cast<uint64_t>(key.threshold)));
    result.push_back(Pair("signers", signers));
    return result;
}
