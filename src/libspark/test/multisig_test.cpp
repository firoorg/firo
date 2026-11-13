#include "../multisig.h"
#include "../spend_transaction.h"
#include "../../hash.h"
#include "../../key.h"

#include "../../test/test_bitcoin.h"
#include <boost/test/unit_test.hpp>

namespace spark {

using namespace secp_primitives;

namespace {

struct Participant {
    Scalar secret;
    MultisigKey key;
};

// Run key generation for a new group and return its participants in identifier order
std::vector<Participant> Keygen(const Params* params, std::size_t threshold, std::size_t n)
{
    std::vector<Scalar> secrets(n);
    std::vector<GroupElement> keys;
    for (Scalar& secret : secrets) {
        secret.randomize();
        keys.emplace_back(params->get_G()*secret);
    }

    std::vector<MultisigKeygen> keygens;
    std::vector<MultisigKeygenMessage> round1, round2;
    for (const Scalar& secret : secrets) {
        keygens.emplace_back(params, threshold, keys, secret);
        round1.emplace_back(keygens.back().round1());
    }
    for (const MultisigKeygen& keygen : keygens) {
        round2.emplace_back(keygen.round2(round1));
    }

    std::vector<Participant> group(n);
    for (std::size_t i = 0; i < n; ++i) {
        const MultisigKey key = keygens[i].finalize(round2);
        group[key.index - 1] = {secrets[i], key};
    }
    return group;
}

// The value at zero of the polynomial through the given points
Scalar Interpolate(const std::vector<std::pair<uint64_t, Scalar>>& points)
{
    Scalar result;
    for (std::size_t i = 0; i < points.size(); ++i) {
        Scalar numerator(uint64_t(1)), denominator(uint64_t(1));
        for (std::size_t j = 0; j < points.size(); ++j) {
            if (j != i) {
                numerator *= Scalar(points[j].first);
                denominator *= Scalar(points[j].first) - Scalar(points[i].first);
            }
        }
        result += points[i].second*numerator*denominator.inverse();
    }
    return result;
}

// A statement over `w` coins of the group, as a spend transaction would present it
struct Statement {
    Scalar mu;
    ChaumV2Context context;
    std::vector<Scalar> serials;
    std::vector<GroupElement> S, T;
};

Statement RandomStatement(const Params* params, const MultisigKey& key, std::size_t w)
{
    Statement statement;
    statement.mu.randomize();
    statement.context.fee = 1000;
    statement.context.transparent_value = 7;
    const GroupElement& D = key.commitments[0];
    for (std::size_t u = 0; u < w; ++u) {
        Scalar s;
        s.randomize();
        statement.serials.emplace_back(s);
        statement.S.emplace_back(params->get_F()*s + params->get_H().inverse()*SparkUtils::hash_ser1(s, D) + D);
        statement.T.emplace_back((params->get_U() + D.inverse())*s.inverse());
    }
    return statement;
}

// Have the given signers authorize a statement. `combiner` only needs the view key.
ChaumProofV2 Authorize(
    const Params* params,
    const std::vector<Participant>& group,
    const std::vector<std::size_t>& signers,
    std::size_t combiner,
    const Statement& statement)
{
    std::vector<MultisigNonce> nonces(signers.size());
    std::vector<MultisigCommitment> commitments;
    for (std::size_t i = 0; i < signers.size(); ++i) {
        commitments.emplace_back(MultisigSession::commit(params, signers[i], statement.S.size(), group[signers[i] - 1].secret, nonces[i]));
    }

    std::vector<MultisigShare> shares;
    for (std::size_t i = 0; i < signers.size(); ++i) {
        const Participant& signer = group[signers[i] - 1];
        MultisigSession session(params, signer.key, statement.mu, statement.context, statement.S, statement.T, commitments);
        shares.emplace_back(session.sign(signer.secret, nonces[i]));
    }

    MultisigSession session(params, group[combiner - 1].key, statement.mu, statement.context, statement.S, statement.T, commitments);
    return session.combine(statement.serials, shares);
}

} // namespace

BOOST_FIXTURE_TEST_SUITE(spark_multisig_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(participant_key_encoding)
{
    const Params* params = Params::get_test();

    // A participant key is an ordinary compressed public key
    CKey key;
    key.MakeNewKey(true);
    const CPubKey pubkey = key.GetPubKey();
    const std::vector<unsigned char> compressed(pubkey.begin(), pubkey.end());
    Scalar secret;
    secret.deserialize(key.begin());

    BOOST_CHECK(MultisigKey::parse_participant(compressed) == params->get_G()*secret);
    BOOST_CHECK(MultisigKey::serialize_participant(params->get_G()*secret) == compressed);

    std::vector<unsigned char> bad = compressed;
    bad[0] = 4;
    BOOST_CHECK_THROW(MultisigKey::parse_participant(bad), std::invalid_argument);
    bad = compressed;
    bad.pop_back();
    BOOST_CHECK_THROW(MultisigKey::parse_participant(bad), std::invalid_argument);
    // An x coordinate at or above the field size is not a canonical encoding
    bad.assign(33, 0xff);
    bad[0] = 2;
    BOOST_CHECK_THROW(MultisigKey::parse_participant(bad), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(keygen)
{
    const Params* params = Params::get_test();

    const std::vector<std::pair<std::size_t, std::size_t>> shapes = {{1, 2}, {2, 2}, {2, 3}, {3, 5}};
    for (const auto& shape : shapes) {
        const std::size_t t = shape.first;
        const std::size_t n = shape.second;
        const std::vector<Participant> group = Keygen(params, t, n);

        const GroupElement D = group[0].key.commitments[0];
        std::vector<std::pair<uint64_t, Scalar>> first, last;
        for (std::size_t i = 0; i < n; ++i) {
            const MultisigKey& key = group[i].key;
            BOOST_CHECK_EQUAL(key.index, i + 1);
            BOOST_CHECK_EQUAL(key.threshold, t);

            // Everyone derives the same view key and the same commitments
            BOOST_CHECK(key.s1 == group[0].key.s1);
            BOOST_CHECK(key.s2 == group[0].key.s2);
            BOOST_CHECK(key.commitments == group[0].key.commitments);
            BOOST_CHECK(key.participants == group[0].key.participants);

            const FullViewKey full_view_key = key.get_full_view_key(params);
            BOOST_CHECK(full_view_key.get_D() == D);
            BOOST_CHECK(full_view_key.get_P2() == params->get_F()*key.s2 + D);

            const Scalar share = key.get_share(params, group[i].secret);
            BOOST_CHECK(params->get_G()*share == group[0].key.get_verification_share(i + 1));
            if (i < t) {
                first.emplace_back(i + 1, share);
            }
            if (i >= n - t) {
                last.emplace_back(i + 1, share);
            }

            // Only its own participant key opens a share
            BOOST_CHECK_THROW(key.get_share(params, group[(i + 1) % n].secret), std::invalid_argument);
        }

        // Any threshold of shares interpolates to the spend key
        BOOST_CHECK(params->get_G()*Interpolate(first) == D);
        BOOST_CHECK(params->get_G()*Interpolate(last) == D);
        if (t > 1) {
            first.pop_back();
            BOOST_CHECK(params->get_G()*Interpolate(first) != D);
        }
    }
}

BOOST_AUTO_TEST_CASE(keygen_is_stateless_and_order_independent)
{
    const Params* params = Params::get_test();

    std::vector<Scalar> secrets(3);
    std::vector<GroupElement> keys;
    for (Scalar& secret : secrets) {
        secret.randomize();
        keys.emplace_back(params->get_G()*secret);
    }
    const std::vector<GroupElement> reversed(keys.rbegin(), keys.rend());

    MultisigKeygen keygen(params, 2, keys, secrets[0]);
    MultisigKeygen again(params, 2, reversed, secrets[0]);
    BOOST_CHECK_EQUAL(keygen.get_index(), again.get_index());
    BOOST_CHECK(keygen.get_participants() == again.get_participants());

    const MultisigKeygenMessage first = keygen.round1();
    const MultisigKeygenMessage second = again.round1();
    BOOST_CHECK(first.C == second.C);
    BOOST_CHECK(first.R == second.R);
    BOOST_CHECK(first.mu == second.mu);
    BOOST_CHECK(first.view_commitment == second.view_commitment);

    // Other parameters give unrelated values
    MultisigKeygen other(params, 3, keys, secrets[0]);
    BOOST_CHECK(other.round1().C[0] != first.C[0]);

    BOOST_CHECK_THROW(MultisigKeygen(params, 0, keys, secrets[0]), std::invalid_argument);
    BOOST_CHECK_THROW(MultisigKeygen(params, 4, keys, secrets[0]), std::invalid_argument);
    BOOST_CHECK_THROW(MultisigKeygen(params, 2, {keys[0]}, secrets[0]), std::invalid_argument);
    BOOST_CHECK_THROW(MultisigKeygen(params, 2, {keys[0], keys[1], keys[0]}, secrets[0]), std::invalid_argument);
    Scalar stranger;
    stranger.randomize();
    BOOST_CHECK_THROW(MultisigKeygen(params, 2, keys, stranger), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(keygen_output_is_stable)
{
    // Key generation is deterministic, so what it produces can be pinned. A change of
    // this value is a change of the protocol: participants on different versions
    // could no longer set up a wallet together, nor repeat the setup of an existing one.
    const Params* params = Params::get_test();

    std::vector<Scalar> secrets;
    std::vector<GroupElement> keys;
    for (uint64_t i = 1; i <= 3; ++i) {
        secrets.emplace_back(Scalar(1000 + i));
        keys.emplace_back(params->get_G()*secrets.back());
    }
    std::vector<MultisigKeygen> keygens;
    std::vector<MultisigKeygenMessage> round1, round2;
    for (const Scalar& secret : secrets) {
        keygens.emplace_back(params, 2, keys, secret);
        round1.emplace_back(keygens.back().round1());
    }
    CHashWriter hasher(SER_GETHASH, 0);
    for (const MultisigKeygen& keygen : keygens) {
        round2.emplace_back(keygen.round2(round1));
    }
    hasher << round2;
    for (const MultisigKeygen& keygen : keygens) {
        hasher << keygen.finalize(round2);
    }
    BOOST_CHECK_EQUAL(hasher.GetHash().GetHex(), "d660b368855275fd8c91230c4148ebdb9f7291331531c1845b6fb62e259486ca");
}

BOOST_AUTO_TEST_CASE(constant_time_multiplication)
{
    // Secret scalars are multiplied in constant time. That gives the same points.
    const Params* params = Params::get_test();
    GroupElement point;
    for (int i = 0; i < 20; ++i) {
        Scalar scalar;
        scalar.randomize();
        point.randomize();
        BOOST_CHECK(point.multiplyConstantTime(scalar) == point*scalar);
        BOOST_CHECK(params->get_G().multiplyConstantTime(scalar) == params->get_G()*scalar);
    }

    const Scalar one(uint64_t(1));
    BOOST_CHECK(point.multiplyConstantTime(one) == point);
    BOOST_CHECK(point.multiplyConstantTime(one.negate()) == point.inverse());
    BOOST_CHECK(point.multiplyConstantTime(Scalar()).isInfinity());
    BOOST_CHECK_THROW(GroupElement().multiplyConstantTime(one), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(keygen_rejects_bad_messages)
{
    const Params* params = Params::get_test();

    std::vector<Scalar> secrets(3);
    std::vector<GroupElement> keys;
    for (Scalar& secret : secrets) {
        secret.randomize();
        keys.emplace_back(params->get_G()*secret);
    }
    std::vector<MultisigKeygen> keygens;
    std::vector<MultisigKeygenMessage> round1, round2;
    for (const Scalar& secret : secrets) {
        keygens.emplace_back(params, 2, keys, secret);
        round1.emplace_back(keygens.back().round1());
    }
    for (const MultisigKeygen& keygen : keygens) {
        round2.emplace_back(keygen.round2(round1));
    }
    BOOST_CHECK_NO_THROW(keygens[0].finalize(round2));

    // A missing or repeated participant
    std::vector<MultisigKeygenMessage> bad(round1.begin(), round1.end() - 1);
    BOOST_CHECK_THROW(keygens[0].round2(bad), std::invalid_argument);
    bad.emplace_back(round1[1]);
    BOOST_CHECK_THROW(keygens[0].round2(bad), std::invalid_argument);

    // A proof of knowledge covers the whole message and its sender
    bad = round1;
    bad[1].mu += Scalar(uint64_t(1));
    BOOST_CHECK_THROW(keygens[0].round2(bad), std::invalid_argument);
    bad = round1;
    bad[1].C[1] = bad[1].C[1] + params->get_G();
    BOOST_CHECK_THROW(keygens[0].round2(bad), std::invalid_argument);
    bad = round1;
    bad[1].view_commitment[0] ^= 1;
    BOOST_CHECK_THROW(keygens[0].round2(bad), std::invalid_argument);
    bad = round1;
    std::swap(bad[1].key, bad[2].key);
    BOOST_CHECK_THROW(keygens[0].round2(bad), std::invalid_argument);

    // A forged message under the participant's own key
    bad = round1;
    bad[0] = round1[1];
    bad[0].key = round1[0].key;
    BOOST_CHECK_THROW(keygens[0].round2(bad), std::invalid_argument);

    // Round two data is required from everyone
    bad = round2;
    bad[1].shares.clear();
    BOOST_CHECK_THROW(keygens[0].finalize(bad), std::invalid_argument);

    // A share is bound to its recipient and cannot be altered
    const std::size_t own = keygens[0].get_index() - 1;
    const std::size_t next = (own + 1) % 3;
    bad = round2;
    std::swap(bad[1].shares[own], bad[1].shares[next]);
    BOOST_CHECK_THROW(keygens[0].finalize(bad), std::invalid_argument);
    bad = round2;
    bad[1].shares[own].ciphertext[0] ^= 1;
    BOOST_CHECK_THROW(keygens[0].finalize(bad), std::invalid_argument);

    // Shares the same participant made for another group do not decrypt
    std::vector<Scalar> other_secrets = secrets;
    other_secrets[2].randomize();
    std::vector<GroupElement> other_keys = {keys[0], keys[1], params->get_G()*other_secrets[2]};
    MultisigKeygen other(params, 2, other_keys, secrets[1]);
    bad = round2;
    bad[1].shares = other.round2({
        MultisigKeygen(params, 2, other_keys, other_secrets[0]).round1(),
        other.round1(),
        MultisigKeygen(params, 2, other_keys, other_secrets[2]).round1()}).shares;
    BOOST_CHECK_THROW(keygens[0].finalize(bad), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(threshold_proof)
{
    const Params* params = Params::get_test();
    Chaum chaum(params->get_F(), params->get_G(), params->get_H(), params->get_U());

    const std::vector<Participant> group = Keygen(params, 2, 3);
    for (const std::size_t w : {1, 3}) {
        const Statement statement = RandomStatement(params, group[0].key, w);

        // Every pair of signers produces a valid proof, combined by any participant
        const std::vector<std::vector<std::size_t>> subsets = {{1, 2}, {3, 1}, {2, 3}};
        for (std::size_t i = 0; i < subsets.size(); ++i) {
            const ChaumProofV2 proof = Authorize(params, group, subsets[i], i + 1, statement);
            BOOST_CHECK(chaum.verify_v2(statement.mu, statement.context, statement.S, statement.T, proof));

            // The proof is bound to the transaction
            Scalar other_mu;
            other_mu.randomize();
            BOOST_CHECK(!chaum.verify_v2(other_mu, statement.context, statement.S, statement.T, proof));
            ChaumV2Context other_context = statement.context;
            other_context.fee += 1;
            BOOST_CHECK(!chaum.verify_v2(statement.mu, other_context, statement.S, statement.T, proof));
        }
    }
}

BOOST_AUTO_TEST_CASE(threshold_proof_rejects_misuse)
{
    const Params* params = Params::get_test();

    const std::vector<Participant> group = Keygen(params, 2, 3);
    const std::size_t w = 2;
    const Statement statement = RandomStatement(params, group[0].key, w);

    std::vector<MultisigNonce> nonces(3);
    std::vector<MultisigCommitment> all;
    for (std::size_t i = 0; i < 3; ++i) {
        all.emplace_back(MultisigSession::commit(params, i + 1, w, group[i].secret, nonces[i]));
    }
    const std::vector<MultisigCommitment> commitments = {all[0], all[2]};
    const auto session = [&](std::size_t participant, const std::vector<MultisigCommitment>& list) {
        return MultisigSession(params, group[participant - 1].key, statement.mu, statement.context, statement.S, statement.T, list);
    };

    // Exactly the threshold of distinct, well-formed signers
    BOOST_CHECK_THROW(session(1, {all[0]}), std::invalid_argument);
    BOOST_CHECK_THROW(session(1, all), std::invalid_argument);
    BOOST_CHECK_THROW(session(1, {all[0], all[0]}), std::invalid_argument);
    std::vector<MultisigCommitment> bad = commitments;
    bad[1].index = 4;
    BOOST_CHECK_THROW(session(1, bad), std::invalid_argument);
    bad = commitments;
    bad[1].D.pop_back();
    BOOST_CHECK_THROW(session(1, bad), std::invalid_argument);
    bad = commitments;
    bad[1].E[0] = GroupElement();
    BOOST_CHECK_THROW(session(1, bad), std::invalid_argument);

    const MultisigSession first = session(1, commitments);
    const MultisigSession third = session(3, commitments);
    const MultisigShare share1 = first.sign(group[0].secret, nonces[0]);
    const MultisigShare share3 = third.sign(group[2].secret, nonces[2]);
    BOOST_CHECK(first.verify(share1));
    BOOST_CHECK(first.verify(share3));

    // Only a signer signs, with its own key and the nonce it committed to
    BOOST_CHECK_THROW(session(2, commitments).sign(group[1].secret, nonces[1]), std::invalid_argument);
    BOOST_CHECK_THROW(first.sign(group[1].secret, nonces[0]), std::invalid_argument);
    BOOST_CHECK_THROW(first.sign(group[0].secret, nonces[2]), std::invalid_argument);

    // A response is valid for one signer, one session and one transaction
    MultisigShare forged = share3;
    forged.z[1] += Scalar(uint64_t(1));
    BOOST_CHECK(!first.verify(forged));
    forged = share3;
    forged.index = 1;
    BOOST_CHECK(!first.verify(forged));
    forged.index = 2;
    BOOST_CHECK(!first.verify(forged));

    MultisigNonce fresh;
    const std::vector<MultisigCommitment> renewed = {MultisigSession::commit(params, 1, w, group[0].secret, fresh), all[2]};
    BOOST_CHECK(!session(1, renewed).verify(share3));

    Statement other = statement;
    other.mu.randomize();
    BOOST_CHECK(!MultisigSession(params, group[0].key, other.mu, other.context, other.S, other.T, commitments).verify(share3));

    // Combining needs every signer's valid response and the right serial numbers
    BOOST_CHECK_NO_THROW(first.combine(statement.serials, {share1, share3}));
    BOOST_CHECK_THROW(first.combine(statement.serials, {share1}), std::invalid_argument);
    BOOST_CHECK_THROW(first.combine(statement.serials, {share1, share1}), std::invalid_argument);
    BOOST_CHECK_THROW(first.combine(statement.serials, {share1, forged}), std::invalid_argument);
    std::vector<Scalar> serials = statement.serials;
    serials[0].randomize();
    BOOST_CHECK_THROW(first.combine(serials, {share1, share3}), std::invalid_argument);
}

BOOST_AUTO_TEST_CASE(binding_factors_cover_the_challenge)
{
    const Params* params = Params::get_test();
    const std::vector<Participant> group = Keygen(params, 2, 3);
    const std::size_t w = 2;
    const Statement statement = RandomStatement(params, group[0].key, w);

    // One set of nonce commitments used for several statements, which a signer never
    // does. It shows what a cosigner could aim for by changing the statement after
    // the commitments are known.
    std::vector<MultisigNonce> nonces(2);
    const std::vector<MultisigCommitment> commitments = {
        MultisigSession::commit(params, 1, w, group[0].secret, nonces[0]),
        MultisigSession::commit(params, 2, w, group[1].secret, nonces[1])};
    const auto authorize = [&](const Statement& s) {
        std::vector<MultisigShare> shares;
        for (std::size_t i = 0; i < 2; ++i) {
            shares.emplace_back(MultisigSession(params, group[i].key, s.mu, s.context, s.S, s.T, commitments).sign(group[i].secret, nonces[i]));
        }
        return MultisigSession(params, group[2].key, s.mu, s.context, s.S, s.T, commitments).combine(s.serials, shares);
    };
    const ChaumProofV2 proof = authorize(statement);

    // Change each thing the challenge is computed from, one at a time
    std::vector<Statement> changed(6, statement);
    changed[0].mu.randomize();
    changed[1].context.serialized_cover_set_references = {1, 2, 3};
    changed[2].context.serialized_outputs = {{4, 5, 6}};
    changed[3].context.fee += 1;
    changed[4].context.transparent_value += 1;
    changed[5].context.extension_commitment = uint256S("01");

    for (const Statement& other : changed) {
        BOOST_CHECK(
            MultisigSession::statement_hash(params, other.mu, other.context, other.S, other.T) !=
            MultisigSession::statement_hash(params, statement.mu, statement.context, statement.S, statement.T));

        // The proof commitments change with it, so the challenge cannot be steered
        // once they are fixed
        const ChaumProofV2 steered = authorize(other);
        for (std::size_t u = 0; u < w; ++u) {
            BOOST_CHECK(steered.A1[u] != proof.A1[u]);
            BOOST_CHECK(steered.A2[u] != proof.A2[u]);
        }
    }
}

BOOST_AUTO_TEST_CASE(nonces_are_fresh)
{
    const Params* params = Params::get_test();
    Scalar secret;
    secret.randomize();

    MultisigNonce first, second;
    const MultisigCommitment commitment = MultisigSession::commit(params, 1, 3, secret, first);
    MultisigSession::commit(params, 1, 3, secret, second);
    BOOST_REQUIRE_EQUAL(first.d.size(), 3);
    BOOST_REQUIRE_EQUAL(first.e.size(), 3);
    for (std::size_t u = 0; u < 3; ++u) {
        BOOST_CHECK(!first.d[u].isZero() && !first.e[u].isZero());
        BOOST_CHECK(first.d[u] != first.e[u]);
        BOOST_CHECK(first.d[u] != second.d[u] && first.e[u] != second.e[u]);
        BOOST_CHECK(first.d[u] != first.d[(u + 1) % 3]);
        BOOST_CHECK(commitment.D[u] == params->get_G()*first.d[u]);
        BOOST_CHECK(commitment.E[u] == params->get_G()*first.e[u]);
    }
}

BOOST_AUTO_TEST_CASE(sealed_messages)
{
    const Params* params = Params::get_test();
    const std::vector<Participant> group = Keygen(params, 2, 3);
    const std::vector<Participant> strangers = Keygen(params, 2, 3);

    const std::string message = "Spam and eggs";
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << message;
    std::vector<unsigned char> sealed = group[0].key.seal(params, stream);

    std::string opened;
    group[2].key.open(params, sealed) >> opened;
    BOOST_CHECK_EQUAL(opened, message);

    BOOST_CHECK_THROW(strangers[0].key.open(params, sealed), std::exception);
    sealed.back() ^= 1;
    BOOST_CHECK_THROW(group[2].key.open(params, sealed), std::exception);

    // Sealing the same data again uses another key
    CDataStream again(SER_NETWORK, PROTOCOL_VERSION);
    again << message;
    CDataStream once(SER_NETWORK, PROTOCOL_VERSION);
    once << message;
    BOOST_CHECK(group[0].key.seal(params, again) != group[0].key.seal(params, once));
}

BOOST_AUTO_TEST_CASE(spend_transaction)
{
    const Params* params = Params::get_test();

    const std::vector<Participant> group = Keygen(params, 2, 3);
    const FullViewKey full_view_key = group[1].key.get_full_view_key(params);
    const IncomingViewKey incoming_view_key(full_view_key);
    const Address address(incoming_view_key, 12345);

    // Mint coins to the group's address
    const std::size_t N = (std::size_t) pow(params->get_n_grootle(), params->get_m_grootle());
    std::vector<Coin> in_coins;
    for (std::size_t i = 0; i < N; ++i) {
        Scalar k;
        k.randomize();
        std::vector<unsigned char> serial_context(SCALAR_ENCODING);
        k.serialize(serial_context.data());
        in_coins.emplace_back(Coin(params, COIN_TYPE_MINT, k, address, 123 + i, "Spam and eggs", serial_context));
    }

    // Spend two of them
    const uint64_t cover_set_id = 31415;
    std::unordered_map<uint64_t, CoverSetData> cover_set_data;
    cover_set_data[cover_set_id].cover_set_size = in_coins.size();
    cover_set_data[cover_set_id].cover_set_representation = std::vector<unsigned char>(32, 7);
    std::unordered_map<uint64_t, std::vector<Coin>> cover_sets;
    cover_sets[cover_set_id] = in_coins;
    const std::map<uint64_t, uint256> block_hashes = {{cover_set_id, uint256S("01")}};

    std::vector<InputCoinData> inputs;
    std::vector<Scalar> serials;
    uint64_t f = 0;
    for (const std::size_t index : {1, 5}) {
        const IdentifiedCoinData identified = in_coins[index].identify(incoming_view_key);
        const RecoveredCoinData recovered = in_coins[index].recover(full_view_key, identified);
        inputs.emplace_back();
        inputs.back().cover_set_id = cover_set_id;
        inputs.back().index = index;
        inputs.back().k = identified.k;
        inputs.back().s = recovered.s;
        inputs.back().T = recovered.T;
        inputs.back().v = identified.v;
        serials.emplace_back(recovered.s);
        f += identified.v;
    }

    std::vector<OutputCoinData> outputs(2);
    for (std::size_t j = 0; j < outputs.size(); ++j) {
        outputs[j].address = address;
        outputs[j].v = 12 + j;
        outputs[j].memo = "Spam and eggs";
        f -= outputs[j].v;
    }

    // Everything but the authorization needs only the view key
    std::vector<Scalar> output_nonces;
    SpendTransaction transaction(params, full_view_key, inputs, cover_set_data, cover_sets, f, 0, outputs, block_hashes, output_nonces);
    BOOST_CHECK(!SpendTransaction::verify(transaction, cover_sets));

    // The nonces let a cosigner check where the outputs go
    BOOST_REQUIRE_EQUAL(output_nonces.size(), outputs.size());
    CDataStream serial_context(SER_NETWORK, PROTOCOL_VERSION);
    serial_context << transaction.getUsedLTags();
    for (std::size_t j = 0; j < outputs.size(); ++j) {
        const std::vector<unsigned char> context(serial_context.begin(), serial_context.end());
        const Coin& coin = transaction.getOutCoins()[j];
        BOOST_CHECK(Coin(params, COIN_TYPE_SPEND, output_nonces[j], outputs[j].address, outputs[j].v, outputs[j].memo, context) == coin);

        // A coin that pays anything else is a different coin
        BOOST_CHECK(Coin(params, COIN_TYPE_SPEND, output_nonces[j], outputs[j].address, outputs[j].v + 1, outputs[j].memo, context) != coin);
        BOOST_CHECK(Coin(params, COIN_TYPE_SPEND, output_nonces[j], outputs[j].address, outputs[j].v, "Eggs and spam", context) != coin);
        BOOST_CHECK(Coin(params, COIN_TYPE_SPEND, output_nonces[j], Address(incoming_view_key, 54321), outputs[j].v, outputs[j].memo, context) != coin);
        BOOST_CHECK(Coin(params, COIN_TYPE_SPEND, output_nonces[(j + 1) % outputs.size()], outputs[j].address, outputs[j].v, outputs[j].memo, context) != coin);
    }

    Statement statement;
    statement.mu = transaction.getBindingHash();
    statement.context = transaction.getChaumContext();
    statement.serials = serials;
    statement.S = transaction.getS1();
    statement.T = transaction.getUsedLTags();

    transaction.setChaumProof(Authorize(params, group, {3, 1}, 2, statement));
    BOOST_CHECK(SpendTransaction::verify(transaction, cover_sets));

    // The draft and the authorized transaction have the same canonical layout
    CDataStream serialized(SER_NETWORK, PROTOCOL_VERSION);
    serialized << transaction;
    SpendTransaction parsed(params, SpendTransactionVersion::V2, outputs.size());
    serialized >> parsed;
    BOOST_CHECK(parsed.getUsedLTags() == transaction.getUsedLTags());
}

BOOST_AUTO_TEST_SUITE_END()

}
