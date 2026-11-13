#include "multisig.h"
#include "transcript.h"

#include <algorithm>
#include <map>
#include <set>

namespace spark {

// Multiplications by a key, a key share, a nonce, or a scalar derived from one use
// GroupElement::multiplyConstantTime, which takes the same time for every scalar.
// operator* does not, and is used only where the scalar is no such secret.

namespace {

// Domain separation. These values never reach the chain: they pass between the
// participants of one wallet.
const std::string LABEL_MULTISIG_POK = "MULTISIG_POK_V1";
const std::string LABEL_MULTISIG_S1 = "MULTISIG_S1_V1";
const std::string LABEL_MULTISIG_S2 = "MULTISIG_S2_V1";
const std::string LABEL_MULTISIG_SESSION = "MULTISIG_SESSION_V1";
const std::string LABEL_MULTISIG_RHO = "MULTISIG_RHO_V1";
const std::string LABEL_MULTISIG_F = "MULTISIG_F_V1";
const std::string LABEL_MULTISIG_H = "MULTISIG_H_V1";
const std::string LABEL_MULTISIG_CONTEXT = "MULTISIG_CONTEXT";
const std::string LABEL_MULTISIG_DERIVE = "MULTISIG_DERIVE";
const std::string LABEL_MULTISIG_VIEW = "MULTISIG_VIEW";
const std::string LABEL_MULTISIG_ROUND1 = "MULTISIG_ROUND1";
const std::string LABEL_MULTISIG_SHARE_KEY = "MULTISIG_SHARE_KEY";
const std::string LABEL_MULTISIG_STORAGE = "MULTISIG_STORAGE";
const std::string LABEL_MULTISIG_SEAL = "MULTISIG_SEAL";
const std::string LABEL_MULTISIG_NONCE = "MULTISIG_NONCE";

const std::string AEAD_SHARE = "Multisig share";
const std::string AEAD_STORAGE = "Multisig key share";
const std::string AEAD_SEAL = "Multisig message";

Scalar Identifier(std::size_t index)
{
    return Scalar(static_cast<uint64_t>(index));
}

// Evaluate at `x` the polynomial whose coefficients are committed to
GroupElement Evaluate(const std::vector<GroupElement>& commitments, const Scalar& x)
{
    GroupElement result;
    Scalar power(uint64_t(1));
    for (const GroupElement& commitment : commitments) {
        result += commitment*power;
        power *= x;
    }
    return result;
}

bool IsValidPoint(const GroupElement& point)
{
    return !point.isInfinity() && point.isMember();
}

} // namespace

GroupElement MultisigKey::parse_participant(const std::vector<unsigned char>& compressed)
{
    if (compressed.size() != 33 || (compressed[0] != 2 && compressed[0] != 3)) {
        throw std::invalid_argument("Bad multisig participant key");
    }
    unsigned char buffer[GroupElement::serialize_size];
    std::copy(compressed.begin() + 1, compressed.end(), buffer);
    buffer[32] = compressed[0] & 1;
    buffer[33] = 0;

    GroupElement key;
    key.deserialize(buffer);
    // Rejects an x coordinate that is not reduced, which deserialization lets through
    if (serialize_participant(key) != compressed) {
        throw std::invalid_argument("Bad multisig participant key");
    }
    return key;
}

std::vector<unsigned char> MultisigKey::serialize_participant(const GroupElement& key)
{
    unsigned char buffer[GroupElement::serialize_size];
    key.serialize(buffer);

    std::vector<unsigned char> compressed(33);
    compressed[0] = 2 + buffer[32];
    std::copy(buffer, buffer + 32, compressed.begin() + 1);
    return compressed;
}

FullViewKey MultisigKey::get_full_view_key(const Params* params) const
{
    return FullViewKey(params, s1, s2, commitments.at(0));
}

GroupElement MultisigKey::get_verification_share(std::size_t index_) const
{
    return Evaluate(commitments, Identifier(index_));
}

GroupElement MultisigKey::storage_key(const Params* params, const Scalar& secret) const
{
    // The commitments fix every participant's share, so this key only ever encrypts one value
    Hash hash(LABEL_MULTISIG_STORAGE);
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << secret << threshold << participants << commitments;
    hash.include(stream);
    return params->get_G().multiplyConstantTime(hash.finalize_scalar());
}

Scalar MultisigKey::get_share(const Params* params, const Scalar& secret) const
{
    Scalar result;
    try {
        AEADEncryptedData encrypted = share;
        CDataStream stream = AEAD::decrypt_and_verify(storage_key(params, secret), AEAD_STORAGE, encrypted);
        stream >> result;
    } catch (const std::exception&) {
        throw std::invalid_argument("The participant key does not open this multisig key share");
    }
    if (params->get_G().multiplyConstantTime(result) != get_verification_share(index)) {
        throw std::invalid_argument("Multisig key share does not match the group key");
    }
    return result;
}

GroupElement MultisigKey::seal_key(const Params* params, const Scalar& salt) const
{
    Hash hash(LABEL_MULTISIG_SEAL);
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << s1 << s2 << salt;
    hash.include(stream);
    return params->get_G().multiplyConstantTime(hash.finalize_scalar());
}

std::vector<unsigned char> MultisigKey::seal(const Params* params, CDataStream& data) const
{
    // The cipher runs with a fixed nonce, so each message takes a key of its own
    Scalar salt;
    salt.randomize();

    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << salt << AEAD::encrypt(seal_key(params, salt), AEAD_SEAL, data);
    return std::vector<unsigned char>(stream.begin(), stream.end());
}

CDataStream MultisigKey::open(const Params* params, const std::vector<unsigned char>& sealed) const
{
    CDataStream stream(sealed, SER_NETWORK, PROTOCOL_VERSION);
    Scalar salt;
    AEADEncryptedData encrypted;
    stream >> salt >> encrypted;
    if (!stream.empty()) {
        throw std::invalid_argument("Trailing data in multisig message");
    }
    return AEAD::decrypt_and_verify(seal_key(params, salt), AEAD_SEAL, encrypted);
}

MultisigKeygen::MultisigKeygen(
    const Params* params_,
    std::size_t threshold_,
    const std::vector<GroupElement>& participants_,
    const Scalar& secret_)
    : params(params_), threshold(threshold_), secret(secret_), index(0)
{
    std::map<std::vector<unsigned char>, GroupElement> sorted;
    for (const GroupElement& key : participants_) {
        if (!IsValidPoint(key)) {
            throw std::invalid_argument("Bad multisig participant key");
        }
        if (!sorted.emplace(MultisigKey::serialize_participant(key), key).second) {
            throw std::invalid_argument("Duplicate multisig participant key");
        }
    }
    if (sorted.size() < 2 || sorted.size() > MULTISIG_MAX_PARTICIPANTS) {
        throw std::invalid_argument("A multisig group has between 2 and " + std::to_string(MULTISIG_MAX_PARTICIPANTS) + " participants");
    }
    if (threshold < 1 || threshold > sorted.size()) {
        throw std::invalid_argument("The multisig threshold must be between 1 and the number of participants");
    }

    const GroupElement own = params->get_G().multiplyConstantTime(secret);
    for (const auto& entry : sorted) {
        participants.emplace_back(entry.second);
        if (entry.second == own) {
            index = participants.size();
        }
    }
    if (index == 0) {
        throw std::invalid_argument("The secret key does not belong to a multisig participant");
    }

    Hash hash(LABEL_MULTISIG_CONTEXT);
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << static_cast<uint64_t>(threshold) << participants;
    hash.include(stream);
    context = hash.finalize();
}

// A secret value of this participant for this group. Deriving it keeps key generation
// free of stored state, and binds it to the participant keys it may be shared with.
Scalar MultisigKeygen::derive(const std::string& purpose, uint64_t i, const std::vector<unsigned char>& data) const
{
    Hash hash(LABEL_MULTISIG_DERIVE);
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << purpose << secret << context << i << data;
    hash.include(stream);
    return hash.finalize_scalar();
}

Scalar MultisigKeygen::pok_challenge(std::size_t sender, const MultisigKeygenMessage& message) const
{
    Transcript transcript(LABEL_MULTISIG_POK);
    transcript.add("context", context);
    transcript.add("index", Identifier(sender));
    transcript.add("C", message.C);
    transcript.add("view", message.view_commitment);
    transcript.add("R", message.R);
    return transcript.challenge("c");
}

std::vector<unsigned char> MultisigKeygen::view_commitment(std::size_t sender, const Scalar& s1, const Scalar& s2) const
{
    Hash hash(LABEL_MULTISIG_VIEW);
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << context << static_cast<uint64_t>(sender) << s1 << s2;
    hash.include(stream);
    return hash.finalize();
}

MultisigKeygenMessage MultisigKeygen::round1() const
{
    MultisigKeygenMessage message;
    message.key = participants[index - 1];
    for (std::size_t j = 0; j < threshold; ++j) {
        message.C.emplace_back(params->get_G().multiplyConstantTime(derive("coefficient", j)));
    }

    const Scalar s1 = derive("s1", 0);
    const Scalar s2 = derive("s2", 0);
    if (s1.isZero() || s2.isZero()) {
        throw std::runtime_error("Unusable multisig view key contribution");
    }
    message.view_commitment = view_commitment(index, s1, s2);

    // Schnorr proof of knowledge of the constant coefficient. Its nonce is derived from
    // everything the proof commits to, so that one nonce never meets two challenges.
    CDataStream proved(SER_NETWORK, PROTOCOL_VERSION);
    proved << message.C << message.view_commitment;
    const Scalar k = derive("nonce", 0, std::vector<unsigned char>(proved.begin(), proved.end()));
    message.R = params->get_G().multiplyConstantTime(k);
    message.mu = k + derive("coefficient", 0)*pok_challenge(index, message);
    return message;
}

// Order the messages by sender identifier and verify their round one content
std::vector<MultisigKeygenMessage> MultisigKeygen::check(const std::vector<MultisigKeygenMessage>& messages) const
{
    if (messages.size() != participants.size()) {
        throw std::invalid_argument("Expected one multisig message from each participant");
    }

    std::vector<MultisigKeygenMessage> ordered;
    for (std::size_t i = 0; i < participants.size(); ++i) {
        const auto found = std::find_if(messages.begin(), messages.end(), [&](const MultisigKeygenMessage& message) {
            return message.key == participants[i];
        });
        if (found == messages.end()) {
            throw std::invalid_argument("Expected one multisig message from each participant");
        }
        const MultisigKeygenMessage& message = *found;
        const std::string sender = "participant " + std::to_string(i + 1);

        if (message.C.size() != threshold ||
            !std::all_of(message.C.begin(), message.C.end(), IsValidPoint) ||
            !message.R.isMember() ||
            (!message.shares.empty() && message.shares.size() != participants.size())) {
            throw std::invalid_argument("Malformed multisig message from " + sender);
        }
        if (params->get_G()*message.mu != message.R + message.C[0]*pok_challenge(i + 1, message)) {
            throw std::invalid_argument("Bad proof of knowledge from " + sender);
        }
        ordered.emplace_back(message);
    }

    // A message under this participant's key that it would not have produced is a forgery
    const MultisigKeygenMessage own = round1();
    const MultisigKeygenMessage& claimed = ordered[index - 1];
    if (claimed.C != own.C || claimed.R != own.R || claimed.mu != own.mu || claimed.view_commitment != own.view_commitment) {
        throw std::invalid_argument("A multisig message carries this participant's key but was not made by it");
    }
    return ordered;
}

std::vector<unsigned char> MultisigKeygen::round1_hash(const std::vector<MultisigKeygenMessage>& ordered) const
{
    Hash hash(LABEL_MULTISIG_ROUND1);
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << context;
    for (const MultisigKeygenMessage& message : ordered) {
        stream << message.key << message.C << message.R << message.mu << message.view_commitment;
    }
    hash.include(stream);
    return hash.finalize();
}

// Key for what `sender` tells `recipient`: a static Diffie-Hellman secret of the two
// participant keys, bound to the round one messages the sender worked from. A recipient
// can therefore decrypt only if it holds the very same messages, which gives the
// consistent delivery of commitments the protocol relies on. Every distinct plaintext
// also gets a key of its own, as the fixed-nonce cipher requires.
GroupElement MultisigKeygen::share_key(const std::vector<unsigned char>& transcript, std::size_t sender, std::size_t recipient) const
{
    Hash hash(LABEL_MULTISIG_SHARE_KEY);
    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << transcript << static_cast<uint64_t>(sender) << static_cast<uint64_t>(recipient);
    hash.include(stream);

    const GroupElement& other = participants[(sender == index ? recipient : sender) - 1];
    return other.multiplyConstantTime(secret*hash.finalize_scalar());
}

MultisigKeygenMessage MultisigKeygen::round2(const std::vector<MultisigKeygenMessage>& messages) const
{
    const std::vector<unsigned char> transcript = round1_hash(check(messages));

    std::vector<Scalar> coefficients;
    for (std::size_t j = 0; j < threshold; ++j) {
        coefficients.emplace_back(derive("coefficient", j));
    }

    MultisigKeygenMessage message = round1();
    for (std::size_t recipient = 1; recipient <= participants.size(); ++recipient) {
        // The sender's polynomial at the recipient's identifier
        Scalar share;
        Scalar power(uint64_t(1));
        for (const Scalar& coefficient : coefficients) {
            share += coefficient*power;
            power *= Identifier(recipient);
        }

        CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
        stream << share << derive("s1", 0) << derive("s2", 0);
        message.shares.emplace_back(AEAD::encrypt(share_key(transcript, index, recipient), AEAD_SHARE, stream));
    }
    return message;
}

// Hash-weighted sum of the view key contributions, so that no participant chooses the result
Scalar MultisigKeygen::aggregate(const std::string& label, const std::vector<Scalar>& contributions) const
{
    Scalar result;
    for (std::size_t i = 0; i < contributions.size(); ++i) {
        Transcript transcript(label);
        transcript.add("context", context);
        transcript.add("contributions", contributions);
        transcript.add("index", Identifier(i + 1));
        result += transcript.challenge("weight")*contributions[i];
    }
    return result;
}

MultisigKey MultisigKeygen::finalize(const std::vector<MultisigKeygenMessage>& messages) const
{
    const std::vector<MultisigKeygenMessage> ordered = check(messages);
    const std::vector<unsigned char> transcript = round1_hash(ordered);

    MultisigKey key;
    key.threshold = threshold;
    key.participants = participants;
    key.index = index;
    key.commitments.resize(threshold);

    Scalar share;
    std::vector<Scalar> s1, s2;
    for (std::size_t i = 0; i < ordered.size(); ++i) {
        const MultisigKeygenMessage& message = ordered[i];
        const std::string sender = "participant " + std::to_string(i + 1);
        if (message.shares.empty()) {
            throw std::invalid_argument("Missing round two data from " + sender);
        }

        Scalar f, v1, v2;
        try {
            AEADEncryptedData encrypted = message.shares[index - 1];
            CDataStream stream = AEAD::decrypt_and_verify(share_key(transcript, i + 1, index), AEAD_SHARE, encrypted);
            stream >> f >> v1 >> v2;
        } catch (const std::exception&) {
            throw std::invalid_argument("Unable to decrypt the share from " + sender + ": it was made for other participant keys or other round one messages");
        }
        if (v1.isZero() || v2.isZero() ||
            view_commitment(i + 1, v1, v2) != message.view_commitment ||
            params->get_G().multiplyConstantTime(f) != Evaluate(message.C, Identifier(index))) {
            throw std::invalid_argument("Bad share from " + sender);
        }

        share += f;
        s1.emplace_back(v1);
        s2.emplace_back(v2);
        for (std::size_t j = 0; j < threshold; ++j) {
            key.commitments[j] += message.C[j];
        }
    }

    key.s1 = aggregate(LABEL_MULTISIG_S1, s1);
    key.s2 = aggregate(LABEL_MULTISIG_S2, s2);
    if (key.s1.isZero() || key.s2.isZero() || key.commitments[0].isInfinity()) {
        throw std::runtime_error("Unusable multisig key");
    }

    CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
    stream << share;
    key.share = AEAD::encrypt(key.storage_key(params, secret), AEAD_STORAGE, stream);
    return key;
}

Scalar MultisigSession::statement_hash(
    const Params* params,
    const Scalar& mu,
    const ChaumV2Context& context,
    const std::vector<GroupElement>& S,
    const std::vector<GroupElement>& T)
{
    // The challenge function itself, evaluated without proof commitments. It can
    // then never bind something that this hash leaves out, and no proof shares
    // its input: a proof has a commitment for every input.
    Chaum chaum(params->get_F(), params->get_G(), params->get_H(), params->get_U());
    return chaum.challenge_v2(mu, context, S, T, {}, {});
}

MultisigCommitment MultisigSession::commit(const Params* params, std::size_t index, std::size_t inputs, const Scalar& secret, MultisigNonce& nonce)
{
    uint64_t counter = 0;
    const auto sample = [&secret, &counter]() {
        Scalar result;
        while (result.isZero()) {
            Scalar random;
            random.randomize();
            Hash hash(LABEL_MULTISIG_NONCE);
            CDataStream stream(SER_NETWORK, PROTOCOL_VERSION);
            stream << random << secret << counter++;
            hash.include(stream);
            result = hash.finalize_scalar();
        }
        return result;
    };

    MultisigCommitment commitment;
    commitment.index = index;
    nonce.d.clear();
    nonce.e.clear();
    for (std::size_t u = 0; u < inputs; ++u) {
        nonce.d.emplace_back(sample());
        nonce.e.emplace_back(sample());
        commitment.D.emplace_back(params->get_G().multiplyConstantTime(nonce.d[u]));
        commitment.E.emplace_back(params->get_G().multiplyConstantTime(nonce.e[u]));
    }
    return commitment;
}

MultisigSession::MultisigSession(
    const Params* params_,
    const MultisigKey& key_,
    const Scalar& mu_,
    const ChaumV2Context& context_,
    const std::vector<GroupElement>& S_,
    const std::vector<GroupElement>& T_,
    const std::vector<MultisigCommitment>& commitments_)
    : params(params_), key(key_), mu(mu_), context(context_), S(S_), T(T_), commitments(commitments_)
{
    const std::size_t w = S.size();
    if (w == 0 || w > MAX_CHAUM_V2_INPUTS || T.size() != w) {
        throw std::invalid_argument("Bad multisig statement");
    }
    if (key.threshold == 0 || commitments.size() != key.threshold) {
        throw std::invalid_argument("A multisig spend is signed by exactly the threshold of participants");
    }
    std::sort(commitments.begin(), commitments.end(), [](const MultisigCommitment& left, const MultisigCommitment& right) {
        return left.index < right.index;
    });

    // Everything a binding factor commits to: all that the challenge will cover,
    // and the canonically ordered list of all nonce commitments
    Transcript session(LABEL_MULTISIG_SESSION);
    session.add("statement", statement_hash(params, mu, context, S, T));
    for (std::size_t i = 0; i < commitments.size(); ++i) {
        const MultisigCommitment& commitment = commitments[i];
        if (commitment.index < 1 || commitment.index > key.participants.size() ||
            (i > 0 && commitments[i - 1].index == commitment.index) ||
            commitment.D.size() != w || commitment.E.size() != w ||
            !std::all_of(commitment.D.begin(), commitment.D.end(), IsValidPoint) ||
            !std::all_of(commitment.E.begin(), commitment.E.end(), IsValidPoint)) {
            throw std::invalid_argument("Bad multisig nonce commitments");
        }
        session.add("index", Identifier(commitment.index));
        session.add("D", commitment.D);
        session.add("E", commitment.E);
    }
    const Scalar session_hash = session.challenge("session");

    // Coefficients that interpolate the signers' shares to the spend key
    for (std::size_t i = 0; i < commitments.size(); ++i) {
        Scalar numerator(uint64_t(1)), denominator(uint64_t(1));
        for (std::size_t j = 0; j < commitments.size(); ++j) {
            if (j != i) {
                numerator *= Identifier(commitments[j].index);
                denominator *= Identifier(commitments[j].index) - Identifier(commitments[i].index);
            }
        }
        lambda.emplace_back(numerator*denominator.inverse());
    }

    rho.assign(commitments.size(), std::vector<Scalar>(w));
    for (std::size_t u = 0; u < w; ++u) {
        std::vector<Scalar> input_rho;
        GroupElement R;
        for (std::size_t i = 0; i < commitments.size(); ++i) {
            Transcript transcript(LABEL_MULTISIG_RHO);
            transcript.add("session", session_hash);
            transcript.add("index", Identifier(commitments[i].index));
            transcript.add("input", Identifier(u));
            rho[i][u] = transcript.challenge("rho");
            input_rho.emplace_back(rho[i][u]);
            R += commitments[i].D[u] + commitments[i].E[u]*rho[i][u];
        }

        Transcript transcript_a(LABEL_MULTISIG_F);
        transcript_a.add("rho", input_rho);
        a.emplace_back(transcript_a.challenge("a"));
        Transcript transcript_b(LABEL_MULTISIG_H);
        transcript_b.add("rho", input_rho);
        b.emplace_back(transcript_b.challenge("b"));

        proof.A1.emplace_back(params->get_F()*a[u] + R + params->get_H()*b[u]);
        proof.A2.emplace_back(T[u]*a[u] + R);
    }

    Chaum chaum(params->get_F(), params->get_G(), params->get_H(), params->get_U());
    c = chaum.challenge_v2(mu, context, S, T, proof.A1, proof.A2);
    if (c.isZero()) {
        throw std::invalid_argument("Unexpected challenge!");
    }
}

// Position of a signer in the ordered commitment list, or its size if it is not a signer
std::size_t MultisigSession::position(std::size_t index) const
{
    std::size_t i = 0;
    while (i < commitments.size() && commitments[i].index != index) {
        ++i;
    }
    return i;
}

MultisigShare MultisigSession::sign(const Scalar& secret, const MultisigNonce& nonce) const
{
    const std::size_t i = position(key.index);
    const std::size_t w = S.size();
    if (i == commitments.size()) {
        throw std::invalid_argument("This participant is not among the signers");
    }
    if (nonce.d.size() != w || nonce.e.size() != w) {
        throw std::invalid_argument("Multisig nonce does not fit this transaction");
    }

    const Scalar weight = c*lambda[i]*key.get_share(params, secret);
    MultisigShare share;
    share.index = key.index;
    for (std::size_t u = 0; u < w; ++u) {
        if (params->get_G().multiplyConstantTime(nonce.d[u]) != commitments[i].D[u] ||
            params->get_G().multiplyConstantTime(nonce.e[u]) != commitments[i].E[u]) {
            throw std::invalid_argument("Multisig nonce does not match this signer's commitment");
        }
        share.z.emplace_back(nonce.d[u] + rho[i][u]*nonce.e[u] + weight);
    }
    return share;
}

bool MultisigSession::verify(const MultisigShare& share) const
{
    const std::size_t i = position(share.index);
    if (i == commitments.size() || share.z.size() != S.size()) {
        return false;
    }

    const GroupElement Y = key.get_verification_share(share.index)*(c*lambda[i]);
    for (std::size_t u = 0; u < share.z.size(); ++u) {
        if (params->get_G()*share.z[u] != commitments[i].D[u] + commitments[i].E[u]*rho[i][u] + Y) {
            return false;
        }
    }
    return true;
}

ChaumProofV2 MultisigSession::combine(const std::vector<Scalar>& serials, const std::vector<MultisigShare>& shares) const
{
    const std::size_t w = S.size();
    if (serials.size() != w) {
        throw std::invalid_argument("Expected one serial number for each input");
    }

    ChaumProofV2 result = proof;
    result.t2.assign(w, Scalar());
    std::set<uint32_t> signers;
    for (const MultisigShare& share : shares) {
        if (!signers.insert(share.index).second || !verify(share)) {
            throw std::invalid_argument("Bad signature share from participant " + std::to_string(share.index));
        }
        for (std::size_t u = 0; u < w; ++u) {
            result.t2[u] += share.z[u];
        }
    }
    if (signers.size() != commitments.size()) {
        throw std::invalid_argument("Missing multisig signature shares");
    }

    const GroupElement& D = key.commitments.at(0);
    for (std::size_t u = 0; u < w; ++u) {
        const Scalar h = SparkUtils::hash_ser1(serials[u], D);
        if (params->get_F()*serials[u] + params->get_H().inverse()*h + D != S[u] || T[u]*serials[u] + D != params->get_U()) {
            throw std::invalid_argument("Serial number does not match the statement");
        }
        result.t1.emplace_back(a[u] + c*serials[u]);
        result.t3.emplace_back(b[u] - c*h);
    }

    Chaum chaum(params->get_F(), params->get_G(), params->get_H(), params->get_U());
    if (!chaum.verify_v2(mu, context, S, T, result)) {
        throw std::runtime_error("Multisig authorization does not verify");
    }
    return result;
}

}
