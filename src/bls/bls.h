// Copyright (c) 2018-2021 The Dash Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DASH_CRYPTO_BLS_H
#define DASH_CRYPTO_BLS_H

#include <hash.h>
#include <serialize.h>
#include <uint256.h>
#include <utilstrencodings.h>

// bls-signatures uses relic, which may define DEBUG and ERROR, which leads to many warnings in some build setups
#undef ERROR
#undef DEBUG
#ifdef __APPLE__
// macOS <mach/error.h> defines err_get_code as a macro which conflicts with relic's function declaration
#undef err_get_code
#endif
#include <bls-dash/bls.hpp>
#include <bls-dash/privatekey.hpp>
#include <bls-dash/elements.hpp>
#include <bls-dash/schemes.hpp>
#include <bls-dash/threshold.hpp>
#undef DOUBLE
// relic's generic configuration macros collide with BCLog category names.
// They are only needed while parsing relic headers and must not leak into
// Firo translation units.
#undef BENCH
#undef RAND

#include <algorithm>
#include <array>
#include <mutex>
#include <stdexcept>
#include <utility>
#include <unistd.h>

static const bool fLegacyDefault{true};

// reversed BLS12-381
#define BLS_CURVE_ID_SIZE 32
#define BLS_CURVE_SECKEY_SIZE 32
#define BLS_CURVE_PUBKEY_SIZE 48
#define BLS_CURVE_SIG_SIZE 96

class CBLSSignature;
class CBLSPublicKey;
struct CBLSIdImplicit;

template <typename ImplType>
struct CBLSImplValidation;

template <typename ImplType>
struct CBLSImplParser
{
    static ImplType FromBytes(const std::vector<uint8_t>& vecBytes, bool fLegacy)
    {
        return ImplType::FromBytes(bls::Bytes(vecBytes), fLegacy);
    }
};

template <>
struct CBLSImplParser<bls::PrivateKey>
{
    static bls::PrivateKey FromBytes(const std::vector<uint8_t>& vecBytes, bool)
    {
        static constexpr std::array<uint8_t, BLS_CURVE_SECKEY_SIZE> groupOrder{
            0x73, 0xed, 0xa7, 0x53, 0x29, 0x9d, 0x7d, 0x48,
            0x33, 0x39, 0xd8, 0x08, 0x09, 0xa1, 0xd8, 0x05,
            0x53, 0xbd, 0xa4, 0x02, 0xff, 0xfe, 0x5b, 0xfe,
            0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x01,
        };
        if (!std::lexicographical_compare(vecBytes.begin(), vecBytes.end(), groupOrder.begin(), groupOrder.end())) {
            throw std::invalid_argument("BLS private key is outside the scalar field");
        }
        return bls::PrivateKey::FromBytes(bls::Bytes(vecBytes));
    }
};

inline bool IsValidBLSGroupElement(const bls::G1Element& impl)
{
    return impl != bls::G1Element() && impl.IsValid();
}

inline bool IsValidBLSGroupElement(const bls::G2Element& impl)
{
    return impl != bls::G2Element() && impl.IsValid();
}

template <>
struct CBLSImplValidation<bls::PrivateKey>
{
    static bool IsValid(const bls::PrivateKey& impl)
    {
        return !impl.IsZero();
    }
};

template <>
struct CBLSImplValidation<bls::G1Element>
{
    static bool IsValid(const bls::G1Element& impl)
    {
        return IsValidBLSGroupElement(impl);
    }
};

template <>
struct CBLSImplValidation<bls::G2Element>
{
    static bool IsValid(const bls::G2Element& impl)
    {
        return IsValidBLSGroupElement(impl);
    }
};

template <typename ImplType, size_t _SerSize, typename C>
class CBLSWrapper
{
    friend class CBLSSecretKey;
    friend class CBLSPublicKey;
    friend class CBLSSignature;

    bool fLegacy{fLegacyDefault};

protected:
    ImplType impl;
    bool fValid{false};
    mutable uint256 cachedHash;

    inline constexpr size_t GetSerSize() const { return SerSize; }

public:
    static const size_t SerSize = _SerSize;

    CBLSWrapper(const bool fLegacyIn = fLegacyDefault) : fLegacy(fLegacyIn)
    {
    }
    CBLSWrapper(const std::vector<unsigned char>& vecBytes, const bool fLegacyIn = fLegacyDefault) : CBLSWrapper<ImplType, _SerSize, C>(fLegacyIn)
    {
        SetByteVector(vecBytes);
    }

    CBLSWrapper(const CBLSWrapper& ref) = default;
    constexpr CBLSWrapper& operator=(const CBLSWrapper& ref) = default;
    CBLSWrapper(CBLSWrapper&& ref)
    {
        std::swap(impl, ref.impl);
        std::swap(fValid, ref.fValid);
        std::swap(cachedHash, ref.cachedHash);
        std::swap(fLegacy, ref.fLegacy);
    }
    CBLSWrapper& operator=(CBLSWrapper&& ref)
    {
        std::swap(impl, ref.impl);
        std::swap(fValid, ref.fValid);
        std::swap(cachedHash, ref.cachedHash);
        std::swap(fLegacy, ref.fLegacy);
        return *this;
    }

    bool operator==(const C& r) const
    {
        return fValid == r.fValid && impl == r.impl;
    }
    bool operator!=(const C& r) const
    {
        return !((*this) == r);
    }

    bool IsValid(bool fStrict = true) const
    {
        return fValid && (!fStrict || CBLSImplValidation<ImplType>::IsValid(impl));
    }

    void Reset()
    {
        *((C*)this) = C(fLegacy);
    }

    void SetByteVector(const std::vector<uint8_t>& vecBytes)
    {
        if (vecBytes.size() != SerSize) {
            Reset();
            return;
        }

        if (std::all_of(vecBytes.begin(), vecBytes.end(), [](uint8_t c) { return c == 0; })) {
            Reset();
        } else {
            try {
                impl = CBLSImplParser<ImplType>::FromBytes(vecBytes, fLegacy);
                fValid = true;
            } catch (...) {
                Reset();
            }
        }
        cachedHash.SetNull();
    }

    std::vector<uint8_t> ToByteVector() const
    {
        if (!fValid) {
            return std::vector<uint8_t>(SerSize, 0);
        }
        return impl.Serialize(fLegacy);
    }

    const uint256& GetHash() const
    {
        if (cachedHash.IsNull()) {
            cachedHash = ::SerializeHash(*this);
        }
        return cachedHash;
    }

    bool SetHexStr(const std::string& str)
    {
        if (!IsHex(str)) {
            Reset();
            return false;
        }
        auto b = ParseHex(str);
        if (b.size() != SerSize) {
            Reset();
            return false;
        }
        SetByteVector(b);
        if (!IsValid()) {
            Reset();
            return false;
        }
        return true;
    }

public:
    inline void Serialize(CSizeComputer& s) const
    {
        s.seek(SerSize);
    }

    template <typename Stream>
    inline void Serialize(Stream& s) const
    {
        s.write((const char*)ToByteVector().data(), SerSize);
    }
    template <typename Stream>
    inline void Unserialize(Stream& s, bool checkMalleable = true)
    {
        std::vector<uint8_t> vecBytes(SerSize, 0);
        s.read((char*)vecBytes.data(), SerSize);
        SetByteVector(vecBytes);

        if (checkMalleable && !CheckMalleable(vecBytes)) {
            throw std::ios_base::failure("malleable BLS object");
        }
    }

    inline bool CheckMalleable(const std::vector<uint8_t>& vecBytes) const
    {
        if (memcmp(vecBytes.data(), ToByteVector().data(), SerSize)) {
            // TODO not sure if this is actually possible with the BLS libs. I'm assuming here that somewhere deep inside
            // these libs masking might happen, so that 2 different binary representations could result in the same object
            // representation
            return false;
        }
        return true;
    }

    inline std::string ToString() const
    {
        std::vector<uint8_t> buf = ToByteVector();
        return HexStr(buf.begin(), buf.end());
    }

    virtual ~CBLSWrapper() = default;
};

struct CBLSIdImplicit : public uint256
{
    CBLSIdImplicit() {}
    CBLSIdImplicit(const uint256& id)
    {
        memcpy(begin(), id.begin(), sizeof(uint256));
    }
    static CBLSIdImplicit FromBytes(const uint8_t* buffer, const bool fLegacy = false)
    {
        CBLSIdImplicit instance;
        memcpy(instance.begin(), buffer, sizeof(CBLSIdImplicit));
        return instance;
    }
    std::vector<uint8_t> Serialize(const bool fLegacy = false) const
    {
        return {begin(), end()};
    }
};

template <>
struct CBLSImplValidation<CBLSIdImplicit>
{
    static bool IsValid(const CBLSIdImplicit&)
    {
        return true;
    }
};

template <>
struct CBLSImplParser<CBLSIdImplicit>
{
    static CBLSIdImplicit FromBytes(const std::vector<uint8_t>& vecBytes, bool fLegacy)
    {
        return CBLSIdImplicit::FromBytes(vecBytes.data(), fLegacy);
    }
};

class CBLSId : public CBLSWrapper<CBLSIdImplicit, BLS_CURVE_ID_SIZE, CBLSId>
{
public:
    using CBLSWrapper::operator=;
    using CBLSWrapper::operator==;
    using CBLSWrapper::operator!=;
    using CBLSWrapper::CBLSWrapper;

    CBLSId() {}
    CBLSId(const uint256& nHash);
};

class CBLSSecretKey : public CBLSWrapper<bls::PrivateKey, BLS_CURVE_SECKEY_SIZE, CBLSSecretKey>
{
public:
    using CBLSWrapper::operator==;
    using CBLSWrapper::operator!=;
    using CBLSWrapper::CBLSWrapper;

    CBLSSecretKey() {}

    void AggregateInsecure(const CBLSSecretKey& o);
    static CBLSSecretKey AggregateInsecure(const std::vector<CBLSSecretKey>& sks);

#ifndef BUILD_BITCOIN_INTERNAL
    void MakeNewKey();
#endif
    bool SecretKeyShare(const std::vector<CBLSSecretKey>& msk, const CBLSId& id);

    CBLSPublicKey GetPublicKey() const;
    CBLSSignature Sign(const uint256& hash) const;
};

class CBLSPublicKey : public CBLSWrapper<bls::G1Element, BLS_CURVE_PUBKEY_SIZE, CBLSPublicKey>
{
    friend class CBLSSecretKey;
    friend class CBLSSignature;

public:
    using CBLSWrapper::operator=;
    using CBLSWrapper::operator==;
    using CBLSWrapper::operator!=;
    using CBLSWrapper::CBLSWrapper;

    CBLSPublicKey() {}

    void AggregateInsecure(const CBLSPublicKey& o);
    static CBLSPublicKey AggregateInsecure(const std::vector<CBLSPublicKey>& pks, bool fLegacy = fLegacyDefault);

    bool PublicKeyShare(const std::vector<CBLSPublicKey>& mpk, const CBLSId& id);
    bool DHKeyExchange(const CBLSSecretKey& sk, const CBLSPublicKey& pk);

};

class CBLSSignature : public CBLSWrapper<bls::G2Element, BLS_CURVE_SIG_SIZE, CBLSSignature>
{
    friend class CBLSSecretKey;

public:
    using CBLSWrapper::operator==;
    using CBLSWrapper::operator!=;
    using CBLSWrapper::CBLSWrapper;

    CBLSSignature() {}
    CBLSSignature(const CBLSSignature&) = default;
    CBLSSignature& operator=(const CBLSSignature&) = default;

    void AggregateInsecure(const CBLSSignature& o);
    static CBLSSignature AggregateInsecure(const std::vector<CBLSSignature>& sigs, bool fLegacy = fLegacyDefault);
    static CBLSSignature AggregateSecure(const std::vector<CBLSSignature>& sigs, const std::vector<CBLSPublicKey>& pks, const uint256& hash, bool fLegacy = fLegacyDefault);

    void SubInsecure(const CBLSSignature& o);

    bool VerifyInsecure(const CBLSPublicKey& pubKey, const uint256& hash, bool fStrict = true) const;
    bool VerifyInsecureAggregated(const std::vector<CBLSPublicKey>& pubKeys, const std::vector<uint256>& hashes) const;

    bool VerifySecureAggregated(const std::vector<CBLSPublicKey>& pks, const uint256& hash, bool fStrict = true) const;

    bool Recover(const std::vector<CBLSSignature>& sigs, const std::vector<CBLSId>& ids);
};

#ifndef BUILD_BITCOIN_INTERNAL
template<typename BLSObject>
class CBLSLazyWrapper
{
private:
    mutable std::mutex mutex;

    mutable std::vector<uint8_t> vecBytes;
    mutable bool bufValid{false};

    mutable BLSObject obj;
    mutable bool objInitialized{false};

    mutable uint256 hash;

public:
    CBLSLazyWrapper() :
        vecBytes(BLSObject::SerSize, 0)
    {
        // the all-zero buf is considered a valid buf, but the resulting object will return false for IsValid
        bufValid = true;
    }

    CBLSLazyWrapper(const CBLSLazyWrapper& r)
    {
        *this = r;
    }

    CBLSLazyWrapper& operator=(const CBLSLazyWrapper& r)
    {
        std::unique_lock<std::mutex> l(r.mutex);
        bufValid = r.bufValid;
        if (r.bufValid) {
            vecBytes = r.vecBytes;
        } else {
            std::fill(vecBytes.begin(), vecBytes.end(), 0);
        }
        objInitialized = r.objInitialized;
        if (r.objInitialized) {
            obj = r.obj;
        } else {
            obj.Reset();
        }
        hash = r.hash;
        return *this;
    }

    inline void Serialize(CSizeComputer& s) const
    {
        s.seek(BLSObject::SerSize);
    }

    template<typename Stream>
    inline void Serialize(Stream& s) const
    {
        std::unique_lock<std::mutex> l(mutex);
        if (!objInitialized && !bufValid) {
            throw std::ios_base::failure("obj and buf not initialized");
        }
        if (!bufValid) {
            vecBytes = obj.ToByteVector();
            bufValid = true;
            hash.SetNull();
        }
        s.write((const char*)vecBytes.data(), vecBytes.size());
    }

    template<typename Stream>
    inline void Unserialize(Stream& s)
    {
        std::unique_lock<std::mutex> l(mutex);
        s.read((char*)vecBytes.data(), BLSObject::SerSize);
        bufValid = true;
        objInitialized = false;
        hash.SetNull();
    }

    void Set(const BLSObject& _obj)
    {
        std::unique_lock<std::mutex> l(mutex);
        bufValid = false;
        objInitialized = true;
        obj = _obj;
        hash.SetNull();
    }
    const BLSObject& Get() const
    {
        std::unique_lock<std::mutex> l(mutex);
        static BLSObject invalidObj;
        if (!bufValid && !objInitialized) {
            return invalidObj;
        }
        if (!objInitialized) {
            obj.SetByteVector(vecBytes);
            if (!obj.CheckMalleable(vecBytes)) {
                bufValid = false;
                objInitialized = false;
                obj = invalidObj;
            } else {
                objInitialized = true;
            }
        }
        return obj;
    }

    bool operator==(const CBLSLazyWrapper& r) const
    {
        if (bufValid && r.bufValid) {
            return vecBytes == r.vecBytes;
        }
        if (objInitialized && r.objInitialized) {
            return obj == r.obj;
        }
        return Get() == r.Get();
    }

    bool operator!=(const CBLSLazyWrapper& r) const
    {
        return !(*this == r);
    }

    uint256 GetHash() const
    {
        std::unique_lock<std::mutex> l(mutex);
        if (!bufValid) {
            vecBytes = obj.ToByteVector();
            bufValid = true;
            hash.SetNull();
        }
        if (hash.IsNull()) {
            CHashWriter ss(SER_GETHASH, PROTOCOL_VERSION);
            ss.write((const char*)vecBytes.data(), vecBytes.size());
            hash = ss.GetHash();
        }
        return hash;
    }
};
typedef CBLSLazyWrapper<CBLSSignature> CBLSLazySignature;
typedef CBLSLazyWrapper<CBLSPublicKey> CBLSLazyPublicKey;
typedef CBLSLazyWrapper<CBLSSecretKey> CBLSLazySecretKey;
#endif

typedef std::vector<CBLSId> BLSIdVector;
typedef std::vector<CBLSPublicKey> BLSVerificationVector;
typedef std::vector<CBLSPublicKey> BLSPublicKeyVector;
typedef std::vector<CBLSSecretKey> BLSSecretKeyVector;
typedef std::vector<CBLSSignature> BLSSignatureVector;

typedef std::shared_ptr<BLSIdVector> BLSIdVectorPtr;
typedef std::shared_ptr<BLSVerificationVector> BLSVerificationVectorPtr;
typedef std::shared_ptr<BLSPublicKeyVector> BLSPublicKeyVectorPtr;
typedef std::shared_ptr<BLSSecretKeyVector> BLSSecretKeyVectorPtr;
typedef std::shared_ptr<BLSSignatureVector> BLSSignatureVectorPtr;

bool BLSInit();

#endif // DASH_CRYPTO_BLS_H
