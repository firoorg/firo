#ifndef FIRO_SPARK_KEYS_H
#define FIRO_SPARK_KEYS_H
#include "bech32.h"
#include "f4grumble.h"
#include "params.h"
#include "util.h"

namespace spark {

using namespace secp_primitives;

class SpendKey {
public:
	SpendKey(const Params* params);
    SpendKey(const Params* params, const Scalar& r_);
	const Params* get_params() const;
	const Scalar& get_s1() const;
	const Scalar& get_s2() const;
	const Scalar& get_r() const;

    SpendKey& operator=(const SpendKey& other);
    bool operator==(const SpendKey& other) const;

private:
	const Params* params;
	Scalar s1, s2, r;
};

class FullViewKey {
public:
	FullViewKey();
    FullViewKey(const Params* params);
	FullViewKey(const SpendKey& spend_key);
	const Params* get_params() const;
	const Scalar& get_s1() const;
	const Scalar& get_s2() const;
	const GroupElement& get_D() const;
	const GroupElement& get_P2() const;


    ADD_SERIALIZE_METHODS;
    template <typename Stream, typename Operation>
    inline void SerializationOp(Stream& s, Operation ser_action) {
        READWRITE(s1);
        READWRITE(s2);
        READWRITE(D);
        READWRITE(P2);
    }

private:
	const Params* params;
	Scalar s1, s2;
	GroupElement D, P2;
};

class IncomingViewKey {
public:
	IncomingViewKey();
    IncomingViewKey(const Params* params);
	IncomingViewKey(const FullViewKey& full_view_key);
	const Params* get_params() const;
	const Scalar& get_s1() const;
	const GroupElement& get_P2() const;
	uint64_t get_diversifier(const std::vector<unsigned char>& d) const;

private:
	const Params* params;
	Scalar s1;
	GroupElement P2;
};

class Address {
public:
    Address();
	Address(const Params* params);
	Address(const IncomingViewKey& incoming_view_key, const uint64_t i);
	const Params* get_params() const;
	const std::vector<unsigned char>& get_d() const;
	const GroupElement& get_Q1() const;
	const GroupElement& get_Q2() const;

	std::string encode(const unsigned char network) const;
	unsigned char decode(const std::string& str);

private:
	const Params* params;
	std::vector<unsigned char> d;
	GroupElement Q1, Q2;

	static std::string get_checksum(const std::string data);
};

}

#endif
