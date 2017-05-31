// Copyright (c) 2014 BctCoin Developers and Nigel Smart
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#include "cryptopp/sha3.h"
#include "schnorr.h"

void LoadSECP256r1Curve(Integer& q, ECP& ec, ECPPoint& G)
{
	// Load in curve secp256r1
	Integer p, a, b, Gx, Gy;

	// Create the group
	p = Integer("0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF");
	a = Integer("-3");
	b = Integer("0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B");
	q = Integer("0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551");
	Gx = Integer("0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296");
	Gy = Integer("0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5");

	ec = ECP(p, a, b);
	G = ECPPoint(Gx, Gy);
}

// generates new public and secret keys
void KeyGen(Integer& secretKey, Integer& publicKeyX, Integer& publicKeyY, AutoSeededRandomPool& rng)
{
	Integer q;
	ECP ec;
	ECPPoint G, Q;
	LoadSECP256r1Curve(q, ec, G);

	secretKey = Integer(rng, 256) % q;

	Q = ec.ScalarMultiply(G, secretKey);
	publicKeyX = Q.x;
	publicKeyY = Q.y;
}

// generates new public and secret keys
void PublicKeyGen(Integer secretKey, Integer& publicKeyX, Integer& publicKeyY)
{
	Integer q;
	ECP ec;
	ECPPoint G, Q;
	LoadSECP256r1Curve(q, ec, G);

	Q = ec.ScalarMultiply(G, secretKey);
	publicKeyX = Q.x;
	publicKeyY = Q.y;
}

Integer HashPointMessage(const ECP& ec, const ECPPoint& R,
	const byte* message, int mlen, bool compress = false)
{
	const int digestsize = 256/8;
	SHA3 sha(digestsize);

	int len = ec.EncodedPointSize();
	byte *buffer = new byte[len];
	ec.EncodePoint(buffer, R, compress);
	sha.Update(buffer, len);
	delete[] buffer;

	sha.Update(message, mlen);

	byte digest[digestsize];
	sha.Final(digest);
	
	Integer ans;
	ans.Decode(digest, digestsize);
	return ans;
}


void Sign(Integer& sigE, Integer& sigS, const Integer& secretKey,
	      const byte* message, int mlen, AutoSeededRandomPool& rng)
{
	Integer q,k;
	ECP ec;
	ECPPoint G, r;
	LoadSECP256r1Curve(q, ec, G);

	k = Integer(rng, 256) % q; // choose random k
	r = ec.ScalarMultiply(G, k); // r = G^k
	sigE = HashPointMessage(ec, r, message, mlen) % q; // e = H(M||r)
	sigS = (k - secretKey*sigE) % q;
}

bool Verify(const Integer& publicKeyX, const Integer& publicKeyY,
	        const Integer& sigE, const Integer& sigS,
	        const byte* message,int mlen)
{
	Integer q, sigEv;
	ECP ec;
	ECPPoint G, rv, Q;
	LoadSECP256r1Curve(q, ec, G);

	Q = ECPPoint(publicKeyX,publicKeyY); 
	rv = ec.CascadeScalarMultiply(G, sigS, Q, sigE); // r = G^s.Q^e

	sigEv = HashPointMessage(ec, rv, message, mlen) % q;
	return (sigE == sigEv);
}
