# Introduction

libzerocoin is a C++ library that implements the core cryptographic routines of the Zerocoin protocol. Zerocoin is a distributed anonymous cash extension for Bitcoin-type (hash chain based) protocols. The protocol uses zero knowledge proofs to implement a fully decentralized coin laundry.

The Zerocoin protocol is provably secure and uses well-studied cryptographic primitives. For a complete description of the protocol, see our white paper published in the IEEE Security & Privacy Symposium (2013) below.

# Overview of the Library

libzerocoin implements the core cryptographic operations of Zerocoin. These include:

1. Parameter generation
2. Coin generation ("Minting")
3. Coin spending (generation of a zero knowledge proof)
4. Accumulator calculation
5. Coin and spend proof verification

This library does _not_ implement the full Zerocoin protocol. In addition to the above cryptographic routines, a full Zerocoin implementation requires several specialized Zerocoin messages, double spending checks, and some additional coin redemption logic that must be supported by all clients in the network. libzerocoin does not provide routines to support these functions, although we do provide an overview on the [Integrating with Bitcoin clients](https://github.com/Zerocoin/libzerocoin/wiki/Integrating-with-bitcoin-clients) page.

# Outside links

* [Zerocoin Project website](http://zerocoin.org/)
* [Zerocoin Paper](http://zerocoin.org/media/pdf/ZerocoinOakland.pdf)
