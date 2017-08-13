# Introduction

libzerocoin is a C++ library that implements the core cryptographic routines of the Zerocoin protocol. Zerocoin is a distributed anonymous cash extension for Bitcoin-type (hash chain based) protocols. The protocol uses zero knowledge proofs to implement a fully decentralized coin laundry.

The Zerocoin protocol is provably secure and uses well-studied cryptographic primitives. For a complete description of the protocol, see our white paper published in the IEEE Security & Privacy Symposium (2013) below.

### WARNING
**THIS IS DEVELOPMENT SOFTWARE. WE DON'T CERTIFY IT FOR PRODUCTION USE. WE ARE RELEASING THIS DEV VERSION FOR THE COMMUNITY TO EXAMINE, TEST AND (PROBABLY) BREAK. IF YOU SEE SOMETHING, [SAY SOMETHING](https://github.com/Zerocoin/libzerocoin/issues)! IN THE COMING WEEKS WE WILL LIKELY MAKE CHANGES TO THE WIRE PROTOCOL THAT COULD BREAK CLIENT COMPATIBILITY. SEE [HOW TO CONTRIBUTE](https://github.com/Zerocoin/libzerocoin/wiki/How-to-contribute) FOR A LIST OF WAYS YOU CAN HELP US.**

### WARNING WARNING
**NO, SERIOUSLY. THE ABOVE WARNING IS NOT JUST BOILERPLATE. THIS REALLY IS DEVELOPMENT CODE AND WE'RE STILL ACTIVELY LOOKING FOR THE THINGS WE'VE INEVITABLY DONE WRONG. PLEASE DON'T BE SURPRISED IF YOU FIND OUT WE MISSED SOMETHING FUNDAMENTAL. WE WILL BE TESTING AND IMPROVING IT OVER THE COMING WEEKS.**

### WARNING WARNING WARNING

**WE'RE NOT JOKING. DON'T MAKE US PULL AN ADAM LANGLEY AND [TAKE AWAY THE MAKEFILE](https://github.com/agl/pond#pond).**

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
