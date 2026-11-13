# Spark multisig wallets

A Spark multisig wallet is a wallet whose Spark keys are held jointly by `n`
participants. Each of them sees the wallet's coins and can prepare transactions;
spending takes any `nrequired` of them. On chain, the wallet's addresses and
transactions look like any other Spark addresses and transactions.

This document describes the wallet RPCs and the choices this implementation makes
on top of the protocol in [spark-multisig.md](spark-multisig.md).

## The flow, next to transparent multisig

| Step | Transparent multisig | Spark multisig |
| --- | --- | --- |
| Each cosigner provides a public key | `getnewaddress`, `validateaddress` | the same |
| Each cosigner adds the address | `addmultisigaddress nrequired keys` | `addsparkmultisigaddress nrequired keys [data]`, three passes |
| Fund it | send to the address | send or mint to the Spark address |
| Create a spend | `createrawtransaction` | `createsparkmultisigspend recipients` |
| Review it | `decoderawtransaction` | `decodesparkmultisigspend hex` |
| Each signer signs and passes it on | `signrawtransaction hex` | `signsparkmultisigspend hex`, two passes |
| Broadcast once `complete` is true | `sendrawtransaction hex` | the same |

The extra passes exist because the spend key is generated jointly and is never
assembled, neither at setup nor when signing.

### Setup

Every participant runs the same call three times and sends the `hex` of each
result to all other participants:

```
addsparkmultisigaddress 2 '["<keyA>","<keyB>","<keyC>"]'                          -> {"complete": false, "hex": "<round 1>"}
addsparkmultisigaddress 2 '["<keyA>","<keyB>","<keyC>"]' '["<B round 1>","<C round 1>"]' -> {"complete": false, "hex": "<round 2>"}
addsparkmultisigaddress 2 '["<keyA>","<keyB>","<keyC>"]' '["<B round 2>","<C round 2>"]' -> {"complete": true, "address": "..."}
```

The order of the keys does not matter. The calls keep no state: repeating one
returns the same result, and the wallet has to be unlocked for them. The third
call stores the group's keys and stops the server, as `encryptwallet` does;
after a restart the wallet is the multisig wallet. From then on the call answers
with the address, and an unlocked wallet also returns its data again.

Before the address receives funds, the participants confirm that each of them
completed the third call and obtained the same address.

The wallet must not hold Spark coins when it is set up, because it stops tracking
its previous Spark addresses. Use a new wallet. Its transparent keys and funds
are not affected. One wallet belongs to one group.

### Spending

```
A: createsparkmultisigspend '{"<address>":{"amount":1,"subtractFee":false}}'  -> {"hex": S0, "fee": ...}
A: signsparkmultisigspend S0   -> {"hex": S1, "complete": false}    A commits
B: signsparkmultisigspend S1   -> {"hex": S2, "complete": false}    B commits and signs
A: signsparkmultisigspend S2   -> {"hex": TX, "complete": true}     A signs
   sendrawtransaction TX
```

A spend has exactly `nrequired` signers: the first participants to commit. A
signer's first call adds its nonce commitment; called again once all signers have
committed, it adds its signature share. The call that brings in the last
commitment does both, so a spend passed along a chain of signers travels there
and back once. Signers working in parallel merge their copies between the passes
with `combinesparkmultisigspend`. Creating, combining and decoding need no key,
so any participant can coordinate, with a locked wallet.

`signsparkmultisigspend` checks a spend against the signer's own wallet before it
signs: the inputs are coins of the wallet, every output pays the address and
amount the spend states, and the amounts and fee balance. `decodesparkmultisigspend`
shows the same, checked the same way, for a person or a policy engine to approve.

A signer keeps its nonce in memory between its two passes and discards it before
its signature share leaves the wallet. A signer that is restarted in between can
no longer sign that spend. Create the spend again in that case, and to replace a
signer who does not respond.

## What travels between the participants

All `hex` values can be sent over any channel. The setup data carries secrets only
in encrypted form, and a spend is encrypted as a whole with a key that derives
from the group's view key. What the participants have to establish themselves is
that the public keys they pass to `addsparkmultisigaddress` are authentic, as for
any multisig address.

A spend shows its holder what the transaction pays and, through the signing
transcript, which coins it consumes. Anyone who can read it therefore belongs to
those who may view the wallet, which is why it is encrypted to the group. That
includes anyone the group has given its view key (`dumpsparkviewkey`).

## Backup

The group's keys are stored in `wallet.dat`. The participant's share of the spend
key is stored encrypted to its participant key, which is an ordinary key of the
wallet and is protected by the wallet passphrase.

A backup of `wallet.dat` taken after the setup restores the multisig wallet. A
wallet restored from its mnemonic alone, or from an older backup, does not contain
the group's keys. Because the setup derives all of a participant's values from its
participant key, such a participant can rejoin: in a wallet that holds its
participant key and no Spark coins, it goes through the three setup calls again
with the data that all the others return again, and restarts with `-rescan` to find
the group's coins. This takes every other participant. As long as `nrequired`
participants have their wallets, the funds can also simply be moved.

## Implementation notes

These complete the protocol description where it leaves room.

- **Identifiers.** Participants are numbered `1..n` in the order of their
  compressed public keys.
- **Derived values.** A participant derives its polynomial coefficients and
  view key contributions from its participant secret key, the threshold and the
  list of participant keys. Shares are only ever encrypted to those keys, so a
  repeated round cannot hand out further points of a polynomial.
- **Rounds.** Round one carries the coefficient commitments, the proof of
  knowledge of the constant coefficient, and a hash commitment to the view key
  contributions. Round two carries, for each participant, its share and the view
  key contributions, encrypted under a key agreed between the two participant
  keys and bound to the hash of all round one messages. A participant can only
  decrypt shares made from the round one messages it holds itself, which gives the
  consistent delivery of commitments that the protocol requires.
- **Proof version.** Spends use the Chaum V2 proof, which proves every input
  separately under one challenge. The single-input signing of the protocol
  description is run once per input, with a nonce pair per input from each signer.
  The resulting proof is an ordinary V2 proof.
- **Binding factors.** The V2 challenge covers more than the binding hash and the
  statement: it also takes the cover set references, outputs, fee and transparent
  value directly. A signer's binding factors therefore commit to the value of the
  challenge function on everything except the proof commitments, together with
  all signers' nonce commitments for all inputs. Nothing the challenge depends on
  can then change without changing every binding factor, which is what keeps a
  cosigner from steering the challenge after seeing the commitments.
- **Nonces.** Sampled from the system's randomness mixed with a secret of the
  signer, never written to disk, tied to the same value the binding factors commit
  to, and removed before the signature share is computed.

## Not included

- No GUI: the wallet shows balances and history, and spending is by RPC.
- A multisig wallet cannot register Spark names or sign messages with its Spark
  addresses, as both take the spend key.
- Nonces are not prepared in advance, so signing always takes two passes.
- No repair or redistribution of key shares. To change the group, move the funds
  to a new wallet.
