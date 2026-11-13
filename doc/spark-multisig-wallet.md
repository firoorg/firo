# Spark multisig wallets

A Spark multisig wallet is a wallet whose Spark keys are held jointly by `n`
participants. Each of them sees the wallet's coins and can prepare transactions;
spending takes any `nrequired` of them. On chain, the wallet's addresses and
transactions look like any other Spark addresses and transactions.

This document describes the wallet RPCs and the choices this implementation makes
on top of the protocol in [spark-multisig.md](https://github.com/firoorg/firo/blob/816ff902704d778def1713bf340b37dfa0a45489/doc/spark-multisig.md).

## The flow, next to transparent multisig

| Step | Transparent multisig | Spark multisig |
| --- | --- | --- |
| Each cosigner provides a public key | `getnewaddress`, `validateaddress` | the same |
| Each cosigner adds the address | `addmultisigaddress nrequired keys` | `addsparkmultisigaddress nrequired keys [data]`, three passes |
| Fund it | send to the address | send or mint to the Spark address |
| Create a spend | `createrawtransaction` | `createsparkmultisigspend recipients` |
| Review it | `decoderawtransaction` | `decodesparkmultisigspend hex` |
| Each signer signs and passes it on | `signrawtransaction hex` | `approvesparkmultisigspend hex`, then `signsparkmultisigspend hex` |
| Broadcast once `complete` is true | `sendrawtransaction hex` | the same |

The extra passes exist because the participants generate the spend key together
and each keeps a share of it. With `nrequired` of 2 or more the key is never
assembled, neither at setup nor when signing. With `nrequired` 1 a share is the
key: every participant holds all of it, as that policy implies.

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
completed the third call and obtained the same address. The address is derived
from everything the participants exchanged, so those who obtained the same address
hold shares of the same key. A participant who was given other data than the rest,
by mistake or by someone trying to leave the others with shares that do not work
together, ends up with a different address.

The wallet must not hold Spark coins when it is set up, because it stops tracking
its previous Spark addresses. Use a new wallet. Its transparent keys and funds
are not affected. One wallet belongs to one group.

### Spending

```
A: createsparkmultisigspend '{"<address>":{"amount":1,"subtractFee":false}}'  -> {"hex": S0, "fee": ..., "id": ID}
A: approvesparkmultisigspend S0  -> {"hex": S1, "complete": false, "id": ID}    A approves
B: approvesparkmultisigspend S1  -> {"hex": S2, "complete": false, "id": ID}    B approves
B: signsparkmultisigspend S2     -> {"hex": S3, "complete": false, "id": ID}    B signs
A: signsparkmultisigspend S3     -> {"hex": TX, "complete": true, "id": ID}     A signs
   sendrawtransaction TX
```

A spend has exactly `nrequired` signers: the first participants to approve it.
Approving adds the signer's nonce commitment. Once all signers have approved,
each adds its signature share with `signsparkmultisigspend`. A spend passed along
a chain of signers travels there and back once. Signers working in parallel merge
their copies with `combinesparkmultisigspend` after approving and again after
signing. Creating, combining and decoding need no key, so any participant can
coordinate, with a locked wallet.

Approving and signing are separate calls, and what a call does never depends on
what the spend it is given already carries. `signsparkmultisigspend` signs a spend
only if this wallet approved it and it has not changed since. A signer that is
handed another transaction in place of the one it approved, by a cosigner or by
anyone who holds the view key, gets an error and signs nothing. Every result names
its spend by an `id`, the same for all copies of one spend, which lets the signers
tell each other, and their records, which spend they mean.

Review a spend with `decodesparkmultisigspend` before approving it. The preparer
of a spend is one of the parties the threshold is there to guard against, so the
wallet checks every spend against its own records before it shows, approves or
signs it: the inputs are coins of the wallet, every output pays the address and
amount the spend states and can be spent on its own (no two outputs share a serial
number), the amounts and fee balance, the transaction has no time lock, and the
signature shares it carries are valid. `decodesparkmultisigspend` shows what the
checks established, for a person or a policy engine to approve.

A signer keeps its nonce in memory between approving and signing, and discards it
before its signature share leaves the wallet. A signer that is restarted in
between can no longer sign that spend. Create the spend again in that case, and to
replace a signer who does not respond. An approval otherwise stands until the
wallet is restarted: there is no call to withdraw one.

### History

`approvesparkmultisigspend`, `signsparkmultisigspend` and
`combinesparkmultisigspend` record in the wallet where the Spark outputs of a
spend go, before anything is signed, and fail if that cannot be saved. The
wallet's transaction history shows the recipients from this record. The chain does
not carry them: a participant that took no part in a spend sees the transaction
and its total, but for an output to someone else the entry in `listtransactions`
and `gettransaction` has no address and an amount of 0. For a complete history,
pass that participant the spend, at any stage of signing, and have it call
`combinesparkmultisigspend` with it.

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

The same key that opens a spend also seals one, so a spend says nothing about who
made it or who changed it on the way. Whoever holds the view key can prepare a
spend, add to one, or put another in its place. This is why a signer goes by what
its own wallet establishes about a spend and not by where the spend came from.
What such a party can still do is get in the way: a spend with made-up approvals
of other signers costs a signer that signs it its nonce, and the spend has to be
created again.

The setup data shows whoever reads it the public keys of the participants and the
threshold. What it keeps secret can be opened with a participant key at any later
time: a recorded exchange together with that key gives away the participant's
share and the group's view key. Use a key that serves no other purpose, and keep
it as safe as the wallet.

A complete spend is broadcast with `sendrawtransaction`, which announces it to all
peers at once and not through Dandelion++, as the wallet's own spends are.

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
  decrypt shares made for the round one messages it holds itself.
- **View key.** The view key is the sum of the participants' contributions,
  weighted by hashes of the contributions and of all round one messages. No
  participant can choose it, and it commits to every coefficient commitment. This
  is what makes comparing addresses a check of the whole setup, and gives the
  consistent delivery of commitments that the protocol requires. Decrypting the
  shares would not: the calls keep no state, so a participant can be led through
  round two for more than one set of round one messages, and two sets can differ
  in nothing but the higher coefficients of one polynomial.
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
  to, and removed before the signature share is computed. A nonce that comes back
  with another transaction is kept for its own.
- **Untrusted view-key holders.** Every participant, and anyone given the view
  key, can make coins and spends that the wallet takes for the group's. The wallet
  treats what they choose as untrusted: the nonces and addresses of outputs, the
  fields of a transaction that its recipients and amounts do not determine, the
  entries of a spend, and the diversifier of a received coin, which moves the
  wallet's count of issued addresses only a bounded distance.

## Not included

- No GUI: the wallet shows balances and history, and spending is by RPC.
- A multisig wallet cannot register Spark names or sign messages with its Spark
  addresses, as both take the spend key.
- Nonces are not prepared in advance, so signing always takes two steps.
- Approvals do not expire and cannot be withdrawn, short of restarting the wallet.
- Spends and the entries signers add to them are not signed by a participant key.
- No repair or redistribution of key shares. To change the group, move the funds
  to a new wallet.
