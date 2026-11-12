# Spark threshold multisignature

Spark's multisignature construction allows any threshold of `t` participants in a
group of `n` to authorize a spend. Each participant holds a share of the spend key
and the group's full view key. They can independently scan the wallet, derive
addresses and prepare transactions; spending requires cooperation from `t` signers.
The spend key does not need to be reconstructed during signing.

This document summarizes Section 5 of the [Lelantus Spark paper][spark], with its
challenge-exponent correction. It describes the protocol design, not the
availability of a wallet feature or a complete wire specification. The signing
equations below illustrate one input; multiple-input proofs must follow the
matching Spark proof-version specification.

## Keys and participants

Participants agree on the threshold (`1 <= t <= n`), group parameters and distinct, nonzero
participant identifiers. Identifiers remain fixed when selecting a signing subset.
Scalars are in the prime-order group's scalar field; `F`, `G`, `H` and `U` are
Spark's independent group generators. Hash functions use their prescribed,
separate domains and consistent input encodings.

| Material | Who holds it | Purpose |
| --- | --- | --- |
| Spend-key share $r_\alpha$ | Participant $\alpha$ only | Produce an authorization share |
| Full view key $(s_1,s_2,D,P_2)$ | Every participant | Identify received coins, detect spends and prepare transactions |
| Verification share $Y_\alpha=r_\alpha G$ | The signing group | Verify participant $\alpha$'s response |
| Spend key $r$, where $D=rG$ | Distributed across participants | Joint spending authority |

The threshold controls spending authority. All participants have wallet visibility.

## Distributed key generation

Key generation follows a FROST-style distributed, verifiable Shamir sharing process:

1. Each participant $\alpha$ samples a polynomial $f_\alpha(x)$ of degree at most
   $t-1$, commits to its coefficients as $C_{\alpha,j}=a_{\alpha,j}G$, and supplies
   a Schnorr proof of knowledge of the constant coefficient $a_{\alpha,0}$.
2. Participants distribute the coefficient commitments consistently and verify
   the proofs. Each also shares two nonzero view-key contributions with the group.
3. Participant $\alpha$ privately sends $f_\alpha(\beta)$ to each participant
   $\beta$. The recipient verifies the share against the coefficient commitments:

   $$
   f_\alpha(\beta)G=\sum_{j=0}^{t-1}\beta^j C_{\alpha,j}.
   $$

4. Each participant combines its received shares with its own polynomial evaluation.
   The group derives the common spend-key commitment:

   $$
   r_\beta=\sum_{\alpha=1}^{n}f_\alpha(\beta),
   \qquad D=\sum_{\alpha=1}^{n}C_{\alpha,0}.
   $$

5. Participants derive $s_1$ and $s_2$ using the paper's hash-weighted aggregation
   of the ordered view-key contributions, then compute $P_2=s_2F+D$.

Each participant obtains the same full view key and can derive ordinary Spark
addresses. Before accepting deposits, participants confirm that key generation
completed successfully and that they agree on the parameters, coefficient
commitments and view-key contributions ordered by participant identifier.

## Nonce preparation

For each future input authorization, every signer independently samples fresh
nonzero scalars $d_\alpha,e_\alpha$ and shares their commitments:

$$
D_\alpha=d_\alpha G,\qquad E_\alpha=e_\alpha G.
$$

The scalar nonces remain private to their owner. Commitments are exchanged within
the viewing group and checked for valid, nonidentity group elements. Nonce pairs
can be prepared in advance, but each pair is used for only one authorization.
Implementations consume nonce state atomically and durably before releasing a
response and never reuse it after an abort, retry or restored backup.

## Transaction preparation and signing

Any participant can use the full view key to prepare the inputs, outputs,
membership proofs and balance proof. The selected signers agree on the transaction
and independently check its recipients, amounts and fee. The transaction binding
value $\mu$ commits to the transaction context required by the proof specification.

For the single-input example, let $s$ be the nonzero recovered coin serial number
and set:

$$
h=H_{\mathrm{ser}'}(s,D),\qquad
S'=sF+D-hH,\qquad T=(U-D)/s.
$$

Here $S'$ is the serial commitment offset and $T$ is the linking tag. Let $I$ be
the selected set of `t` original participant identifiers and let $L$ be its
canonically ordered list of $(\alpha,D_\alpha,E_\alpha)$ nonce commitments.
Each signer computes:

$$
\rho_\alpha=H_\rho(L,\alpha,\mu,S',T),\qquad
a=H_F((\rho_\alpha)_{\alpha\in I}),\qquad
b=H_H((\rho_\alpha)_{\alpha\in I}).
$$

The signers form the proof commitments:

$$
R=\sum_{\alpha\in I}(D_\alpha+\rho_\alpha E_\alpha),\qquad
A_1=aF+R+bH,\qquad A_2=aT+R.
$$

They derive the Fiat-Shamir challenge $c$ from the prescribed Spark proof
transcript, including the transaction binding, statement and proof commitments.
Signer $\alpha$ computes its interpolation coefficient and response share:

$$
\lambda_\alpha=\prod_{\beta\in I\setminus\{\alpha\}}
\frac{\beta}{\beta-\alpha},\qquad
z_\alpha=d_\alpha+\rho_\alpha e_\alpha+c\lambda_\alpha r_\alpha.
$$

The group verifies each response using the verification share derived from the
DKG commitments:

$$
z_\alpha G=D_\alpha+\rho_\alpha E_\alpha+c\lambda_\alpha Y_\alpha.
$$

If all shares are valid, the final responses are:

$$
t_1=a+cs,\qquad t_2=\sum_{\alpha\in I}z_\alpha,\qquad t_3=b-ch.
$$

The resulting authorization proof satisfies the ordinary single-input equations:

$$
A_1+cS'=t_1F+t_2G+t_3H,\qquad A_2+cU=t_1T+t_2G.
$$

The completed transaction is verified and broadcast normally. The transaction
proof does not need to publish the participant list, threshold or individual
response shares. A selected signer can prevent completion by withholding its
response; retrying with another subset requires fresh nonces.

With nonce commitments exchanged and the transaction agreed, authorization needs
one exchange of response shares.

## Communication assumptions and scope

Participants authenticate one another, deliver DKG commitments consistently, and
protect private shares and off-chain signing transcripts with confidential
channels. A coordinator that sees the complete signing transcript belongs within
the wallet's viewing trust boundary. An external relay can carry encrypted
messages. These are implementation requirements of the protocol.

In the paper's Section 5.3, the input index starts at zero, so its witness-response
factors must read $c^{u+1}$ rather than $c^u$ to agree with Appendix A. For the
single-input example above, the factor is therefore $c$. This notation correction
does not specify a multi-input adapter for later Spark proof versions; their
transcript, response layout and verification rules remain authoritative.

The paper bases the threshold construction on MuSig and FROST techniques and
defers a complete security analysis of the combined construction. This overview
does not extend the security claims of those underlying schemes.

## References

- [Lelantus Spark: Secure and Flexible Private Transactions][spark], Sections 4-5
  and Appendix A.
- [FROST: Flexible Round-Optimized Schnorr Threshold Signatures][frost], especially
  the distributed key-generation and commitment-consistency requirements.

[spark]: https://eprint.iacr.org/2021/1173
[frost]: https://cypherpunks.ca/~iang/pubs/frost-sac20.pdf
