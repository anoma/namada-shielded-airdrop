## Binding Signature

Consistency of balance with the claim description and the output description which would be minted in the MASP pool is enforced by the _Airdrop Binding Signature_. Similarly to a standard MASP or Sapling transaction, this signature has a dual role:
* To prove that the total value claimed in NAM within the output descriptions respects the allowed conversion set with the _zatoshi_ allocated in the claim description.
* To prove that signer knew the randomness used for the Claim, Output and Convert _value commitments_, in order to prevent reply attacks.

Let $\mathbb{J}^{(r)}$ and $\mathbb{J}^{(r)*}$ be defined as in §5.4.9.3 'Jubjub' of the _Zcash Protocol Specification_. Following §5.4.8.3 'Homomorphic Pedersen commitments (Sapling and Orchard)' from the former specs we have:

$\mathsf{ValueCommit^{x} : ValueCommit^{Sapling}.Trapdoor \times {-\frac{r_{\mathbb{J}-1}}{2}..\frac{r_{\mathbb{J}-1}}{2}}\rightarrow ValueCommitment^{Sapling}.Output}$

$\mathsf{ValueCommit^{Sapling}}$ is the above function with:

* $\mathcal{R}^{\mathsf{Sapling}} = \mathsf{FindGroupHash^{\mathbb{J}^{(r)*}}(''{Zcash\\_cv}'', ''r'')}$
* $\mathcal{V}^{\mathsf{Sapling}} = \mathsf{FindGroupHash^{\mathbb{J}^{(r)*}}(''{Zcash\\_cv}'', ''v'')}$

$\mathsf{ValueCommit^{MASP}}$ is the above function with:

* $\mathcal{R}^{\mathsf{MASP}} = \mathsf{FindGroupHash^{\mathbb{J}^{(r)*}}(''{MASP\\_r\\\_\\\_}'', ''r'')}$
* $\mathcal{V}^{\mathsf{MASP}} \equiv \mathsf{ vb_{NAM} = abst_{\mathbb{J}}(PRF^{vcgMASP}(t_{NAM}))}$

Where $\mathsf{t_{NAM}}$ is the bytestring representing the NAM asset type.

$\mathsf{ValueCommit^{mint}}$ is the above function with:

* $\mathcal{R}^{\mathsf{MASP}}$
* $\mathcal{V}^{\mathsf{mint}} = \mathsf{[V_{MASP}]\mathcal{V}^{\mathsf{MASP}}+[V_{Sapling}]\mathcal{V}^{\mathsf{Sapling}}}$

where $\mathsf{V_{Sapling}}$ and $\mathsf{V_{MASP}}$ are defined in a _allowed conversion_ $\mathsf{{\{(A_{Sapling}, V_{Sapling}), (A_{MASP}, V_{MASP})\}}}$, as described in the _Multi Asset Shielded Pool Specification_ § 0.12.4 'Convert'.

Since the value commitments in Sapling and MASP use different random base, introduce the _Randomness Renormalization Factor_ $\mathcal{N} : \mathbb{J}^{(r)}$

$\mathcal{N} = \mathsf{[rcv^{Sapling}]\mathcal{R}^{\mathsf{MASP}}-[rcv^{Sapling}]\mathcal{R}^{\mathsf{Sapling}}}$

Suppose the transaction has:
* A _Claim description_ with value commitment $\mathsf{cv^{Sapling}}$, committing to value $\mathsf{v^{Sapling}}$ with randomness $\mathsf{rcv^{Sapling}}$ using $\mathsf{ValueCommit^{Sapling}}$
* An _Output description_ with value commitment $\mathsf{cv^{MASP}}$, committing to value $\mathsf{v^{MASP}}$ with randomness $\mathsf{rcv^{MASP}}$ using $\mathsf{ValueCommit^{MASP}}$
* A _Convert description_ with value commitment $\mathsf{cv^{mint}}$, committing to value $\mathsf{v^{mint}}$ with randomness $\mathsf{rcv^{mint}}$ using $\mathsf{ValueCommit^{mint}}$

Validators calculate the _airdrop transaction validating key_ as:
$\mathsf{bvk^{Airdrop} = cv^{Sapling}+cv^{mint}-cv^{MASP}+\mathcal{N}}$

The signer calculates the _airdrop transaction signing key_ as:
$\mathsf{bsk^{Airdrop} = rcv^{Sapling}+rcv^{mint}-rcv^{MASP}}$

In order to check for implementation faults, the signer SHOULD also check that
$\mathsf{bvk^{Airdrop} = BindingSig^{Airdrop}.DerivePublic(bsk)}$

Let $\mathsf{SigHash}$ be the _SIGHASH transaction hash_ as defined in [ZIP-243], not associated with an input, using the _SIGHASH type_ SIGHASH_ALL.

A validator checks balance by validating that $\mathsf{BindingSig^{Sapling}.Validate_{bvk^{Airdrop}}(SigHAsh, bindingSigAirdrop) = 1}.$