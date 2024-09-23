## Claim Statement
Let $\mathsf{\ell_{Merkle}^{Sapling}, \ell_{PRFnfSapling}. \ell_{scalar}^{Sapling}, ValueCommit, SpendAuthSig, \mathbb{J}, \mathbb{J}^{(r)}, repr_{\mathbb{J}}},$ $q_\mathbb{J}, r_\mathbb{J}, h_\mathbb{J}, \mathsf{Extract_{\mathbb{J}^{(r)}} : \mathbb{{J}^{(r)} \rightarrow B^{[\ell_{MerkleSapling}]}}}$ be defined as in the original Sapling specification.
Furthermore let:
$\mathsf{\ell_{PRFnfsAlt} : \mathbb{N} := 256}$
$\mathsf{PRF^{nfsAlt}_{nk\star}(\rho\star) = BLAKE2s-256(''MASP\_alt'',\fbox{LESBS2OP_{256}(nk\star)}\framebox{LESBS2OP_{256}(\rho\star)})}$

A valid instance of $\mathsf{\pi_{Claim}}$ assures that given a _primary input_:

$$
\begin{align*}
& \mathsf{(rt : \mathbb{B}^{[\ell_{Merkle}^{Sapling}]},} \\
& \; \mathsf{cv^{Sapling} : ValueCommitment.Output,}\\
& \; \mathsf{nf_{Alt} : \mathbb{B}^{[\ell_{PRFnfsAlt}]},} \\
& \; \mathsf{rk : SpendAuthSig.Public)}  
\end{align*}
$$

the prover knows an _auxiliary input_:

$$
\begin{align}
& \mathsf{(path : \mathbb{B}^{[\ell_{Merkle}^{Sapling}][MerkleDepth^{Sapling}]},} \\
& \; \mathsf{pos : \{ 0..2^{MerkleDepth^{Sapling}} \},} \\
& \; \mathsf{g_d : \mathbb{J}, }\\
& \; \mathsf{pk_d : \mathbb{J}, }\\
& \; \mathsf{v^{Sapling} : \{ 0..2^{\ell_{value}} -1\} ,}\\
& \; \mathsf{rcv^{Sapling} : \{ 0..2^{\ell^{Sapling}_{scalar}} -1\} ,}\\
& \; \mathsf{cm^{Sapling} : \mathbb{J}, }\\
& \; \mathsf{rcm^{Sapling} : \{ 0..2^{\ell^{Sapling}_{scalar}} -1\} ,}\\
& \; \mathsf{\alpha : \{ 0..2^{\ell^{Sapling}_{scalar}} -1\} ,}\\
& \; \mathsf{ak : SpendAuthSig.Public ,}\\
& \; \mathsf{nsk : \{ 0..2^{\ell^{Sapling}_{scalar}} -1\} ,}\\
& \: \mathsf{path^{excl} ⦂ \mathbb{B}^{[\ell_{Merkle}^{Sapling}][MerkleDepth^{excl}]}},\\
& \; \mathsf{pos^{excl}} ⦂ \{ 0 .. 2^{\mathsf{MerkleDepth^{excl}}}\!-1 \},\\
& \; \mathsf{start} ⦂ \{ 0 .. 2^{\mathsf{MerkleDepth^{Sapling}}}\!-1 \},\\
& \; \mathsf{end} ⦂ \{ 0 .. 2^{\mathsf{MerkleDepth^{S}}}\!-1 \})\\
\end{align}
$$

Such that the following conditions hold:

**Note commitment integrity** $\hspace{0.5em} \mathsf{NoteCommit^{Sapling}_{rcm^{Sapling}}}(\mathsf{repr}_{\mathbb{J}}(\mathsf{g_d}), \mathsf{repr}_{\mathbb{J}}(\mathsf{pk_d}), \mathsf{v^{Sapling}} )$.


**Merkle path validity for** Either $\mathsf{v^{Sapling} = 0}$, or $\mathsf{(path, pos)} is a valid _Merkle Path_ of depth $\mathsf{MerkleDepth^{Sapling}}$, as defined in the original Sapling specification, from $\mathsf{cm_{u}=Extract_{\mathbb{J}^{(r)}}(cm^{Sapling})}$ to the _anchor_ $\mathsf{rt}$

**Value commitment integrity** $\hspace{0.5em} \mathsf{cv^{Sapling}} = \mathsf{ValueCommit^{Sapling}_{rcv}}(\mathsf{v^{Sapling}})$.

**Small order checks** $\hspace{0.5em} \mathsf{g_d}$ and $\mathsf{ak}$ are not  of small order, i.e. $[h_{\mathbb{J}}]\mathsf{g_d}\neq \mathcal{O}_{\mathbb{J}}$ and $[h_{\mathbb{J}}]\mathsf{ak}\neq \mathcal{O}_{\mathbb{J}}$.

**Nullifier Integrity** $\hspace{0.5em} \mathsf{nf^{Sapling} = PRF_{nk\star}^{nfSapling}(\rho\star)}$ where
$\hspace{2.5em} \mathsf{nk\star = repr_{\mathbb{J}}([nsk]\mathcal{H})}$
$\hspace{2.5em} \mathsf{\rho\star = repr_{\mathbb{J}}(MixingPedersenHash(cm^{Sapling}, pos))}$.

**Alternate Nullifier Integrity** $\hspace{0.5em} \mathsf{nf_{Alt} = PRF_{nk\star}^{nfsAlt}(\rho\star)}$

**Spend authority** $\hspace{0.5em} \mathsf{rk = SpendAuthoritySig.RandomizePublic(\alpha, ak )}$.

**Diversifier address integrity** $\hspace{0.5em} \mathsf{pk_d = [ivk]g_d}$ where
$\hspace{2.5em} \mathsf{ivk = CRH^{ivk}(ak\star,nk\star)}$
$\hspace{2.5em} \mathsf{ak\star = repr_\mathbb{J}(ak)}$.

**Merkle path validity for** $(\mathsf{start}, \mathsf{end}) \hspace{0.5em} (\mathsf{path^{excl}}, \mathsf{pos^{excl}})$ is a valid Merkle path of depth $\mathsf{MerkleDepth^{excl}}$, as defined in § 4.9 'Merkle Path Validity', from $\mathsf{excl}$ to the anchor $\mathsf{rt^{excl}}$, where $\mathsf{excl} = \mathsf{MerkleCRH^{Sapling}}(\mathsf{MerkleDepth^{excl}}, \mathsf{start}, \mathsf{end})$.

**Nullifier in excluded range** $\hspace{0.5em} \mathsf{start} \leq \mathsf{nf^{Sapling}} \leq \mathsf{end}$.

## Outoput Statement

The _Output Circuit_ is defined in § 0.12.3 'Output Statement (MASP)' of the Multi-Asset Shielded Pool Specification.

## Convert Statement

The _Convert Circuit_ is defined in § 0.12.5 'Convert Statement' of the Multi-Asset Shielded Pool Specification.
