# A protocol to Air-drop shielded Namada native token to Zcash Shielded Assets holders

### Recap of the shielded-airdrop goal

Both Zcash and Namada are chains that allow shielded transactions using a shielded pool. Zcash comes with multiple pools, that differ in technical implementation but share the same privacy goal. Namada comes with a pool (called Multi Asset Shielded Pool, or MASP in short) which, in a nutshell, generalizes Zcash's pool design allowing assets of different nature to coexist and be transferred within the same pool. 
Here I am going to introduce a protocol that targets those who have a wallet with a shielded Sapling address holding shielded zcash assets. The invitation for them is to open a Namada wallet: so that following a few steps, they can end up with an airdrop reward in Namada native token (NAM) directly in their Namada shielded address.
The protocol design guarantees that the amount of assets held in shielded zcash, and amount of the reward claimed _remain shielded_ during the entire process: what was shielded never gets revealed. 
The only additional requirement for the actor holding shielded ZEC, is that assets has to be in their wallet prior to a fixed moment in time, which we refer to as the snapshot block height. 
The airdrop protocol gives a reward linear in the amount of ZEC that gets involved in the process. So the more ZEC gets used, the higher the NAM reward.
The protocol design envisions a collaboration with Zcash wallets which support a "claim shielded NAM" feature. Users would insert their Namada Shielded Address in to the Zcash wallet extension together with information about the ZEC they want to use for the airdrop, and this would allow them to claim the airdrop reward from their Namada wallet. This approach reduces the trust requirements that Zcash user have towards the Namada developed airdrop tool, as they would not have to input their secret keys in a new tool; keeping the protocol compliant to principles of least authority.

It should be noted that even if the transaction that gives the airdrop reward is shielded, it still will be possible to differentiate it from other shielded transactions going around the pool. This has the positive side effect to easily allow us (airdrop designers) to put a time limit for claiming the airdrop.

## Transaction between Zcash Sapling and Namada MASP
The MASP has a built-in feature that allows a burn-and-mint like process to convert a shielded asset of a given type, to an asset of different type. This is achieved using a _Convert description_ that through a fixed (as in: decided by the governance of the Namada chain) convert ratio, effectively transforms MASP notes into new ones of different type. We can use the same design for a shielded airdrop between Zcash and Namada: transforming a zcash note into a MASP one. This transformation is possible since MASP notes can be interpreted as a generalization of Sapling note, or equivalently a Sapling note can be interpreted as a MASP note of fixed type.
### Set up
The MASP is implemented as a Validity Predicate in Namada, and as a consequence it has its own Namada address. To set up the protocol, we store within the MASP address and the zcash wallet the Sapling commitment tree at the snapshot block height as well as the related nullifier set at that moment. We should distinguish which notes in the commitment tree have been nullified; we can do this dynamically as ZEC are used to claim NAM. We assume having in the MASP address and the Zcash wallet:
* $\mathsf{NoteCommit^{Sapling}}$: the note commitment tree. We refer to the root $\mathsf{rt^{Sapling}}$ of this commitment tree as the _anchor_.
* $\mathsf{nf^{Sapling}}$: the nullifier set  associated with $\mathsf{NoteCommit^{Sapling}}$ at that height.

As we will see later, some secret information has to be shared between the two wallets for constructing successful transactions. There are many ways to create secret communication channels between the wallets, but for the sake of simplicity we can think of the user having the two wallets app open on their local machine and just "copy and pasting" all the needed information from one wallet to the other. 

### Within the Zcash wallet 
The Zcash wallet will:
1. Create a _Spend description_ of the notes they want to use to claim the airdrop reward. To do so, they generate a proof of the _Spend Statement_ $\mathsf{\pi^{Sapling}_ZKSpend},$  as described in the Zcash specs. Just like they would if they were creating a transaction. 
2. Compute the corresponding value commitment, defined as: $\mathsf{cv^{Sapling} = [v^{Sapling}]vb^{Sapling} +[rcv^{Sapling}]}\mathcal{R}^{\mathsf{Sapling}}$
3. Send to the Namada wallet the Spend Description, the value commitment and (secretly) the randomness used for the value commitment $\mathsf{rcv^{Sapling}}$.

As we are within a Zcash wallet, all the information needed for creating $\mathsf{\pi^{Sapling}_ZKSpend}$ are at hand. The $\mathsf{\pi^{Sapling}_ZKSpend}$ generated needs to be constructed using the note commitment tree at the snapshot time. This allows users that had the note at the snapshot time, but later spent it, to claim the airdrop reward, as long as they are still in possession of the relevant information.

### Within the Namada wallet
The Namada wallet will:
1. verify the validity of the _Spend Statement_. The verification of a Sapling _Spend Statement_ differs slightly from the verification of MASP _spend circuit_, so the MASP VP would have implemented inside a Sapling verifier.
2. checks if the root referred to in $\mathsf{\pi^{Sapling}_ZKSpend}$ corresponds to the root it stores. 
3. Check if the nullifier for the spend note is already present in the nullifier set. If present, it gets added to the set; if missing, the airdrop protocol is aborted.
5. Creates an Airdrop Transaction as described in the following paragraph.

### Building the Airdrop Transaction validity
We now have to construct a valid transaction. We do so by using the convert circuit. We distinguish two asset types:
* $A_{Sapling}$, corresponding to the Sapling note
* $A_{NAM}$, corresponding to the NAM reward

We assume that the value base for a NAM $vb_{NAM}$ has already been defined according the MASP specifications. We define an _allowed conversion_ ${\{(A_{Sapling}, V_{Sapling}), (A_{NAM}, V_{NAM})\}}$ between the Sapling note to claim the airdrop and the NAM reward. ${V_{Sapling}}$ and $V_{NAM}$ set the conversion rate. For instance we can set $V_{Sapling} = -1$ and $V_{NAM} = 1$ and  to convert 1 ZEC into 1 NAM.
We call $\mathsf{vb^{NAM}}$ the asset generator for the NAM reward, and we use the Sapling value base as asset generator for the Sapling note. We refer to it as $\mathsf{vb^{Sapling}}$. We can now construct the asset generator for the conversion as:
$vb^{mint} = [V_{NAM}]vb^{NAM}+[V_{Sapling}]vb^{Sapling}$

We define:

- $\mathcal{R}^{\mathsf{Sapling}} = \mathsf{FindGroupHash^{\mathbb{J}^{(r)*}}(''Zcash\_cv'', ''r'')}$
- $\mathcal{R}^{\mathsf{MASP}} = \mathsf{FindGroupHash^{\mathbb{J}^{(r)*}}(''MASP\_\_r\_'', ''r'')}$
- $\mathsf{cv^{NAM} = [v^{NAM}h_{\mathbb{J}}]vb^{NAM} +[rcv^{NAM}]}\mathcal{R}^{\mathsf{MASP}}$
- $\mathsf{cv^{mint} = [v^{mint}h_{\mathbb{J}}]vb^{mint} +[rcv^{mint}]}\mathcal{R}^{\mathsf{MASP}}$

The transaction build for the Airdrop would be made of:
1. Sapling Spend description
2. MASP Output description 
3. Convert description
4. Randomness renormailzation factor $\mathsf{\mathcal{N} = [rcv^{Sapling}]\mathcal{R}^{MASP} - [rcv^{Sapling}]\mathcal{R}^{Sapling} }$

Note that at this point within the Namada wallet there is all the information needed to create a transaction: 1 & 2 come from the secret information channel with the Zcash wallet ($\mathsf{rcv^{Sapling}}$ is the randomness mentioned earlier) ; 2 & 3 can be generated locally.

### Checking the transcation validity
Using the value commitments from the _Sapling Spend Description_, _MASP Ouput Description_ and _Convert Description_, togherer with $\mathcal{N}$ validators can compute the transacrion binding validating key $\mathsf{bvk^{Airdrop} = cv^{Sapling}+cv^{mint} - cv^{NAM} + \mathcal{N}}$; which is equivalent to:

$\mathsf{bvk^{Airdrop} =[v^{Sapling}+V_{Sapling}v^{mint}]vb^{Sapling}+[V_{NAM}v^{mint}-v^{NAM}]vb^{NAM}+[rcv^{Sapling} +rcv^{mint}-rcv^{NAM}]\mathcal{R}^{MASP}}$
And opens to $0$ if the transaction was built correctly. 
The signer of the transaction knows $\mathsf{rcv^{Sapling}}$, $\mathsf{rcv^{NAM}}$, $\mathsf{rcv^{mint}}$. With this information they compute the signing key $\mathsf{bsk^{Airdrop}}$:
$\mathsf{bsk^{Airdrop} = rcv^{Sapling} +rcv^{mint}-rcv^{NAM}}$
Similarly to the Sapling design, a binding signature here proves knowledge of the discrete logarithm $\mathsf{bsk^{Airdrop}}$ of $\mathsf{bvk^{Airdrop}}$ with respect to $\mathcal{R}^{MASP}$: $\mathsf{bvk^{Airdrop} = [bsk^{Airdrop}]\mathcal{R}^{MASP}}$. 

## Conclusions 

Thanks to the flexibility that comes from the usage of  the convert circuit, this protocol guarantees a shielded reward which never requires sharing secret keys to external tools. At the cost of needing some degree of involvement from the user. The main novelty in the transaction construction is the presence of the Randomness renormalization factor. 

