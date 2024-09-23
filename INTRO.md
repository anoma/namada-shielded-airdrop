Both Zcash and Namada are chains that allow shielded transactions using a shielded pool. Zcash comes with multiple pools, that differ in technical implementation but share the same privacy goal. Namada comes with a pool (called Multi Asset Shielded Pool, or MASP in short) which, in a nutshell, generalizes Zcash's pool design allowing assets of different nature to coexist and be transferred within the same pool.
Here I am going to introduce a protocol that targets those who have a wallet with a shielded Sapling address holding shielded zcash assets. The invitation for them is to open a Namada wallet: so that following a few steps, they can end up with an airdrop reward in Namada native token (NAM) directly in their Namada shielded address.
The protocol design guarantees that the amount of assets held in shielded zcash, and amount of the reward claimed _remain shielded_ during the entire process: what was shielded never gets revealed.
The only additional requirement for the actor holding shielded ZEC, is that assets has to be in their wallet prior to a fixed moment in time, which we refer to as the snapshot block height.
The airdrop protocol gives a reward linear in the amount of ZEC that gets involved in the process. So the more ZEC gets used, the higher the NAM reward.
The protocol design envisions a collaboration with Zcash wallets which support a "claim shielded NAM" feature. Users would insert their Namada Shielded Address in to the Zcash wallet extension together with information about the ZEC they want to use for the airdrop, and this would allow them to claim the airdrop reward from their Namada wallet. This approach reduces the trust requirements that Zcash user have towards the Namada developed airdrop tool, as they would not have to input their secret keys in a new tool; keeping the protocol compliant to principles of least authority.

It should be noted that even if the transaction that gives the airdrop reward is shielded, it still will be possible to differentiate it from other shielded transactions going around the pool. This has the positive side effect to easily allow us (airdrop designers) to put a time limit for claiming the airdrop.