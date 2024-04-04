# Namada Shielded Zcash Airdrop Prototype

This GitHub repo shows a proof-of-concept transaction validity check for the Namada shielded ZEC airdrop.

Please see [this blog post](https://forum.zcashcommunity.com/t/rfc-proposal-for-a-strategic-alliance-between-namada-and-zcash/44372) for historical context and [PROTOCOL.md](./PROTOCOL.md) for details on the protocol.

----

To run the demo, simply execute in the root of this repository:

```
cargo test
```

This runs two tests:
- one where there is a valid signature for the airdrop transaction (the amount of ZEC and NAM match)
- one where the transaction is not balanced and should be rejected
