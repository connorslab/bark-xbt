# XBT default-policy emergency exits

Status: experimental development branch `knots-default-exits`, not a release.
Funded board, shared-tree, and repeated-payment recovery passed a default-policy
Knots regtest at commit `aad3daba` in [run 36499238589](https://github.com/connorslab/bark-xbt/actions/runs/36499238589).
This result is the standalone transaction test, not the complete workflow result.
The test confirmed peer relay, recovery after a backend restart, and recovery
after another party consumed the public board anchor. An early CSV claim and
the old zero-fee parent were rejected as expected.

Wallet/server integration and default-policy lifecycle validation remain open.
The normal application still requires its previous special relay configuration;
the new constructors must not be confused with an enabled deployment feature.
Wallet recognition of parents without anchor children is a subsequent change
under test. Funded transaction creation, fee quotation, negotiation, automatic
broadcast and fee bumping, admission checks, and full lifecycle tests remain
necessary before enabling this profile.

## Recovery contract

An emergency exit must not require the Ark server to be online or to sign again.
The user confirmed that the normal Ark expiry deadline remains. A wallet that
stays offline past that deadline has no unconditional recovery guarantee.
This change does not attempt recovery after an indefinite offline period.

Even a protocol without expiry cannot guarantee transaction inclusion under
unbounded fees, censorship, or a chain halt.

## Target policy

Use the pinned Knots v29.4.2.knots20260508 binary from the existing XBT tests.
Retain its default minimum relay fee, TRUC accept mode, and subdust fee penalty.
Enable standardness on regtest with acceptnonstdtxn=0. Do not set
mempooltruc=enforce or subdustfeepenalty=0 in the new policy test fixture.
Retain XBT activation and private network isolation.

The existing fixture remains necessary to test recovery of the old signed
transaction format. Do not silently change its interpretation.

## Findings that determine scope

- bitcoin-ext/src/fee.rs creates zero-value P2A anchors.
- lib/src/vtxo/genesis.rs records anchor value in fee_amount. That field does not
  represent a miner fee. other_output_sum currently reconstructs input value
  from outputs alone.
- lib/src/tree/signed.rs funds tree leaves from user amounts and constructs
  zero-fee internal and leaf transactions.
- lib/src/arkoor/mod.rs requires input and output values to be equal. It also
  permits some sub-dust payments that cannot independently exit under default
  relay policy. Changing only boarding and round exits is insufficient.
- bark/src/exit/estimate.rs expects confirmed wallet UTXOs to fund CPFP and
  deducts the final claim fee from recovered value. A fee estimate does not
  reserve that money or enforce sufficient reserves.
- bark/src/config.rs has refresh and exit margins. A fixed margin does not
  prove that every possible ancestor chain can confirm before expiry.

## Transaction and accounting changes

1. Introduce an explicit versioned exit profile. Encode actual miner fees
   separately from fee-bump output values. Keep old decoders and recovery paths.
   Reject unknown profiles before any user signs or commits funds.
2. Give every transaction in the recovery path an individual baseline fee.
   Include board exits, tree nodes, leaves, transfer checkpoints, and transfer
   outputs. A child fee cannot repair an individually underfunded parent under
   the target policy.
3. Remove ephemeral dust from this profile. Check every output against its
   script-specific threshold. Reject payments or change outputs whose recovery
   paths depend on dust exceptions. Do not advertise those balances as
   independently recoverable.
4. Fund reserves before signatures are made. For each node:
   input value = child output values + fee-bump output value + miner fee.
   Include descendant reserves in child values. Use checked arithmetic and
   validate identical accounting on both client and server.
5. Charge new transfer recovery costs explicitly. Do not silently subtract them
   from a recipient's agreed amount. Define who owns unused reserves and prevent
   shared ancestors from being counted as multiple independent reserves.
6. Select a fee-bump construction after adversarial tests. A funded P2A output
   is anyone-can-spend; do not treat it as a protected reserve. A server-only
   key is unacceptable. A key-controlled alternative must preserve independent
   access for every participant in a shared tree.
7. Keep unified ALL signatures and replay-negative tests. Do not mutate signed
   parent transactions to add fees: their transaction IDs bind descendants.

## Recovery safeguards if expiry is retained

- Persist the full signed recovery chain before a payment is considered final.
  Test wallet-data backup and restore. Do not promise seed-only recovery unless
  the required transaction data can also be recovered without the server.
- Validate fee reserves, remaining lifetime, chain depth, and dust limits before
  accepting each new balance. Reject unsafe transitions without surrendering
  the prior recovery path.
- Calculate an exit deadline from the actual path and relative timelocks, with
  an explicit confirmation and reorg margin. Warn well before that deadline.
- Provide a monitored client-side exit path when refresh is unavailable. Such a
  process only operates while the client or an authorized monitor is running;
  it cannot protect a wallet that remains offline indefinitely.
- Keep extra fee-bump reserves distinct from spendable balance. Report the
  supported fee assumptions. No finite reserve covers all future fee policies.

## Required validation before a compatibility claim

Run the real client and server lifecycle against the unmodified target relay
defaults, with a second independently configured relay node and a miner node.
Do not use direct block construction to bypass mempool rejection.

Test board, refresh, transfer, cooperative withdrawal, and server-offline
emergency exit. Include multiple users with shared ancestors, repeated
transfers, minimum amounts, reserve exhaustion, and near-expiry refusal.
Verify user amounts and all reserve ownership after every transition.

Test competing anchor spends, insufficient and sufficient CPFP fees, mempool
eviction, process restart, recovery from persisted wallet data, and reorgs.
Test both normal and elevated relay/dust policies. Higher policies may require
refusal of new balances; they must not be described as universally supported.

Keep old signed positions recoverable under their original policy assumptions.
Require an explicit refresh for migration. Retain unified sighash enforcement
and BTC replay rejection throughout. Keep mainnet disabled until this work and
independent security review are complete.
