# XBT private regtest validation

Date: September 28, 2026.

Tested code: `1529339461a5d4e96574268ba9738bdfa5144e76`.

[GitHub Actions run](https://github.com/connorslab/bark-xbt/actions/runs/36493727834).

## Results

| Check | Result |
| --- | --- |
| Modified Ark library, wallet, and server compilation | Pass |
| Knots reference digest vectors and legacy-mode rejection | Pass |
| Two-input wallet signing, atomic rejection, and signature weight | Pass |
| Mandatory XBT invoice identity and unrelated unknown-bit rejection | Pass |
| Full block round trip and 32 Blake2b header variants | Pass |
| Unified spend accepted by XBT and rejected by BTC with the same funding outpoint | Pass |
| Ark MuSig exit, CPFP child, and delayed claim mined on XBT | Pass |
| Board, refresh, payment, cooperative offboard, and emergency exit with server stopped | Pass |

The targeted `xbt_lifecycle` integration test passed in 21.608 seconds.
The other 193 tests in the Bark integration binary were not run. This is not
a claim that the full upstream test suite passes.

The [consensus report](xbt-consensus-2026-09-28.json) contains transaction IDs
and raw transactions. Its `complete_server_test` field is false because the
probe does not run the server. The separate
[lifecycle log](xbt-lifecycle-2026-09-28.log) records the application test.
All transactions use disposable regtest bitcoin. No mainnet sats were spent.

## Required test-node policy

The test uses Knots `v29.4.2.knots20260508`, with the binary archive hash pinned
in the workflow. It explicitly enables:

```ini
acceptnonstdtxn=0
mempooltruc=enforce
subdustfeepenalty=0
```

Default minimum relay fees and consensus signature checks remain enabled.
The last two settings differ from Knots defaults. Default-policy peers and
miners are not proven to relay these exit packages. See the
[policy explanation and remaining release gates](../xbt-port.md).

This remains a regtest prototype. Real Lightning payments, hostile-peer
scenarios, reorganization recovery, and mainnet operation are not validated.
