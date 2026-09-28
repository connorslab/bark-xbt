# Paperclip Bark XBT experiment

This is a private, regtest-only port of Second's Bark. No production services,
wallets, or funds are used by the test workflow. Do not import a real seed.

## Starting points

- Bark: `3e1e4bf2e8594a1d1faa96dc953d0f8cd764ef8c` from
  <https://gitlab.com/ark-bitcoin/bark>.
- Consensus reference: Knots `v29.4.2.knots20260508rc2` unified-sighash
  documentation, reference vectors, and extended block-header implementation.
- Runtime test node: final `v29.4.2.knots20260508`, pinned by SHA256 in the workflow.
- Vendored rust-bitcoin 0.32.9 and lightning-types 0.3.1 retain their licenses
  and upstream package/source metadata.
- Vendored corepc-types 0.13.0 and bitcoincore-rpc-json 0.19.0 accept
  `difficulty_blake2b` as an RPC field alias. Their source archives were checked
  against the hashes in the upstream Cargo.lock before modification.

## Changes

The digest implementation uses the `UnifiedSighash` SHA256 tag, including the
five-byte locktime field and all required prevout commitments. It does not
replace transaction IDs, Taproot tweaks, MuSig, or Lightning payment hashes
with Blake2b. The digest primitive accepts the six standard unified selectors;
the Ark signing API deliberately permits only unified ALL, `0x21`.

Ark signatures remain 64-byte Schnorr signatures in its existing protocol
structures. Their on-chain witness form includes the extra `0x21` byte.
Boarding, virtual transaction trees, connectors, forfeits, offboarding, and
exit policies use the same digest implementation. Weight estimates account for
the extra witness byte.

The on-chain BDK signer supports the application's `tr(key)` descriptors. It
requires complete prevouts, checks key derivation and the output script, and
rejects unsupported signing modes. Signing is atomic on error. It never falls
back to BDK's BTC signer. Foreign pre-signed Ark inputs still require independent
consensus validation; witness suffix checks are not proof of authorization.

rust-bitcoin can decode and hash the 164-byte Blake2b header while preserving
historical 80-byte headers. RPC startup requires an activated regtest backend.
Both RPC clients accept the XBT difficulty field without assuming it is a
SHA-256 difficulty value. Existing internal field names remain unchanged.
Mainnet wallet startup and the unvalidated Esplora backend are rejected.
Knots must explicitly use `mempooltruc=enforce`: its default `accept` mode
rejects Bark's zero-fee parent transactions even in a funded package. The
startup checks reject this incompatible default. Tests keep
`acceptnonstdtxn=0` and the default minimum relay fee.

The backend also requires `subdustfeepenalty=0`. Knots' default penalty makes
the modified fee of a zero-value anchor transaction negative. Its ephemeral
transaction check then rejects that transaction because it requires both the
base fee and modified fee to be zero. The full emergency-exit test exposed this
conflict. The private fixture disables this additional fee penalty; it does
not disable standardness, signature validation, or minimum relay fees.
Knots does not expose this setting through `getmempoolinfo`, so the operator
must verify it in the node configuration. This port does not claim relay
compatibility with unchanged default-policy peers or miners. Production use
would require an agreed relay policy or a separate funded-anchor redesign.

The Ark protocol has a separate experimental version namespace. Lightning
invoice parsing recognizes identity bit 512, and outgoing payments and generated
hold invoices require that mandatory bit. Other unknown mandatory invoice bits
remain rejected. CLN owns peer/channel negotiation; this library is not a
replacement implementation of CLN's channel protocol.

Knots 29 lacks Core 31 mempool chunks. The adapter reports a conservative minimum
individual ancestor fee rate instead of crediting a low-fee transaction with a
high-fee parent that may confirm independently. This can cause extra bump
attempts. It is not an exact chunk estimate and requires workload testing.

## Private tests

Run the `XBT isolated validation` workflow in the private repository. The workflow
uses the upstream Nix environment and records its tested commit in GitHub Actions.

`testing/xbt_regtest.py` starts two temporary, disconnected localhost regtest
nodes. It copies pre-activation blocks so both nodes possess identical funding
outputs. It checks:

1. Unified digest results against Knots' standard reference vectors.
2. Wallet unified signing and atomic rejection of legacy signature requests.
3. Blake2b header decoding, hash, time, and serialization against Knots RPC.
   This includes 32 combinations of mining mode, time offset, and XOR mask.
4. A unified Taproot key spend accepted by XBT and rejected by BTC, alongside
   a BTC legacy control spend of the same funding output.
5. A real Ark BoardBuilder MuSig transaction, its CPFP child, and a delayed
   script-path exit claim with standard-transaction checks and explicit TRUC enforcement.

These are **test assertions, not a statement that the latest run passed**.
Consult the workflow result and `xbt-regtest-report.json` artifact. The report
contains transaction IDs and raw transactions using deterministic worthless
test keys. Regtest transaction IDs are not public-chain payments.

The workflow also builds the real client and server. It runs `xbt_lifecycle`
through `just int`. That test covers a board, a refresh round, an out-of-round
payment, an offboard, and an emergency exit with the server stopped. Its result
is separate from the consensus probe. Check both results.

## Release gates

Full client/server lifecycle, unilateral recovery after restart, hostile peers,
reorganizations, mainnet coinbase maturity, fee bumping under load, Lightning hold-plugin interoperability,
and all upstream tests remain separate gates. Upstream tests using the BTC
bitcoinkernel and old signature fixtures are not XBT consensus tests; they must
be ported without weakening their assertions. A library compile or passing
digest vectors does not establish that the complete service is safe.

The current port must not be presented as production ready or used for custody.
