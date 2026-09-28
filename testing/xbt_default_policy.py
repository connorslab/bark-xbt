"""Funded board recovery through a separate default-policy Knots relay.

This is a library-level experiment, not the full Bark wallet/server lifecycle.
All keys and chains are disposable regtest fixtures.
"""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import time

from xbt_regtest import Node, probe


def wait_for(check):
    for _ in range(120):
        if check():
            return
        time.sleep(0.5)
    raise RuntimeError("private peer did not relay within 60 seconds")


def main():
    nodes = []
    report = {"scope": "funded board recovery only; wallet integration pending",
              "mainnet_sats_spent": 0, "complete_server_test": False}
    try:
        with tempfile.TemporaryDirectory(prefix="paperclip-default-policy-") as directory:
            root = Path(directory)
            binary = os.environ["XBT_BITCOIND"]
            report["xbt_binary_sha256"] = hashlib.sha256(Path(binary).read_bytes()).hexdigest()
            common = ["-testactivationheight=blake2b@120", "-networkactive=1", "-listen=1",
                      "-listenonion=0", "-natpmp=0", "-upnp=0"]
            xbt = Node(root, "xbt", binary, 18943,
                       common + ["-bind=127.0.0.1:18945", "-port=18945"])
            nodes.append(xbt)
            relay = Node(root, "relay", binary, 18944,
                         common + ["-bind=127.0.0.1:18946", "-port=18946"])
            nodes.append(relay)
            btc = Node(root, "bootstrap", os.environ["BITCOIND_EXEC"], 18947, [])
            nodes.append(btc)
            for node in [xbt, relay]:
                assert node.rpc("getmempoolinfo")["truc_policy"] == "accept"
            btc.rpc("createwallet", "test")
            miner = btc.rpc("getnewaddress", wallet=True)
            btc.rpc("generatetoaddress", 110, miner)
            addresses = probe("addresses")
            funding_id = btc.rpc("sendmany", "", {
                addresses["key"]: 0.001, addresses["board"]: 0.001}, wallet=True)
            btc.rpc("generatetoaddress", 1, miner)
            funding = btc.rpc("gettransaction", funding_id, wallet=True)["hex"]
            for height in range(1, 112):
                block = btc.rpc("getblock", btc.rpc("getblockhash", height), 0)
                for node in [xbt, relay]:
                    assert node.rpc("submitblock", block) is None
            relay.rpc("addnode", "127.0.0.1:18945", "onetry")
            wait_for(lambda: len(relay.rpc("getpeerinfo")) == 1)
            xbt.rpc("generatetoaddress", 20, miner)
            wait_for(lambda: relay.rpc("getbestblockhash") == xbt.rpc("getbestblockhash"))

            old = probe("sign", funding)
            rejected = xbt.rpc("testmempoolaccept", [old["board"]])[0]
            assert not rejected["allowed"], rejected
            report["legacy_parent_rejected"] = rejected

            # Signing finishes before any withdrawal is broadcast. No server
            # process or RPC participates in the following recovery steps.
            txs = probe("funded", funding)
            report["transactions"] = txs
            accepted = xbt.rpc("testmempoolaccept", [txs["board"]])[0]
            assert accepted["allowed"], accepted
            report["standalone_parent_acceptance"] = accepted
            board_id = xbt.rpc("sendrawtransaction", txs["board"])
            wait_for(lambda: board_id in relay.rpc("getrawmempool"))

            # The anchor is public. Another spender taking it must not remove
            # the user's already-funded recovery path.
            anchor_id = xbt.rpc("sendrawtransaction", txs["cpfp"])
            wait_for(lambda: anchor_id in relay.rpc("getrawmempool"))
            early = relay.rpc("testmempoolaccept", [txs["claim"]])[0]
            assert not early["allowed"], early
            report["early_claim_rejected"] = early
            blocks = relay.rpc("generatetoaddress", 7, miner)
            wait_for(lambda: xbt.rpc("getbestblockhash") == relay.rpc("getbestblockhash"))
            claim = xbt.rpc("testmempoolaccept", [txs["claim"]])[0]
            assert claim["allowed"], claim
            claim_id = xbt.rpc("sendrawtransaction", txs["claim"])
            wait_for(lambda: claim_id in relay.rpc("getrawmempool"))
            blocks += relay.rpc("generatetoaddress", 1, miner)
            included = {txid for block in blocks for txid in relay.rpc("getblock", block)["tx"]}
            assert {board_id, anchor_id, claim_id}.issubset(included)
            report["confirmed_txids"] = {"board": board_id, "anchor": anchor_id, "claim": claim_id}
            report["default_policy_peer_relay"] = True
            report["passed"] = True
            for node in reversed(nodes):
                node.stop()
            nodes.clear()
    except Exception as exc:
        report["passed"] = False
        report["error"] = str(exc)
        raise
    finally:
        for node in reversed(nodes):
            try:
                node.stop()
            except Exception:
                node.proc.terminate()
        Path("xbt-default-policy-report.json").write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
