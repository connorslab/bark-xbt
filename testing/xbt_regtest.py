"""Isolated consensus/relay test. No production RPC, wallets or network peers."""
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

PROBE = str(Path("target/debug/xbt-probe").resolve())
REPORT = Path("xbt-regtest-report.json")


def probe(mode, data=""):
    return json.loads(subprocess.check_output([PROBE, mode], input=data, text=True))


class Node:
    def __init__(self, root, name, binary, port, extra):
        self.data = root / name
        self.data.mkdir(mode=0o700)
        self.port = port
        self.log = (self.data / "process.log").open("w")
        args = [binary, f"-datadir={self.data}", "-regtest", "-server", "-listen=0",
                "-connect=0", "-dnsseed=0", "-discover=0", "-networkactive=0",
                "-rpcbind=127.0.0.1", f"-rpcport={port}", "-dbcache=64", "-par=1",
                "-acceptnonstdtxn=0", "-fallbackfee=0.00002", *extra]
        self.proc = subprocess.Popen(args, stdout=self.log, stderr=subprocess.STDOUT)
        for _ in range(120):
            try:
                assert self.rpc("getblockchaininfo")["chain"] == "regtest"
                assert self.rpc("getnetworkinfo")["connections"] == 0
                return
            except Exception:
                if self.proc.poll() is not None:
                    raise RuntimeError((self.data / "process.log").read_text())
                time.sleep(0.25)
        raise RuntimeError("private regtest failed to start")

    def rpc(self, method, *params, wallet=False):
        auth = base64.b64encode((self.data / "regtest/.cookie").read_bytes().strip()).decode()
        req = urllib.request.Request(f"http://127.0.0.1:{self.port}/" + ("wallet/test" if wallet else ""),
            json.dumps({"id": 1, "method": method, "params": params}).encode(),
            {"Authorization": "Basic " + auth, "Content-Type": "application/json"})
        try:
            response = urllib.request.urlopen(req, timeout=60)
        except urllib.error.HTTPError as exc:
            response = exc
        with response:
            value = json.load(response)
        if value.get("error"):
            raise RuntimeError(f"{method}: {value['error']}")
        return value["result"]

    def stop(self):
        try:
            self.rpc("stop")
        finally:
            try:
                self.proc.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self.proc.terminate()
                self.proc.wait(timeout=10)
            self.log.close()


def main():
    nodes = []
    report = {"scope": "regtest consensus, Ark boarding/MuSig/exit and replay tests",
              "mainnet_sats_spent": 0, "complete_server_test": False}
    try:
        report["lightning_identity"] = probe("identity")
        with tempfile.TemporaryDirectory(prefix="paperclip-bark-xbt-") as directory:
            root = Path(directory)
            xbt = Node(root, "xbt", os.environ["XBT_BITCOIND"], 18843,
                       ["-testactivationheight=blake2b@120", "-mempooltruc=enforce"])
            nodes.append(xbt)
            report["truc_policy"] = xbt.rpc("getmempoolinfo")["truc_policy"]
            assert report["truc_policy"] == "enforce"
            btc = Node(root, "btc", os.environ["BITCOIND_EXEC"], 18844, [])
            nodes.append(btc)
            report["xbt_binary_sha256"] = hashlib.sha256(Path(os.environ["XBT_BITCOIND"]).read_bytes()).hexdigest()
            btc.rpc("createwallet", "test")
            miner = btc.rpc("getnewaddress", wallet=True)
            btc.rpc("generatetoaddress", 110, miner)
            addresses = probe("addresses")
            funding_id = btc.rpc("sendmany", "", {addresses["key"]: 0.001, addresses["board"]: 0.001}, wallet=True)
            btc.rpc("generatetoaddress", 1, miner)
            funding = btc.rpc("gettransaction", funding_id, wallet=True)["hex"]
            for height in range(1, 112):
                block = btc.rpc("getblock", btc.rpc("getblockhash", height), 0)
                assert xbt.rpc("submitblock", block) is None
            xbt.rpc("generatetoaddress", 20, miner)
            btc.rpc("generatetoaddress", 20, miner)
            header_hash = xbt.rpc("getbestblockhash")
            raw_header = xbt.rpc("getblockheader", header_hash, False)
            parsed = probe("header", raw_header)
            assert len(raw_header) == 328
            assert parsed["hash"] == header_hash
            assert parsed["roundtrip"] == raw_header
            assert parsed["time"] == xbt.rpc("getblockheader", header_hash)["time"]
            report["header"] = parsed
            raw_block = xbt.rpc("getblock", header_hash, 0)
            parsed_block = probe("block", raw_block)
            assert parsed_block["hash"] == header_hash, parsed_block
            assert parsed_block["roundtrip"] == raw_block
            report["full_block_roundtrip"] = True
            transactions = probe("sign", funding)
            # Both nodes have exactly the same funding outpoints. Prove the
            # negative replay result is a signature failure, not missing coins.
            for node in [xbt, btc]:
                decoded = node.rpc("decoderawtransaction", transactions["key"])
                vin = decoded["vin"][0]
                assert node.rpc("gettxout", vin["txid"], vin["vout"]) is not None
            assert btc.rpc("testmempoolaccept", [transactions["legacy"]])[0]["allowed"]
            accepted = xbt.rpc("testmempoolaccept", [transactions["key"]])[0]
            rejected = btc.rpc("testmempoolaccept", [transactions["key"]])[0]
            assert accepted["allowed"], accepted
            assert not rejected["allowed"], rejected
            reason = str(rejected).lower()
            assert "sighash" in reason or "signature" in reason, rejected
            report["unified_keypath"] = {"xbt": accepted, "btc": rejected}
            report["key_txid"] = xbt.rpc("sendrawtransaction", transactions["key"])
            package = xbt.rpc("submitpackage", [transactions["board"], transactions["cpfp"]])
            assert package["package_msg"] == "success", package
            report["board_package"] = package
            xbt.rpc("generatetoaddress", 7, miner)
            claim = xbt.rpc("testmempoolaccept", [transactions["claim"]])[0]
            assert claim["allowed"], claim
            report["claim_txid"] = xbt.rpc("sendrawtransaction", transactions["claim"])
            xbt.rpc("generatetoaddress", 1, miner)
            report["claim"] = claim
            report["transactions"] = transactions
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
        REPORT.write_text(json.dumps(report, indent=2) + "\n")


if __name__ == "__main__":
    main()
