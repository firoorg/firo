#!/usr/bin/env python3
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

class SparkSpendProofTest(BitcoinTestFramework):
    """createsparkspendproof / verifysparkspendproof round trip between two nodes."""

    def __init__(self):
        super().__init__()
        self.num_nodes = 2
        self.setup_clean_chain = True

    def setup_network(self, split=False):
        # Spark tests require mocktime
        enable_mocktime()
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir)
        connect_nodes_bi(self.nodes, 0, 1)
        self.is_network_split = False
        self.sync_all()

    def run_test(self):
        prover, verifier = self.nodes
        prover.generate(501)
        self.sync_all()

        sparkAddress = prover.getnewsparkaddress()[0]
        for _ in range(2):
            prover.mintspark({sparkAddress: {"amount": 5, "memo": "Test memo"}})
        prover.generate(1)
        self.sync_all()

        txid = prover.spendspark({verifier.getnewaddress(): {"amount": 1, "subtractFee": False}})
        message = "support ticket 4821"

        # An unconfirmed spend cannot be proven: the verifier has no ledger copy to check against
        assert_raises_message(JSONRPCException, "not confirmed", prover.createsparkspendproof, txid, message)

        prover.generate(1)
        self.sync_all()

        proof = prover.createsparkspendproof(txid, message)

        # A node without the keys verifies the proof against its own chain
        assert_equal(verifier.verifysparkspendproof(proof, message), {"valid": True, "txid": txid})
        assert_equal(prover.verifysparkspendproof(proof, message), {"valid": True, "txid": txid})

        # The proof is bound to the exact message
        assert_equal(verifier.verifysparkspendproof(proof, message + "!"), {"valid": False, "txid": txid})

        # Damaged proofs are rejected outright
        assert_raises_message(JSONRPCException, "Malformed spend proof", verifier.verifysparkspendproof, proof[:-2], message)
        assert_raises_message(JSONRPCException, "Malformed spend proof", verifier.verifysparkspendproof, "zz", message)

        # Only the wallet that made the spend can prove it, and only for Spark spends
        assert_raises_message(JSONRPCException, "does not spend coins from this wallet", verifier.createsparkspendproof, txid, message)
        coinbase = prover.getblock(prover.getblockhash(1))["tx"][0]
        assert_raises_message(JSONRPCException, "not a Spark spend", prover.createsparkspendproof, coinbase, message)

if __name__ == '__main__':
    SparkSpendProofTest().main()
