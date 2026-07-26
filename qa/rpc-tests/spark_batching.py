#!/usr/bin/env python3
"""Test deferred Spark batch proof verification (-batching) across reindex.

All blocks are mined with timestamps more than a day in the past, so a
later reindex takes the old-block batching path: Spark spend proofs are
collected into the batch container and must batch-verify before the node
persists validation state and clears the reindex flag.
"""
import os
import time

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import (
    assert_equal,
    set_node_times,
    start_nodes,
    stop_nodes,
)

BATCH_SUCCESS_LOG = "Spark batch verification finished successfully."


class SparkBatchingTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 1
        self.setup_clean_chain = True

    def setup_network(self):
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir)

    def reindex(self, batching):
        blockcount = self.nodes[0].getblockcount()
        besthash = self.nodes[0].getbestblockhash()
        stop_nodes(self.nodes)
        extra_args = [["-reindex", "-batching=" + ("1" if batching else "0")]]
        self.nodes = start_nodes(self.num_nodes, self.options.tmpdir, extra_args)
        # The tip can reach the target height while the final deferred batch
        # is still pending, so a batched reindex is only complete once the
        # batch verification success marker is in the log as well.
        deadline = time.time() + 300
        while True:
            if self.nodes[0].getblockcount() >= blockcount and \
                    (not batching or BATCH_SUCCESS_LOG in self.read_debug_log()):
                break
            assert time.time() < deadline, "reindex did not complete in time"
            time.sleep(0.1)
        assert_equal(self.nodes[0].getblockcount(), blockcount)
        assert_equal(self.nodes[0].getbestblockhash(), besthash)

    def read_debug_log(self):
        path = os.path.join(self.options.tmpdir, "node0", "regtest", "debug.log")
        with open(path, encoding="utf8", errors="replace") as f:
            return f.read()

    def run_test(self):
        # Mine everything with old timestamps so a later reindex treats the
        # whole chain as old blocks and defers Spark proof verification.
        set_node_times(self.nodes, int(time.time()) - 2 * 86400)

        self.nodes[0].generate(501)
        spark_address = self.nodes[0].getsparkdefaultaddress()[0]
        self.nodes[0].mintspark({spark_address: {"amount": 10, "memo": "batch test"}})
        self.nodes[0].generate(6)

        # Two Spark spends in separate blocks.
        self.nodes[0].spendspark({self.nodes[0].getnewaddress(): {"amount": 1, "subtractFee": False}})
        self.nodes[0].generate(1)
        self.nodes[0].spendspark({self.nodes[0].getnewaddress(): {"amount": 2, "subtractFee": False}})
        self.nodes[0].generate(6)

        spark_balance = self.nodes[0].getsparkbalance()

        # Reindex with batching: the Spark spends must be batch verified
        # before reindexing is allowed to complete.
        self.reindex(batching=True)
        log = self.read_debug_log()
        assert BATCH_SUCCESS_LOG in log, \
            "batched reindex did not batch verify Spark proofs"
        assert "Spark batch verification failed." not in log
        assert_equal(self.nodes[0].getsparkbalance(), spark_balance)

        # Control: block-by-block verification reaches the same chain.
        self.reindex(batching=False)
        assert_equal(self.nodes[0].getsparkbalance(), spark_balance)

        print("Success")


if __name__ == '__main__':
    SparkBatchingTest().main()
