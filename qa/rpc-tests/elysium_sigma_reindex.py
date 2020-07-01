#!/usr/bin/env python3
from test_framework.test_framework import ElysiumTestFramework
from test_framework.util import assert_equal, connect_nodes, start_node, stop_node, sync_blocks
import time

class ElysiumSigmaReindexTest(ElysiumTestFramework):
    def run_test(self):
        super().run_test()

        sigma_start_block = 550
        self.nodes[0].generate(sigma_start_block - self.nodes[0].getblockcount())

        # generate mints to spend
        for _ in range(0, 10):
            self.nodes[0].mint(1)

        self.nodes[0].generate(10)
        self.sync_all()

        # create sigma with denominations (1, 2)
        balance = '1000000'
        self.nodes[0].elysium_sendissuancefixed(
            self.addrs[0], 1, 1, 0, '', '', 'Sigma', '', '', balance, 1
        )

        self.nodes[0].generate(1)
        sigma_property = 3

        self.nodes[0].elysium_sendcreatedenomination(self.addrs[0], sigma_property, '1')
        self.nodes[0].generate(1)

        self.nodes[0].elysium_sendcreatedenomination(self.addrs[0], sigma_property, '2')
        self.nodes[0].generate(10)

        # mint 4 coins
        self.nodes[0].elysium_sendmint(self.addrs[0], sigma_property, {0: 2, 1: 2})

        # spend 2 coins, then 2 coins remaining
        self.nodes[0].generate(1)
        self.nodes[0].elysium_sendspend(self.addrs[0], sigma_property, 0)
        self.nodes[0].elysium_sendspend(self.addrs[0], sigma_property, 1)

        self.nodes[0].generate(1)

        # generate 2 coins more
        unconfirmed_txid = self.nodes[0].elysium_sendmint(self.addrs[0], sigma_property, {0: 1, 1: 1})
        raw_unconfirmed = self.nodes[0].getrawtransaction(unconfirmed_txid)

        # check before reindex
        self.sync_all()
        confirmed_mints = self.nodes[0].elysium_listmints()
        unconfirmed_mints = self.nodes[0].elysium_listpendingmints()

        assert_equal(2, len(confirmed_mints))
        assert_equal(2, len(unconfirmed_mints))

        blockcount = self.nodes[0].getblockcount()

        # restart with reindexing
        stop_node(self.nodes[0], 0)
        self.nodes[0] = start_node(0, self.options.tmpdir, ['-elysium', '-reindex'])

        while self.nodes[0].getblockcount() < blockcount:
            time.sleep(0.1)

        connect_nodes(self.nodes[0], 1)

        reindexed_confirmed_mints = self.nodes[0].elysium_listmints()
        self.compare_mints(confirmed_mints, reindexed_confirmed_mints)

        reindexed_unconfirmed_mints = self.nodes[0].elysium_listpendingmints()
        self.compare_mints(unconfirmed_mints, reindexed_unconfirmed_mints)

        # spend remaining mints
        self.nodes[0].elysium_sendspend(self.addrs[0], sigma_property, 0)
        self.nodes[0].elysium_sendspend(self.addrs[0], sigma_property, 1)

        self.nodes[0].generate(1)

        # all mints should be spend
        remaining_mints = self.nodes[0].elysium_listmints()
        assert_equal(0, len(remaining_mints))

        # re-broadcast and try to remint remaining coins
        self.nodes[0].clearmempool()
        self.nodes[0].sendrawtransaction(raw_unconfirmed)
        self.nodes[0].generate(1)

        new_confirmed_mints = self.nodes[0].elysium_listmints()
        self.compare_mints(unconfirmed_mints, new_confirmed_mints)

        self.nodes[0].elysium_sendspend(self.addrs[0], sigma_property, 0)
        self.nodes[0].elysium_sendspend(self.addrs[0], sigma_property, 1)

        self.nodes[0].generate(1)

        remaining_mints = self.nodes[0].elysium_listmints()
        assert_equal(0, len(remaining_mints))

        # all mints are spend then elysium balance should be the same as before
        assert_equal(balance, self.nodes[0].elysium_getbalance(self.addrs[0], sigma_property)['balance'])

if __name__ == '__main__':
    ElysiumSigmaReindexTest().main()
