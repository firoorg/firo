#!/usr/bin/env python3
import time
from decimal import getcontext

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import bitcoind_processes, enable_mocktime, start_node, start_nodes
from test_framework.mn_utils import *

# Zapwallettxes, rescan, reindex, reindex-chainstate are not affect existing transactions


#1. Generate some blocks
#2. Mint firos
#3. 2 Spend firos in different time
#4. Send firos
#5. Gerate blocks
#6. Remint some firos
#7. Mint sigma coins
#8. 2 Spend in different time
#9. Send
#10. Restart with zapwallettxes=1
#11. Check all transactions shown properly as before restart
#12. Restart with zapwallettxes=2
#13. Check all transactions shown properly as before restart
#14. Restart with rescan
#15. Check all transactions shown properly as before restart
#16. Restart with reindex
#17. Check all transactions shown properly as before restart
#18. Restart with reindex-chainstate
#19. Check all transactions shown properly as before restart

class TransactionsVerAfterRestartTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 4
        self.setup_clean_chain = False

    def setup_nodes(self):
        # This test requires mocktime
        enable_mocktime()
        return start_nodes(self.num_nodes, self.options.tmpdir)

    def log_point(self, point):
        f = open('/tmp/out.txt', 'a')
        print (point, file=f)
        f.flush()
        f.close()

    def compare_no_time(self, l_tx_list, r_tx_list):
        if len(l_tx_list) != len(r_tx_list):
            return False

        for i in range(len(l_tx_list)):
            l_tx = l_tx_list[i]
            l_tx.pop("timereceived", None)
            r_tx = r_tx_list[i]
            r_tx.pop("timereceived", None)
            if l_tx != r_tx:
                return False
        return True

    def run_test(self):
        getcontext().prec = 6

        #1. Generate some blocks
        self.nodes[0].generate(101)
        self.sync_all()

        firo_denoms = [1, 10, 25, 50, 100]

        #2. Send firos
        self.nodes[0].sendtoaddress('TNZMs3dtwRddC5BuZ9zQUdvksPUjmJPRfL', 25)

        #3. Gerate blocks

        while self.nodes[0].getblockcount() < 550:
            self.nodes[0].generate(1)
        mn1 = prepare_mn(self.nodes[0], 1, "mn-1")
        create_mn_collateral(self.nodes[0], mn1)
        register_mn(self.nodes[0], mn1)

        self.nodes[0].generate(150)

        #4. Mint sigma coins
        for denom in sigma_denoms:
                 self.nodes[0].mint(denom)
                 self.nodes[0].mint(denom)

        self.nodes[0].generate(100)

        #5. 2 Spend in different time
        args = {'THAYjKnnCsN5xspnEcb1Ztvw4mSPBuwxzU': 100}
        self.nodes[0].spendmany("", args)

        args = {'THAYjKnnCsN5xspnEcb1Ztvw4mSPBuwxzU': 25}
        self.nodes[0].spendmany("", args)

        #6. Send
        self.nodes[0].sendtoaddress('TNZMs3dtwRddC5BuZ9zQUdvksPUjmJPRfL', 10)

        self.nodes[0].generate(10)

        transactions_before = sorted(self.nodes[0].listtransactions("*", 99999), key=lambda k: k['txid'], reverse=True)

        self.nodes[0].stop()
        bitcoind_processes[0].wait()

        #7. Restart with zapwallettxes=1
        self.nodes[0] = start_node(0,self.options.tmpdir, ["-zapwallettxes=1"])

        #list of transactions should be same as initial after restart with flag
        transactions_after_zapwallettxes1 = sorted(self.nodes[0].listtransactions("*", 99999), key=lambda k: k['txid'], reverse=True)

        #8. Check all transactions shown properly as before restart
        assert transactions_before == transactions_after_zapwallettxes1, \
            'List of transactions after restart with zapwallettxes=1 unexpectedly changed.'

        self.nodes[0].stop()
        bitcoind_processes[0].wait()

        #9. Restart with zapwallettxes=2
        self.nodes[0] = start_node(0,self.options.tmpdir, ["-zapwallettxes=2"])

        #list of transactions should be same as initial after restart with flag
        transactions_after_zapwallettxes2 = sorted(self.nodes[0].listtransactions("*", 99999), key=lambda k: k['txid'], reverse=True)

        #10. Check all transactions shown properly as before restart
        assert self.compare_no_time(transactions_before, transactions_after_zapwallettxes2), \
            'List of transactions after restart with zapwallettxes=2 unexpectedly changed.'

        self.nodes[0].stop()
        bitcoind_processes[0].wait()

        #11. Restart with rescan
        self.nodes[0] = start_node(0,self.options.tmpdir, ["-rescan"])

        #12. Check all transactions shown properly as before restart
        transactions_after_rescan = sorted(self.nodes[0].listtransactions("*", 99999), key=lambda k: k['txid'], reverse=True)

        assert self.compare_no_time(transactions_before, transactions_after_rescan), \
            'List of transactions after restart with rescan unexpectedly changed.'

        last_block_height = self.nodes[0].getinfo()["blocks"]
        transactions_before_reindex = sorted(self.nodes[0].listtransactions("*", 99999), key=lambda k: k['txid'], reverse=True)

        self.nodes[0].stop()
        bitcoind_processes[0].wait()

        #13. Restart with reindex
        self.nodes[0] = start_node(0,self.options.tmpdir, ["-reindex"])

        tm = 0
        while tm < 30 and self.nodes[0].getinfo()["blocks"] != last_block_height:
            time.sleep(1)
            tm += 1

        #14. Check all transactions shown properly as before restart
        tx_before = sorted(transactions_before_reindex, key=lambda k: k['txid'], reverse=True)
        tx_after_reindex = sorted(self.nodes[0].listtransactions("*", 99999), key=lambda k: k['txid'], reverse=True)

        assert self.compare_no_time(tx_before, tx_after_reindex), \
            'List of transactions after restart with reindex unexpectedly changed.'

        self.nodes[0].stop()
        bitcoind_processes[0].wait()

        #15. Restart with reindex-chainstate
        self.nodes[0] = start_node(0,self.options.tmpdir, ["-reindex-chainstate"])

        time.sleep(5)

        #16. Check all transactions shown properly as before restart
        tx_after_reindex_chainstate = sorted(self.nodes[0].listtransactions("*", 99999), key=lambda k: k['txid'], reverse=True)

        assert self.compare_no_time(tx_before, tx_after_reindex_chainstate), \
            'List of transactions after restart with reindex-chainstate unexpectedly changed.'



if __name__ == '__main__':
    TransactionsVerAfterRestartTest().main()
