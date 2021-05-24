#!/usr/bin/env python3
from decimal import *

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

class JoinSplitGettransactionTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 4
        self.setup_clean_chain = True

    def setup_nodes(self):
        # This test requires mocktime
        enable_mocktime()
        return start_nodes(self.num_nodes, self.options.tmpdir)

    def run_test(self):
        self.nodes[0].generate(401)
        self.sync_all()

        # get a watch only address
        watchonly_address = self.nodes[3].getnewaddress()
        watchonly_pubkey = self.nodes[3].validateaddress(watchonly_address)["pubkey"]
        self.nodes[0].importpubkey(watchonly_pubkey, "", True)

        valid_address = self.nodes[0].getnewaddress()

        for _ in range(10):
            self.nodes[0].mintlelantus(1)

        self.nodes[0].generate(10)
        self.sync_all()

        # case 1: Spend many with watchonly address
        spendto_wo_id = self.nodes[0].joinsplit({watchonly_address: 1})
        spendto_wo_tx = self.nodes[0].gettransaction(spendto_wo_id)

        assert spendto_wo_tx['amount'] == Decimal('-1')
        assert spendto_wo_tx['fee'] < Decimal('0')
        assert isinstance(spendto_wo_tx['details'], list)
        assert len(spendto_wo_tx['details']) == 1
        assert spendto_wo_tx['details'][0]['involvesWatchonly']

        # case 2: Spend many with watchonly address and valid address
        spendto_wo_and_valid_id = self.nodes[0].joinsplit({watchonly_address: 1, valid_address: 2})
        spendto_wo_and_valid_tx = self.nodes[0].gettransaction(spendto_wo_and_valid_id)

        assert spendto_wo_and_valid_tx['amount'] == Decimal('-1')
        assert spendto_wo_and_valid_tx['fee'] < Decimal('0')
        assert isinstance(spendto_wo_and_valid_tx['details'], list)
        assert len(spendto_wo_and_valid_tx['details']) == 3

        involves_watch_only_count = 0
        for detial in spendto_wo_and_valid_tx['details']:
            if 'involvesWatchonly' in detial and bool(detial['involvesWatchonly']):
                involves_watch_only_count += 1

        assert involves_watch_only_count == 1

        # case 3: spend many with watchonly address and invalid address
        assert_raises(JSONRPCException, self.nodes[0].joinsplit, [{watchonly_address: 1, 'invalidaddress': 2}])

if __name__ == '__main__':
    JoinSplitGettransactionTest().main()


