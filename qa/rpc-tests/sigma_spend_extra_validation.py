#!/usr/bin/env python3
from decimal import *

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

#TODO fix to proper rpc_msgs after special card will be fixed.
validation_inputs_no_funds = [
    ('valid_double_same_denom', {'THAYjKnnCsN5xspnEcb1Ztvw4mSPBuwxzU': 1, 'THAYjKnnCsN5xspnEcb1Ztvw4mSPBuwxzU': 1}),
    ('valid_double_diff_denom', {'THAYjKnnCsN5xspnEcb1Ztvw4mSPBuwxzU': 1, 'THAYjKnnCsN5xspnEcb1Ztvw4mSPBuwxzU': 100}),
    ('valid_mult_same_denom', {'THAYjKnnCsN5xspnEcb1Ztvw4mSPBuwxzU': 1, 'TY6wpjiuTcFsxq1AuEbX7mUR2pNAM9ahhx': 1}),
    ('valid_lotof_same_denom',
     {
         'THAYjKnnCsN5xspnEcb1Ztvw4mSPBuwxzU': 1,
         'TY6wpjiuTcFsxq1AuEbX7mUR2pNAM9ahhx': 1,
         'THAYjKnnCsN5xspnEcb1Ztvw4mSPBuwxzU': 1,
         'TY6wpjiuTcFsxq1AuEbX7mUR2pNAM9ahhx': 1,
         'THAYjKnnCsN5xspnEcb1Ztvw4mSPBuwxzU': 1,
         'TY6wpjiuTcFsxq1AuEbX7mUR2pNAM9ahhx': 1,
         'THAYjKnnCsN5xspnEcb1Ztvw4mSPBuwxzU': 1,
         'TY6wpjiuTcFsxq1AuEbX7mUR2pNAM9ahhx': 1,
         'THAYjKnnCsN5xspnEcb1Ztvw4mSPBuwxzU': 1,
         'TY6wpjiuTcFsxq1AuEbX7mUR2pNAM9ahhx': 1,
         'THAYjKnnCsN5xspnEcb1Ztvw4mSPBuwxzU': 1,
         'TY6wpjiuTcFsxq1AuEbX7mUR2pNAM9ahhx': 1,
         'THAYjKnnCsN5xspnEcb1Ztvw4mSPBuwxzU': 1,
         'TY6wpjiuTcFsxq1AuEbX7mUR2pNAM9ahhx': 1,

     }
    ),
    ('valid_lotof_diff_denom',
     {
         'THAYjKnnCsN5xspnEcb1Ztvw4mSPBuwxzU': 1,
         'TY6wpjiuTcFsxq1AuEbX7mUR2pNAM9ahhx': 1,
         'THAYjKnnCsN5xspnEcb1Ztvw4mSPBuwxzU': 10,
         'TY6wpjiuTcFsxq1AuEbX7mUR2pNAM9ahhx': 10,
         'THAYjKnnCsN5xspnEcb1Ztvw4mSPBuwxzU': 0.1,
         'TY6wpjiuTcFsxq1AuEbX7mUR2pNAM9ahhx': 0.1,
         'THAYjKnnCsN5xspnEcb1Ztvw4mSPBuwxzU': 0.5,
         'TY6wpjiuTcFsxq1AuEbX7mUR2pNAM9ahhx': 0.5,
         'THAYjKnnCsN5xspnEcb1Ztvw4mSPBuwxzU': 20,
         'TY6wpjiuTcFsxq1AuEbX7mUR2pNAM9ahhx': 20,
         'THAYjKnnCsN5xspnEcb1Ztvw4mSPBuwxzU': 1,
         'TY6wpjiuTcFsxq1AuEbX7mUR2pNAM9ahhx': 1,
         'THAYjKnnCsN5xspnEcb1Ztvw4mSPBuwxzU': 11,
         'TY6wpjiuTcFsxq1AuEbX7mUR2pNAM9ahhx': 11,

     }
    ),
    ('invalid_input_empty_addr', {"": 1}),
    ('valid_double_same_denom', {'THAYjKnnCsN5xspnEcb1Ztvw4mSPBuwxzU': ""}),
    ]

post_outputs_no_funds = [
    (None, None),
    (None, None),
    (None, None),
    (None, None),
    (None, None),
    (-5, 'Invalid Firo address: '),
    (-3, 'Invalid amount'),
]

class SigmaSpendValidationWithFundsExtraTest(BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.num_nodes = 4
        self.setup_clean_chain = False

    def setup_nodes(self):
        #This test requires mocktime
        enable_mocktime()
        return start_nodes(self.num_nodes, self.options.tmpdir)

    def run_test(self):
        # Decimal formating: 6 digits for balance will be enought 000.000
        getcontext().prec = 6
        self.nodes[0].generate(150)
        self.sync_all()
        self.nodes[0].mint(240.8)
        self.nodes[0].mint(2000)

        self.nodes[0].generate(10)
        self.sync_all()
        for input_data, exp_err in zip(validation_inputs_no_funds, post_outputs_no_funds):
            case_name, denom = input_data
            exp_code, exp_msg = exp_err
            msg = None
            code = None
            print('Current case: {}'.format(case_name))
            try:
                res = self.nodes[0].spendmany("", denom)
            except JSONRPCException as ex:
                msg = ex.error['message']
                code = ex.error['code']
                assert msg == exp_msg, \
                'Unexpected error raised to RPC:{}, but should:{}'.format(msg, exp_msg)
                assert code == exp_code, \
                'Unexpected error raised to RPC: {}, but should {}.'.format(code, exp_code)
            assert exp_msg == msg, 'Unexpected exception appeared {}, but should be {}'  .format(msg, exp_msg)

if __name__ == '__main__':
    SigmaSpendValidationWithFundsExtraTest().main()
