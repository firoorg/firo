#!/usr/bin/env python3
from decimal import *

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

# TODO fix to proper rpc_msgs after special card will be fixed.
validation_inputs_with_funds = [
    ('valid_denom_101', 101),
    ('valid_denom_400', 400),
    ('valid_denom_1000_exceed_limit', 1000),
    ('valid_denom_1', 1),
    ('valid_denom_1.0', 1.0),
    ('ivalid_input_string', 'string'),
    ('valid_input_string_with_num', '1'),
    ('ivalid_input_empty', None),
    ('valid_denom_1_account', (1, '')),
    ('valid_denom_1_invalid_account', (1, 'InvalidAccount')),
    ('invalid_denom_invalid_account', (10000000000000, 'InvalidAccount')),
]

post_outputs_with_funds = [
    (None, None),
    (None, None),
    (-4, 'Required amount exceed value spend limit'),
    (None, None),
    (None, None),
    (-3, 'Invalid amount'),
    (None, None),
    (-3, 'Amount is not a number or string'),
    (None, None),
    (-6, 'Account has insufficient funds'),
    (-6, 'Account has insufficient funds'),
]


class SigmaSpendValidationWithFundsTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 4
        self.setup_clean_chain = False

    def setup_nodes(self):
        # This test requires mocktime
        enable_mocktime()
        return start_nodes(self.num_nodes, self.options.tmpdir)

    def run_test(self):
        # Decimal formating: 6 digits for balance will be enought 000.000
        getcontext().prec = 6
        self.nodes[0].generate(200)
        self.sync_all()
        self.nodes[0].mint(240.8)
        self.nodes[0].mint(2000)
        self.nodes[0].generate(200)
        print(self.nodes[0].getblockcount())
        self.sync_all()
        for input_data, exp_err in zip(validation_inputs_with_funds, post_outputs_with_funds):
            case_name, denom = input_data
            exp_code, exp_msg = exp_err
            msg = None
            code = None
            print('Current case: {}'.format(case_name))
            try:
                # With address
                if isinstance(denom, tuple):
                    val = {'THAYjKnnCsN5xspnEcb1Ztvw4mSPBuwxzU': denom[0]}
                    res = self.nodes[0].spendmany(denom[1], val)
                else:
                    val = {'THAYjKnnCsN5xspnEcb1Ztvw4mSPBuwxzU': denom}
                    res = self.nodes[0].spendmany("", val)
            except JSONRPCException as ex:
                msg = ex.error['message']
                code = ex.error['code']
                assert msg == exp_msg, \
                    'Unexpected error raised to RPC:{}, but should:{}'.format(msg, exp_msg)
                assert code == exp_code, \
                    'Unexpected error raised to RPC: {}, but should {}.'.format(code, exp_code)
            assert exp_msg == msg, 'Unexpected exception appeared {}, but should be {}'.format(msg, exp_msg)


if __name__ == '__main__':
    SigmaSpendValidationWithFundsTest().main()


