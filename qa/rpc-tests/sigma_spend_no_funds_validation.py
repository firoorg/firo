#!/usr/bin/env python3
from decimal import *

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

# TODO fix to proper rpc_msgs after special card will be fixed.
validation_inputs_no_funds = [
    ('valid_denom_101', 101),
    ('valid_denom_1', 1),
    ('valid_denom_1.0', 1.0),
    ('ivalid_input_string', 'string'),
    ('valid_input_string_with_num', '1'),
    ('ivalid_input_empty', None),
    ('valid_denom_1_address', (1, 'TFfXrFRs4eJStyBL9dSoNTUXL1MZ2fCwq4')),
    ('valid_denom_1_invalid_address', (1, 'SomeAdress')),
    ('invalid_denom_invalid_address', (10000000000000, 'SomeAdress')),
]

post_outputs_no_funds = [
    (-6, 'Insufficient funds'),
    (-6, 'Insufficient funds'),
    (-6, 'Insufficient funds'),
    (-3, 'Invalid amount'),
    (-6, 'Insufficient funds'),
    (-3, 'Amount is not a number or string'),
    (-6, 'Insufficient funds'),
    (-6, 'Insufficient funds'),
    (-3, 'Invalid amount'),
]


class SigmaSpendValidationNoFundsTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 4
        self.setup_clean_chain = True

    def setup_nodes(self):
        # This test requires mocktime
        enable_mocktime()
        return start_nodes(self.num_nodes, self.options.tmpdir)

    def run_test(self):
        # Decimal formating: 6 digits for balance will be enought 000.000
        getcontext().prec = 6
        for input_data, exp_err in zip(validation_inputs_no_funds, post_outputs_no_funds):
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
    SigmaSpendValidationNoFundsTest().main()


