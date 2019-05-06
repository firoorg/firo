#!/usr/bin/env python3
from decimal import *

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import *

validation_inputs_no_funds = [
    ('valid_denom_1', 1),
    ('valid_denom_0.1', 0.1),
    ('valid_denom_101', 101),
    ('valid_denom_1.0', 1.0),
    ('ivalid_input_string', 'string'),
    ('ivalid_input_string_with_num', '1'),
    ('ivalid_input_empty', None),
    ('invalid_denom_big', 10000000000000000000000000000),
    ('invalid_denom_out_of_100000000', 100000000),
    ('valid_denom_1000', 1000),
    ('invalid_denom_0.01', 0.01),
    ('invalid_denom_-1', -1),
]

post_outputs_no_funds = [
    (-4, 'Insufficient funds'),
    (-4, 'Insufficient funds'),
    (-4, 'Insufficient funds'),
    (-4, 'Insufficient funds'),
    (-3, 'Invalid amount'),
    (-4, 'Insufficient funds'),
    (-3, 'Amount is not a number or string'),
    (-3, 'Invalid amount'),
    (-3, 'Amount out of range'),
    (-4, 'Insufficient funds'),
    (-8, 'Amount to mint is invalid.\n'),
    (-3, 'Amount out of range')
]


class SigmaMintValidationNoFundsTest(BitcoinTestFramework):
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
                res = self.nodes[0].mint(denom)
            except JSONRPCException as ex:
                msg = ex.error['message']
                code = ex.error['code']
                assert msg == exp_msg, \
                    'Unexpected error raised to RPC:{}, but should:{}'.format(msg, exp_msg)
                assert code == exp_code, \
                    'Unexpected error raised to RPC: {}, but should {}.'.format(code, exp_code)
            assert exp_msg == msg, 'Unexpected exception appeared {}, but should be {}'.format(msg, exp_msg)


if __name__ == '__main__':
    SigmaMintValidationNoFundsTest().main()

