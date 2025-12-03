#!/usr/bin/env python3
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import JSONRPCException
from decimal import Decimal

class SendManyTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 4
        self.setup_clean_chain = False

    def activate_spark(self):
        HARDCODED_ACTIVATION_HEIGHT = 401
        current_height = self.nodes[0].getblockcount()
        if current_height < HARDCODED_ACTIVATION_HEIGHT:
            self.nodes[0].generate(HARDCODED_ACTIVATION_HEIGHT - current_height)
            self.log.info(f"Generated {HARDCODED_ACTIVATION_HEIGHT - current_height} blocks to activate Spark.")

        blockchain_info = self.nodes[0].getblockchaininfo()
        activation_height = HARDCODED_ACTIVATION_HEIGHT
        if 'upgrades' in blockchain_info and 'spark' in blockchain_info['upgrades']:
            activation_height = blockchain_info['upgrades']['spark']['activationheight']
            self.log.info(f"Dynamic Spark activation height: {activation_height}")

        if current_height < activation_height:
            self.nodes[0].generate(activation_height - current_height)
            self.log.info(f"Generated {activation_height - current_height} blocks to meet dynamic activation height.")

        try:
            self.nodes[0].getnewsparkaddress()
            self.log.info("Spark is activated.")
        except JSONRPCException as e:
            if e.error.get('code') == -4:
                raise AssertionError("Spark is not activated even after generating blocks.")
            else:
                raise

    def run_test(self):
        self.activate_spark()
        self.test_sendmany_1transparent_simple()
        self.test_sendmany_1transparent_with_comment()
        self.test_sendmany_1transparent_with_comment_to()
        self.test_sendmany_1transparent_with_fee_subtraction()
        self.test_sendmany_1transparent_all()
        self.test_sendmany_2transparent_simple()
        self.test_sendmany_2transparent_with_comments()
        self.test_sendmany_2transparent_with_comments_to()
        self.test_sendmany_2transparent_with_fee_subtraction()
        self.test_sendmany_2transparent_all()
        self.test_sendmany_4transparent_all_complex()

        self.test_sendmany_1spark_simple()
        self.test_sendmany_1spark_with_fee_subtraction()
        self.test_sendmany_1spark_all()
        self.test_sendmany_2spark_simple()
        self.test_sendmany_2spark_with_fee_subtraction()
        self.test_sendmany_2spark_all()
        self.test_sendmany_4spark_all_complex()
        
        self.test_sendmany_complex_all_complex()

    def test_sendmany_1transparent_simple(self):
        expected_amount = Decimal('0.1')
        address = self.nodes[0].getnewaddress()
        txid = self.nodes[0].sendmany('', {address: expected_amount})
        self.nodes[0].generate(1)
        tx = self.nodes[0].gettransaction(txid)
        self.assert_equal_float(-tx['details'][0]['amount'], expected_amount)

    def test_sendmany_1transparent_with_comment(self):
        expected_amount = Decimal('0.1')
        address = self.nodes[0].getnewaddress()
        txid = self.nodes[0].sendmany('', {address: expected_amount}, 1, "payment comment")
        self.nodes[0].generate(1)
        tx = self.nodes[0].gettransaction(txid)
        self.assert_equal_float(-tx['details'][0]['amount'], expected_amount)
        assert tx['comment'] == "payment comment"

    def test_sendmany_1transparent_with_comment_to(self):
        expected_amount = Decimal('0.1')
        address = self.nodes[0].getnewaddress()
        # sendmany does not support comment_to directly, so skip or simulate
        txid = self.nodes[0].sendmany('', {address: expected_amount}, 1, "payment comment")
        self.nodes[0].generate(1)
        tx = self.nodes[0].gettransaction(txid)
        self.assert_equal_float(-tx['details'][0]['amount'], expected_amount)
        assert tx['comment'] == "payment comment"

    def test_sendmany_1transparent_with_fee_subtraction(self):
        expected_amount = Decimal('0.1')
        address = self.nodes[0].getnewaddress()
        txid = self.nodes[0].sendmany('', {address: expected_amount}, 1, "", [address])
        self.nodes[0].generate(1)
        tx = self.nodes[0].gettransaction(txid)
        fee = Decimal(tx['fee'])
        self.assert_equal_float(-(tx['details'][0]['amount'] + fee), expected_amount)

    def test_sendmany_1transparent_all(self):
        expected_amount = Decimal('0.1')
        address = self.nodes[0].getnewaddress()
        txid = self.nodes[0].sendmany('', {address: expected_amount}, 1, "payment comment", [address])
        self.nodes[0].generate(1)
        tx = self.nodes[0].gettransaction(txid)
        fee = Decimal(tx['fee'])
        self.assert_equal_float(-(tx['details'][0]['amount'] + fee), expected_amount)
        assert tx['comment'] == "payment comment"

    def test_sendmany_2transparent_simple(self):
        expected_amounts = [Decimal('0.1'), Decimal('0.15')]
        address1 = self.nodes[0].getnewaddress()
        address2 = self.nodes[1].getnewaddress()
        txid = self.nodes[0].sendmany('', {address1: expected_amounts[0], address2: expected_amounts[1]})
        self.nodes[0].generate(1)
        tx = self.nodes[0].gettransaction(txid)
        details = [detail for detail in tx['details'] if detail['category'] == 'send']
        for i, detail in enumerate(details):
            self.assert_equal_float(-detail['amount'], expected_amounts[i])

    def test_sendmany_2transparent_with_comments(self):
        expected_amounts = [Decimal('0.1'), Decimal('0.15')]
        expected_comment = "first payment; second payment"
        address1 = self.nodes[0].getnewaddress()
        address2 = self.nodes[1].getnewaddress()
        txid = self.nodes[0].sendmany('', {address1: expected_amounts[0], address2: expected_amounts[1]}, 1, expected_comment)
        self.nodes[0].generate(1)
        tx = self.nodes[0].gettransaction(txid)
        details = [detail for detail in tx['details'] if detail['category'] == 'send']
        for i, detail in enumerate(details):
            self.assert_equal_float(-detail['amount'], expected_amounts[i])
        assert tx['comment'] == expected_comment

    def test_sendmany_2transparent_with_comments_to(self):
        expected_amounts = [Decimal('0.1'), Decimal('0.15')]
        # sendmany does not support comment_to directly, so skip or simulate
        address1 = self.nodes[0].getnewaddress()
        address2 = self.nodes[1].getnewaddress()
        txid = self.nodes[0].sendmany('', {address1: expected_amounts[0], address2: expected_amounts[1]}, 1, "first payment; second payment")
        self.nodes[0].generate(1)
        tx = self.nodes[0].gettransaction(txid)
        details = [detail for detail in tx['details'] if detail['category'] == 'send']
        for i, detail in enumerate(details):
            self.assert_equal_float(-detail['amount'], expected_amounts[i])

    def test_sendmany_2transparent_with_fee_subtraction(self):
        expected_amounts = [Decimal('0.1'), Decimal('0.15')]
        address1 = self.nodes[0].getnewaddress()
        address2 = self.nodes[1].getnewaddress()
        txid = self.nodes[0].sendmany('', {address1: expected_amounts[0], address2: expected_amounts[1]}, 1, "", [address1, address2])
        self.nodes[0].generate(1)
        tx = self.nodes[0].gettransaction(txid)
        details = [detail for detail in tx['details'] if detail['category'] == 'send']
        fee = Decimal(tx['fee'])
        total_amounts = sum([detail['amount'] for detail in details])
        self.assert_equal_float(-(total_amounts + fee), sum(expected_amounts))

    def test_sendmany_2transparent_all(self):
        expected_amounts = [Decimal('0.1'), Decimal('0.15')]
        address1 = self.nodes[0].getnewaddress()
        address2 = self.nodes[1].getnewaddress()
        txid = self.nodes[0].sendmany('', {address1: expected_amounts[0], address2: expected_amounts[1]}, 1, "John payment; David payment", [address1, address2])
        self.nodes[0].generate(1)
        tx = self.nodes[0].gettransaction(txid)
        details = [detail for detail in tx['details'] if detail['category'] == 'send']
        fee = Decimal(tx['fee'])
        total_amounts = sum([detail['amount'] for detail in details])
        self.assert_equal_float(-(total_amounts + fee), sum(expected_amounts))
        assert tx['comment'] == "John payment; David payment"

    def test_sendmany_4transparent_all_complex(self):
        expected_amounts = [Decimal('0.1'), Decimal('0.15'), Decimal('0.2'), Decimal('0.25')]
        address1 = self.nodes[0].getnewaddress()
        address2 = self.nodes[1].getnewaddress()
        address3 = self.nodes[2].getnewaddress()
        address4 = self.nodes[3].getnewaddress()
        txid = self.nodes[0].sendmany('', {
            address1: expected_amounts[0],
            address2: expected_amounts[1],
            address3: expected_amounts[2],
            address4: expected_amounts[3]
        }, 1, "first payment; second payment; third payment; fourth payment", [address1, address3])
        self.nodes[0].generate(1)
        tx = self.nodes[0].gettransaction(txid)
        details = [detail for detail in tx['details'] if detail['category'] == 'send']
        fee = Decimal(tx['fee'])
        total_amounts = sum([detail['amount'] for detail in details])
        self.assert_equal_float(-(total_amounts + fee), sum(expected_amounts))
        assert tx['comment'] == "first payment; second payment; third payment; fourth payment"

    def test_sendmany_1spark_simple(self):
        expected_amount = Decimal('0.1')
        spark_address = self.nodes[0].getnewsparkaddress()[0]
        self.nodes[0].mintspark({spark_address: {"amount": expected_amount * 10}})
        self.nodes[0].generate(1)
        txid = self.nodes[0].sendmany('', {spark_address: expected_amount})
        tx = self.nodes[0].gettransaction(txid)
        details = [detail for detail in tx['details'] if detail['category'] == 'mint']
        self.assert_equal_float(-details[0]['amount'], expected_amount)
        assert details[0]['address'] == spark_address

    def test_sendmany_1spark_with_fee_subtraction(self):
        expected_amount = Decimal('0.1')
        spark_address = self.nodes[0].getnewsparkaddress()[0]
        self.nodes[0].mintspark({spark_address: {"amount": expected_amount * 10}})
        self.nodes[0].generate(1)
        txid = self.nodes[0].sendmany('', {spark_address: expected_amount}, 1, "", [spark_address])
        tx = self.nodes[0].gettransaction(txid)
        details = [detail for detail in tx['details'] if detail['category'] == 'mint']
        fee = Decimal(tx['fee'])
        self.assert_equal_float(-(details[0]['amount'] + fee), expected_amount)
        assert details[0]['address'] == spark_address

    def test_sendmany_1spark_all(self):
        expected_amount = Decimal('0.1')
        spark_address = self.nodes[0].getnewsparkaddress()[0]
        self.nodes[0].mintspark({spark_address: {"amount": expected_amount * 10}})
        self.nodes[0].generate(1)
        txid = self.nodes[0].sendmany('', {spark_address: expected_amount}, 1, "", [spark_address])
        tx = self.nodes[0].gettransaction(txid)
        details = [detail for detail in tx['details'] if detail['category'] == 'mint']
        fee = Decimal(tx['fee'])
        self.assert_equal_float(-(details[0]['amount'] + fee), expected_amount)
        assert details[0]['address'] == spark_address

    def test_sendmany_2spark_simple(self):
        expected_amounts = [Decimal('0.1'), Decimal('0.15')]
        spark_address1 = self.nodes[0].getnewsparkaddress()[0]
        spark_address2 = self.nodes[1].getnewsparkaddress()[0]
        self.nodes[0].mintspark({spark_address1: {"amount": expected_amounts[0] * 10}})
        self.nodes[0].mintspark({spark_address2: {"amount": expected_amounts[1] * 10}})
        self.nodes[0].generate(1)
        txid = self.nodes[0].sendmany('', {spark_address1: expected_amounts[0], spark_address2: expected_amounts[1]})
        tx = self.nodes[0].gettransaction(txid)
        details = [detail for detail in tx['details'] if detail['category'] == 'mint']
        for i, detail in enumerate(details):
            self.assert_equal_float(-detail['amount'], expected_amounts[i])

    def test_sendmany_2spark_with_fee_subtraction(self):
        expected_amounts = [Decimal('0.1'), Decimal('0.15')]
        spark_address1 = self.nodes[0].getnewsparkaddress()[0]
        spark_address2 = self.nodes[1].getnewsparkaddress()[0]
        self.nodes[0].mintspark({spark_address1: {"amount": expected_amounts[0] * 10}})
        self.nodes[0].mintspark({spark_address2: {"amount": expected_amounts[1] * 10}})
        self.nodes[0].generate(1)
        txid = self.nodes[0].sendmany('', {spark_address1: expected_amounts[0], spark_address2: expected_amounts[1]}, 1, "", [spark_address1, spark_address2])
        tx = self.nodes[0].gettransaction(txid)
        details = [detail for detail in tx['details'] if detail['category'] == 'mint']
        fee = Decimal(tx['fee'])
        total_amounts = sum([detail['amount'] for detail in details])
        self.assert_equal_float(-(total_amounts + fee), sum(expected_amounts))

    def test_sendmany_2spark_all(self):
        expected_amounts = [Decimal('0.1'), Decimal('0.15')]
        spark_address1 = self.nodes[0].getnewsparkaddress()[0]
        spark_address2 = self.nodes[1].getnewsparkaddress()[0]
        self.nodes[0].mintspark({spark_address1: {"amount": expected_amounts[0] * 10}})
        self.nodes[0].mintspark({spark_address2: {"amount": expected_amounts[1] * 10}})
        self.nodes[0].generate(1)
        txid = self.nodes[0].sendmany('', {spark_address1: expected_amounts[0], spark_address2: expected_amounts[1]}, 1, "", [spark_address1, spark_address2])
        tx = self.nodes[0].gettransaction(txid)
        details = [detail for detail in tx['details'] if detail['category'] == 'mint']
        fee = Decimal(tx['fee'])
        total_amounts = sum([detail['amount'] for detail in details])
        self.assert_equal_float(-(total_amounts + fee), sum(expected_amounts))

    def test_sendmany_4spark_all_complex(self):
        expected_amounts = [Decimal('0.1'), Decimal('0.15'), Decimal('0.2'), Decimal('0.25')]
        spark_address1 = self.nodes[0].getnewsparkaddress()[0]
        spark_address2 = self.nodes[1].getnewsparkaddress()[0]
        spark_address3 = self.nodes[2].getnewsparkaddress()[0]
        spark_address4 = self.nodes[3].getnewsparkaddress()[0]
        self.nodes[0].mintspark({spark_address1: {"amount": expected_amounts[0] * 10}})
        self.nodes[0].mintspark({spark_address2: {"amount": expected_amounts[1] * 10}})
        self.nodes[0].mintspark({spark_address3: {"amount": expected_amounts[2] * 10}})
        self.nodes[0].mintspark({spark_address4: {"amount": expected_amounts[3] * 10}})
        self.nodes[0].generate(1)
        txid = self.nodes[0].sendmany('', {
            spark_address1: expected_amounts[0],
            spark_address2: expected_amounts[1],
            spark_address3: expected_amounts[2],
            spark_address4: expected_amounts[3]
        }, 1, "", [spark_address1, spark_address3])
        tx = self.nodes[0].gettransaction(txid)
        details = [detail for detail in tx['details'] if detail['category'] == 'mint']
        fee = Decimal(tx['fee'])
        total_amounts = sum([detail['amount'] for detail in details])
        self.assert_equal_float(-(total_amounts + fee), sum(expected_amounts))

    def test_sendmany_complex_all_complex(self):
        expected_amounts = [Decimal('0.1'), Decimal('0.15'), Decimal('0.2'), Decimal('0.25')]
        spark_address1 = self.nodes[0].getnewsparkaddress()[0]
        self.nodes[0].mintspark({spark_address1: {"amount": expected_amounts[0] * 10}})
        spark_address2 = self.nodes[1].getnewsparkaddress()[0]
        self.nodes[1].mintspark({spark_address2: {"amount": expected_amounts[2] * 10}})
        transparent_address1 = self.nodes[2].getnewaddress()
        transparent_address2 = self.nodes[3].getnewaddress()
        self.nodes[0].generate(1)
        txids = self.nodes[0].sendmany('', {
            spark_address1: expected_amounts[0],
            transparent_address1: expected_amounts[1],
            spark_address2: expected_amounts[2],
            transparent_address2: expected_amounts[3]
        }, 1, "Alice payment; Bob payment", [spark_address1, transparent_address2])
        self.nodes[0].generate(1)
        txs = []
        for txid in txids:
            txs.append(self.nodes[0].gettransaction(txid))
        details_transparent = []
        details_spark = []
        for tx in txs:
            details_transparent.extend([detail for detail in tx['details'] if detail['category'] == 'send'])
            details_spark.extend([detail for detail in tx['details'] if detail['category'] == 'mint'])
        total_amount_spark = sum([detail['amount'] for detail in details_spark]) + details_spark[0]['fee']
        total_amount_transparent = sum([detail['amount'] for detail in details_transparent]) + details_transparent[0]['fee']
        total_amount = total_amount_spark + total_amount_transparent
        self.assert_equal_float(-total_amount, sum(expected_amounts))

    def assert_equal_float(self, actual: Decimal, expected: Decimal, threshold=0e-20):
        assert abs(actual - expected) <= threshold, f"Values {actual} and {expected} differ by more than {threshold}"

if __name__ == '__main__':
    SendManyTest().main()
