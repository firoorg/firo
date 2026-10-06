#!/usr/bin/env python3
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import JSONRPCException
from decimal import Decimal

class SendTransparentTest(BitcoinTestFramework):
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
        self.test_sendtransparent_simple()
        self.test_sendtransparent_with_comment()
        self.test_sendtransparent_with_comment_to()
        self.test_sendtransparent_with_fee_subtraction()
        self.test_sendtransparent_all()
        
        self.test_sendtransparent_2addresses_simple()
        self.test_sendtransparent_2addresses_with_comments()
        self.test_sendtransparent_2addresses_with_comments_to()
        self.test_sendtransparent_2addresses_with_fee_subtraction()
        self.test_sendtransparent_2addresses_all()
        
        self.test_sendtransparent_4addresses_all_complex()

    def test_sendtransparent_simple(self):
        expected_amount = Decimal('0.1')
        address = self.nodes[0].getnewaddress()
        txid = self.nodes[0].sendtransparent(address, expected_amount)
        self.nodes[0].generate(1)
        tx = self.nodes[0].gettransaction(txid)
        self.assert_equal_float(-tx['details'][0]['amount'], expected_amount)

    def test_sendtransparent_with_comment(self):
        expected_amount = Decimal('0.1')
        address = self.nodes[0].getnewaddress()
        txid = self.nodes[0].sendtransparent(address, expected_amount, "payment comment")
        self.nodes[0].generate(1)
        tx = self.nodes[0].gettransaction(txid)
        self.assert_equal_float(-tx['details'][0]['amount'], expected_amount)
        assert tx['comment'] == "payment comment"

    def test_sendtransparent_with_comment_to(self):
        expected_amount = Decimal('0.1')
        address = self.nodes[0].getnewaddress()
        txid = self.nodes[0].sendtransparent(address, expected_amount, "payment comment", "recipient name")
        self.nodes[0].generate(1)
        tx = self.nodes[0].gettransaction(txid)
        self.assert_equal_float(-tx['details'][0]['amount'], expected_amount)
        assert tx['comment'] == "payment comment"
        assert tx['to'] == "recipient name"

    def test_sendtransparent_with_fee_subtraction(self):
        expected_amount = Decimal('0.1')
        address = self.nodes[0].getnewaddress()
        txid = self.nodes[0].sendtransparent(address, expected_amount, "", "", True)
        self.nodes[0].generate(1)
        tx = self.nodes[0].gettransaction(txid)
        fee = Decimal(tx['fee'])
        self.assert_equal_float(-(tx['details'][0]['amount'] + fee), expected_amount)

    def test_sendtransparent_all(self):
        expected_amount = Decimal('0.1')
        address = self.nodes[0].getnewaddress()
        txid = self.nodes[0].sendtransparent(address, expected_amount, "payment comment", "recipient name", True)
        self.nodes[0].generate(1)
        tx = self.nodes[0].gettransaction(txid)
        fee = Decimal(tx['fee'])
        self.assert_equal_float(-(tx['details'][0]['amount'] + fee), expected_amount)
        assert tx['comment'] == "payment comment"
        assert tx['to'] == "recipient name"

    def test_sendtransparent_2addresses_simple(self):
        expected_amounts = [Decimal('0.1'), Decimal('0.15')]
        address1 = self.nodes[0].getnewaddress()
        address2 = self.nodes[1].getnewaddress()
        txid = self.nodes[0].sendtransparent({
            address1: {"amount": expected_amounts[0]},
            address2: {"amount": expected_amounts[1]}
        })
        self.nodes[0].generate(1)
        tx = self.nodes[0].gettransaction(txid)
        details = [detail for detail in tx['details'] if detail['category'] == 'send']
        for i, detail in enumerate(details):
            self.assert_equal_float(-detail['amount'], expected_amounts[i])

    def test_sendtransparent_2addresses_with_comments(self):
            expected_amounts = [Decimal('0.1'), Decimal('0.15')]
            expected_comments = ["first payment", "second payment"]
            address1 = self.nodes[0].getnewaddress()
            address2 = self.nodes[1].getnewaddress()
            txid = self.nodes[0].sendtransparent({
                address1: {
                    "amount": expected_amounts[0],
                    "comment": expected_comments[0],
                },
                address2: {
                    "amount": expected_amounts[1],
                    "comment": expected_comments[1],
                }
            })
            self.nodes[0].generate(1)
            tx = self.nodes[0].gettransaction(txid)
            details = [detail for detail in tx['details'] if detail['category'] == 'send']
            for i, detail in enumerate(details):
                self.assert_equal_float(-detail['amount'], expected_amounts[i])
            self.assert_comments(tx['comment'], expected_comments)

    def test_sendtransparent_2addresses_with_comments_to(self):
            expected_amounts = [Decimal('0.1'), Decimal('0.15')]
            expected_comments_to = ["John", "David"]
            address1 = self.nodes[0].getnewaddress()
            address2 = self.nodes[1].getnewaddress()
            txid = self.nodes[0].sendtransparent({
                address1: {
                    "amount": expected_amounts[0],
                    "comment_to": expected_comments_to[0],
                },
                address2: {
                    "amount": expected_amounts[1],
                    "comment_to": expected_comments_to[1],
                }
            })
            self.nodes[0].generate(1)
            tx = self.nodes[0].gettransaction(txid)
            details = [detail for detail in tx['details'] if detail['category'] == 'send']
            for i, detail in enumerate(details):
                self.assert_equal_float(-detail['amount'], expected_amounts[i])
            self.assert_comments(tx['to'], expected_comments_to)

    def test_sendtransparent_2addresses_with_fee_subtraction(self):
            expected_amounts = [Decimal('0.1'), Decimal('0.15')]
            address1 = self.nodes[0].getnewaddress()
            address2 = self.nodes[1].getnewaddress()
            txid = self.nodes[0].sendtransparent({
                address1: {
                    "amount": expected_amounts[0],
                    "subtractFee": True
                },
                address2: {
                    "amount": expected_amounts[1],
                    "subtractFee": True
                }
            })
            self.nodes[0].generate(1)
            tx = self.nodes[0].gettransaction(txid)
            details = [detail for detail in tx['details'] if detail['category'] == 'send']
            fee = Decimal(tx['fee'])
            total_amounts = sum([detail['amount'] for detail in details])
            self.assert_equal_float(-(total_amounts + fee), sum(expected_amounts))

    def test_sendtransparent_2addresses_all(self):
            expected_amounts = [Decimal('0.1'), Decimal('0.15')]
            expected_comments = ["John payment", "David payment"]
            expected_comments_to = ["John", "David"]
            address1 = self.nodes[0].getnewaddress()
            address2 = self.nodes[1].getnewaddress()
            txid = self.nodes[0].sendtransparent({
                address1: {
                    "amount": expected_amounts[0],
                    "comment": expected_comments[0],
                    "comment_to": expected_comments_to[0],
                    "subtractFee": True
                },
                address2: {
                    "amount": expected_amounts[1],
                    "comment": expected_comments[1],
                    "comment_to": expected_comments_to[1],
                    "subtractFee": True
                }
            })
            self.nodes[0].generate(1)
            tx = self.nodes[0].gettransaction(txid)
            details = [detail for detail in tx['details'] if detail['category'] == 'send']
            fee = Decimal(tx['fee'])
            total_amounts = sum([detail['amount'] for detail in details])
            self.assert_equal_float(-(total_amounts + fee), sum(expected_amounts))
            self.assert_comments(tx['comment'], expected_comments)
            self.assert_comments(tx['to'], expected_comments_to)

    def test_sendtransparent_4addresses_all_complex(self):
            expected_amounts = [Decimal('0.1'), Decimal('0.15'), Decimal('0.2'), Decimal('0.25')]
            expected_comments = ["first payment", "second payment", "third payment", "fourth payment"]
            expected_comments_to = ["Alice", "Bob", "Charlie", "David"]
            address1 = self.nodes[0].getnewaddress()
            address2 = self.nodes[1].getnewaddress()
            address3 = self.nodes[2].getnewaddress()
            address4 = self.nodes[3].getnewaddress()
            txid = self.nodes[0].sendtransparent({
                address1: {
                    "amount": expected_amounts[0],
                    "comment": expected_comments[0],
                    "comment_to": expected_comments_to[0],
                    "subtractFee": True
                },
                address2: {
                    "amount": expected_amounts[1],
                    "comment": expected_comments[1],
                    "comment_to": expected_comments_to[1],
                    "subtractFee": False
                },
                address3: {
                    "amount": expected_amounts[2],
                    "comment": expected_comments[2],
                    "comment_to": expected_comments_to[2],
                    "subtractFee": True
                },
                address4: {
                    "amount": expected_amounts[3],
                    "comment": expected_comments[3],
                    "comment_to": expected_comments_to[3],
                    "subtractFee": False
                }
            })
            self.nodes[0].generate(1)
            tx = self.nodes[0].gettransaction(txid)
            details = [detail for detail in tx['details'] if detail['category'] == 'send']
            fee = Decimal(tx['fee'])
            total_amounts = sum([detail['amount'] for detail in details])
            self.assert_equal_float(-(total_amounts + fee), sum(expected_amounts))
            self.assert_comments(tx['comment'], expected_comments)
            self.assert_comments(tx['to'], expected_comments_to)


    def assert_comments(self, actual_comments, expected_comments):
        """
        Helper function to assert transaction comments or comment_to values.

        :param actual_comments: String of actual comments from the transaction, separated by '; '.
        :param expected_comments: List of expected comments.
        """
        actual_comments_list = actual_comments.split('; ')
        assert len(actual_comments_list) == len(expected_comments), \
            f"Mismatch in number of comments. Expected {len(expected_comments)}, got {len(actual_comments_list)}."
        for expected in expected_comments:
            assert expected in actual_comments_list, f"Expected comment '{expected}' not found in actual comments."

    def assert_equal_float(self, actual: Decimal, expected: Decimal, threshold=0e-20):
        assert abs(actual - expected) <= threshold, f"Values {actual} and {expected} differ by more than {threshold}"

if __name__ == '__main__':
    SendTransparentTest().main()
