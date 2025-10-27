#!/usr/bin/env python3
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import JSONRPCException
from decimal import Decimal

class SendToAddressTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 4
        self.setup_clean_chain = False

    def activate_spark(self):
        """Ensure Spark is activated before running tests."""
        HARDCODED_ACTIVATION_HEIGHT = 401  # Replace with the actual activation height for Spark
        current_height = self.nodes[0].getblockcount()
        if current_height < HARDCODED_ACTIVATION_HEIGHT:
            self.nodes[0].generate(HARDCODED_ACTIVATION_HEIGHT - current_height)
            self.log.info(f"Generated {HARDCODED_ACTIVATION_HEIGHT - current_height} blocks to activate Spark.")

        blockchain_info = self.nodes[0].getblockchaininfo()
        activation_height = HARDCODED_ACTIVATION_HEIGHT
        if 'upgrades' in blockchain_info and 'spark' in blockchain_info['upgrades']:
            activation_height = blockchain_info['upgrades']['spark']['activationheight']
            self.log.info(f"Dynamic Spark activation height: {activation_height}")

        # Ensure the chain height meets the activation height
        if current_height < activation_height:
            self.nodes[0].generate(activation_height - current_height)
            self.log.info(f"Generated {activation_height - current_height} blocks to meet dynamic activation height.")

        # Check Spark activation explicitly
        try:
            self.nodes[0].getnewsparkaddress()
            self.log.info("Spark is activated.")
        except JSONRPCException as e:
            if e.error.get('code') == -4:
                raise AssertionError("Spark is not activated even after generating blocks.")
            else:
                raise

    def run_test(self):
        """Run all test cases."""
        self.activate_spark()  # Ensure Spark is activated
        self.test_sendtoaddress_1transparent_simple()
        self.test_sendtoaddress_1transparent_with_comment()
        self.test_sendtoaddress_1transparent_with_comment_to()
        self.test_sendtoaddress_1transparent_with_fee_subtraction()
        self.test_sendtoaddress_1transparent_all()
        self.test_sendtoaddress_2transparent_simple()
        self.test_sendtoaddress_2transparent_with_comments()
        self.test_sendtoaddress_2transparent_with_comments_to()
        self.test_sendtoaddress_2transparent_with_fee_subtraction()
        self.test_sendtoaddress_2transparent_all()
        self.test_sendtoaddress_4transparent_all_complex()
        
        self.test_sendtoaddress_1spark_simple()
        self.test_sendtoaddress_1spark_with_fee_subtraction()
        self.test_sendtoaddress_1spark_all()
        self.test_sendtoaddress_2spark_simple()
        self.test_sendtoaddress_2spark_with_fee_subtraction()
        self.test_sendtoaddress_2spark_all()
        self.test_sendtoaddress_4spark_all_complex()

        self.test_sendtoaddress_complex_all_complex()

    def test_sendtoaddress_1transparent_simple(self):
        """Test sendtoaddress with simple format."""
        expected_amount = Decimal('0.1')
        address = self.nodes[0].getnewaddress()
        txid = self.nodes[0].sendtoaddress(address, expected_amount)
        self.nodes[0].generate(1)
        tx = self.nodes[0].gettransaction(txid)
        self.assert_equal_float(-tx['details'][0]['amount'], expected_amount)

    def test_sendtoaddress_1transparent_with_comment(self):
        """Test sendtoaddress with a comment."""
        expected_amount = Decimal('0.1')
        address = self.nodes[0].getnewaddress()
        txid = self.nodes[0].sendtoaddress(address, expected_amount, "payment comment")
        self.nodes[0].generate(1)
        tx = self.nodes[0].gettransaction(txid)
        self.assert_equal_float(-tx['details'][0]['amount'], expected_amount)
        assert tx['comment'] == "payment comment"

    def test_sendtoaddress_1transparent_with_comment_to(self):
        """Test sendtoaddress with a comment and comment_to."""
        expected_amount = Decimal('0.1')
        address = self.nodes[0].getnewaddress()
        txid = self.nodes[0].sendtoaddress(address, expected_amount, "payment comment", "recipient name")
        self.nodes[0].generate(1)
        tx = self.nodes[0].gettransaction(txid)
        self.assert_equal_float(-tx['details'][0]['amount'], expected_amount)
        assert tx['comment'] == "payment comment"
        assert tx['to'] == "recipient name"

    def test_sendtoaddress_1transparent_with_fee_subtraction(self):
        """Test sendtoaddress with fee subtraction."""
        expected_amount = Decimal('0.1')
        address = self.nodes[0].getnewaddress()
        txid = self.nodes[0].sendtoaddress(address, expected_amount, "", "", True)
        self.nodes[0].generate(1)
        tx = self.nodes[0].gettransaction(txid)
        fee = Decimal(tx['fee'])
        self.assert_equal_float(-(tx['details'][0]['amount'] + fee), expected_amount)

    def test_sendtoaddress_1transparent_all(self):
        """Test sendtoaddress with all parameters."""
        expected_amount = Decimal('0.1')
        address = self.nodes[0].getnewaddress()
        txid = self.nodes[0].sendtoaddress(address, expected_amount, "payment comment", "recipient name", True)
        self.nodes[0].generate(1)
        tx = self.nodes[0].gettransaction(txid)
        fee = Decimal(tx['fee'])
        self.assert_equal_float(-(tx['details'][0]['amount'] + fee), expected_amount)
        assert tx['comment'] == "payment comment"
        assert tx['to'] == "recipient name"

    def test_sendtoaddress_2transparent_simple(self):
        """Test sendmany with 2 transparent addresses."""
        expected_amounts = [Decimal('0.1'), Decimal('0.15')]
        address1 = self.nodes[0].getnewaddress()
        address2 = self.nodes[1].getnewaddress()
        txid = self.nodes[0].sendtoaddress({
            address1: { 
                "amount": expected_amounts[0],
            },
            address2: { 
                "amount": expected_amounts[1]
            }
        })
        self.nodes[0].generate(1)
        tx = self.nodes[0].gettransaction(txid)
        details = [detail for detail in tx['details'] if detail['category'] == 'send']
        for i, detail in enumerate(details):
            self.assert_equal_float(-detail['amount'], expected_amounts[i])

    def test_sendtoaddress_2transparent_with_comments(self):
        """Test sendtoaddress with 2 transparent addresses and comments."""
        expected_amounts = [Decimal('0.1'), Decimal('0.15')]
        expected_comments = ["first payment", "second payment"]
        address1 = self.nodes[0].getnewaddress()
        address2 = self.nodes[1].getnewaddress()
        txid = self.nodes[0].sendtoaddress({
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
        comments = tx.get('comment', [])
        assert comments == (f"{expected_comments[0]}; {expected_comments[1]}")
        
    def test_sendtoaddress_2transparent_with_comments_to(self):
        """Test sendtoaddress with 2 transparent addresses and comments_to."""
        expected_amounts = [Decimal('0.1'), Decimal('0.15')]
        expected_comments_to = ["John", "David"]
        address1 = self.nodes[0].getnewaddress()
        address2 = self.nodes[1].getnewaddress()
        txid = self.nodes[0].sendtoaddress({
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
        comments_to = tx.get('to', [])
        assert comments_to == (f"{expected_comments_to[1]}; {expected_comments_to[0]}")

    def test_sendtoaddress_2transparent_with_fee_subtraction(self):
        """Test sendtoaddress with 2 transparent addresses and fee subtraction."""
        expected_amounts = [Decimal('0.1'), Decimal('0.15')]
        total_expected_amounts = sum(expected_amounts)
        address1 = self.nodes[0].getnewaddress()
        address2 = self.nodes[1].getnewaddress()
        txid = self.nodes[0].sendtoaddress({
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
        self.assert_equal_float(-(total_amounts + fee), total_expected_amounts)

    def test_sendtoaddress_2transparent_all(self):
        """Test sendtoaddress with 2 transparent addresses and all parameters."""
        expected_amounts = [Decimal('0.1'), Decimal('0.15')]
        expected_comments_to = ["John", "David"]
        expected_comments = ["John payment", "David payment"]
        total_expected_amounts = sum(expected_amounts)
        address1 = self.nodes[0].getnewaddress()
        address2 = self.nodes[1].getnewaddress()
        txid = self.nodes[0].sendtoaddress({
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
        comments_to = tx.get('to', [])
        comments = tx.get('comment', [])
        
        self.assert_equal_float(-(total_amounts + fee), total_expected_amounts)
        self.assert_comments(comments, expected_comments)
        self.assert_comments(comments_to, expected_comments_to)

    def test_sendtoaddress_4transparent_all_complex(self):
        """Test sendtoaddress with 4 transparent addresses and all parameters."""
        expected_amounts = [Decimal('0.1'), Decimal('0.15'), Decimal('0.2'), Decimal('0.25')]
        expected_comments = ["first payment", "second payment", "third payment", "fourth payment"]
        expected_comments_to = ["Alice", "Bob", "Charlie", "David"]
        total_expected_amounts = sum(expected_amounts)
        address1 = self.nodes[0].getnewaddress()
        address2 = self.nodes[1].getnewaddress()
        address3 = self.nodes[2].getnewaddress()
        address4 = self.nodes[3].getnewaddress()
        txid = self.nodes[0].sendtoaddress({
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
        comments_to = tx.get('to', [])
        comments = tx.get('comment', [])

        self.assert_equal_float(-(total_amounts + fee), total_expected_amounts)
        self.assert_comments(comments, expected_comments)
        self.assert_comments(comments_to, expected_comments_to)

    def test_sendtoaddress_1spark_simple(self):
        """Test sendtoaddress with a Spark address."""
        expected_amount = Decimal('0.1')
        spark_address = self.nodes[0].getnewsparkaddress()[0]
        self.nodes[0].mintspark({spark_address: {"amount": expected_amount * 10}})
        self.nodes[0].generate(1)
        txid = self.nodes[0].sendtoaddress({
            spark_address: {
                "amount": expected_amount
            }
        })
        tx = self.nodes[0].gettransaction(txid)
        details = [detail for detail in tx['details'] if detail['category'] == 'mint']
        self.assert_equal_float(-details[0]['amount'], expected_amount)
        assert details[0]['address'] == spark_address, f"Expected Spark address '{spark_address}', got '{details[0]['address']}'"

    def test_sendtoaddress_1spark_with_fee_subtraction(self):
        """Test sendtoaddress with a Spark address and fee subtraction."""
        expected_amount = Decimal('0.1')
        spark_address = self.nodes[0].getnewsparkaddress()[0]
        self.nodes[0].mintspark({spark_address: {"amount": expected_amount * 10}})
        self.nodes[0].generate(1)
        txid = self.nodes[0].sendtoaddress({
            spark_address: {
                "amount": expected_amount,
                "subtractFee": True
            }
        })
        tx = self.nodes[0].gettransaction(txid)
        details = [detail for detail in tx['details'] if detail['category'] == 'mint']
        fee = Decimal(tx['fee'])
        self.assert_equal_float(-(details[0]['amount'] + fee), expected_amount)
        assert details[0]['address'] == spark_address

    def test_sendtoaddress_1spark_all(self):
        """Test sendtoaddress with all parameters for a Spark address."""
        expected_amount = Decimal('0.1')
        spark_address = self.nodes[0].getnewsparkaddress()[0]
        self.nodes[0].mintspark({spark_address: {"amount": expected_amount * 10}})
        self.nodes[0].generate(1)
        txid = self.nodes[0].sendtoaddress({
            spark_address: {
                "amount": expected_amount,
                "subtractFee": True
            }
        })
        tx = self.nodes[0].gettransaction(txid)
        details = [detail for detail in tx['details'] if detail['category'] == 'mint']
        fee = Decimal(tx['fee'])
        self.assert_equal_float(-(details[0]['amount'] + fee), expected_amount)
        assert details[0]['address'] == spark_address

    def test_sendtoaddress_2spark_simple(self):
        """Test sendtoaddress with two Spark addresses."""
        expected_amounts = [Decimal('0.1'), Decimal('0.15')]
        spark_address1 = self.nodes[0].getnewsparkaddress()[0]
        spark_address2 = self.nodes[1].getnewsparkaddress()[0]
        self.nodes[0].mintspark({spark_address1: {"amount": expected_amounts[0] * 10}})
        self.nodes[0].mintspark({spark_address2: {"amount": expected_amounts[1] * 10}})
        self.nodes[0].generate(1)
        txid = self.nodes[0].sendtoaddress({
            spark_address1: {"amount": expected_amounts[0]},
            spark_address2: {"amount": expected_amounts[1]}
        })
        tx = self.nodes[0].gettransaction(txid)
        details = [detail for detail in tx['details'] if detail['category'] == 'mint']
        for i, detail in enumerate(details):
            self.assert_equal_float(-detail['amount'], expected_amounts[i])

    def test_sendtoaddress_2spark_with_fee_subtraction(self):
        """Test sendtoaddress with two Spark addresses and fee subtraction."""
        expected_amounts = [Decimal('0.1'), Decimal('0.15')]
        spark_address1 = self.nodes[0].getnewsparkaddress()[0]
        spark_address2 = self.nodes[1].getnewsparkaddress()[0]
        self.nodes[0].mintspark({spark_address1: {"amount": expected_amounts[0] * 10}})
        self.nodes[0].mintspark({spark_address2: {"amount": expected_amounts[1] * 10}})
        self.nodes[0].generate(1)
        txid = self.nodes[0].sendtoaddress({
            spark_address1: {"amount": expected_amounts[0], "subtractFee": True},
            spark_address2: {"amount": expected_amounts[1], "subtractFee": True}
        })
        tx = self.nodes[0].gettransaction(txid)
        details = [detail for detail in tx['details'] if detail['category'] == 'mint']
        fee = Decimal(tx['fee'])
        total_amounts = sum([detail['amount'] for detail in details])
        self.assert_equal_float(-(total_amounts + fee), sum(expected_amounts))

    def test_sendtoaddress_2spark_all(self):
        """Test sendtoaddress with all parameters for two Spark addresses."""
        expected_amounts = [Decimal('0.1'), Decimal('0.15')]
        spark_address1 = self.nodes[0].getnewsparkaddress()[0]
        spark_address2 = self.nodes[1].getnewsparkaddress()[0]
        self.nodes[0].mintspark({spark_address1: {"amount": expected_amounts[0] * 10}})
        self.nodes[0].mintspark({spark_address2: {"amount": expected_amounts[1] * 10}})
        self.nodes[0].generate(1)
        txid = self.nodes[0].sendtoaddress({
            spark_address1: {
                "amount": expected_amounts[0],
                "subtractFee": True
            },
            spark_address2: {
                "amount": expected_amounts[1],
                "subtractFee": True
            }
        })
        tx = self.nodes[0].gettransaction(txid)
        details = [detail for detail in tx['details'] if detail['category'] == 'mint']
        fee = Decimal(tx['fee'])
        total_amounts = sum([detail['amount'] for detail in details])
        self.assert_equal_float(-(total_amounts + fee), sum(expected_amounts))

    def test_sendtoaddress_4spark_all_complex(self):
        """Test sendtoaddress with four Spark addresses and all parameters."""
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
        txid = self.nodes[0].sendtoaddress({
            spark_address1: {
                "amount": expected_amounts[0],
                "subtractFee": True
            },
            spark_address2: {
                "amount": expected_amounts[1],
                "subtractFee": False
            },
            spark_address3: {
                "amount": expected_amounts[2],
                "subtractFee": True
            },
            spark_address4: {
                "amount": expected_amounts[3],
                "subtractFee": False
            }
        })
        tx = self.nodes[0].gettransaction(txid)
        details = [detail for detail in tx['details'] if detail['category'] == 'mint']
        fee = Decimal(tx['fee'])
        total_amounts = sum([detail['amount'] for detail in details])
        self.assert_equal_float(-(total_amounts + fee), sum(expected_amounts))
    
    def test_sendtoaddress_complex_all_complex(self):
        """Multiple various addresses and complex arguments."""
        expected_amounts = [Decimal('0.1'), Decimal('0.15'), Decimal('0.2'), Decimal('0.25')]
        expected_comments = ["Alice payment", "Bob payment"]
        expected_comments_to = ["Alice", "Bob"]
        total_expected_amounts = sum(expected_amounts)

        spark_address1 = self.nodes[0].getnewsparkaddress()[0]
        self.nodes[0].mintspark({spark_address1: {"amount": expected_amounts[0] * 10}})
        spark_address2 = self.nodes[1].getnewsparkaddress()[0]
        self.nodes[1].mintspark({spark_address2: {"amount": expected_amounts[2] * 10}})
        transparent_address1 = self.nodes[2].getnewaddress()
        transparent_address2 = self.nodes[3].getnewaddress()

        address1 = spark_address1
        address2 = transparent_address1
        address3 = spark_address2
        address4 = transparent_address2

        self.nodes[0].generate(1)

        txids = self.nodes[0].sendtoaddress({
            address1: {
                "amount": expected_amounts[0],
                "subtractFee": True
            },
            address2: {
                "amount": expected_amounts[1],
                "comment": expected_comments[0],
                "comment_to": expected_comments_to[0],
                "subtractFee": False
            },
            address3: {
                "amount": expected_amounts[2],
                "subtractFee": False
            },
            address4: {
                "amount": expected_amounts[3],
                "comment": expected_comments[1],
                "comment_to": expected_comments_to[1],
                "subtractFee": True
            }
        })
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
        self.assert_equal_float(-total_amount, total_expected_amounts)

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
        """Assert that two float values are equal within a certain threshold."""
        assert abs(actual - expected) <= threshold, \
            f"Values {actual} and {expected} differ by more than {threshold}"


if __name__ == '__main__':
    SendToAddressTest().main()