#!/usr/bin/env python3
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import JSONRPCException, enable_mocktime
from decimal import Decimal

class SpendSparkTest(BitcoinTestFramework):
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
        self.sync_all()

    def run_test(self):
        
        self.activate_spark()

        sparkAddress = self.nodes[0].getsparkdefaultaddress()[0]
        self.nodes[0].mintspark({sparkAddress: {"amount": 10}})
        self.nodes[0].generate(1)
        self.sync_all()

        self.test_spendspark_1transparent_simple()
        self.test_spendspark_1transparent_with_fee()
        self.test_spendspark_1transparent_all()
        self.test_spendspark_2transparent_simple()
        self.test_spendspark_2transparent_with_fee()
        self.test_spendspark_2transparent_all()
        self.test_spendspark_4transparent_all_complex()


        self.test_spendspark_1spark_simple()
        self.test_spendspark_1spark_with_fee()
        self.test_spendspark_1spark_all()
        self.test_spendspark_2spark_simple()
        self.test_spendspark_2spark_with_fee()
        self.test_spendspark_2spark_all()
        self.test_spendspark_4spark_all_complex()

        self.test_spendspark_complex_all_complex()

    def test_spendspark_1transparent_simple(self):
        """Test spending Spark to a transparent address without fee subtraction."""
        expected_amount = Decimal('0.01')
        sparkAddress = self.nodes[0].getsparkdefaultaddress()[0]
        self.nodes[0].mintspark({sparkAddress: {"amount": expected_amount * 10}})
        self.nodes[0].generate(1)
        self.sync_all()

        transparent_address = self.nodes[0].getnewaddress()
        txid = self.nodes[0].spendspark({transparent_address: {"amount": expected_amount, "subtractFee": False}})
        self.nodes[0].generate(1)
        self.sync_all()

        tx = self.nodes[0].gettransaction(txid)
        details = [detail for detail in tx['details'] if detail['category'] == 'spend']
        self.assert_equal_float(-details[0]['amount'], expected_amount)
    
    def test_spendspark_1transparent_with_fee(self):
        """Test spending Spark to a transparent address with fee subtraction."""
        expected_amount = Decimal('0.01')
        sparkAddress = self.nodes[0].getsparkdefaultaddress()[0]
        self.nodes[0].mintspark({sparkAddress: {"amount": expected_amount * 10}})
        self.nodes[0].generate(1)
        self.sync_all()

        transparent_address = self.nodes[0].getnewaddress()
        txid = self.nodes[0].spendspark({transparent_address: {"amount": expected_amount, "subtractFee": True}})
        self.nodes[0].generate(1)
        self.sync_all()

        tx = self.nodes[0].gettransaction(txid)
        details = [detail for detail in tx['details'] if detail['category'] == 'spend']
        fee = Decimal(tx['fee'])
        self.assert_equal_float(-(details[0]['amount'] + fee), expected_amount)

    def test_spendspark_1transparent_all(self):
        """Test spending Spark to a transparent address with memo and fee subtraction."""
        expected_amount = Decimal('0.01')
        sparkAddress = self.nodes[0].getsparkdefaultaddress()[0]
        self.nodes[0].mintspark({sparkAddress: {"amount": expected_amount * 10}})
        self.nodes[0].generate(1)
        self.sync_all()

        transparent_address = self.nodes[0].getnewaddress()
        txid = self.nodes[0].spendspark({transparent_address: {"amount": expected_amount, "memo": "test memo", "subtractFee": True}})
        self.nodes[0].generate(1)
        self.sync_all()

        tx = self.nodes[0].gettransaction(txid)
        details = [detail for detail in tx['details'] if detail['category'] == 'spend']
        fee = Decimal(tx['fee'])
        self.assert_equal_float(-(details[0]['amount'] + fee), expected_amount)

    def test_spendspark_2transparent_simple(self):
        """Test spending Spark to two transparent addresses without fee subtraction."""
        expected_amounts = [Decimal('0.1'), Decimal('0.5')]
        sparkAddress = self.nodes[0].getsparkdefaultaddress()[0]
        self.nodes[0].mintspark({sparkAddress: {"amount": sum(expected_amounts) * 10}})
        self.nodes[0].generate(1)
        self.sync_all()

        transparent_address_1 = self.nodes[0].getnewaddress()
        transparent_address_2 = self.nodes[0].getnewaddress()
        txid = self.nodes[0].spendspark({
            transparent_address_1: {"amount": expected_amounts[0], "subtractFee": False}, 
            transparent_address_2: {"amount": expected_amounts[1], "subtractFee": False}
        })
        self.nodes[0].generate(1)
        self.sync_all()

        tx = self.nodes[0].gettransaction(txid)
        details = [detail for detail in tx['details'] if detail['category'] == 'spend']
        total_spent = sum([detail['amount'] for detail in details])
        self.assert_equal_float(-total_spent, sum(expected_amounts))

    def test_spendspark_2transparent_with_fee(self):
        """Test spending Spark to two transparent addresses with fee subtraction."""
        expected_amounts = [Decimal('0.01'), Decimal('0.5')]
        sparkAddress = self.nodes[0].getsparkdefaultaddress()[0]
        self.nodes[0].mintspark({sparkAddress: {"amount": sum(expected_amounts) * 10}})
        self.nodes[0].generate(1)
        self.sync_all()

        transparent_address_1 = self.nodes[0].getnewaddress()
        transparent_address_2 = self.nodes[0].getnewaddress()
        txid = self.nodes[0].spendspark({
            transparent_address_1: {"amount": expected_amounts[0], "subtractFee": True},
            transparent_address_2: {"amount": expected_amounts[1], "subtractFee": True}
        })
        self.nodes[0].generate(1)
        self.sync_all()

        tx = self.nodes[0].gettransaction(txid)
        details = [detail for detail in tx['details'] if detail['category'] == 'spend']
        fee = Decimal(tx['fee'])
        total_spent = sum([detail['amount'] for detail in details]) + fee
        self.assert_equal_float(-total_spent, sum(expected_amounts))

    def test_spendspark_2transparent_all(self):
        """Test spending Spark to two transparent addresses with memo and fee subtraction."""
        expected_amounts = [Decimal('0.1'), Decimal('0.1')]
        sparkAddress = self.nodes[0].getsparkdefaultaddress()[0]
        self.nodes[0].mintspark({sparkAddress: {"amount": sum(expected_amounts) * 10}})
        self.nodes[0].generate(1)
        self.sync_all()

        transparent_address_1 = self.nodes[0].getnewaddress()
        transparent_address_2 = self.nodes[0].getnewaddress()
        txid = self.nodes[0].spendspark({
            transparent_address_1: {"amount": expected_amounts[0], "memo": "memo1", "subtractFee": True},
            transparent_address_2: {"amount": expected_amounts[1], "memo": "memo2", "subtractFee": True}
        })
        self.nodes[0].generate(1)
        self.sync_all()

        tx = self.nodes[0].gettransaction(txid)
        details = [detail for detail in tx['details'] if detail['category'] == 'spend']
        fee = Decimal(tx['fee'])
        total_spent = sum([detail['amount'] for detail in details]) + fee
        self.assert_equal_float(-total_spent, sum(expected_amounts))

    def test_spendspark_4transparent_all_complex(self):
        """Test spending Spark to four transparent addresses with complex amounts and fee subtraction."""
        expected_amounts = [Decimal('0.01'), Decimal('0.05'), Decimal('0.1'), Decimal('0.2')]
        sparkAddress = self.nodes[0].getsparkdefaultaddress()[0]
        self.nodes[0].mintspark({sparkAddress: {"amount": sum(expected_amounts) * 10}})
        self.nodes[0].generate(1)
        self.sync_all()

        transparent_addresses = [self.nodes[0].getnewaddress() for _ in range(4)]
        txid = self.nodes[0].spendspark({
            transparent_addresses[0]: {"amount": expected_amounts[0], "subtractFee": True},
            transparent_addresses[1]: {"amount": expected_amounts[1], "subtractFee": False},
            transparent_addresses[2]: {"amount": expected_amounts[2], "subtractFee": True},
            transparent_addresses[3]: {"amount": expected_amounts[3], "subtractFee": False}
        })
        self.nodes[0].generate(1)
        self.sync_all()

        tx = self.nodes[0].gettransaction(txid)
        details = [detail for detail in tx['details'] if detail['category'] == 'spend']
        fee = Decimal(tx['fee'])
        total_spent = sum([detail['amount'] for detail in details]) + fee
        self.assert_equal_float(-total_spent, sum(expected_amounts))


    def test_spendspark_1spark_simple(self):
        """Test spending Spark to a Spark address without fee subtraction."""
        expected_amount = Decimal('0.01')
        sparkAddress = self.nodes[0].getsparkdefaultaddress()[0]
        self.nodes[0].mintspark({sparkAddress: {"amount": expected_amount * 10}})
        self.nodes[0].generate(1)
        self.sync_all()

        spark_addr = self.nodes[0].getnewsparkaddress()[0]
        txid = self.nodes[0].spendspark({spark_addr: {"amount": expected_amount, "subtractFee": False}})
        self.nodes[0].generate(1)
        self.sync_all()

        tx = self.nodes[0].gettransaction(txid)
        details = [detail for detail in tx['details'] if detail['category'] == 'spend']
        self.assert_equal_float(-details[0]['amount'], expected_amount)
    
    def test_spendspark_1spark_with_fee(self):
        """Test spending Spark to a Spark address with fee subtraction."""
        expected_amount = Decimal('0.01')
        sparkAddress = self.nodes[0].getsparkdefaultaddress()[0]
        self.nodes[0].mintspark({sparkAddress: {"amount": expected_amount * 10}})
        self.nodes[0].generate(1)
        self.sync_all()

        spark_addr = self.nodes[0].getnewsparkaddress()[0]
        txid = self.nodes[0].spendspark({spark_addr: {"amount": expected_amount, "subtractFee": True}})
        self.nodes[0].generate(1)
        self.sync_all()

        tx = self.nodes[0].gettransaction(txid)
        details = [detail for detail in tx['details'] if detail['category'] == 'spend']
        fee = Decimal(tx['fee'])
        self.assert_equal_float(-(details[0]['amount'] + fee), expected_amount)

    def test_spendspark_1spark_all(self):
        """Test spending Spark to a Spark address with memo and fee subtraction."""
        expected_amount = Decimal('0.01')
        sparkAddress = self.nodes[0].getsparkdefaultaddress()[0]
        self.nodes[0].mintspark({sparkAddress: {"amount": expected_amount * 10}})
        self.nodes[0].generate(1)
        self.sync_all()

        spark_addr = self.nodes[0].getnewsparkaddress()[0]
        txid = self.nodes[0].spendspark({spark_addr: {"amount": expected_amount, "memo": "test memo", "subtractFee": True}})
        self.nodes[0].generate(1)
        self.sync_all()

        tx = self.nodes[0].gettransaction(txid)
        details = [detail for detail in tx['details'] if detail['category'] == 'spend']
        fee = Decimal(tx['fee'])
        self.assert_equal_float(-(details[0]['amount'] + fee), expected_amount)

    def test_spendspark_2spark_simple(self):
        """Test spending Spark to two Spark addresses without fee subtraction."""
        expected_amounts = [Decimal('0.1'), Decimal('0.5')]
        sparkAddress = self.nodes[0].getsparkdefaultaddress()[0]
        self.nodes[0].mintspark({sparkAddress: {"amount": sum(expected_amounts) * 10}})
        self.nodes[0].generate(1)
        self.sync_all()

        spark_addr_1 = self.nodes[0].getnewsparkaddress()[0]
        spark_addr_2 = self.nodes[0].getnewsparkaddress()[0]
        txid = self.nodes[0].spendspark({
            spark_addr_1: {"amount": expected_amounts[0], "subtractFee": False}, 
            spark_addr_2: {"amount": expected_amounts[1], "subtractFee": False}
        })
        self.nodes[0].generate(1)
        self.sync_all()

        tx = self.nodes[0].gettransaction(txid)
        details = [detail for detail in tx['details'] if detail['category'] == 'spend']
        total_spent = sum([detail['amount'] for detail in details])
        self.assert_equal_float(-total_spent, sum(expected_amounts))

    def test_spendspark_2spark_with_fee(self):
        """Test spending Spark to two Spark addresses with fee subtraction."""
        expected_amounts = [Decimal('0.01'), Decimal('0.5')]
        sparkAddress = self.nodes[0].getsparkdefaultaddress()[0]
        self.nodes[0].mintspark({sparkAddress: {"amount": sum(expected_amounts) * 10}})
        self.nodes[0].generate(1)
        self.sync_all()

        spark_addr_1 = self.nodes[0].getnewsparkaddress()[0]
        spark_addr_2 = self.nodes[0].getnewsparkaddress()[0]
        txid = self.nodes[0].spendspark({
            spark_addr_1: {"amount": expected_amounts[0], "subtractFee": True},
            spark_addr_2: {"amount": expected_amounts[1], "subtractFee": True}
        })
        self.nodes[0].generate(1)
        self.sync_all()

        tx = self.nodes[0].gettransaction(txid)
        details = [detail for detail in tx['details'] if detail['category'] == 'spend']
        fee = Decimal(tx['fee'])
        total_spent = sum([detail['amount'] for detail in details]) + fee
        self.assert_equal_float(-total_spent, sum(expected_amounts))

    def test_spendspark_2spark_all(self):
        """Test spending Spark to two Spark addresses with memo and fee subtraction."""
        expected_amounts = [Decimal('0.1'), Decimal('0.1')]
        sparkAddress = self.nodes[0].getsparkdefaultaddress()[0]
        self.nodes[0].mintspark({sparkAddress: {"amount": sum(expected_amounts) * 10}})
        self.nodes[0].generate(1)
        self.sync_all()

        spark_addr_1 = self.nodes[0].getnewsparkaddress()[0]
        spark_addr_2 = self.nodes[0].getnewsparkaddress()[0]
        txid = self.nodes[0].spendspark({
            spark_addr_1: {"amount": expected_amounts[0], "memo": "memo1", "subtractFee": True},
            spark_addr_2: {"amount": expected_amounts[1], "memo": "memo2", "subtractFee": True}
        })
        self.nodes[0].generate(1)
        self.sync_all()

        tx = self.nodes[0].gettransaction(txid)
        details = [detail for detail in tx['details'] if detail['category'] == 'spend']
        fee = Decimal(tx['fee'])
        total_spent = sum([detail['amount'] for detail in details]) + fee
        self.assert_equal_float(-total_spent, sum(expected_amounts))

    def test_spendspark_4spark_all_complex(self):
        """Test spending Spark to four Spark addresses with complex amounts and fee subtraction."""
        expected_amounts = [Decimal('0.01'), Decimal('0.05'), Decimal('0.1'), Decimal('0.2')]
        sparkAddress = self.nodes[0].getsparkdefaultaddress()[0]
        self.nodes[0].mintspark({sparkAddress: {"amount": sum(expected_amounts) * 10}})
        self.nodes[0].generate(1)
        self.sync_all()

        spark_addresses = [self.nodes[0].getnewsparkaddress()[0] for _ in range(4)]
        txid = self.nodes[0].spendspark({
            spark_addresses[0]: {"amount": expected_amounts[0], "subtractFee": True},
            spark_addresses[1]: {"amount": expected_amounts[1], "subtractFee": False},
            spark_addresses[2]: {"amount": expected_amounts[2], "subtractFee": True},
            spark_addresses[3]: {"amount": expected_amounts[3], "subtractFee": False}
        })
        self.nodes[0].generate(1)
        self.sync_all()

        tx = self.nodes[0].gettransaction(txid)
        details = [detail for detail in tx['details'] if detail['category'] == 'spend']
        fee = Decimal(tx['fee'])
        total_spent = sum([detail['amount'] for detail in details]) + fee
        self.assert_equal_float(-total_spent, sum(expected_amounts))

    def test_spendspark_complex_all_complex(self):
        """Test spending Spark to two transparent and two Spark addresses with mixed memos and fee subtraction."""
        expected_amounts = [Decimal('0.01'), Decimal('0.05'), Decimal('0.1'), Decimal('0.2')]
        sparkAddress = self.nodes[0].getsparkdefaultaddress()[0]
        self.nodes[0].mintspark({sparkAddress: {"amount": sum(expected_amounts) * 10}})
        self.nodes[0].generate(1)
        self.sync_all()

        transparent_addr_1 = self.nodes[0].getnewaddress()
        transparent_addr_2 = self.nodes[0].getnewaddress()
        spark_addr_1 = self.nodes[0].getnewsparkaddress()[0]
        spark_addr_2 = self.nodes[0].getnewsparkaddress()[0]
        txid = self.nodes[0].spendspark({
            transparent_addr_1: {"amount": expected_amounts[0], "memo": "memo1", "subtractFee": True},
            spark_addr_1: {"amount": expected_amounts[2], "subtractFee": False},
            transparent_addr_2: {"amount": expected_amounts[1], "memo": "memo2", "subtractFee": False},
            spark_addr_2: {"amount": expected_amounts[3], "subtractFee": True}
        })
        self.nodes[0].generate(1)
        self.sync_all()

        tx = self.nodes[0].gettransaction(txid)
        details = [detail for detail in tx['details'] if detail['category'] == 'spend']
        fee = Decimal(tx['fee'])
        total_spent = sum([detail['amount'] for detail in details]) + fee
        self.assert_equal_float(-total_spent, sum(expected_amounts))
        
    def assert_equal_float(self, actual: Decimal, expected: Decimal, threshold=0e-20):
        assert abs(actual - expected) <= threshold, f"Values {actual} and {expected} differ by more than {threshold}"

if __name__ == '__main__':
    SpendSparkTest().main()
