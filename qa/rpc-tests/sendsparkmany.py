#!/usr/bin/env python3
from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import JSONRPCException
from decimal import Decimal

class sendsparkmanyTest(BitcoinTestFramework):
    def __init__(self):
        super().__init__()
        self.num_nodes = 4
        self.setup_clean_chain = False

    def activate_spark(self):
        """Ensure Spark is activated before running tests."""
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

        # Ensure the chain height meets the activation height
        if current_height < activation_height:
            self.nodes[0].generate(activation_height - current_height)
            self.log.info(f"Generated {activation_height - current_height} blocks to meet dynamic activation height.")

        # Check Spark activation explicitly
        try:
            self.nodes[0].getnewsparkaddress()[0]
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

        self.test_sendsparkmany_1transparent_simple()
        self.test_sendsparkmany_1transparent_with_fee()
        self.test_sendsparkmany_1transparent_all()
        self.test_sendsparkmany_2transparent_simple()
        self.test_sendsparkmany_2transparent_with_fee()
        self.test_sendsparkmany_2transparent_all()
        self.test_sendsparkmany_4transparent_all_complex()


        self.test_sendsparkmany_1spark_simple()
        self.test_sendsparkmany_1spark_with_fee()
        self.test_sendsparkmany_1spark_all()
        self.test_sendsparkmany_2spark_simple()
        self.test_sendsparkmany_2spark_with_fee()
        self.test_sendsparkmany_2spark_all()
        self.test_sendsparkmany_4spark_all_complex()

        self.test_sendsparkmany_complex_all_complex()

    def test_sendsparkmany_1transparent_simple(self):
        """Test sending to a Spark address without fee subtraction."""
        expected_amount = Decimal('0.01')
        sparkAddress = self.nodes[0].getsparkdefaultaddress()[0]
        self.nodes[0].mintspark({sparkAddress: {"amount": expected_amount * 10}})
        self.nodes[0].generate(1)
        self.sync_all()

        spark_addr = self.nodes[0].getnewsparkaddress()[0]
        txid = self.nodes[0].sendsparkmany("", {spark_addr: expected_amount})
        self.nodes[0].generate(1)
        self.sync_all()

        tx = self.nodes[0].gettransaction(txid)
        details = [detail for detail in tx['details'] if detail['category'] == 'spend']
        self.assert_equal_float(-details[0]['amount'], expected_amount)
    
    def test_sendsparkmany_1transparent_with_fee(self):
        """Test sending to a Spark address with fee subtraction."""
        expected_amount = Decimal('0.01')
        sparkAddress = self.nodes[0].getsparkdefaultaddress()[0]
        self.nodes[0].mintspark({sparkAddress: {"amount": expected_amount * 10}})
        self.nodes[0].generate(1)
        self.sync_all()

        spark_addr = self.nodes[0].getnewsparkaddress()[0]
        txid = self.nodes[0].sendsparkmany("", {spark_addr: expected_amount}, "", [spark_addr])
        self.nodes[0].generate(1)
        self.sync_all()

        tx = self.nodes[0].gettransaction(txid)
        details = [detail for detail in tx['details'] if detail['category'] == 'spend']
        fee = Decimal(tx['fee'])
        self.assert_equal_float(-(details[0]['amount'] + fee), expected_amount)

    def test_sendsparkmany_1transparent_all(self):
        """Test sending to a Spark address with memo and fee subtraction."""
        expected_amount = Decimal('0.01')
        sparkAddress = self.nodes[0].getsparkdefaultaddress()[0]
        self.nodes[0].mintspark({sparkAddress: {"amount": expected_amount * 10}})
        self.nodes[0].generate(1)
        self.sync_all()

        spark_addr = self.nodes[0].getnewsparkaddress()[0]
        txid = self.nodes[0].sendsparkmany("", {spark_addr: expected_amount}, "test memo", [spark_addr])
        self.nodes[0].generate(1)
        self.sync_all()

        tx = self.nodes[0].gettransaction(txid)
        details = [detail for detail in tx['details'] if detail['category'] == 'spend']
        fee = Decimal(tx['fee'])
        self.assert_equal_float(-(details[0]['amount'] + fee), expected_amount)

    def test_sendsparkmany_2transparent_simple(self):
        """Test sending to two Spark addresses without fee subtraction."""
        expected_amounts = [Decimal('0.1'), Decimal('0.5')]
        sparkAddress = self.nodes[0].getsparkdefaultaddress()[0]
        self.nodes[0].mintspark({sparkAddress: {"amount": sum(expected_amounts) * 10}})
        self.nodes[0].generate(1)
        self.sync_all()

        spark_addr_1 = self.nodes[0].getnewsparkaddress()[0]
        spark_addr_2 = self.nodes[0].getnewsparkaddress()[0]
        txid = self.nodes[0].sendsparkmany("", {
            spark_addr_1: expected_amounts[0], 
            spark_addr_2: expected_amounts[1]
        })
        self.nodes[0].generate(1)
        self.sync_all()

        tx = self.nodes[0].gettransaction(txid)
        details = [detail for detail in tx['details'] if detail['category'] == 'spend']
        total_spent = sum([detail['amount'] for detail in details])
        self.assert_equal_float(-total_spent, sum(expected_amounts))

    def test_sendsparkmany_2transparent_with_fee(self):
        """Test sending to two Spark addresses with fee subtraction."""
        expected_amounts = [Decimal('0.01'), Decimal('0.5')]
        sparkAddress = self.nodes[0].getsparkdefaultaddress()[0]
        self.nodes[0].mintspark({sparkAddress: {"amount": sum(expected_amounts) * 10}})
        self.nodes[0].generate(1)
        self.sync_all()

        spark_addr_1 = self.nodes[0].getnewsparkaddress()[0]
        spark_addr_2 = self.nodes[0].getnewsparkaddress()[0]
        txid = self.nodes[0].sendsparkmany("", {
            spark_addr_1: expected_amounts[0],
            spark_addr_2: expected_amounts[1]
        }, "", [spark_addr_1, spark_addr_2])
        self.nodes[0].generate(1)
        self.sync_all()

        tx = self.nodes[0].gettransaction(txid)
        details = [detail for detail in tx['details'] if detail['category'] == 'spend']
        fee = Decimal(tx['fee'])
        total_spent = sum([detail['amount'] for detail in details]) + fee
        self.assert_equal_float(-total_spent, sum(expected_amounts))

    def test_sendsparkmany_2transparent_all(self):
        """Test sending to two Spark addresses with memo and fee subtraction."""
        expected_amounts = [Decimal('0.1'), Decimal('0.1')]
        sparkAddress = self.nodes[0].getsparkdefaultaddress()[0]
        self.nodes[0].mintspark({sparkAddress: {"amount": sum(expected_amounts) * 10}})
        self.nodes[0].generate(1)
        self.sync_all()

        spark_addr_1 = self.nodes[0].getnewsparkaddress()[0]
        spark_addr_2 = self.nodes[0].getnewsparkaddress()[0]
        txid = self.nodes[0].sendsparkmany("", {
            spark_addr_1: expected_amounts[0],
            spark_addr_2: expected_amounts[1]
        }, "memo1 memo2", [spark_addr_1, spark_addr_2])
        self.nodes[0].generate(1)
        self.sync_all()

        tx = self.nodes[0].gettransaction(txid)
        details = [detail for detail in tx['details'] if detail['category'] == 'spend']
        fee = Decimal(tx['fee'])
        total_spent = sum([detail['amount'] for detail in details]) + fee
        self.assert_equal_float(-total_spent, sum(expected_amounts))

    def test_sendsparkmany_4transparent_all_complex(self):
        """Test sending to four Spark addresses with complex amounts and fee subtraction."""
        expected_amounts = [Decimal('0.01'), Decimal('0.05'), Decimal('0.1'), Decimal('0.2')]
        sparkAddress = self.nodes[0].getsparkdefaultaddress()[0]
        self.nodes[0].mintspark({sparkAddress: {"amount": sum(expected_amounts) * 10}})
        self.nodes[0].generate(1)
        self.sync_all()

        spark_addresses = [self.nodes[0].getnewsparkaddress()[0] for _ in range(4)]
        txid = self.nodes[0].sendsparkmany("", {
            spark_addresses[0]: expected_amounts[0],
            spark_addresses[1]: expected_amounts[1],
            spark_addresses[2]: expected_amounts[2],
            spark_addresses[3]: expected_amounts[3]
        }, "", [spark_addresses[0], spark_addresses[2]])
        self.nodes[0].generate(1)
        self.sync_all()

        tx = self.nodes[0].gettransaction(txid)
        details = [detail for detail in tx['details'] if detail['category'] == 'spend']
        fee = Decimal(tx['fee'])
        total_spent = sum([detail['amount'] for detail in details]) + fee
        self.assert_equal_float(-total_spent, sum(expected_amounts))


    def test_sendsparkmany_1spark_simple(self):
        """Test sending to a Spark address without fee subtraction."""
        expected_amount = Decimal('0.01')
        sparkAddress = self.nodes[0].getsparkdefaultaddress()[0]
        self.nodes[0].mintspark({sparkAddress: {"amount": expected_amount * 10}})
        self.nodes[0].generate(1)
        self.sync_all()

        spark_addr = self.nodes[0].getnewsparkaddress()[0]
        txid = self.nodes[0].sendsparkmany("", {spark_addr: expected_amount})
        self.nodes[0].generate(1)
        self.sync_all()

        tx = self.nodes[0].gettransaction(txid)
        details = [detail for detail in tx['details'] if detail['category'] == 'spend']
        self.assert_equal_float(-details[0]['amount'], expected_amount)
    
    def test_sendsparkmany_1spark_with_fee(self):
        """Test sending to a Spark address with fee subtraction."""
        expected_amount = Decimal('0.01')
        sparkAddress = self.nodes[0].getsparkdefaultaddress()[0]
        self.nodes[0].mintspark({sparkAddress: {"amount": expected_amount * 10}})
        self.nodes[0].generate(1)
        self.sync_all()

        spark_addr = self.nodes[0].getnewsparkaddress()[0]
        txid = self.nodes[0].sendsparkmany("", {spark_addr: expected_amount}, "", [spark_addr])
        self.nodes[0].generate(1)
        self.sync_all()

        tx = self.nodes[0].gettransaction(txid)
        details = [detail for detail in tx['details'] if detail['category'] == 'spend']
        fee = Decimal(tx['fee'])
        self.assert_equal_float(-(details[0]['amount'] + fee), expected_amount)

    def test_sendsparkmany_1spark_all(self):
        """Test sending to a Spark address with memo and fee subtraction."""
        expected_amount = Decimal('0.01')
        sparkAddress = self.nodes[0].getsparkdefaultaddress()[0]
        self.nodes[0].mintspark({sparkAddress: {"amount": expected_amount * 10}})
        self.nodes[0].generate(1)
        self.sync_all()

        spark_addr = self.nodes[0].getnewsparkaddress()[0]
        txid = self.nodes[0].sendsparkmany("", {spark_addr: expected_amount}, "test memo", [spark_addr])
        self.nodes[0].generate(1)
        self.sync_all()

        tx = self.nodes[0].gettransaction(txid)
        details = [detail for detail in tx['details'] if detail['category'] == 'spend']
        fee = Decimal(tx['fee'])
        self.assert_equal_float(-(details[0]['amount'] + fee), expected_amount)

    def test_sendsparkmany_2spark_simple(self):
        """Test sending to two Spark addresses without fee subtraction."""
        expected_amounts = [Decimal('0.1'), Decimal('0.5')]
        sparkAddress = self.nodes[0].getsparkdefaultaddress()[0]
        self.nodes[0].mintspark({sparkAddress: {"amount": sum(expected_amounts) * 10}})
        self.nodes[0].generate(1)
        self.sync_all()

        spark_addr_1 = self.nodes[0].getnewsparkaddress()[0]
        spark_addr_2 = self.nodes[0].getnewsparkaddress()[0]
        txid = self.nodes[0].sendsparkmany("", {
            spark_addr_1: expected_amounts[0], 
            spark_addr_2: expected_amounts[1]
        })
        self.nodes[0].generate(1)
        self.sync_all()

        tx = self.nodes[0].gettransaction(txid)
        details = [detail for detail in tx['details'] if detail['category'] == 'spend']
        total_spent = sum([detail['amount'] for detail in details])
        self.assert_equal_float(-total_spent, sum(expected_amounts))

    def test_sendsparkmany_2spark_with_fee(self):
        """Test sending to two Spark addresses with fee subtraction."""
        expected_amounts = [Decimal('0.01'), Decimal('0.5')]
        sparkAddress = self.nodes[0].getsparkdefaultaddress()[0]
        self.nodes[0].mintspark({sparkAddress: {"amount": sum(expected_amounts) * 10}})
        self.nodes[0].generate(1)
        self.sync_all()

        spark_addr_1 = self.nodes[0].getnewsparkaddress()[0]
        spark_addr_2 = self.nodes[0].getnewsparkaddress()[0]
        txid = self.nodes[0].sendsparkmany("", {
            spark_addr_1: expected_amounts[0],
            spark_addr_2: expected_amounts[1]
        }, "", [spark_addr_1, spark_addr_2])
        self.nodes[0].generate(1)
        self.sync_all()

        tx = self.nodes[0].gettransaction(txid)
        details = [detail for detail in tx['details'] if detail['category'] == 'spend']
        fee = Decimal(tx['fee'])
        total_spent = sum([detail['amount'] for detail in details]) + fee
        self.assert_equal_float(-total_spent, sum(expected_amounts))

    def test_sendsparkmany_2spark_all(self):
        """Test sending to two Spark addresses with memo and fee subtraction."""
        expected_amounts = [Decimal('0.1'), Decimal('0.1')]
        sparkAddress = self.nodes[0].getsparkdefaultaddress()[0]
        self.nodes[0].mintspark({sparkAddress: {"amount": sum(expected_amounts) * 10}})
        self.nodes[0].generate(1)
        self.sync_all()

        spark_addr_1 = self.nodes[0].getnewsparkaddress()[0]
        spark_addr_2 = self.nodes[0].getnewsparkaddress()[0]
        txid = self.nodes[0].sendsparkmany("", {
            spark_addr_1: expected_amounts[0],
            spark_addr_2: expected_amounts[1]
        }, "memo1 memo2", [spark_addr_1, spark_addr_2])
        self.nodes[0].generate(1)
        self.sync_all()

        tx = self.nodes[0].gettransaction(txid)
        details = [detail for detail in tx['details'] if detail['category'] == 'spend']
        fee = Decimal(tx['fee'])
        total_spent = sum([detail['amount'] for detail in details]) + fee
        self.assert_equal_float(-total_spent, sum(expected_amounts))

    def test_sendsparkmany_4spark_all_complex(self):
        """Test sending to four Spark addresses with complex amounts and fee subtraction."""
        expected_amounts = [Decimal('0.01'), Decimal('0.05'), Decimal('0.1'), Decimal('0.2')]
        sparkAddress = self.nodes[0].getsparkdefaultaddress()[0]
        self.nodes[0].mintspark({sparkAddress: {"amount": sum(expected_amounts) * 10}})
        self.nodes[0].generate(1)
        self.sync_all()

        spark_addresses = [self.nodes[0].getnewsparkaddress()[0] for _ in range(4)]
        txid = self.nodes[0].sendsparkmany("", {
            spark_addresses[0]: expected_amounts[0],
            spark_addresses[1]: expected_amounts[1],
            spark_addresses[2]: expected_amounts[2],
            spark_addresses[3]: expected_amounts[3]
        }, "", [spark_addresses[0], spark_addresses[2]])
        self.nodes[0].generate(1)
        self.sync_all()

        tx = self.nodes[0].gettransaction(txid)
        details = [detail for detail in tx['details'] if detail['category'] == 'spend']
        fee = Decimal(tx['fee'])
        total_spent = sum([detail['amount'] for detail in details]) + fee
        self.assert_equal_float(-total_spent, sum(expected_amounts))

    def test_sendsparkmany_complex_all_complex(self):
        """Test sending to four Spark addresses with mixed memos and fee subtraction."""
        expected_amounts = [Decimal('0.01'), Decimal('0.05'), Decimal('0.1'), Decimal('0.2')]
        sparkAddress = self.nodes[0].getsparkdefaultaddress()[0]
        self.nodes[0].mintspark({sparkAddress: {"amount": sum(expected_amounts) * 10}})
        self.nodes[0].generate(1)
        self.sync_all()

        spark_addr_1 = self.nodes[0].getnewsparkaddress()[0]
        spark_addr_2 = self.nodes[0].getnewsparkaddress()[0]
        spark_addr_3 = self.nodes[0].getnewsparkaddress()[0]
        spark_addr_4 = self.nodes[0].getnewsparkaddress()[0]
        txid = self.nodes[0].sendsparkmany("", {
            spark_addr_1: expected_amounts[0],
            spark_addr_2: expected_amounts[1],
            spark_addr_3: expected_amounts[2],
            spark_addr_4: expected_amounts[3]
        }, "mixed test", [spark_addr_1, spark_addr_3])
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
    sendsparkmanyTest().main()

