#!/usr/bin/env python3
from test_framework.authproxy import JSONRPCException
from test_framework.test_framework import ElysiumTestFramework
from test_framework.util import assert_equal, assert_raises_message

class ElysiumCreatePayloadMintByPublicKeysTests(ElysiumTestFramework):
    def run_test(self):
        super().run_test()
        super().ensure_reach_sigmaactivated_block()

        sigma_propid = super().create_default_property("Sigma", sigma = True, amount = "1000000")
        self.nodes[0].elysium_sendcreatedenomination(self.addrs[0], sigma_propid, "1")
        self.nodes[0].generate(10)
        self.nodes[0].elysium_sendcreatedenomination(self.addrs[0], sigma_propid, "2")
        self.nodes[0].generate(10)

        nonsigma_propid = super().create_default_property("Non Sigma", sigma = False, amount = "1000000")

        # prepare payload
        id1 = "52cd0023a3a40b91201d199f9f1623125371b20256957325bf210b5492a8eb9c0100"
        id2 = "b4933ec7000f4083fb6d87ea8501e3bf7bad31af84e5dd8f7c6b59287ef152170100"
        valid_mints = [{"id": id1, "denomination": 0}, {"id": id2, "denomination": 1}]

        # create payload for non-sigma property should throw
        assert_raises_message(
            JSONRPCException,
            'Property has not enabled Sigma',
            self.nodes[0].elysium_createpayload_mintbypublickeys, nonsigma_propid, valid_mints
        )

        # create payload for non-exist property should throw
        assert_raises_message(
            JSONRPCException,
            'Property identifier does not exist',
            self.nodes[0].elysium_createpayload_mintbypublickeys, 99, valid_mints
        )

        # invalid key
        assert_raises_message(
            JSONRPCException,
            'Public key is invalid',
            self.nodes[0].elysium_createpayload_mintbypublickeys, sigma_propid, [{"id": "0", "denomination": 0}]
        )

        # invalid denom
        assert_raises_message(
            JSONRPCException,
            'Denomination id is invalid',
            self.nodes[0].elysium_createpayload_mintbypublickeys,
            sigma_propid,
            [{"id": "52cd0023a3a40b91201d199f9f1623125371b20256957325bf210b5492a8eb9c0100", "denomination": 256}]
        )

        # not exist denom
        assert_raises_message(
            JSONRPCException,
            'Denomination is not exist',
            self.nodes[0].elysium_createpayload_mintbypublickeys,
            sigma_propid,
            [{"id": "52cd0023a3a40b91201d199f9f1623125371b20256957325bf210b5492a8eb9c0100", "denomination": 99}]
        )

        # success create payload
        payload = self.nodes[0].elysium_createpayload_mintbypublickeys(sigma_propid, valid_mints)

        hex_prop = "%08x" % sigma_propid
        raw = f"00000402{hex_prop}0200{id1}01{id2}"

        assert_equal(raw, payload)

if __name__ == '__main__':
    ElysiumCreatePayloadMintByPublicKeysTests().main()
