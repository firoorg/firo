#!/usr/bin/env python3
# Copyright (c) 2015-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

#
# Test mulitple rpc user config option rpcauth
#

from test_framework.test_framework import BitcoinTestFramework
from test_framework.util import str_to_b64str, assert_equal

import os
import http.client
import urllib.parse

class HTTPBasicsTest (BitcoinTestFramework):

    def __init__(self):
        super().__init__()
        self.setup_clean_chain = False
        self.num_nodes = 1

    def setup_chain(self):
        super().setup_chain()
        #Append rpcauth to zcoin.conf before initialization
        rpcauth = "rpcauth=rt:e930a0a14788a334ae2c545e39508250$6d052cf1883539e3a3b2c1b4d3823e8fa7298161dbe15037e05725eb70186f9a"
        rpcauth2 = "rpcauth=rt2:a04ee00b7ed091e693efcb4e58cb2d$caa5c015cccc868b5c9b988c79b79d44501263b4554401d01dc6cd09ddbc0906"
        print(os.path.join(self.options.tmpdir+"/node0", "zcoin.conf"))
        with open(os.path.join(self.options.tmpdir+"/node0", "zcoin.conf"), 'a', encoding='utf8') as f:
            f.write(rpcauth+"\n")
            f.write(rpcauth2+"\n")

    def setup_network(self):
        self.nodes = self.setup_nodes()

    def run_test(self):

        ##################################################
        # Check correctness of the rpcauth config option #
        ##################################################
        url = urllib.parse.urlparse(self.nodes[0].url)

        #Old authpair
        authpair = url.username + ':' + url.password

        #New authpair generated via share/rpcuser tool
        rpcauth = "rpcauth=rt:e930a0a14788a334ae2c545e39508250$6d052cf1883539e3a3b2c1b4d3823e8fa7298161dbe15037e05725eb70186f9a"
        password = "feoi3-aT-p9Q0YcUpAwquYmD4XzJiQA0VDZ8wUgtrY8="

        #Second authpair with different username
        rpcauth2 = "rpcauth=rt2:a04ee00b7ed091e693efcb4e58cb2d$caa5c015cccc868b5c9b988c79b79d44501263b4554401d01dc6cd09ddbc0906"
        password2 = "ellGsewQKtEczmlhfXa--oRr8QUP6lJSSWwODWxRZTY="

        authpairnew = "rt:"+password

        headers = {"Authorization": "Basic " + str_to_b64str(authpair)}

        conn = http.client.HTTPConnection(url.hostname, url.port)
        conn.connect()
        conn.request('POST', '/', '{"method": "getbestblockhash"}', headers)
        resp = conn.getresponse()
        assert_equal(resp.status==401, False)
        conn.close()
        
        #Use new authpair to confirm both work
        headers = {"Authorization": "Basic " + str_to_b64str(authpairnew)}

        conn = http.client.HTTPConnection(url.hostname, url.port)
        conn.connect()
        conn.request('POST', '/', '{"method": "getbestblockhash"}', headers)
        resp = conn.getresponse()
        print('DONE')
        assert_equal(resp.status==401, False)
        conn.close()

        #Wrong login name with rt's password
        authpairnew = "rtwrong:"+password
        headers = {"Authorization": "Basic " + str_to_b64str(authpairnew)}

        conn = http.client.HTTPConnection(url.hostname, url.port)
        conn.connect()
        conn.request('POST', '/', '{"method": "getbestblockhash"}', headers)
        resp = conn.getresponse()
        assert_equal(resp.status==401, True)
        conn.close()

        #Wrong password for rt
        authpairnew = "rt:"+password+"wrong"
        headers = {"Authorization": "Basic " + str_to_b64str(authpairnew)}

        conn = http.client.HTTPConnection(url.hostname, url.port)
        conn.connect()
        conn.request('POST', '/', '{"method": "getbestblockhash"}', headers)
        resp = conn.getresponse()
        assert_equal(resp.status==401, True)
        conn.close()

        #Correct for rt2
        authpairnew = "rt2:"+password2
        headers = {"Authorization": "Basic " + str_to_b64str(authpairnew)}

        conn = http.client.HTTPConnection(url.hostname, url.port)
        conn.connect()
        conn.request('POST', '/', '{"method": "getbestblockhash"}', headers)
        resp = conn.getresponse()
        assert_equal(resp.status==401, False)
        conn.close()

        #Wrong password for rt2
        authpairnew = "rt2:"+password2+"wrong"
        headers = {"Authorization": "Basic " + str_to_b64str(authpairnew)}

        conn = http.client.HTTPConnection(url.hostname, url.port)
        conn.connect()
        conn.request('POST', '/', '{"method": "getbestblockhash"}', headers)
        resp = conn.getresponse()
        assert_equal(resp.status==401, True)
        conn.close()


if __name__ == '__main__':
    HTTPBasicsTest ().main ()
