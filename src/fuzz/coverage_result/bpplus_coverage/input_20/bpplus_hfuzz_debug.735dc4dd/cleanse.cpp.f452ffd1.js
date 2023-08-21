var data = {lines:[
{"lineNum":"    1","line":"// Copyright (c) 2009-2010 Satoshi Nakamoto"},
{"lineNum":"    2","line":"// Copyright (c) 2009-2015 The Bitcoin Core developers"},
{"lineNum":"    3","line":"// Distributed under the MIT software license, see the accompanying"},
{"lineNum":"    4","line":"// file COPYING or http://www.opensource.org/licenses/mit-license.php."},
{"lineNum":"    5","line":""},
{"lineNum":"    6","line":"#include \"cleanse.h\""},
{"lineNum":"    7","line":""},
{"lineNum":"    8","line":"#include <openssl/crypto.h>"},
{"lineNum":"    9","line":""},
{"lineNum":"   10","line":"void memory_cleanse(void *ptr, size_t len)"},
{"lineNum":"   11","line":"{","class":"lineCov","hits":"2","order":"95","possible_hits":"2",},
{"lineNum":"   12","line":"    OPENSSL_cleanse(ptr, len);","class":"lineCov","hits":"1","order":"96","possible_hits":"1",},
{"lineNum":"   13","line":"}","class":"linePartCov","hits":"1","order":"97","possible_hits":"2",},
]};
var percent_low = 25;var percent_high = 75;
var header = { "command" : "bpplus_hfuzz_debug", "date" : "2023-08-17 17:18:19", "instrumented" : 3, "covered" : 3,};
var merged_data = [];
