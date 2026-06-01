// Copyright (c) 2015-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "bench.h"

#include "chainparams.h"
#include "key.h"
#include "pubkey.h"
#include "stacktraces.h"
#include "validation.h"
#include "util.h"

#include <string>

int
main(int argc, char** argv)
{
#ifdef ENABLE_CRASH_HOOKS
    RegisterPrettySignalHandlers();
    RegisterPrettyTerminateHander();
#endif
    ECC_Start();
    {
        ECCVerifyHandle globalVerifyHandle;

        SetupEnvironment();
        SelectParams(CBaseChainParams::MAIN);
        fPrintToDebugLog = false; // don't want to write to debug.log file

        double elapsed_time_for_one = 1.0;
        for (int i = 1; i < argc; ++i) {
            if (std::string(argv[i]) == "-sanity-check") {
                elapsed_time_for_one = 0.001;
            }
        }

        benchmark::BenchRunner::RunAll(elapsed_time_for_one);
    }

    ECC_Stop();
}
