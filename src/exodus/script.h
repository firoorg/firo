#ifndef ZCOIN_ELYSIUM_SCRIPT_H
#define ZCOIN_ELYSIUM_SCRIPT_H

#include "../script/script.h"
#include "../script/standard.h"

#include <vector>

#include <inttypes.h>

/** Determines the minimum output amount to be spent by an output. */
int64_t GetDustThreshold(const CScript& scriptPubKey);

/** Identifies standard output types based on a scriptPubKey. */
bool GetOutputType(const CScript& scriptPubKey, txnouttype& whichTypeRet);

/** Returns public keys or hashes from scriptPubKey, for standard transaction types. */
bool SafeSolver(const CScript& scriptPubKey, txnouttype& typeRet, std::vector<std::vector<unsigned char> >& vSolutionsRet);

namespace exodus {

/**
 * Extracts the pushed data from a script.
 **/
template<typename Output>
Output GetPushedValues(const CScript& script, Output output)
{
    auto pc = script.begin();

    while (pc < script.end()) {
        opcodetype op;
        std::vector<unsigned char> data;

        if (!script.GetOp(pc, op, data)) {
            return output;
        }

        if (op >= 0x00 && op <= OP_PUSHDATA4) {
            *output++ = data;
        }
    }

    return output;
}

} // namespace exodus

#endif // ZCOIN_ELYSIUM_SCRIPT_H
