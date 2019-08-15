#include "txprocessor.h"

namespace exodus {

int TxProcessor::ProcessTx(CMPTransaction& tx)
{
    tx.unlockLogic();

    auto result = tx.interpretPacket();

    TransactionProcessed(tx);

    return result;
}

}
