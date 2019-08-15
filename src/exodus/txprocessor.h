#ifndef ZCOIN_EXODUS_TXPROCESSOR_H
#define ZCOIN_EXODUS_TXPROCESSOR_H

#include "tx.h"

#include <boost/signals2/signal.hpp>

namespace exodus {

class TxProcessor
{
public:
    int ProcessTx(CMPTransaction& tx);

public:
    boost::signals2::signal<void(const CMPTransaction&)> TransactionProcessed;
};

}

#endif // ZCOIN_EXODUS_TXPROCESSOR_H
