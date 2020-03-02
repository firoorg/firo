#ifndef EXODUS_PENDING_H
#define EXODUS_PENDING_H

class uint256;
struct CMPPending;

#include "sync.h"

#include <boost/optional/optional.hpp>

#include <stdint.h>
#include <map>
#include <string>

namespace exodus
{
//! Map of pending transaction objects
typedef std::map<uint256, CMPPending> PendingMap;

//! Global map of pending transaction objects
extern PendingMap my_pending;

/** Adds a transaction to the pending map using supplied parameters. */
void PendingAdd(const uint256& txid, const std::string& sendingAddress, uint16_t type, uint32_t propertyId,
    int64_t amount, bool fSubtract = true, const boost::optional<std::string> &receivingAddress = boost::none);

/** Deletes a transaction from the pending map and credits the amount back to the pending tally for the address. */
void PendingDelete(const uint256& txid);

/** Performs a check to ensure all pending transactions are still in the mempool. */
void PendingCheck();

}

/** Structure to hold information about pending transactions.
 */
struct CMPPending
{
    std::string src;  // the source address
    uint32_t prop;
    int64_t amount;
    uint32_t type;
    boost::optional<std::string> dest;

    /** Default constructor. */
    CMPPending() : prop(0), amount(0), type(0) {};

    /** Prints information about a pending transaction object. */
    void print(const uint256& txid) const;
};


#endif // EXODUS_PENDING_H
