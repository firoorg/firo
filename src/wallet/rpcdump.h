#ifndef FIRO_RPCDUMP_H
#define FIRO_RPCDUMP_H

#include <univalue.h>

#include "rpcwallet.h"

UniValue dumpprivkey(const JSONRPCRequest& request);
UniValue dumpsparkviewkey(const JSONRPCRequest& request);
UniValue importprivkey(const JSONRPCRequest& request);
UniValue importaddress(const JSONRPCRequest& request);
UniValue importpubkey(const JSONRPCRequest& request);
UniValue dumpwallet(const JSONRPCRequest& request);
UniValue importwallet(const JSONRPCRequest& request);
UniValue importprunedfunds(const JSONRPCRequest& request);
UniValue removeprunedfunds(const JSONRPCRequest& request);
UniValue importmulti(const JSONRPCRequest& request);

#endif // FIRO_RPCDUMP_H