#ifndef BITCOIN_ZMQAPI_REGISTER_H
#define BITCOIN_ZMQAPI_REGISTER_H

class CZMQTable;

/** Register block chain RPC commands */
// void RegisterBlockchainRPCCommands(CRPCTable &tableRPC);
void SettingModuleZMQReqRep(CZMQTable &tableZMQ);

static inline void RegisterAllCoreZMQCommands(CZMQTable &tableZMQ)
{
	// TODO register some method here
	SettingModuleZMQReqRep(tableZMQ);
}

#endif // BITCOIN_ZMQAPI_REGISTER_H
