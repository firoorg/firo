#
#   Subscriber in Python
#   Connects SUB socket to tcp://localhost:{network}
#   call with one of the strings defined below. defaults to testnet
#
import zmq
import json
import sys
    
MAINNET = 18332;
TESTNET = 28332;
REGTEST = 38332;

def get_network(network):
    if(network=="mainnet"):
        return MAINNET
    if(network=="testnet"):
        return TESTNET
    if(network=="regtest"):
        return REGTEST
    return TESTNET

if __name__ == "__main__":
    #  Prepare our context and sockets
    network = sys.argv[1]
    network = get_network(network)
    context = zmq.Context()
    socket = context.socket(zmq.SUB)
    print(str(network))
    socket.connect("tcp://localhost:" + str(network))


    blockfilter = b"block"
    socket.setsockopt(zmq.SUBSCRIBE, blockfilter)

    addressfilter = b"address"
    socket.setsockopt(zmq.SUBSCRIBE, addressfilter)

    balancefilter = b"balance"
    socket.setsockopt(zmq.SUBSCRIBE, balancefilter)

    transactionfilter = b"transaction"
    socket.setsockopt(zmq.SUBSCRIBE, transactionfilter)

    znodefilter = b"znode"
    socket.setsockopt(zmq.SUBSCRIBE, znodefilter)

    while True:
      message = socket.recv()
      print("Received reply [%s]" % (message))