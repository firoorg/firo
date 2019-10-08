#
#   Subscriber in Python
#   Connects SUB socket to tcp://localhost:{network}
#   call with one of the strings defined below.
#
import zmq
import json
import sys
from os.path import expanduser
from getpass import getuser

def get_base(base):
    if(base=="mac"):
        return expanduser("~") + "/Library/Application Support/zcoin/"
    if(base=="ubuntu"):
        return expanduser("~") + "/.zcoin/"
    if(base=="windows_wsl"):
        return "/mnt/c/Users/" + getuser() + "/AppData/Roaming/zcoin/"
    raise ValueError('Incorrect base string passed.') 

def get_network_directory(network):
    if(network=="mainnet"):
        return "";
    if(network=="testnet"):
        return "testnet3/";
    if(network=="regtest"):
        return "regtest/";
    raise ValueError('Incorrect network string passed.') 

def get_network(network):
    if(network=="mainnet"):
        return "18332"
    if(network=="testnet"):
        return "28332"
    if(network=="regtest"):
        return "38332"
    raise ValueError('Incorrect network string passed.') 

def get_auth(auth):
    if(auth=="auth"):
        return True
    if(auth=="noauth"):
        return False
    raise ValueError('Incorrect auth string passed.') 

if __name__ == "__main__":
    #  Prepare our context and sockets
    network = get_network(sys.argv[1])
    print(network)

    auth = get_auth(sys.argv[2])

    base = get_base(sys.argv[3])

    # Prepare our context and sockets
    ctx = zmq.Context.instance()
    socket = ctx.socket(zmq.SUB)

    if(auth):
        base_dir = base + get_network_directory(sys.argv[1]) + "certificates"
        print(base_dir)
        # We need two certificates, one for the client and one for
        # the server. The client must know the server's public key
        # to make a CURVE connection. This is read from the filesystem.

        # load keys from file into JSONS
        with open(base_dir + "/client/keys.json") as f:
            client_json = json.load(f)

        with open(base_dir + "/server/keys.json") as f:
            server_json = json.load(f)

        # Load keys into the client
        socket.curve_secretkey = client_json["data"]["private"].encode('ascii')
        socket.curve_publickey = client_json["data"]["public"].encode('ascii')
        socket.curve_serverkey = server_json["data"]["public"].encode('ascii')

    socket.connect("tcp://localhost:" + network)

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

    mintstatusfilter = b"mintStatus"
    socket.setsockopt(zmq.SUBSCRIBE, mintstatusfilter)

    settingsfilter = b"settings"
    socket.setsockopt(zmq.SUBSCRIBE, settingsfilter)

    while True:
      message = socket.recv()
      print("Received reply [%s]" % (message))
