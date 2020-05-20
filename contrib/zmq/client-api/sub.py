#
#   Subscriber in Python
#   Connects SUB socket to tcp://localhost:{port}
#   call with one of the strings defined below.
#
import zmq
import json
import sys
from os.path import expanduser
from getpass import getuser

############ START DEFAULTS #########################
network = "regtest"
auth = True
os = "mac"
############ END DEFAULTS ###########################

############ START UTIL FUNCTIONS ###########################
def params(args):
    global network
    global auth
    global os
    if(len(args) > 1):
        network = sys.argv[1]
    if(len(args) > 2):
        auth = sys.argv[2]
    if(len(args) > 3):
        os = sys.argv[3]

def get_os_datadir(os):
    if(os=="mac"):
        return expanduser("~") + "/Library/Application Support/zcoin/"
    if(os=="ubuntu"):
        return expanduser("~") + "/.zcoin/"
    if(os=="windows_wsl"):
        return "/mnt/c/Users/" + getuser() + "/AppData/Roaming/zcoin/"
    raise ValueError('Incorrect os string passed.') 

def get_network_directory(network):
    if(network=="mainnet"):
        return "";
    if(network=="testnet"):
        return "testnet3/";
    if(network=="regtest"):
        return "regtest/";
    raise ValueError('Incorrect network string passed.') 

def get_port(network):
    if(network=="mainnet"):
        return "18332"
    if(network=="testnet"):
        return "28332"
    if(network=="regtest"):
        return "38332"
    raise ValueError('Incorrect network string passed.') 

############ END UTIL FUNCTIONS ###########################

'''
Params:
0: req.py
1: function (required)
2: auth (optional: defaults to True (False if function=="apistatus"))
3: OS (optional: defaults to "mac")
4: network (optional: defaults to "regtest")
5: passphrase (optional: defaults to "passphrase" (has no effect for locked wallet))
'''
if __name__ == "__main__":
    # Setup parameters
    params(sys.argv)

    # Prepare our context and sockets
    ctx = zmq.Context.instance()
    socket = ctx.socket(zmq.SUB)

    # Setup authentication
    if(auth):
        os_dir = get_os_datadir(os) + get_network_directory(network) + "certificates"

        # Load keys from file into JSONS
        with open(os_dir + "/client/keys.json") as f:
            client_json = json.load(f)

        with open(os_dir + "/server/keys.json") as f:
            server_json = json.load(f)

        # Load keys into the socket
        socket.curve_secretkey = client_json["data"]["private"].encode('ascii')
        socket.curve_publickey = client_json["data"]["public"].encode('ascii')
        socket.curve_serverkey = server_json["data"]["public"].encode('ascii')

    # make socket connection
    socket.connect("tcp://localhost:" + get_port(network))

    # Subscribe to endpoints from zcoind
    socket.setsockopt(zmq.SUBSCRIBE, b"block")
    socket.setsockopt(zmq.SUBSCRIBE, b"address")
    socket.setsockopt(zmq.SUBSCRIBE, b"balance")
    socket.setsockopt(zmq.SUBSCRIBE, b"transaction")
    socket.setsockopt(zmq.SUBSCRIBE, b"znode")
    socket.setsockopt(zmq.SUBSCRIBE, b"mintStatus")
    socket.setsockopt(zmq.SUBSCRIBE, b"settings")
    socket.setsockopt(zmq.SUBSCRIBE, b"walletSegment")

    # print any publisher events
    while True:
        try:
            message = json.loads(socket.recv())
            print("Received reply [%s]" % (json.dumps(message, indent=4, sort_keys=True)))
        except:
            message = socket.recv()
            print("Received reply [%s]" % message)
