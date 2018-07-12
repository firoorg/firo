#
#   Request-reply client in Python
#   Connects REQ socket to tcp://localhost:5557
#   Sends json request to zcoind
#
import zmq
import json
from os.path import expanduser

addressfilter = b"address-"
blockfilter = b"block-"

REGTEST = "regtest"
MAINNET = "mainnet"
TESTNET = "testnet3"

base_dir = expanduser("~") + "/Library/Application Support/zcoin/" + REGTEST +"/certificates"

#  Prepare our context and sockets
ctx = zmq.Context.instance()
socket = ctx.socket(zmq.SUB)


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

# connect client to ZMQ endpoint
socket.connect('tcp://localhost:28332')

socket.setsockopt(zmq.SUBSCRIBE, addressfilter)
socket.setsockopt(zmq.SUBSCRIBE, blockfilter)
while True:
  message = socket.recv()
  print("Received reply [%s]" % (message))