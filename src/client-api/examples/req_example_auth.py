#
#   Request-reply client in Python
#   Connects REQ socket to tcp://localhost:5557
#   Sends json request to zcoind
#
import zmq
import json

MAINNET = "15557"
TESTNET = "25557"
REGTEST = "35557"

base_dir = "/Users/tadhgriordan/Library/Application Support/zcoin/testnet3/certificates"

#  Prepare our context and sockets
context = zmq.Context()
socket = context.socket(zmq.REQ)

# We need two certificates, one for the client and one for
# the server. The client must know the server's public key
# to make a CURVE connection. This is read from the filesystem.

#load keys from file into JSONS
with open(base_dir + "/client/keys.json") as f:
    client_json = json.load(f)

with open(base_dir + "/server/keys.json") as f:
    server_json = json.load(f)

# Load keys into the client
socket.curve_secretkey = client_json["data"]["private"].encode('ascii')
socket.curve_publickey = client_json["data"]["public"].encode('ascii')
socket.curve_serverkey = server_json["data"]["public"].encode('ascii')

socket.connect("tcp://localhost:" + TESTNET)

message_input_pr = b"{ \
                    \"type\": \"create\", \
                    \"collection\": \"payment-request\",\
                    \"data\": { \
                        \"amount\": 4000, \
                        \"label\": \"Joern's Payment Request\",\
                        \"message\": \"this is a payment request for Joern.\" \
                     } \
                  }";

message_input_list = b"{ \
                    \"type\": \"getblock\", \
                    \"data\": { \
                        \"56b0558e170b2184ee0dbd053f517507dbaf4ad9289ba027dca62b6c03fc8645\" \
                     } \
                  }";

message_input_object = b"{ \
                    \"type\": \"getaddressbalance\", \
                    \"data\": { \
                        \"addresses\": [\"aQ18FBVFtnueucZKeVg4srhmzbpAeb1KoN\"] \
                     } \
                  }";
                  
socket.send(message_input_pr)
message = socket.recv()
print("Received reply [%s]" % (message))