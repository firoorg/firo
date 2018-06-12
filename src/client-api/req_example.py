#
#   Request-reply client in Python
#   Connects REQ socket to tcp://localhost:5557
#   Sends json request to zcoind
#
import zmq
import json

#  Prepare our context and sockets
context = zmq.Context()
socket = context.socket(zmq.REQ)
socket.connect("tcp://localhost:5557")

message_input_pr = b"{ \
                    \"type\": \"getpaymentrequest\", \
                    \"payload\": [ \
                        \"4000\", \
                        \"Joern's Payment Request\",\
                        \"this is a payment request for Joern.\" \
                     ] \
                  }";

message_input_list = b"{ \
                    \"type\": \"getblock\", \
                    \"payload\": [ \
                        \"56b0558e170b2184ee0dbd053f517507dbaf4ad9289ba027dca62b6c03fc8645\" \
                     ] \
                  }";

message_input_object = b"{ \
                    \"type\": \"getaddressbalance\", \
                    \"payload\": { \
                        \"addresses\": [\"aQ18FBVFtnueucZKeVg4srhmzbpAeb1KoN\"] \
                     } \
                  }";
                  
socket.send(message_input_pr)
message = socket.recv()
print("Received reply [%s]" % (message))