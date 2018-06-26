#
#   Request-reply client in Python
#   Connects REQ socket to tcp://localhost:5557
#   Sends json request to zcoind
#
import zmq
import json


#  Prepare our context and sockets
context = zmq.Context()
socket = context.socket(zmq.SUB)
socket.connect("tcp://localhost:28332")

addressfilter = b"address-"
blockfilter = b"block-"

socket.setsockopt(zmq.SUBSCRIBE, addressfilter)
socket.setsockopt(zmq.SUBSCRIBE, blockfilter)
while True:
  message = socket.recv()
  print("Received reply [%s]" % (message))