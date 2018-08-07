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


blockfilter = b"block"
socket.setsockopt(zmq.SUBSCRIBE, blockfilter)

addressfilter = b"address"
socket.setsockopt(zmq.SUBSCRIBE, addressfilter)

balancefilter = b"balance"
socket.setsockopt(zmq.SUBSCRIBE, balancefilter)

transactionfilter = b"transaction"
socket.setsockopt(zmq.SUBSCRIBE, transactionfilter)

while True:
  message = socket.recv()
  print("Received reply [%s]" % (message))