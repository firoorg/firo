#
#   APIStatus Subscriber in Python
#   Connects SUB socket to tcp://localhost:25558
#
import zmq

if __name__ == "__main__":
    # Prepare our context and sockets
    ctx = zmq.Context.instance()
    socket = ctx.socket(zmq.SUB)

    socket.connect("tcp://localhost:28333")

    apistatusfilter = b"apiStatus"
    socket.setsockopt(zmq.SUBSCRIBE, apistatusfilter)

    while True:
      message = socket.recv()
      print("Received reply [%s]" % (message))
