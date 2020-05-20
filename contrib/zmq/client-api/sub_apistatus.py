#
#   APIStatus Subscriber in Python
#   Connects SUB socket to tcp://localhost:25558
#
import zmq
import json

if __name__ == "__main__":
    # prepare our context and sockets
    ctx = zmq.Context.instance()
    socket = ctx.socket(zmq.SUB)

    # Make socket connection
    socket.connect("tcp://localhost:28333")

    # Subscribe to apiStatus endpoint from zcoind
    socket.setsockopt(zmq.SUBSCRIBE, b"apiStatus")

    while True:
        try:
            message = json.loads(socket.recv())
            print("Received reply [%s]" % (json.dumps(message, indent=4, sort_keys=True)))
        except:
            message = socket.recv()
            print("Received reply [%s]" % message)