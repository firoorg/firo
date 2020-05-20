#
#   Requester client in Python
#   Connects REQ socket to tcp://localhost:{port}
#   Sends json request to zcoind
#
import zmq
import json
import sys
from os.path import expanduser
from getpass import getuser

############ START DEFAULTS #########################
function_id = "" # see 'get_function' for possible values
auth = True
os = "mac"
network = "regtest"
passphrase = "d"
############ END DEFAULTS ###########################

############ START UTIL FUNCTIONS ###################
def params(args):
  global function_id
  global auth
  global os
  global network
  global passphrase
  function_id = sys.argv[1]
  if(len(args) > 2):
    auth = sys.argv[2]
  if(len(args) > 3):
    os = sys.argv[3]
  if(len(args) > 4):
    network = sys.argv[4]
  if(len(args) > 5):
    passphrase = sys.argv[5]

def get_auth(auth, function_id):
    if(function_id=="apistatus"):
      return False
    else:
      return auth

def get_port(network, auth, function_id):
    port = ""
    if(function_id=="apistatus"):
        return "25558"
    if(network=="mainnet"):
        port = "1555"
    if(network=="testnet"):
        port = "2555"
    if(network=="regtest"):
        port = "3555"
    if(auth):
      return port + "7"
    else:
      return port + "8"
    raise ValueError('Incorrect OS string passed.') 

def get_function(function_id, passphrase):
    if(function_id=="apistatus"):
        return apistatus()
    if(function_id=="blockchain"):
        return blockchain()
    if(function_id=="listmints"):
        return list_mints(passphrase)
    if(function_id=="mint"):
        return mint(passphrase)
    raise ValueError('Incorrect function_id string passed.')

def get_datadir(os):
    if(os=="mac"):
        return expanduser("~") + "/Library/Application Support/zcoin/"
    if(os=="ubuntu"):
        return expanduser("~") + "/.zcoin/"
    if(os=="windows_wsl"):
        return "/mnt/c/Users/" + getuser() + "/AppData/Roaming/zcoin/"
    raise ValueError('Incorrect OS string passed.')

def get_network_directory(network):
    if(network=="mainnet"):
        return "";
    if(network=="testnet"):
        return "testnet3/";
    if(network=="regtest"):
        return "regtest/";
    raise ValueError('Incorrect network string passed.') 

def format(request):
  ignore_mode = False
  index = 0
  for char in request:
    if char is '"':
      if ignore_mode:
        ignore_mode = False
      else:
        ignore_mode = True
    if char is "'" and not(ignore_mode):
        request = request[:index] + '"' + request[index + 1:]  
    index = index + 1
  return request

################### END UTIL FUNCTONS #####################

################### START COLLECTIONS #####################
def apistatus():
    request = {}
    request["type"] = "initial"
    request["collection"] = "apiStatus"
    return format(str(request))

def blockchain():
    request = {}
    request["type"] = "initial"
    request["collection"] = "blockchain"
    return format(str(request))

def mint(passphrase):
    request = {}
    auth = {}
    data = {}
    denominations = {}
    auth["passphrase"] = passphrase
    denominations["1"] = 1
    data["denominations"] = denominations
    request["type"] = "create"
    request["collection"] = "mint"
    request["data"] = data
    request["auth"] = auth
    return format(str(request))

def list_mints(passphrase):
    request = {}
    auth = {}
    auth["passphrase"] = passphrase
    request["type"] = "initial"
    request["collection"] = "listMints"
    request["auth"] = auth
    return format(str(request))
################### END COLLECTIONS #######################

'''
Params:
0: req.py
1: network (optional: defaults to "regtest")
2: auth (optional: defaults to True)
3: OS (optional: defaults to "mac")
'''
if __name__ == "__main__":
    # Setup parameters
    params(sys.argv)
    
    # Prepare our context and sockets  
    ctx = zmq.Context.instance()
    socket = ctx.socket(zmq.REQ)

    # Setup authentication
    if(get_auth(auth, function_id)):
        os_dir = get_datadir(os) + get_network_directory(network) + "certificates"

        # load keys from file into JSONS
        with open(os_dir + "/client/keys.json") as f:
            client_json = json.load(f)

        with open(os_dir + "/server/keys.json") as f:
            server_json = json.load(f)

        # Load keys into the socket
        socket.curve_secretkey = client_json["data"]["private"].encode('ascii')
        socket.curve_publickey = client_json["data"]["public"].encode('ascii')
        socket.curve_serverkey = server_json["data"]["public"].encode('ascii')

    # Make socket connection
    socket.connect("tcp://localhost:" + get_port(network, auth, function_id))

    # Send request
    socket.send(get_function(function_id, passphrase))

    # Print response
    message = json.loads(socket.recv())
    print("Received reply [%s]" % (json.dumps(message, indent=4, sort_keys=True)))
