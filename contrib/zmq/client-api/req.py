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
function_id = "" # see 'get_function' for possible values. edit "data" object in each function as is needed
auth = True
os = "ubuntu"
network = "regtest"
passphrase = "passphrase"
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
    if(function_id=="apiStatus"):
      return False
    else:
      return auth

def get_port(network, auth, function_id):
    port = ""
    if(function_id=="apiStatus"):
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
    if(function_id=="apiStatus"):
        return api_status()
    if(function_id=="backup"):
        return backup()
    if(function_id=="balance"):
        return balance()
    if(function_id=="balance"):
        return block()
    if(function_id=="blockchain"):
        return blockchain()
    if(function_id=="editAddressBook"):
        return edit_address_book()
    if(function_id=="listMints"):
        return list_mints(passphrase)
    if(function_id=="lockCoins"):
        return lock_coin()
    if(function_id=="masternodeList"):
        return masternode_list()
    if(function_id=="mint"):
        return mint(passphrase)
    if(function_id=="paymentRequest"):
        return payment_request()
    if(function_id=="paymentRequestAddress"):
        return payment_request_address()
    if(function_id=="privateTxFee"):
        return private_tx_fee()
    if(function_id=="readAddressBook"):
        return read_address_book()
    if(function_id=="rebroadcast"):
        return rebroadcast()
    if(function_id=="rpc_initial"):
        return rpc_initial()
    if(function_id=="rpc_create"):
        return rpc_create()
    if(function_id=="sendPrivate"):
        return send_private(passphrase)
    if(function_id=="sendZcoin"):
        return send_zcoin(passphrase)
    if(function_id=="setPassphrase_update"):
        return set_passphrase_update(passphrase)
    if(function_id=="setPassphrase_create"):
        return set_passphrase_create(passphrase)
    if(function_id=="setting_initial"):
        return setting_initial()
    if(function_id=="setting_create"):
        return setting_create()
    if(function_id=="setting_update"):
        return setting_update()
    if(function_id=="setting_get"):
        return setting_get()
    if(function_id=="showMnemonics"):
        return show_mnemonics()
    if(function_id=="stateWallet"):
        return state_wallet()
    if(function_id=="txFee"):
        return tx_fee()
    if(function_id=="unlockWallet"):
        return unlock_wallet()
    if(function_id=="verifyMnemonicValidity"):
        return verify_mnemonic_validity()
    if(function_id=="apiStatus"):
        return write_show_mnemonic_warning()
    if(function_id=="writeShowMnemonicWarning"):
        return znode_control(passphrase)
    if(function_id=="znodeControl"):
        return znode_key()
    if(function_id=="znodeKey"):
        return znode_list()

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
        return ""
    if(network=="testnet"):
        return "testnet3/"
    if(network=="regtest"):
        return "regtest/"
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
def api_status():
    request = {}
    request["type"] = "none"
    request["collection"] = "apiStatus"
    return format(str(request))

def backup():
    global os
    request = {}
    data = {}
    data["directory"] = get_datadir(os)
    # Formulate request
    request["type"] = "none"
    request["collection"] = "backup"
    request["data"] = data
    return format(str(request))

def balance():
    request = {}
    request["type"] = "none"
    request["collection"] = "balance"
    return format(str(request))

def block():
    request = {}
    data = {}
    data["hashBlock"] = ""
    # Formulate request
    request["type"] = "none"
    request["collection"] = "block"
    request["data"] = data
    return format(str(request))

def blockchain():
    request = {}
    request["type"] = "none"
    request["collection"] = "blockchain"
    return format(str(request))

def edit_address_book():
    request = {}
    data = {}
    data["action"] = "add"
    data["address"] = "TTGxLSFXi2LXYU8oiQDMLUE1vxkAuJHMgk"
    data["label"] = "test_label"
    data["purpose"] = "test_purpose"
    # Formulate request
    request["type"] = "none"
    request["collection"] = "editAddressBook"
    request["data"] = data
    return format(str(request))

def list_mints(passphrase):
    request = {}
    auth = {}
    auth["passphrase"] = passphrase
    # formulate request
    request["type"] = "none"
    request["collection"] = "listMints"
    request["auth"] = auth
    return format(str(request))

def lock_coin():
    request = {}
    data = {}
    data["lockedCoins"] = "be3b8da5fd23b63b3e52f95475b62894a7fd31cf16b1a24218fc4eaa2f3fe5ac|0:08190ef8e593860a11856b3b5a92683e121c997b1f34c090496dfd77bc0dd27a|1"
    # formulate request
    request["type"] = "none"
    request["collection"] = "lockCoins"
    request["data"] = data
    return format(str(request))

def lock_wallet():
    request = {}
    request["type"] = "none"
    request["collection"] = "lockWallet"
    return format(str(request))

def masternode_list():
    request = {}
    data = {}
    # formulate request
    request["type"] = "none"
    request["collection"] = "masternodeList"
    request["data"] = data
    return format(str(request))

def mint(passphrase):
    request = {}
    auth = {}
    data = {}
    denominations = {}
    auth["passphrase"] = passphrase
    denominations["1"] = 1
    data["denominations"] = denominations
    # formulate request
    request["type"] = "none"
    request["collection"] = "mint"
    request["data"] = data
    request["auth"] = auth
    return format(str(request))

def payment_request():
    request = {}
    data = {}
    data["amount"] = 1
    data["label"] = "test_label"
    data["message"] = "test_message"
    data["address"] = "TCe9ccb62S5wQtyNaSoo9iG91cbirL2Vuc"
    # formulate request
    request["collection"] = "paymentRequest"
    request["type"] = "create"
    request["data"] = data
    return format(str(request))

def payment_request_address():
    request = {}
    data = {}
    # formulate request
    request["type"] = "none"
    request["collection"] = "paymentRequestAddress"
    request["data"] = data
    return format(str(request))

def private_tx_fee():
    request = {}
    data = {}
    outputs = []
    output = {}
    output["address"] = "TXQvbAsNKTGsKsk3279QsgGF2Uvbyc1vXm"
    output["amount"] = 100000000
    outputs.append(output)
    data["outputs"] = outputs
    data["label"] = "private_tx_fee label"
    data["subtractFeeFromAmount"] = False
    # formulate request
    request["type"] = "none"
    request["collection"] = "privateTxFee"
    request["data"] = data
    return format(str(request))

def read_address_book():
    request = {}
    request["type"] = "none"
    request["collection"] = "readAddressBook"
    return format(str(request))

def rebroadcast():
    request = {}
    data = {}
    data["txHash"] = ""
    request["type"] = "none"
    request["collection"] = "rebroadcast"
    return format(str(request))

def rpc_initial():
    request = {}
    request["type"] = "initial"
    request["collection"] = "rpc"
    return format(str(request))

def rpc_create():
    request = {}
    data = {}
    data["method"] = ""
    data["args"] = ""
    request["type"] = "create"
    request["collection"] = "rpc"
    request["data"] = data
    return format(str(request))

def send_private(passphrase):
    request = {}
    auth = {}
    data = {}
    outputs = []
    output = {}
    coin_control = {}
    auth["passphrase"] = passphrase
    output["address"] = "TXQvbAsNKTGsKsk3279QsgGF2Uvbyc1vXm"
    output["amount"] = 100000000
    outputs.append(output)
    coin_control["selected"] = ""
    data["outputs"] = outputs
    data["label"] = "send_private label"
    data["subtractFeeFromAmount"] = False
    data["coinControl"] = coin_control
    # formulate request
    request["type"] = "none"
    request["collection"] = "sendPrivate"
    request["data"] = data
    request["auth"] = auth
    return format(str(request))

def send_zcoin(passphrase):
    request = {}
    data = {}
    auth = {}
    auth["passphrase"] = passphrase
    ##### Data construction ####
    addresses = {}
    address_value = {}
    coin_control = {}
    address_key = ""
    address_value["label"] = address_value + " label"
    address_value["amount"] = 100000000
    addresses[address_key] = address_value
    data["addresses"] = addresses
    data["feePerKb"] = 1000
    data["label"] = "send_private label"
    data["subtractFeeFromAmount"] = False
    coin_control["selected"] = ""
    data["coinControl"] = coin_control
    # formulate request
    request["type"] = "none"
    request["collection"] = "sendZcoin"
    request["data"] = data
    request["auth"] = auth
    return format(str(request))

def set_passphrase_update(passphrase):
    request = {}
    auth = {}
    auth["passphrase"] = "passphrase"
    auth["newPassphrase"] = "newPassphrase"
    request["type"] = "update"
    request["collection"] = "setPassphrase"
    request["auth"] = auth
    return format(str(request))

def set_passphrase_create(passphrase):
    request = {}
    auth = {}
    auth["passphrase"] = "passphrase"
    request["type"] = "create"
    request["collection"] = "setPassphrase"
    request["auth"] = auth
    return format(str(request))

def setting_initial():
    request = {}
    request["type"] = "initial"
    request["collection"] = "setting"
    return format(str(request))

def setting_create():
    request = {}
    data = {}
    setting_0_key = ""
    setting_0_value = ""
    setting_1_key = ""
    setting_1_value = ""
    data[setting_0_key] = setting_0_value
    data[setting_1_key] = setting_1_value
    request["type"] = "create"
    request["collection"] = "setting"
    request["data"] = data
    return format(str(request))

def setting_update():
    request = {}
    data = {}
    setting_0_key = ""
    setting_0_value = ""
    setting_1_key = ""
    setting_1_value = ""
    data[setting_0_key] = setting_0_value
    data[setting_1_key] = setting_1_value
    request["type"] = "update"
    request["collection"] = "setting"
    request["data"] = data
    return format(str(request))

def setting_get():
    request = {}
    data = {}
    settings = []
    setting_0 = ""
    setting_1 = ""
    settings.append(setting_0, setting_1)
    data["settings"] = settings
    request["type"] = "update"
    request["collection"] = "setting"
    request["data"] = data
    return format(str(request))

def show_mnemonics():
    request = {}
    auth = {}
    auth["passphrase"] = "passphrase"
    request["type"] = "none"
    request["collection"] = "showMnemonics"
    request["auth"] = auth
    return format(str(request))

def state_wallet():
    request = {}
    request["type"] = "none"
    request["collection"] = "stateWallet"
    return format(str(request))

def tx_fee():
    request = {}
    data = {}
    addresses = {}
    address = ""
    amount = 0
    addresses[address] = amount
    data["addresses"] = addresses
    data["feePerKb"] = 0
    data["subtractFeeFromAmount"] = False
    request["type"] = "none"
    request["collection"] = "txFee"
    request["data"] = data
    return format(str(request))

def unlock_wallet():
    request = {}
    auth = {}
    auth["passphrase"] = "passphrase"
    request["type"] = "none"
    request["collection"] = "unlockWallet"
    request["auth"] = auth
    return format(str(request))

def verify_mnemonic_validity():
    request = {}
    data = {}
    data["mnemonic"] = ""
    request["type"] = "none"
    request["collection"] = "verifyMnemonicValidity"
    request["data"] = data
    return format(str(request))

def write_show_mnemonic_warning():
    request = {}
    request["type"] = "none"
    request["collection"] = "writeShowMnemonicWarning"
    request["data"] = True
    return format(str(request))

def znode_control(passphrase):
    request = {}
    data = {}
    auth = {}
    data["method"] = ""
    data["alias"] = ""
    auth["passphrase"] = "passphrase"
    request["type"] = "none"
    request["collection"] = "znodeControl"
    request["data"] = data
    request["auth"] = auth
    return format(str(request))

def znode_key():
    request = {}
    request["type"] = "none"
    request["collection"] = "znodeKey"
    return format(str(request))

def znode_list():
    request = {}
    request["type"] = "none"
    request["collection"] = "znodeList"
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
