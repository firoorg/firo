Vnode Build Instructions and Notes
=============================
 - Version 0.1.0
 - Date: April 2018
 
Prerequisites
-------------
 - Ubuntu 16.04+
 - Libraries to build from verticalcoin source
 - Port **8168** is open

Step 1. Build
----------------------
**1.1.**  Check out from source:

    git clone https://github.com/DerUntote/verticalcoin

**1.2.**  See [README.md](README.md) for instructions on building.

Step 2. (Optional - only if firewall is running). Open port 8168
----------------------
**2.1.**  Run:

    sudo ufw allow 8168
    sudo ufw default allow outgoing
    sudo ufw enable

Step 3. First run on your Local Wallet
----------------------
**3.0.**  Go to the checked out folder

    cd verticalcoin

**3.1.**  Start daemon in testnet mode:

    ./src/verticalcoind -daemon -server -testnet

**3.2.**  Generate vnodeprivkey:

    ./src/verticalcoin-cli vnode genkey

(Store this key)

**3.3.**  Get wallet address:

    ./src/verticalcoin-cli getaccountaddress 0

**3.4.**  Send to received address **exactly 1000 XZC** in **1 transaction**. Wait for 15 confirmations.

**3.5.**  Stop daemon:

    ./src/verticalcoin-cli stop

Step 4. In your VPS where you are hosting your Vnode. Update config files
----------------------
**4.1.**  Create file **verticalcoin.conf** (in folder **~/.verticalcoin**)

    rpcuser=username
    rpcpassword=password
    rpcallowip=127.0.0.1
    debug=1
    txindex=1
    daemon=1
    server=1
    listen=1
    maxconnections=24
    vnode=1
    vnodeprivkey=XXXXXXXXXXXXXXXXX  ## Replace with your vnode private key
    externalip=XXX.XXX.XXX.XXX:8168 ## Replace with your node external IP

**4.2.**  Create file **vnode.conf** (in 2 folders **~/.verticalcoin** and **~/.verticalcoin/testnet3**) contains the following info:
 - LABEL: A one word name you make up to call your node (ex. ZN1)
 - IP:PORT: Your vnode VPS's IP, and the port is always 18168.
 - ZNODEPRIVKEY: This is the result of your "vnode genkey" from earlier.
 - TRANSACTION HASH: The collateral tx. hash from the 1000 XZC deposit.
 - INDEX: The Index is always 0 or 1.

To get TRANSACTION HASH, run:

    ./src/verticalcoin-cli vnode outputs

The output will look like:

    { "d6fd38868bb8f9958e34d5155437d009b72dfd33fc28874c87fd42e51c0f74fdb" : "0", }

Sample of vnode.conf:

    ZN1 51.52.53.54:18168 XrxSr3fXpX3dZcU7CoiFuFWqeHYw83r28btCFfIHqf6zkMp1PZ4 d6fd38868bb8f9958e34d5155437d009b72dfd33fc28874c87fd42e51c0f74fdb 0

Step 5. Run a vnode
----------------------
**5.1.**  Start vnode:

    ./src/verticalcoin-cli vnode start-alias <LABEL>

For example:

    ./src/verticalcoin-cli vnode start-alias ZN1

**5.2.**  To check node status:

    ./src/verticalcoin-cli vnode debug

If not successfully started, just repeat start command
