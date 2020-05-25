# Overview
API for interaction with the new `zcoin-client` application. This project closely resembles the `rpc` layout, however it instead uses ZeroMQ as a transport mechanism, the code for which is contained within `src/zmqserver`. 

# Request
A request to be passed contains three elements: `type`, `collection`, and `data`.

## type
operation to be performed on `collection`.
### values
`get`: get a previously created object of type `collection`\
    requirements: see `Data Formats`. \
    *returns*: the full object previously created.

`create`: create an object of type `collection` to be stored. \
    requirements: see `Data Formats`. \
    *returns*: the full object that has been created.

`update`: update an object of type `collection`. \
    requirements: - see `Data Formats` (requires passing `id`. all other fields optional). \
    *returns*: the full object that has been modified.

`delete`: delete an object of type `collection`. requires passing `id` in `data`. \
    requirements: - see `Data Formats`. \
    *returns*: the status of the call.

`initial`: gets all objects of type `collection`. \
    requirements: - see `Data Formats`. (requires passing `id`. all other fields optional) \
    *returns*: the stored `data` object for type `collection`.

Some methods do not need to have a `type` parameter passed. These will be indicated by the preceding
`None` type in the `Data Formats` section below.

## collection
A function with one or more operations.

| Collection     | Description      | Port   | Passphrase | Warmup Ok
| :------------- | :--------------- | :----- | :--------- | :--------- |
| [apiStatus](#apistatus)                                           | Initial status of core. | 👁  | – |   ✅   |
| [backup](#backup)                                                 | Creates a zip file from wallet.dat and the `persistent/` folder, and stores in the filepath specified, as `zcoin_backup-{TIMESTAMP}.zip`.  | 🔐 | – |  – |
| [balance](#balance)                                               | Coin balance of a number of different categories. | 🔐 | – | – |
| [block](#block)                                                   | All transaction information from, and including, the blockHash parameter passed. | 🔐 | – | – |
| [blockchain](#blockchain)                                         | Information related to chain sync status and tip. | 🔐 | – | – |
| [editAddressBook](#editaddressbook)                               | Make a change to the wallet address book. | 🔐 | - | - |
| [listMints](#listmints)                                           | Returns a list of unspent Sigma mints.  | 🔐 | 🔐 | – |
| [lockCoin](#lockcoin)                                             | Lock/unlock specified UTXOs.  | 🔐 | – | – |
| [lockWallet](#lockwallet)                                         | Lock core wallet, should it be encrypted.  | 🔐 | – | – |
| [mint](#mint)                                                     | Mint 1 or more Sigma mints. | 🔐 | ✅ | – |
| [paymentRequest](#paymentrequest)                                 | Bundles of information related to a Zcoin payment. | 🔐 | – | – |
| [privateTxFee](#privatetxfee)                                     | Gets the transaction fee and inputs required for the private spend data passed. | 🔐 | - | – |
| [readAddressBook](#readaddressbook)                               | Read the addresses from the wallet address book. | 🔐 | - | - |
| [readWalletMnemonicWarningState](#readwalletmnemonicwarningstate) | Read mnemonic status from the wallet database. | 🔐 | - | - |
| [rebroadcast](#rebroadcast)                                       | Rebroadcast a transaction from mempool. | 🔐 | - | - |
| [rpc](#rpc)                                                       | Call an RPC command, or return a list of them. | 🔐 | - | - |
| [sendPrivate](#sendprivate)                                       | Spend 1 or more Sigma mints. Allows specifying third party addresses to spend to. | 🔐    | ✅ | – |
| [sendZcoin](#sendzcoin)                                           | Send Zcoin to the specified address(es). | 🔐 | ✅ | – |
| [setPassphrase](#setpassphrase)                                   |  Set, or update, the passphrase for the encryption of the wallet. | 🔐 | – | – |
| [setting](#setting)                                               | Interact with settings. | 🔐 | - | – |
| [showMnemonics](#showmnemonics)                                   | Show the wallet mnemonic. | 🔐 | ✅ | – |
| [stateWallet](#statewallet)                                       | Returns all information related to addresses in the wallet.  | 🔐 | – | – |
| [stop](#stop)                                                     | Stop the Zcoin daemon. | 🔐 | - | – |
| [txFee](#txfee)                                                   | Gets the transaction fee required for the size of the tx passed + fee per kb. | 🔐 | – | – |
| [unlockWallet](#unlockwallet)                                     | Unlock core wallet, should it be encrypted. | 🔐 | – | – |
| [verifyMnemonicValidity](#verifymnemonicvalidity)                 | Verify mnemonic is valid. | 🔐 | – | – |
| [writeShowMnemonicWarning](#writeshowmnemonicwarning)             | Write the wallet database entry to show the warning for mnemonics. | 🔐 | – | – |
| [znodeControl](#znodecontrol)                                     | Start/stop Znode(s) by alias. | 🔐 | ✅ | – |
| [znodeKey](#znodekey)                                             | Generate a new znode key. | 🔐 | - | – |
| [znodeList](#znodelist)                                           | list information related to all Znodes. | 🔐 | – | – |

## data
to be passed with `type` to be performed on `collection`.

## Reply
Replies contain two elements: `meta` and `data`.

### meta
status of the request performed.

#### values
`200`: successful request.
`400`: unsuccessful request.

### data
payload of the reply.

## Data Formats

#### Guide
VAR: value being returned is dependant on the condition stated.
OPTIONAL: not a necessary parameter to pass.

#### Categories
Transaction outputs are listed under particular categories. They are as follows:

`coinbase` | `znode` | `mined` | `spendIn` | `receive` | `mint` | `send` | `spendOut`

These categories are considered from the wallet perspective: the first five categories are considered the `receive` (ie. UTXO "into" the wallet) categories, while the latter three are considered the `send` (ie. UTXO "out of" the wallet) categories. As a result, in certain cases, the same UTXO can be listed under more than one category.

As an example, if the wallet is to send a transaction containing at least one UTXO to itself, that UTXO will be listed under both the `send` and `receive` categories. It is the same UTXO however, and so the client should only consider the incoming case if eg. showing available UTXOs for Coin Control.

Another example is a Sigma spend transaction to the wallet: the same output(s) will be labelled both a `spendIn` and `spendOut` UTXO.

`mint` is a special case: it is considered a part of the `send` category but there is no value leaving the wallet. The reason for this labelling is so that in a Sigma spend-to-mint transaction, `mint` takes priority over the `spendOut` category.

### `apiStatus`
`none`:
```
    data: {
    }
``` 
*Returns:*
```
    data: { 
        version: INT,
        protocolVersion: INT,
        walletinitialized: BOOL,
        walletVersion: INT, (VAR: Wallet initialized)
        walletLock: BOOL, (VAR: Wallet initialized)
        shouldShowWarning: BOOL, (VAR: Wallet initialized)
        unlockedUntil: INT,
        Znode: {
            localCount: INT,
            totalCount: INT,
            enabledCount: INT
        },
        dataDir: STRING,
        network: STRING("main"|"testnet"|"regtest"),
        blocks: INT,
        connections: INT,
        devAuth: BOOL,
        synced: BOOL,
        rescanning: BOOL,
        hasMnemonic: BOOL,
        reindexing: BOOL,
        safeMode: BOOL,
        pid: INT,
        modules: {
            API: BOOL,
            Znode: BOOL
        }
    },
    meta:{
       status: 200
    }
```

### `backup`
`none`:
```
    data: {
        directory: STRING ("absolute/path/to/backup/location")
    }
``` 
*Returns:*
```
    data: { 
        true
    },
    meta:{
       status: 200
    }
```

### `balance`
`none`:
```
    data: {
    }
```
*Returns:*
```
{ 
    data: {
        total: {
            all: INT,
            pending: INT,
            available: INT
        },
        public: {
            confirmed: INT,
            unconfirmed: INT,
            locked: INT,
        },
        private: {
            confirmed: INT,
            unconfirmed: INT,
        },
        unspentMints: {
            "1": {
                confirmed: INT,
                unconfirmed: INT,
            },
            "10": {
                confirmed: INT,
                unconfirmed: INT,
            },
            "25": {
                confirmed: INT,
                unconfirmed: INT,
            },
            "100": {
                confirmed: INT,
                unconfirmed: INT,
            },
            "0.05": {
                confirmed: INT,
                unconfirmed: INT,
            },
            "0.1": {
                confirmed: INT,
                unconfirmed: INT,
            },
            "0.5": {
                confirmed: INT,
                unconfirmed: INT,
            }
        },
    }, 
    meta:{
        status: 200
    }
}
```

### `block`
`none`:
```
    data: {
        hashBlock: STRING
    }
``` 
*Returns:*
```
    data: {
        addresses: {
            [STRING | "MINT"]: (address) {
                total: {
                    ["mined"|"send"|"receive"|"znode"|"spendIn"|"spendOut"|"mint"]{
                        sent: INT, (VAR : category=="send"|"mint"|"spendOut")
                        balance: INT, (VAR: category=="mined"|"znode"|"receive"|"spendIn"|"mint")
                    },
                    ["mined"|"send"|"receive"|"znode"|"spendIn"|"spendOut"|"mint"]{
                        sent: INT, (VAR : category=="send"|"mint"|"spendOut")
                        balance: INT, (VAR: category=="mined"|"znode"|"receive"|"spendIn"|"mint")
                    },
                    ... (For all used categories)
                },
                txids: {
                    ["mined"|"send"|"receive"|"znode"|"spendIn"|"spendOut"|"mint"][1..n]: (category + vout_index) {
                        STRING: (txid): {
                            address: STRING,
                            isChange: BOOL,
                            category: STRING("mined"|"send"|"receive"|"znode"|"spendIn"|"spendOut"|"mint"),
                            amount: INT,
                            fee: INT(sats),
                            label: STRING (VAR : address is part of zcoind "account")
                            firstSeenAt: INT(secs), 
                            blockHash: STRING,
                            blockTime: INT(secs),                            
                            blockHeight: INT,
                            txid: STRING,
                            available: BOOL (VAR: category == "mint"),
                            spendable: BOOL ((VAR: available == True),
                            locked: BOOL ((VAR: spendable == True)
                        },
                    },
                    ["mined"|"send"|"receive"|"znode"|"spendIn"|"spendOut"|"mint"][1..n]: (category + vout_index) {
                        STRING: (txid): {
                            address: STRING,
                            isChange: BOOL,
                            category: STRING("mined"|"send"|"receive"|"znode"|"spendIn"|"spendOut"|"mint"),
                            amount: INT,
                            fee: INT(sats),
                            label: STRING (VAR : address is part of zcoind "account")
                            firstSeenAt: INT(secs), 
                            blockHash: STRING,
                            blockTime: INT(secs),                            
                            blockHeight: INT,
                            txid: STRING,
                            available: BOOL (VAR: category == "mint"),
                            spendable: BOOL ((VAR: available == True),
                            locked: BOOL ((VAR: spendable == True)
                        },
                    },
                    ...
                }
            },
            [STRING | "MINT"]: (address) {
                total: {
                    ["mined"|"send"|"receive"|"znode"|"spendIn"|"spendOut"|"mint"]{
                        sent: INT, (VAR : category=="send"|"mint"|"spendOut")
                        balance: INT, (VAR: category=="mined"|"znode"|"receive"|"spendIn"|"mint")
                    },
                    ["mined"|"send"|"receive"|"znode"|"spendIn"|"spendOut"|"mint"]{
                        sent: INT, (VAR : category=="send"|"mint"|"spendOut")
                        balance: INT, (VAR: category=="mined"|"znode"|"receive"|"spendIn"|"mint")
                    },
                    ... (For all used categories)
                },
                txids: {
                    ["mined"|"send"|"receive"|"znode"|"spendIn"|"spendOut"|"mint"][1..n]: (category + vout_index) {
                        STRING: (txid): {
                            address: STRING,
                            isChange: BOOL,
                            category: STRING("mined"|"send"|"receive"|"znode"|"spendIn"|"spendOut"|"mint"),
                            amount: INT,
                            fee: INT(sats),
                            label: STRING (VAR : address is part of zcoind "account")
                            firstSeenAt: INT(secs), 
                            blockHash: STRING,
                            blockTime: INT(secs),                            
                            blockHeight: INT,
                            txid: STRING,
                            available: BOOL (VAR: category == "mint"),
                            spendable: BOOL ((VAR: available == True),
                            locked: BOOL ((VAR: spendable == True)
                        },
                    },
                    ["mined"|"send"|"receive"|"znode"|"spendIn"|"spendOut"|"mint"][1..n]: (category + vout_index) {
                        STRING: (txid): {
                            address: STRING,
                            isChange: BOOL,
                            category: STRING("mined"|"send"|"receive"|"znode"|"spendIn"|"spendOut"|"mint"),
                            amount: INT,
                            fee: INT(sats),
                            label: STRING (VAR : address is part of zcoind "account")
                            firstSeenAt: INT(secs), 
                            blockHash: STRING,
                            blockTime: INT(secs),                            
                            blockHeight: INT,
                            txid: STRING,
                            available: BOOL (VAR: category == "mint"),
                            spendable: BOOL ((VAR: available == True),
                            locked: BOOL ((VAR: spendable == True)
                        },
                    },
                    ...
                }
            },
            ...
        },
        "inputs": [
            {
                txid: STRING,
                index: STRING
            },
            {
                txid: STRING,
                index: STRING
            },
            ...
        ],
        "lockedCoins": [ (VAR: pending locked coins)
            {
                txid: STRING,
                index: STRING
            },
            {
                txid: STRING,
                index: STRING
            },
            ...
        ],
        "unlockedCoins": [ (VAR: pending unlocked coins)
            {
                txid: STRING,
                index: STRING
            },
            {
                txid: STRING,
                index: STRING
            },
            ...
        ]
        meta: {
            status: 200
        }
    }
```

### `blockchain`
`none`:
```
    data: {
    }
```
*Returns:*
```
{ 
    data: {
        testnet: BOOL,
        connections: INT,
        type: STRING,
        status: {
            isBlockchainSynced: BOOL,
            isZnodeListSynced: BOOL,
            isWinnersListSynced: BOOL,
            isSynced: BOOL,
            isFailed: BOOL
        },
        currentBlock: {
            height: INT,
            timestamp: INT,
        },
        avgBlockTime(secs): INT,
        timeUntilSynced(secs): INT (VAR: !isBlockchainSynced)
    } 
    meta:{
        status: 200
    }
}
```

### `editAddressBook`
`none`:
```
    data: {
        "action": STRING ("add"|"edit"|"delete"),
        "address": STRING,
        "label": STRING (VAR: action != "delete")
        "purpose": STRING (VAR: action != "delete")
    }
```
*Returns:*
```
{
    data: {
        true
    }
    meta:{
        status: 200
    }
}
```

### `listMints`:
`none`:
```
    data: {
    }
``` 
*Returns:*
```
{ 
    data: {
        STRING (serialNumberHash) {
            id: INT,
            IsUsed: BOOL,
            denomination: INT,
            value:  STRING,
            serialNumber: STRING,
            nHeight: INT, 
            randomness: STRING
        },
        STRING (serialNumberHash) {
            id: INT,
            IsUsed: BOOL,
            denomination: INT,
            value:  STRING,
            serialNumber: STRING,
            nHeight: INT, 
            randomness: STRING
        },
        ...
    }, 
    meta:{
       status: 200
    }
}
```

### `lockCoins`:
`none`:
```
    data: {
        lockedCoins: STRING ("txid0|vout:txid1|vout...txidn|vout")
        unlockedCoins: STRING ("txid0|vout:txid1|vout...txidn|vout")
    }
```
*Returns:*
```
{
    data: {
        true
    },
    meta:{
       status: 200
    }
}
```

### `lockWallet`:
`None`:
```
    data: {
    }
``` 
*Returns:*
```
{ 
    data: {
        true
    }, 
    meta:{
       status: 200
    }
}
```

### `mint`
`none`:
```
    data: {
        value: INT (VAR: denominations.IsNull())
        denominations: { (VAR: value.IsNull())
            STRING (denomination) : INT (amount),
            STRING (denomination) : INT (amount),
            STRING (denomination) : INT (amount),
            ...
        }
    },
    auth: {
        passphrase: STRING
    }
``` 
*Returns:*
```
{ 
    txids: {
       STRING (txid)
   },
    meta:{
       status: 200
    }
}
```


### `mintTxFee`
`none`:
```
    data: {
        value: INT (sats) (VAR: denominations.IsNull())
        denominations: { (VAR: value.IsNull())
            STRING (denomination) : INT (amount),
            STRING (denomination) : INT (amount),
            STRING (denomination) : INT (amount),
            ...
        }
    },
    auth: {
        passphrase: STRING
    }
```
*Returns:*
```
{
    "fee": INT(sats)
    meta:{
       status: 200
    }
}
```

### `paymentRequest`
`create`:
```
    data: {
        amount: INT (OPTIONAL),
        label: STRING,
        message: STRING
    }
```
*Returns:*
```
    data: {
        address: STRING, 
        createdAt: INT(secs)
        amount: INT,
        label: STRING,
        message: STRING
        state: STRING ("active")
    },
    meta:{
        status: 200
    }
```

`update`:
```
    data: {
        id: STRING,
        amount: INT, (OPTIONAL)
        label: STRING, (OPTIONAL)
        message: STRING, (OPTIONAL)
        state: STRING, (OPTIONAL) ("active"|"hidden"|"deleted"|"archived")
    }
```
*Returns:*
```
    data: {
        address: STRING,
        amount: INT, (OPTIONAL)
        label: STRING, (OPTIONAL)
        message: STRING (OPTIONAL)
        state: STRING, (OPTIONAL) ("active"|"hidden"|"deleted"|"archived")
    },
    meta:{
        status: 200
    }
```

`delete`:
```
    data: {
        id: STRING
    }
```
*Returns:*
```
    data: {
        true
    },
    meta:{
        status: 200
    }
```

`initial`:
```
    data: {
    }
```
*Returns:*
```
   data: {
        STRING (address): {
            "amount": INT,
            "createdAt": INT,
            "label": STRING,
            "message": STRING,
            state: STRING, ("active"|"hidden"|"deleted"|"archived")
        },
        STRING (address): {
            "amount": INT,
            "created_at": INT,
            "label": STRING,
            "message": STRING,
            state: STRING, ("active"|"hidden"|"deleted"|"archived")
        },
    ...
    },
    meta:{
        status: 200
    }
```

### `privateTxFee`
`none`:
```
    data: {
        outputs: [
            {
                address: STRING,
                amount: INT
            },
            {
                address: STRING,
                amount: INT
            },
            ...
        ],
        label: STRING,
        subtractFeeFromAmount: BOOL
    }
```

*Returns:*
```
{
    data: {
        inputs: INT,
        fee: INT(sats)
    },
    meta:{
        status: 200
    }
}
```

### `readAddressBook`
`none`:
```
    data: {
    }
```

*Returns:*
```
{
    data: {
        [
            {
                "address": STRING,
                "label": STRING,
                "purpose": STRING
            },
            {
                "address": STRING,
                "label": STRING,
                "purpose": STRING
            },
            ...
        ]
    },
    meta:{
        status: 200
    }
}
```

### `rebroadcast`
`create`:
```
    data: {
        "txHash" : STRING
    }
```
*Returns:*
```
   data: {
        "result": BOOL
        "error": STRING (VAR: failure in call)
    },
    meta:{
        status: 200
    }
```

### `rpc`
`initial`:
```
    data: {
    }
```
*Returns:*
```
    data: {
        categories: [
            "category" : {
                [
                    "command",
                    "command",
                    ...
                ]
            },
            "category" : {
                [
                    "command",
                    "command",
                    ...
                ]
            },
            ...
        ]
    }
```

`create`:
```
    data: {
        "method": STRING
        "args": STRING
    }
```
*Returns:*
```
   data: {
        "result": STRING,
        "error": STRING (VAR: failure in call)
    },
    meta:{
        status: 200
    }
```

### `sendPrivate`
`none`:
```
    data: {
        outputs: [
            {
                address: STRING,
                amount: INT
            },
            {
                address: STRING,
                amount: INT
            },
            ...
        ],
        label: STRING,
        subtractFeeFromAmount: BOOL,
        coinControl: { (OPTIONAL)
            selected: STRING ("txid0|vout:txid1|vout...txidn|vout")
        }
    }
    auth: {
        passphrase: STRING
    }
``` 

*Returns:*
```
{ 
    data: {
        txids: {
           STRING (txid)
       }
    }, 
    meta:{
        status: 200
    }
}
```

### `sendZcoin`
`none`:
```
    data: {
        addresses: {
          STRING (address): {
            amount: INT,
            label: STRING
          },
          STRING (address): {
            amount: INT,
            label: STRING
          },
          ...
        },
        feePerKb: INT (sats),
        subtractFeeFromAmount: BOOL,
        coinControl: { (OPTIONAL)
            selected: STRING ("txid0|vout:txid1|vout...txidn|vout")
        }
    },
    auth: {
        passphrase: STRING
    }
``` 
*Returns:*
```
{ 
    data: {
        txids: {
           STRING (txid)
       }
    }, 
    meta:{
       status: 200
    }
}
```

### `setPassphrase`
`create`:
```
    data: {
    },
    auth: {
        passphrase: STRING
    }
```

*Returns:*
```
{ 
    data: {
        true
    }, 
    meta:{
        status: 200
    }
}
```

`update`:
```
    data: {
    },
    auth: {
        passphrase: STRING,
        newPassphrase: STRING
    }
```
*Returns:*
```
{ 
    data: {
        true
    }, 
    meta:{
        status: 200
    }
}
```

### `setting`
`initial`:
```
    data: {
      }
```
*Returns:*
```
{
    data: {
        STRING (setting): {
            data: STRING,
            changed: BOOL,
            disabled: BOOL
        },
        STRING (setting): {
            data: STRING,
            changed: BOOL,
            disabled: BOOL
        },
        ...
        restartNow: BOOL
    },
    meta:{
       status: 200
    }
}
```

`create`:
```
    data: {
        STRING (setting): STRING (data),
        STRING (setting): STRING (data),
        ...
        }
    }
```
*Returns:*
```
{
    data: {
        true
    },
    meta:{
       status: 200
    }
}
```

`update`:
```
    data: {
        STRING (setting): STRING (data),
        STRING (setting): STRING (data),
        ...
    }
```
*Returns:*
```
{
    data: {
        true
    },
    meta:{
       status: 200
    }
}
```

`get`:
```
{
    data: {
        settings: [STRING,STRING,...]
    }
}
```
*Returns:*
```
{
    data: {
        STRING (setting): {
            data: STRING,
            changed: BOOL,
            restartRequired: BOOL
        },
        STRING (setting): {
            data: STRING,
            changed: BOOL,
            restartRequired: BOOL
        },
        ...
    },
    meta:{
       status: 200
    }
}
```

### `showMnemonics`
`none`:
```
    data: {
    }
```
*Returns:*
```
{
    data: {
        STRING (mnemonics)
    }
    meta:{
       status: 200
    }
}
```

### `stateWallet`
`none`:
```
    data: {
    }
``` 
*Returns:*
```
    data: {
        addresses: {
            [STRING | "MINT"]: (address) {
                total: {
                    ["mined"|"send"|"receive"|"znode"|"spendIn"|"spendOut"|"mint"]{
                        sent: INT, (VAR : category=="send"|"mint"|"spendOut")
                        balance: INT, (VAR: category=="mined"|"znode"|"receive"|"spendIn"|"mint")
                    },
                    ["mined"|"send"|"receive"|"znode"|"spendIn"|"spendOut"|"mint"]{
                        sent: INT, (VAR : category=="send"|"mint"|"spendOut")
                        balance: INT, (VAR: category=="mined"|"znode"|"receive"|"spendIn"|"mint")
                    },
                    ... (For all used categories)
                },
                txids: {
                    ["mined"|"send"|"receive"|"znode"|"spendIn"|"spendOut"|"mint"][1..n]: (category + vout_index) {
                        STRING: (txid): {
                            address: STRING,
                            isChange: BOOL,
                            category: STRING("mined"|"send"|"receive"|"znode"|"spendIn"|"spendOut"|"mint"),
                            amount: INT,
                            fee: INT(sats),
                            label: STRING (VAR : address is part of zcoind "account")
                            firstSeenAt: INT(secs), 
                            blockHash: STRING,
                            blockTime: INT(secs),                            
                            blockHeight: INT,
                            txid: STRING,
                            available: BOOL (VAR: category == "mint"),
                            spendable: BOOL ((VAR: available == True),
                            locked: BOOL ((VAR: spendable == True)
                        },
                    },
                    ["mined"|"send"|"receive"|"znode"|"spendIn"|"spendOut"|"mint"][1..n]: (category + vout_index) {
                        STRING: (txid): {
                            address: STRING,
                            isChange: BOOL,
                            category: STRING("mined"|"send"|"receive"|"znode"|"spendIn"|"spendOut"|"mint"),
                            amount: INT,
                            fee: INT(sats),
                            label: STRING (VAR : address is part of zcoind "account")
                            firstSeenAt: INT(secs), 
                            blockHash: STRING,
                            blockTime: INT(secs),                            
                            blockHeight: INT,
                            txid: STRING,
                            available: BOOL (VAR: category == "mint"),
                            spendable: BOOL ((VAR: available == True),
                            locked: BOOL ((VAR: spendable == True)
                        },
                    },
                    ...
                },
            }
            [STRING | "MINT"]: (address) {
                total: {
                    ["mined"|"send"|"receive"|"znode"|"spendIn"|"spendOut"|"mint"]{
                        sent: INT, (VAR : category=="send"|"mint"|"spendOut")
                        balance: INT, (VAR: category=="mined"|"znode"|"receive"|"spendIn"|"mint")
                    },
                    ["mined"|"send"|"receive"|"znode"|"spendIn"|"spendOut"|"mint"]{
                        sent: INT, (VAR : category=="send"|"mint"|"spendOut")
                        balance: INT, (VAR: category=="mined"|"znode"|"receive"|"spendIn"|"mint")
                    },
                    ... (For all used categories)
                },
                txids: {
                    ["mined"|"send"|"receive"|"znode"|"spendIn"|"spendOut"|"mint"][1..n]: (category + vout_index) {
                        STRING: (txid): {
                            address: STRING,
                            isChange: BOOL,
                            category: STRING("mined"|"send"|"receive"|"znode"|"spendIn"|"spendOut"|"mint"),
                            amount: INT,
                            fee: INT(sats),
                            label: STRING (VAR : address is part of zcoind "account")
                            firstSeenAt: INT(secs), 
                            blockHash: STRING,
                            blockTime: INT(secs),                            
                            blockHeight: INT,
                            txid: STRING,
                            available: BOOL (VAR: category == "mint"),
                            spendable: BOOL ((VAR: available == True),
                            locked: BOOL ((VAR: spendable == True)
                        },
                    },
                    ["mined"|"send"|"receive"|"znode"|"spendIn"|"spendOut"|"mint"][1..n]: (category + vout_index) {
                        STRING: (txid): {
                            address: STRING,
                            isChange: BOOL,
                            category: STRING("mined"|"send"|"receive"|"znode"|"spendIn"|"spendOut"|"mint"),
                            amount: INT,
                            fee: INT(sats),
                            label: STRING (VAR : address is part of zcoind "account")
                            firstSeenAt: INT(secs), 
                            blockHash: STRING,
                            blockTime: INT(secs),                            
                            blockHeight: INT,
                            txid: STRING,
                            available: BOOL (VAR: category == "mint"),
                            spendable: BOOL ((VAR: available == True),
                            locked: BOOL ((VAR: spendable == True)
                        },
                    },
                    ...
                }
            },
            ...
        },
        "inputs": [
            {
                txid: STRING,
                index: STRING
            },
            {
                txid: STRING,
                index: STRING
            },
            ...
        ],
        "lockedCoins": [ (VAR: pending locked coins)
            {
                txid: STRING,
                index: STRING
            },
            {
                txid: STRING,
                index: STRING
            },
            ...
        ],
        "unlockedCoins": [ (VAR: pending unlocked coins)
            {
                txid: STRING,
                index: STRING
            },
            {
                txid: STRING,
                index: STRING
            },
            ...
        ]
        meta: {
            status: 200
        }
    }
```

### `stop`
`stop`:
```
    data: {
      }
``` 
*Returns:*
```
{ 
    data: {
        true
    }, 
    meta:{
       status: 200
    }
}
```

### `txFee`
```
    data: {
          addresses: {
              STRING (address): INT (amount),
              STRING (address): INT (amount),
              ...
          },
          feePerKb: INT (sats),
          subtractFeeFromAmount: BOOL
      }
``` 
*Returns:*
```
{ 
    data: {
        fee: INT(sats),
    }, 
    meta:{
       status: 200
    }
}
```

### `unlockWallet`:
`none`:
```
    auth: {
        passphrase: STRING
    }
``` 
*Returns:*
```
{ 
    data: {
        true
    }, 
    meta:{
       status: 200
    }
}
```

### `verifyMnemonicValidity`
```
    data: {
        "mnemonic": STRING
    }
```
*Returns:*
```
{
    data: {
        "valid": BOOL,
        "reason": STRING, (VAR: valid==false)
    }
    meta:{
       status: 200
    }
}
```

### `writeShowMnemonicWarning`
```
    data: BOOL
```
*Returns:*
```
{
    data: {
        true
    }
    meta:{
       status: 200
    }
}
```


### `znodeControl`
`none`:
```
    data: {
        method: STRING, ["start-all" || "start-missing" || "start-alias"]
        alias: STRING (VAR: method=="start-alias")
      }
``` 
*Returns:*
```
{ 
    data: {
        detail: {
            status: {
                alias: STRING,
                success: BOOL,
                info: STRING (VAR: success==false)
            },
            status: {
                alias: STRING,
                success: BOOL,
                info: STRING (VAR: success==false)
            },
            ...
        },
        overall: {
          successful: INT,
          failed: INT,
          total: INT 
        }
    }, 
    meta:{
       status: 200
    }
}
```

### `znodeKey`
`create`:
```
    data: {
      }
```
*Returns:*
```
{
    data: {
        key: STRING
    },
    meta:{
       status: 200
    }
}
```

### `znodeList`
`initial`:
```
    data: {
      }
``` 
*Returns:*
```
{

    data: (VAR: Znodes not synced) {
        nodes: {
            STRING: (txid) {
                label: STRING,
                isMine: BOOL,
                outpoint: {
                    txid: STRING,
                    index: INT
                },
                authority: {
                    ip: STRING,
                    port: STRING
                },
                position: INT
            },
            STRING: (txid) {
                label: STRING,
                isMine: BOOL,
                outpoint: {
                    txid: STRING,
                    index: INT
                },
                authority: {
                    ip: STRING,
                    port: STRING
                },
                position: INT
            },
            ...
            }
        },
        total: INT
    },

    data: (VAR: Znodes synced) {
        STRING: { (payeeAddress)
            rank: INT,
            outpoint: {
                txid: STRING,
                index: STRING
            },
            status: STRING,
            protocolVersion: INT,
            payeeAddress: STRING,
            lastSeen: INT,
            activeSince: INT,
            lastPaidTime: INT,
            lastPaidBlock: INT,
            authority: {
                ip: STRING,
                port: STRING
            }
            isMine: BOOL,
            label: STRING, (VAR: isMine==true)
            position: INT, (VAR: isMine==true)
            qualify: {
                result: BOOL,
                description: STRING ["Is scheduled"             ||
                                     "Invalid nProtocolVersion" ||
                                     "Too new"                  ||
                                     "collateralAge < znCount"] (VAR: result==false)
                data: { (VAR: result==false)
                    nProtocolVersion: INT, (VAR: description=="Invalid nProtocolVersion")
                    sigTime:          INT, (VAR: description=="Too new"),
                    qualifiedAfter:   INT, (VAR: description=="Too new"),
                    collateralAge:    INT, (VAR: description=="collateralAge < znCount"),
                    znCount:          INT, (VAR: description=="collateralAge < znCount")
                }
            }
        },
        STRING: { (payeeAddress)
            rank: INT,
            outpoint: {
                txid: STRING,
                index: STRING
            },
            status: STRING,
            protocolVersion: INT,
            payeeAddress: STRING,
            lastSeen: INT,
            activeSince: INT,
            lastPaidTime: INT,
            lastPaidBlock: INT,
            authority: {
                ip: STRING,
                port: STRING
            }
            isMine: BOOL,
            label: STRING, (VAR: isMine==true)
            position: INT, (VAR: isMine==true)
            qualify: {
                result: BOOL,
                description: STRING ["Is scheduled"             ||
                                     "Invalid nProtocolVersion" ||
                                     "Too new"                  ||
                                     "collateralAge < znCount"] (VAR: result==false)
                data: { (VAR: result==false)
                    nProtocolVersion: INT, (VAR: description=="Invalid nProtocolVersion")
                    sigTime:          INT, (VAR: description=="Too new"),
                    qualifiedAfter:   INT, (VAR: description=="Too new"),
                    collateralAge:    INT, (VAR: description=="collateralAge < znCount"),
                    znCount:          INT, (VAR: description=="collateralAge < znCount")
                }
            }
        },
        ...
    }, 
    meta:{
       status: 200
    }
}
```

# Publish
The publisher module is comprised of various _topics_ that are triggered under specific conditions, called _events_. Both topics and events have a 1 to N relationship with each other; ie. 1 event may trigger 1 to N topics, and 1 topic may be triggered by 1 to N events.


|               | _Event_       | NotifyAPIStatus  | SyncTransaction | NumConnectionsChanged | UpdatedBlockTip | UpdatedMasternodeStatus  | UpdatedSettings | UpdatedZnode | UpdateSyncStatus |
| ------------- | ------------- | ---------------  | --------------- | --------------------- | --------------- | -----------------  | --------------- | ------------ | ---------------- |
| **_Topic_**   | Description   | API status notification | new transactions | zcoind peer list updated | blockchain head updated | EVO Znode added/updated | settings changed/updated | Znode update | Blockchain sync update
**address** (triggers [block](#block))                          | block tx data.                            | -  | -  | -  | ✅ | -  | -  | -  | -  |
**apiStatus** (triggers [apiStatus](#apistatus))                | Status of API                             | ✅ | -  | -  | -  | -  | -  | -  | -  |
**balance** (triggers [balance](#balance))                      | Balance info                              | -  | -  | -  | ✅ | -  | -  | -  | -  |
**block** (triggers [blockchain](#blockchain))                  | general block data (sync status + header) | -  | -  | ✅ | ✅ | -  | -  | -  | ✅ |
**masternode** (triggers [masternodeUpdate](#masternodeupdate)) | update to masternode                      | -  | -  | -  | -  | ✅ | -  | -  | -  |
**settings** (triggers [readSettings](#readsettings))           | settings changed                          | -  | -  | -  | -  | -  | ✅ | -  | -  |
**transaction** (triggers [transaction](#transaction))          | new transaction data                      | -  | ✅ | -  | -  | -  | -  | -  | -  |
**znode** (triggers [znodeUpdate](#znodeupdate))                | update to znode                           | -  | -  | -  | -  | -  | -  | ✅ | -  |

## Methods

Methods specific to the publisher.

### `readSettings` 
*Returns:*
```
{
    data: {
        STRING: (setting) {
            data: STRING,
            changed: BOOL,
            disabled: BOOL
        },
        STRING: (setting) {
            data: STRING,
            changed: BOOL,
            disabled: BOOL
        },
        ...
        restartNow: BOOL
    }

    meta: {
        status: 200
    },
    "error": null
}
```



### `transaction` 
*Returns:*
```
{ 
    data: {
        [STRING | "MINT"]: (address) {
            total: {
                ["mined"|"send"|"receive"|"znode"|"spendIn"|"spendOut"|"mint"]{
                    sent: INT, (VAR : category=="send"|"mint"|"spendOut")
                    balance: INT, (VAR: category=="mined"|"znode"|"receive"|"spendIn"|"mint")
                },
                ["mined"|"send"|"receive"|"znode"|"spendIn"|"spendOut"|"mint"]{
                    sent: INT, (VAR : category=="send"|"mint"|"spendOut")
                    balance: INT, (VAR: category=="mined"|"znode"|"receive"|"spendIn"|"mint")
                },
                ... (For all used categories)
            },
            txids: {
                ["mined"|"send"|"receive"|"znode"|"spendIn"|"spendOut"|"mint"][1..n]: (category + vout_index) {
                    STRING: (txid): {
                        address: STRING,
                        isChange: BOOL,
                        category: STRING("mined"|"send"|"receive"|"znode"|"spendIn"|"spendOut"|"mint"),
                        amount: INT,
                        fee: INT(sats),
                        label: STRING (VAR : address is part of zcoind "account")
                        firstSeenAt: INT(secs), 
                        blockHash: STRING,
                        blockTime: INT(secs),                            
                        blockHeight: INT,
                        txid: STRING,
                        available: BOOL (VAR: category == "mint"),
                        spendable: BOOL ((VAR: available == True),
                        locked: BOOL ((VAR: spendable == True)
                    },
                },
                ["mined"|"send"|"receive"|"znode"|"spendIn"|"spendOut"|"mint"][1..n]: (category + vout_index) {
                    STRING: (txid): {
                        address: STRING,
                        isChange: BOOL,
                        category: STRING("mined"|"send"|"receive"|"znode"|"spendIn"|"spendOut"|"mint"),
                        amount: INT,
                        fee: INT(sats),
                        label: STRING (VAR : address is part of zcoind "account")
                        firstSeenAt: INT(secs), 
                        blockHash: STRING,
                        blockTime: INT(secs),                            
                        blockHeight: INT,
                        txid: STRING,
                        available: BOOL (VAR: category == "mint"),
                        spendable: BOOL ((VAR: available == True),
                        locked: BOOL ((VAR: spendable == True)
                    },
                },
                ...
            }
        },
        [STRING | "MINT"]: (address) {
            total: {
                ["mined"|"send"|"receive"|"znode"|"spendIn"|"spendOut"|"mint"]{
                    sent: INT, (VAR : category=="send"|"mint"|"spendOut")
                    balance: INT, (VAR: category=="mined"|"znode"|"receive"|"spendIn"|"mint")
                },
                ["mined"|"send"|"receive"|"znode"|"spendIn"|"spendOut"|"mint"]{
                    sent: INT, (VAR : category=="send"|"mint"|"spendOut")
                    balance: INT, (VAR: category=="mined"|"znode"|"receive"|"spendIn"|"mint")
                },
                ... (For all used categories)
            },
            txids: {
                ["mined"|"send"|"receive"|"znode"|"spendIn"|"spendOut"|"mint"][1..n]: (category + vout_index) {
                    STRING: (txid): {
                        address: STRING,
                        isChange: BOOL,
                        category: STRING("mined"|"send"|"receive"|"znode"|"spendIn"|"spendOut"|"mint"),
                        amount: INT,
                        fee: INT(sats),
                        label: STRING (VAR : address is part of zcoind "account")
                        firstSeenAt: INT(secs), 
                        blockHash: STRING,
                        blockTime: INT(secs),                            
                        blockHeight: INT,
                        txid: STRING,
                        available: BOOL (VAR: category == "mint"),
                        spendable: BOOL ((VAR: available == True),
                        locked: BOOL ((VAR: spendable == True)
                    },
                },
                ["mined"|"send"|"receive"|"znode"|"spendIn"|"spendOut"|"mint"][1..n]: (category + vout_index) {
                    STRING: (txid): {
                        address: STRING,
                        isChange: BOOL,
                        category: STRING("mined"|"send"|"receive"|"znode"|"spendIn"|"spendOut"|"mint"),
                        amount: INT,
                        fee: INT(sats),
                        label: STRING (VAR : address is part of zcoind "account")
                        firstSeenAt: INT(secs), 
                        blockHash: STRING,
                        blockTime: INT(secs),                            
                        blockHeight: INT,
                        txid: STRING,
                        available: BOOL (VAR: category == "mint"),
                        spendable: BOOL ((VAR: available == True),
                        locked: BOOL ((VAR: spendable == True)
                    },
                },
                ...
            }
        },
        ...
    },
    "inputs": [
        {
            txid: STRING,
            index: STRING
        },
        {
            txid: STRING,
            index: STRING
        },
        ...
    ],
    "lockedCoins": [ (VAR: pending locked coins)
        {
            txid: STRING,
            index: STRING
        },
        {
            txid: STRING,
            index: STRING
        },
        ...
    ],
    "unlockedCoins": [ (VAR: pending unlocked coins)
        {
            txid: STRING,
            index: STRING
        },
        {
            txid: STRING,
            index: STRING
        },
        ...
    ]
    meta: {
        status: 200
    }
}
```

### `znodeUpdate` 
*Returns:*
```
{
    data: {
        STRING: (txid + index) {
            rank: INT,
            outpoint: {
                txid: STRING,
                index: STRING
            },
            status: STRING,
            protocolVersion: INT,
            payeeAddress: STRING,
            lastSeen: INT,
            activeSince: INT,
            lastPaidTime: INT,
            lastPaidBlock: INT,
            authority: {
                ip: STRING,
                port: STRING
            }
            isMine: BOOL,
            label: STRING, (VAR: isMine==true)
            position: INT, (VAR: isMine==true)
            qualify: {
                result: BOOL,
                description: STRING ["Is scheduled"             ||
                                     "Invalid nProtocolVersion" ||
                                     "Too new"                  ||
                                     "collateralAge < znCount"] (VAR: result==false)
                data: { (VAR: result==false)
                    nProtocolVersion: INT, (VAR: description=="Invalid nProtocolVersion")
                    sigTime:          INT, (VAR: description=="Too new"),
                    qualifiedAfter:   INT, (VAR: description=="Too new"),
                    collateralAge:    INT, (VAR: description=="collateralAge < znCount"),
                    znCount:          INT, (VAR: description=="collateralAge < znCount")
                }
            }
        }
    },
    meta: {
        status: 200
    },
    "error": null
}
```



### `masternodeUpdate`
*Returns:*
```
{
    data: {
        STRING (proTxHash): {
            proTxHash: STRING,
            collateralHash: STRING,
            "collateralIndex: INT,
            collateralAddress: STRING,
            operatorReward: INT,
            state: {
                service: STRING,
                registeredHeight: INT,
                lastPaidHeight: INT,
                nextPaymentHeight: INT, (VAR: Znode in next payments list)
                PoSePenalty: INT,
                PoSeRevivedHeight: INT,
                PoSeBanHeight: INT,
                revocationReason: INT,
                ownerAddress: STRING,
                votingAddress: STRING,
                payoutAddress: STRING,
                pubKeyOperator: STRING (VAR),
                operatorPayoutAddress: STRING (VAR)
            }
        }
    },
    meta: {
        status: 200
    },
    "error": null
}
```
