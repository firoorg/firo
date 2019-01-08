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
| [apiStatus](#apistatus)           | Initial status of core. | 👁  | – |   ✅   |
| [backup](#backup)                 | Creates a zip file from wallet.dat and the `persistent/` folder, and stores in the filepath specified, as `zcoin_backup-{TIMESTAMP}.zip`.  | 🔐 | – |  – |
| [lockWallet](#lockwallet)         | Lock core wallet, should it be encrypted.  | 🔐 | – | – |
| [unlockWallet](#unlockwallet)     | Unlock core wallet, should it be encrypted. | 🔐 | – | – |
| [stateWallet](#statewallet)       | Returns all information related to addresses in the wallet.  | 🔐 | – | – |
| [setPassphrase](#setpassphrase)   |  Set, or update, the passphrase for the encryption of the wallet. | 🔐 | – | – |
| [balance](#balance)               | Coin balance of a number of different categories. | 🔐 | – | – |
| [blockchain](#blockchain)         | Information related to chain sync status and tip. | 🔐 | – | – |
| [block](#block)                   | All transaction information from, and including, the blockHash parameter passed. | 🔐 | – | – |
| [paymentRequest](#paymentrequest) | Bundles of information related to a Zcoin payment. | 🔐 | – | – |
| [txFee](#txfee)                   | Gets the transaction fee required for the size of the tx passed + fee per kb. | 🔐 | – | – |
| [znodeList](#znodelist)           | list information related to all Znodes. | 🔐 | – | – |
| [updateLabels](#updateLabels)     | Update transaction labels stored in the persistent tx metadata file. | 🔐 | – | – |
| [stop](#stop)                     | Stop the Zcoin daemon. | 🔐 | - | – |
| [setting](#setting)               | Interact with settings. | 🔐 | - | – |
| [znodeControl](#znodecontrol)     | Start/stop Znode(s) by alias. | 🔐 | ✅ | – |
| [mint](#mint)                     | Mint 1 or more Zerocoins. | 🔐 | ✅ | – |
| [sendPrivate](#sendprivate)       | Spend 1 or more Zerocoins. Allows specifying third party addresses to spend to. | 🔐    | ✅ | – |
| [sendZcoin](#sendzcoin)           | Send Zcoin to the specified address(es). | 🔐 | ✅ | – |


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
VAR: variable return value.
OPTIONAL: not a necessary parameter to pass.

### `apiStatus`
`initial`:
```
    data: {
    }
``` 
*Returns:*
```
    data: { 
        version: INT,
        protocolVersion: INT,
        walletVersion: INT,
        walletLock: BOOL, 
        unlockedUntil: INT, (VAR : wallet is unlocked)
        dataDir: STRING,
        network: STRING("main"|"testnet"|"regtest"),
        blocks: INT,
        connections: INT,
        devAuth: BOOL,
        synced: BOOL,
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
`create`:
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

### `unlockWallet`:
`None`:
```
    data: {
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

### `stateWallet`
`initial`:
```
    data: {
    }
``` 
*Returns:*
```
    data: {
        [STRING | "ZEROMINT"]: (address)
            { 
                txids: 
                    {
                        STRING: (txid)
                            { 
                            ["mined"|"send"|"receive"|"znode"|"spend"|"mint"]: (category) 
                                 {
                                    address: STRING,
                                    category: STRING("mined"|"send"|"receive"|"znode"|"spend"|"mint"),
                                    amount: INT,
                                    fee: INT(sats),
                                    label: STRING (VAR : address is part of zcoind "account")
                                    firstSeenAt: INT(secs), 
                                    blockHash: STRING,
                                    blockTime: INT(secs),                            
                                    blockHeight: INT,
                                    txid: STRING
                                },
                            ["mined"|"send"|"receive"|"znode"|"spend"|"mint"]: (category) 
                                 {
                                    address: STRING,
                                    category: STRING("mined"|"send"|"receive"|"znode"|"spend"|"mint"),
                                    amount: INT,
                                    fee: INT(sats),
                                    label: STRING (VAR : address is part of zcoind "account")
                                    firstSeenAt: INT(secs), 
                                    blockHash: STRING,
                                    blockTime: INT(secs),                            
                                    blockHeight: INT,
                                    txid: STRING
                                },
                                ...
                            },
                        STRING: (txid)
                            { 
                            ["mined"|"send"|"receive"|"znode"|"spend"|"mint"]: (category) 
                                 {
                                    address: STRING,
                                    category: STRING("mined"|"send"|"receive"|"znode"|"spend"|"mint"),
                                    amount: INT,
                                    fee: INT(sats),
                                    label: STRING (VAR : address is part of zcoind "account")
                                    firstSeenAt: INT(secs), 
                                    blockHash: STRING,
                                    blockTime: INT(secs),                            
                                    blockHeight: INT,
                                    txid: STRING                                    
                                },
                            ["mined"|"send"|"receive"|"znode"|"spend"|"mint"]: (category) 
                                 {
                                    address: STRING,
                                    category: STRING("mined"|"send"|"receive"|"znode"|"spend"|"mint"),
                                    amount: INT,
                                    fee: INT(sats),
                                    label: STRING (VAR : address is part of zcoind "account")
                                    firstSeenAt: INT(secs), 
                                    blockHash: STRING,
                                    blockTime: INT(secs),                            
                                    blockHeight: INT,
                                    txid: STRING 
                                },
                                ...
                            },
                        ...
                    },
                total: 
                    {
                        sent: INT, (VAR : category=="send"|"mint"|"spend")
                        balance: INT, (VAR: category=="mined"|"znode"|"receive"|)
                    } 
            },
        [STRING | "ZEROMINT"]: (address)
            { 
                txids: 
                    {
                        STRING: (txid)
                            { 
                            ["mined"|"send"|"receive"|"znode"|"spend"|"mint"]: (category) 
                                 {
                                    address: STRING,
                                    category: STRING("mined"|"send"|"receive"|"znode"|"spend"|"mint"),
                                    amount: INT,
                                    fee: INT(sats),
                                    label: STRING (VAR : address is part of zcoind "account")
                                    firstSeenAt: INT(secs), 
                                    blockHash: STRING,
                                    blockTime: INT(secs),                            
                                    blockHeight: INT,
                                    txid: STRING 
                                },
                            ["mined"|"send"|"receive"|"znode"|"spend"|"mint"]: (category) 
                                 {
                                    address: STRING,
                                    category: STRING("mined"|"send"|"receive"|"znode"|"spend"|"mint"),
                                    amount: INT,
                                    fee: INT(sats),
                                    label: STRING (VAR : address is part of zcoind "account")
                                    firstSeenAt: INT(secs), 
                                    blockHash: STRING,
                                    blockTime: INT(secs),                            
                                    blockHeight: INT,
                                    txid: STRING 
                                },
                                ...
                            },
                        STRING: (txid)
                            { 
                            ["mined"|"send"|"receive"|"znode"|"spend"|"mint"]: (category) 
                                 {
                                    address: STRING,
                                    category: STRING("mined"|"send"|"receive"|"znode"|"spend"|"mint"),
                                    amount: INT,
                                    fee: INT(sats),
                                    label: STRING (VAR : address is part of zcoind "account")
                                    firstSeenAt: INT(secs), 
                                    blockHash: STRING,
                                    blockTime: INT(secs),                            
                                    blockHeight: INT,
                                    txid: STRING 
                                },
                            ["mined"|"send"|"receive"|"znode"|"spend"|"mint"]: (category) 
                                 {
                                    address: STRING,
                                    category: STRING("mined"|"send"|"receive"|"znode"|"spend"|"mint"),
                                    amount: INT,
                                    fee: INT(sats),
                                    label: STRING (VAR : address is part of zcoind "account")
                                    firstSeenAt: INT(secs), 
                                    blockHash: STRING,
                                    blockTime: INT(secs),                            
                                    blockHeight: INT,
                                    txid: STRING 
                                },
                                ...
                            },
                        ...
                    },
                total: 
                    {
                        sent: INT, (VAR : category=="send"|"mint"|"spend")
                        balance: INT, (VAR: category=="mined"|"znode"|"receive"|)
                    }  
            },
        ...
        },
    meta: {
        status: 200
    }
```

### `setPassphrase`
`create`:
```
    auth: {
        passphrase: STRING
        }
    }
```
`update`:
```
    auth: {
        passphrase: STRING,
        newPassphrase: STRING
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

### `balance`
`get`:
```
    data: {
        }
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
        xzc: {
            confirmed: INT,
            unconfirmed: INT,
            locked: INT,
        },
        zerocoin: {
            confirmed: INT,
            unconfirmed: INT,
        }
    }, 
    meta:{
        status: 200
    }
}
```

### `blockchain`
`get`:
```
    data: {
        }
    }
```
*Returns:*
```
{ 
    data: {
        status: {
            isBlockchainSynced: BOOL,
            isZnodeListSynced: BOOL,
            isWinnersListSynced: BOOL,
            isSynced: BOOL,
            isFailed: BOOL
        },
        testnet: BOOL,
        connections: INT,
        type: STRING,
        currentBlock: {
            height: INT,
            timestamp: INT,
        },
        avgBlockTime(secs): INT,
        timeUntilSynced(secs): INT
    } 
    meta:{
        status: 200
    }
}
```


### `block`
`GET`:
```
    data: {
        blockHash: STRING
    }
``` 
*Returns:*
```
    data: {
        [STRING | "ZEROMINT"]: (address)
            { 
                txids: 
                    {
                        STRING: (txid)
                            { 
                            ["mined"|"send"|"receive"|"znode"|"spend"|"mint"]: (category) 
                                 {
                                    address: STRING,
                                    category: STRING("mined"|"send"|"receive"|"znode"|"spend"|"mint"),
                                    amount: INT,
                                    fee: INT(sats),
                                    label: STRING (VAR : address is part of zcoind "account")
                                    firstSeenAt: INT(secs), 
                                    blockHash: STRING,
                                    blockTime: INT(secs),                            
                                    blockHeight: INT,
                                    txid: STRING
                                },
                            ["mined"|"send"|"receive"|"znode"|"spend"|"mint"]: (category) 
                                 {
                                    address: STRING,
                                    category: STRING("mined"|"send"|"receive"|"znode"|"spend"|"mint"),
                                    amount: INT,
                                    fee: INT(sats),
                                    label: STRING (VAR : address is part of zcoind "account")
                                    firstSeenAt: INT(secs), 
                                    blockHash: STRING,
                                    blockTime: INT(secs),                            
                                    blockHeight: INT,
                                    txid: STRING
                                },
                                ...
                            },
                        STRING: (txid)
                            { 
                            ["mined"|"send"|"receive"|"znode"|"spend"|"mint"]: (category) 
                                 {
                                    address: STRING,
                                    category: STRING("mined"|"send"|"receive"|"znode"|"spend"|"mint"),
                                    amount: INT,
                                    fee: INT(sats),
                                    label: STRING (VAR : address is part of zcoind "account")
                                    firstSeenAt: INT(secs), 
                                    blockHash: STRING,
                                    blockTime: INT(secs),                            
                                    blockHeight: INT,
                                    txid: STRING                                    
                                },
                            ["mined"|"send"|"receive"|"znode"|"spend"|"mint"]: (category) 
                                 {
                                    address: STRING,
                                    category: STRING("mined"|"send"|"receive"|"znode"|"spend"|"mint"),
                                    amount: INT,
                                    fee: INT(sats),
                                    label: STRING (VAR : address is part of zcoind "account")
                                    firstSeenAt: INT(secs), 
                                    blockHash: STRING,
                                    blockTime: INT(secs),                            
                                    blockHeight: INT,
                                    txid: STRING 
                                },
                                ...
                            },
                        ...
                    },
                total: 
                    {
                        sent: INT, (VAR : category=="send"|"mint"|"spend")
                        balance: INT, (VAR: category=="mined"|"znode"|"receive"|)
                    } 
            },
        [STRING | "ZEROMINT"]: (address)
            { 
                txids: 
                    {
                        STRING: (txid)
                            { 
                            ["mined"|"send"|"receive"|"znode"|"spend"|"mint"]: (category) 
                                 {
                                    address: STRING,
                                    category: STRING("mined"|"send"|"receive"|"znode"|"spend"|"mint"),
                                    amount: INT,
                                    fee: INT(sats),
                                    label: STRING (VAR : address is part of zcoind "account")
                                    firstSeenAt: INT(secs), 
                                    blockHash: STRING,
                                    blockTime: INT(secs),                            
                                    blockHeight: INT,
                                    txid: STRING 
                                },
                            ["mined"|"send"|"receive"|"znode"|"spend"|"mint"]: (category) 
                                 {
                                    address: STRING,
                                    category: STRING("mined"|"send"|"receive"|"znode"|"spend"|"mint"),
                                    amount: INT,
                                    fee: INT(sats),
                                    label: STRING (VAR : address is part of zcoind "account")
                                    firstSeenAt: INT(secs), 
                                    blockHash: STRING,
                                    blockTime: INT(secs),                            
                                    blockHeight: INT,
                                    txid: STRING 
                                },
                                ...
                            },
                        STRING: (txid)
                            { 
                            ["mined"|"send"|"receive"|"znode"|"spend"|"mint"]: (category) 
                                 {
                                    address: STRING,
                                    category: STRING("mined"|"send"|"receive"|"znode"|"spend"|"mint"),
                                    amount: INT,
                                    fee: INT(sats),
                                    label: STRING (VAR : address is part of zcoind "account")
                                    firstSeenAt: INT(secs), 
                                    blockHash: STRING,
                                    blockTime: INT(secs),                            
                                    blockHeight: INT,
                                    txid: STRING 
                                },
                            ["mined"|"send"|"receive"|"znode"|"spend"|"mint"]: (category) 
                                 {
                                    address: STRING,
                                    category: STRING("mined"|"send"|"receive"|"znode"|"spend"|"mint"),
                                    amount: INT,
                                    fee: INT(sats),
                                    label: STRING (VAR : address is part of zcoind "account")
                                    firstSeenAt: INT(secs), 
                                    blockHash: STRING,
                                    blockTime: INT(secs),                            
                                    blockHeight: INT,
                                    txid: STRING 
                                },
                                ...
                            },
                        ...
                    },
                total: 
                    {
                        sent: INT, (VAR : category=="send"|"mint"|"spend")
                        balance: INT, (VAR: category=="mined"|"znode"|"receive"|)
                    }  
            },
        ...
        },
    meta: {
        status: 200
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
        createdAt:
        amount: INT,
        label: STRING,
        message: STRING
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
    }
```
*Returns:*
```
    data: {
        address: STRING,
        amount: INT, (OPTIONAL)
        label: STRING, (OPTIONAL)
        message: STRING (OPTIONAL)
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
            "message": STRING
        },
        STRING (address): {
            "amount": INT,
            "created_at": INT,
            "label": STRING,
            "message": STRING
        },
    ...
    },
    meta:{
        status: 200
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
          feePerKb(sats): INT,
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

### `znodeList`
`initial`:
```
    data: {
      }
``` 
*Returns:*
```
{ 
    data: {
        STRING: { (payeeAddress)
            rank: INT,
            outpoint: STRING,
            status: STRING,
            protocolVersion: INT,
            payeeAddress: STRING,
            lastSeen: INT,
            activeSeconds: INT,
            lastPaidTime: INT,
            lastPaidBlock: INT,
            authority: STRING,
            isMine: BOOL,
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
            outpoint: STRING,
            status: STRING,
            protocolVersion: INT,
            payeeAddress: STRING,
            lastSeen: INT,
            activeSeconds: INT,
            lastPaidTime: INT,
            lastPaidBlock: INT,
            authority: STRING,
            isMine: BOOL,
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

### `updateLabels`
`update`:
```
    data: {
        txid: STRING,
        label: STRING,
        address: STRING (OPTIONAL)
      }
```
*Returns:*
```
{
    data: {
        txid: STRING,
        address: STRING,
        label: STRING
    },
    meta:{
       status: 200
    }
}
```

### `znodeControl`
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

### `mint`
`create`:
```
    data: {
        denominations: {
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
       STRING (txid),
       STRING (txid),
       STRING (txid),
       ...
   },
    meta:{
       status: 200
    }
}
```

### `sendPrivate`
`create`:
```
    data: {
        address: STRING,
        denomination: [
            {
                value: INT,
                amount: INT
            },
            {
                value: INT,
                amount: INT
            }
        ],
        label: STRING
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
           STRING (txid),
           STRING (txid),
           STRING (txid),
           ...
       }
    }, 
    meta:{
        status: 200
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

### `sendZcoin`
`create`:
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
        feePerKb(sats): INT
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

### `stop`
`initial`:
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
        client: {
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
        daemon: {
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
        restartNow: false
    },
    meta:{
       status: 200
    }
}
```

`create`:
```
    data: {
        STRING (setting): {
            data: STRING,
            restartRequired: BOOL
        },
        STRING (setting): {
            data: STRING,
            restartRequired: BOOL
        },
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
        STRING (setting): {
            data: STRING, (OPTIONAL)
            restartRequired: (OPTIONAL) (VAR: program=="client")
        },
        STRING (setting): {
            data: STRING, (OPTIONAL)
            restartRequired: (OPTIONAL) (VAR: program=="client")
        },
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

`delete`:
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

# Publish
The publisher module is comprised of various _topics_ that are triggered under specific conditions, called _events_. Both topics and events have a 1 to N relationship with each other; ie. 1 event may trigger 1 to N topics, and 1 topic may be triggered by 1 to N events.


|               | _Event_         | updatedBlockTip  | syncUpdated | newTransaction | connectionsChanged |
| ------------- | ------------- | -------------    | ----------- | -------------- | ------------------ |
| **_Topic_**         | Description   | blockchain head updated | blockchain syncing update | new transaction detected | number of node connections changed                   
| **address**       | block tx data.|    ✅        |     -       |       -        |       -            |
| **block**         | general block data (sync status + header) | ✅  | ✅ | - | ✅  |
| **transaction**   | new transaction data | - | - | ✅ | - |
| **balance**       | Balance info  | ✅ | - | ✅ | - |
| **settings**       | settings changed  | TBD | TBD | TBD | TBD |