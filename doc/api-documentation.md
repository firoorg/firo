# Firo API and Component Documentation

This document provides comprehensive documentation for all public APIs, functions, and components in the Firo codebase.

## Table of Contents

1. [Overview](#overview)
2. [RPC API Reference](#rpc-api-reference)
   - [Blockchain RPCs](#blockchain-rpcs)
   - [Wallet RPCs](#wallet-rpcs)
   - [Network RPCs](#network-rpcs)
   - [Mining RPCs](#mining-rpcs)
   - [Masternode RPCs](#masternode-rpcs)
   - [Privacy RPCs](#privacy-rpcs)
   - [Mobile RPCs](#mobile-rpcs)
3. [Privacy Protocols](#privacy-protocols)
   - [Lelantus Protocol](#lelantus-protocol)
   - [Spark Protocol](#spark-protocol)
4. [LLMQ and ChainLocks](#llmq-and-chainlocks)
5. [Masternode System](#masternode-system)
6. [Core Components](#core-components)
7. [Examples](#examples)

---

## Overview

Firo is a privacy-focused cryptocurrency that utilizes the **Lelantus Spark protocol** for high anonymity without requiring trusted setup. The codebase includes:

- **Privacy Protocols**: Lelantus and Spark for anonymous transactions
- **LLMQ ChainLocks**: Protection against 51% attacks with quick finality
- **FiroPOW**: ProgPOW-based proof-of-work algorithm
- **Deterministic Masternodes**: For network services and governance

---

## RPC API Reference

### Blockchain RPCs

#### `getblockchaininfo`
Returns an object containing various state info regarding blockchain processing.

**Arguments:** None

**Result:**
```json
{
  "chain": "main",
  "blocks": 123456,
  "headers": 123456,
  "bestblockhash": "000000...",
  "difficulty": 12345.678,
  "mediantime": 1234567890,
  "verificationprogress": 0.99,
  "chainwork": "000000...",
  "pruned": false,
  "softforks": [...],
  "bip9_softforks": {...}
}
```

**Example:**
```bash
firo-cli getblockchaininfo
```

---

#### `getblockcount`
Returns the number of blocks in the longest blockchain.

**Arguments:** None

**Result:** `n` (numeric) - The current block count

**Example:**
```bash
firo-cli getblockcount
```

---

#### `getbestblockhash`
Returns the hash of the best (tip) block in the longest blockchain.

**Arguments:** None

**Result:** `"hex"` (string) - The block hash hex encoded

**Example:**
```bash
firo-cli getbestblockhash
```

---

#### `getblock "blockhash" [verbose]`
Returns block data for the given block hash.

**Arguments:**
1. `blockhash` (string, required) - The block hash
2. `verbose` (boolean, optional, default=true) - true for JSON object, false for hex data

**Result (verbose=true):**
```json
{
  "hash": "000000...",
  "confirmations": 123,
  "size": 1234,
  "height": 123456,
  "version": 4,
  "merkleroot": "abc123...",
  "tx": ["txid1", "txid2", ...],
  "time": 1234567890,
  "nonce": 12345,
  "bits": "1d00ffff",
  "difficulty": 12345.678,
  "chainlock": true
}
```

**Example:**
```bash
firo-cli getblock "00000000c937983704a73af28acdec37b049d214adbda81d7e2a3dd146f6ed09"
```

---

#### `getblockhash height`
Returns hash of block at given height.

**Arguments:**
1. `height` (numeric, required) - The height index

**Result:** `"hash"` (string) - The block hash

**Example:**
```bash
firo-cli getblockhash 1000
```

---

#### `getblockheader "hash" [verbose]`
Returns block header information.

**Arguments:**
1. `hash` (string, required) - The block hash
2. `verbose` (boolean, optional, default=true) - true for JSON, false for hex

**Result:**
```json
{
  "hash": "...",
  "confirmations": 123,
  "height": 123456,
  "version": 4,
  "merkleroot": "...",
  "time": 1234567890,
  "mediantime": 1234567880,
  "nonce": 12345,
  "bits": "1d00ffff",
  "difficulty": 12345.678,
  "chainwork": "...",
  "previousblockhash": "...",
  "nextblockhash": "...",
  "chainlock": true
}
```

---

#### `getdifficulty`
Returns the proof-of-work difficulty as a multiple of the minimum difficulty.

**Arguments:** None

**Result:** `n.nnn` (numeric) - The difficulty value

---

#### `getrawmempool [verbose]`
Returns all transaction ids in memory pool.

**Arguments:**
1. `verbose` (boolean, optional, default=false) - true for JSON object with details

**Result (verbose=false):**
```json
["txid1", "txid2", ...]
```

**Result (verbose=true):**
```json
{
  "txid": {
    "size": 1234,
    "fee": 0.0001,
    "time": 1234567890,
    "height": 123456,
    "depends": [...],
    "instantlock": true
  }
}
```

---

#### `gettxout "txid" n [include_mempool]`
Returns details about an unspent transaction output.

**Arguments:**
1. `txid` (string, required) - The transaction id
2. `n` (numeric, required) - vout number
3. `include_mempool` (boolean, optional) - Whether to include mempool

**Result:**
```json
{
  "bestblock": "...",
  "confirmations": 123,
  "value": 1.0,
  "scriptPubKey": {...},
  "coinbase": false
}
```

---

#### `gettxoutsetinfo`
Returns statistics about the unspent transaction output set.

**Arguments:** None

**Result:**
```json
{
  "height": 123456,
  "bestblock": "...",
  "transactions": 123456,
  "txouts": 234567,
  "hash_serialized_2": "...",
  "disk_size": 123456789,
  "total_amount": 12345678.0
}
```

---

#### `getchaintips`
Returns information about all known tips in the block tree.

**Arguments:** None

**Result:**
```json
[
  {
    "height": 123456,
    "hash": "...",
    "branchlen": 0,
    "status": "active"
  }
]
```

---

#### `getmempoolinfo`
Returns details on the active state of the TX memory pool.

**Arguments:** None

**Result:**
```json
{
  "size": 123,
  "bytes": 123456,
  "usage": 234567,
  "maxmempool": 300000000,
  "mempoolminfee": 0.00001,
  "instantsendlocks": 5
}
```

---

#### `verifychain [checklevel] [nblocks]`
Verifies blockchain database.

**Arguments:**
1. `checklevel` (numeric, optional, 0-4, default=3) - How thorough
2. `nblocks` (numeric, optional, default=6) - Number of blocks to check

**Result:** `true|false` (boolean)

---

### Spark Name RPCs

#### `getsparknamedata "sparkname"`
Returns information about a Spark name.

**Arguments:**
1. `sparkname` (string, required) - The Spark name

**Result:**
```json
{
  "address": "spark address",
  "validUntil": 123456,
  "additionalInfo": "optional info"
}
```

---

#### `getsparknames [onlyown]`
Returns a list of all Spark names.

**Arguments:**
1. `onlyown` (boolean, optional, default=false) - Only show wallet's names

**Result:**
```json
[
  {
    "name": "myname",
    "address": "spark1...",
    "validUntil": 123456
  }
]
```

---

### Wallet RPCs

#### `getnewaddress ["account"]`
Returns a new Firo address for receiving payments.

**Arguments:**
1. `account` (string, optional) - DEPRECATED. The account name

**Result:** `"firoaddress"` (string) - The new Firo address

**Example:**
```bash
firo-cli getnewaddress
firo-cli getnewaddress "myaccount"
```

---

#### `getbalance ["account"] [minconf] [include_watchonly]`
Returns the total available balance.

**Arguments:**
1. `account` (string, optional) - DEPRECATED
2. `minconf` (numeric, optional, default=1) - Minimum confirmations
3. `include_watchonly` (boolean, optional, default=false) - Include watch-only

**Result:** `n` (numeric) - Balance in FIRO

**Example:**
```bash
firo-cli getbalance
firo-cli getbalance "*" 6
```

---

#### `sendtoaddress "address" amount [comment] [comment_to] [subtractfeefromamount]`
Send an amount to a given address.

**Arguments:**
1. `address` (string, required) - The Firo address
2. `amount` (numeric, required) - Amount in FIRO
3. `comment` (string, optional) - Comment for reference
4. `comment_to` (string, optional) - Recipient comment
5. `subtractfeefromamount` (boolean, optional, default=false)

**Result:** `"txid"` (string) - The transaction id

**Example:**
```bash
firo-cli sendtoaddress "aXy123..." 0.1
firo-cli sendtoaddress "aXy123..." 0.1 "donation" "seans outance"
```

---

#### `listunspent [minconf] [maxconf] [addresses]`
Returns array of unspent transaction outputs.

**Arguments:**
1. `minconf` (numeric, optional, default=1) - Minimum confirmations
2. `maxconf` (numeric, optional, default=9999999) - Maximum confirmations
3. `addresses` (array, optional) - Filter by addresses

**Result:**
```json
[
  {
    "txid": "...",
    "vout": 0,
    "address": "...",
    "amount": 1.0,
    "confirmations": 123,
    "spendable": true,
    "solvable": true
  }
]
```

---

#### `gettransaction "txid" [include_watchonly]`
Get detailed information about an in-wallet transaction.

**Arguments:**
1. `txid` (string, required) - The transaction id
2. `include_watchonly` (boolean, optional, default=false)

**Result:**
```json
{
  "amount": 1.0,
  "fee": -0.0001,
  "confirmations": 123,
  "blockhash": "...",
  "txid": "...",
  "time": 1234567890,
  "details": [...],
  "hex": "..."
}
```

---

#### `listreceivedbyaddress [minconf] [include_empty] [include_watchonly]`
List balances by receiving address.

**Arguments:**
1. `minconf` (numeric, optional, default=1)
2. `include_empty` (boolean, optional, default=false)
3. `include_watchonly` (boolean, optional, default=false)

**Result:**
```json
[
  {
    "address": "...",
    "account": "",
    "amount": 1.0,
    "confirmations": 123
  }
]
```

---

#### `listtransactions ["account"] [count] [skip] [include_watchonly]`
Returns recent transactions for the wallet.

**Arguments:**
1. `account` (string, optional) - DEPRECATED
2. `count` (numeric, optional, default=10)
3. `skip` (numeric, optional, default=0)
4. `include_watchonly` (boolean, optional, default=false)

**Result:**
```json
[
  {
    "account": "",
    "address": "...",
    "category": "send|receive",
    "amount": 1.0,
    "confirmations": 123,
    "txid": "...",
    "time": 1234567890
  }
]
```

---

#### `walletpassphrase "passphrase" timeout`
Stores the wallet decryption key in memory for 'timeout' seconds.

**Arguments:**
1. `passphrase` (string, required) - The wallet passphrase
2. `timeout` (numeric, required) - Seconds to keep unlocked

**Example:**
```bash
firo-cli walletpassphrase "my pass phrase" 60
```

---

#### `walletlock`
Removes the wallet encryption key from memory, locking the wallet.

**Arguments:** None

**Example:**
```bash
firo-cli walletlock
```

---

#### `encryptwallet "passphrase"`
Encrypts the wallet with 'passphrase'.

**Arguments:**
1. `passphrase` (string, required) - The passphrase

**Example:**
```bash
firo-cli encryptwallet "my pass phrase"
```

---

#### `dumpprivkey "address"`
Reveals the private key corresponding to 'address'.

**Arguments:**
1. `address` (string, required) - The Firo address

**Result:** `"key"` (string) - The private key

---

#### `importprivkey "privkey" ["label"] [rescan]`
Adds a private key to your wallet.

**Arguments:**
1. `privkey` (string, required) - The private key
2. `label` (string, optional, default="")
3. `rescan` (boolean, optional, default=true)

---

#### `backupwallet "destination"`
Safely copies wallet.dat to destination.

**Arguments:**
1. `destination` (string, required) - Destination path/filename

---

### Network RPCs

#### `getnetworkinfo`
Returns information about P2P networking.

**Arguments:** None

**Result:**
```json
{
  "version": 140400,
  "subversion": "/Firo:0.14.4/",
  "protocolversion": 70214,
  "localservices": "000000000000000d",
  "localrelay": true,
  "timeoffset": 0,
  "networkactive": true,
  "connections": 8,
  "networks": [...],
  "relayfee": 0.00001,
  "localaddresses": [...]
}
```

---

#### `getpeerinfo`
Returns data about each connected network node.

**Arguments:** None

**Result:**
```json
[
  {
    "id": 1,
    "addr": "192.168.1.1:8168",
    "services": "000000000000000d",
    "lastsend": 1234567890,
    "lastrecv": 1234567890,
    "bytessent": 123456,
    "bytesrecv": 234567,
    "conntime": 1234567800,
    "version": 70214,
    "subver": "/Firo:0.14.4/",
    "inbound": false,
    "synced_headers": 123456,
    "synced_blocks": 123456
  }
]
```

---

#### `getconnectioncount`
Returns the number of connections to other nodes.

**Arguments:** None

**Result:** `n` (numeric) - The connection count

---

#### `addnode "node" "command"`
Attempts to add or remove a node from the addnode list.

**Arguments:**
1. `node` (string, required) - The node address
2. `command` (string, required) - "add", "remove", or "onetry"

**Example:**
```bash
firo-cli addnode "192.168.0.6:8168" "onetry"
```

---

#### `disconnectnode "address"`
Immediately disconnects from the specified node.

**Arguments:**
1. `address` (string, required) - The IP address/port

---

#### `ping`
Requests a ping to be sent to all other nodes.

**Arguments:** None

---

#### `setban "subnet" "command" [bantime] [absolute]`
Adds or removes an IP/Subnet from the banned list.

**Arguments:**
1. `subnet` (string, required) - IP/Subnet
2. `command` (string, required) - "add" or "remove"
3. `bantime` (numeric, optional) - Time in seconds
4. `absolute` (boolean, optional)

---

#### `listbanned`
List all banned IPs/Subnets.

**Arguments:** None

---

#### `clearbanned`
Clear all banned IPs.

**Arguments:** None

---

### Mining RPCs

#### `getmininginfo`
Returns mining-related information.

**Arguments:** None

**Result:**
```json
{
  "blocks": 123456,
  "currentblocksize": 1234,
  "currentblockweight": 4000,
  "currentblocktx": 5,
  "difficulty": 12345.678,
  "networkhashps": 123456789.0,
  "pooledtx": 10,
  "chain": "main"
}
```

---

#### `getnetworkhashps [nblocks] [height]`
Returns estimated network hashes per second.

**Arguments:**
1. `nblocks` (numeric, optional, default=120) - Blocks to average over
2. `height` (numeric, optional, default=-1) - Estimate at height

**Result:** `n` (numeric) - Hashes per second

---

#### `getblocktemplate [template_request]`
Returns data needed to construct a block for mining.

**Arguments:**
1. `template_request` (json object, optional) - BIP 22/23 compliant request

**Result:**
```json
{
  "version": 4,
  "previousblockhash": "...",
  "transactions": [...],
  "coinbaseaux": {...},
  "coinbasevalue": 625000000,
  "target": "...",
  "mintime": 1234567890,
  "mutable": ["time", "transactions", "prevblock"],
  "noncerange": "00000000ffffffff",
  "sigoplimit": 80000,
  "sizelimit": 1000000,
  "curtime": 1234567900,
  "bits": "1d00ffff",
  "height": 123457,
  "znode": [...],
  "znode_payments_started": true,
  "znode_payments_enforced": true
}
```

---

#### `submitblock "hexdata"`
Attempts to submit a new block to the network.

**Arguments:**
1. `hexdata` (string, required) - The hex-encoded block data

---

#### `generate nblocks [maxtries]`
Mine up to nblocks blocks immediately (regtest only).

**Arguments:**
1. `nblocks` (numeric, required) - Number of blocks
2. `maxtries` (numeric, optional, default=1000000)

**Result:** `[blockhashes]` (array) - Hashes of generated blocks

---

#### `generatetoaddress nblocks address [maxtries]`
Mine blocks immediately to a specified address.

**Arguments:**
1. `nblocks` (numeric, required)
2. `address` (string, required)
3. `maxtries` (numeric, optional, default=1000000)

---

#### `pprpcsb "header_hash" "mix_hash" "nonce"`
Submit a ProgPOW solution via RPC.

**Arguments:**
1. `header_hash` (string, required) - ProgPOW header hash
2. `mix_hash` (string, required) - Mix hash from GPU miner
3. `nonce` (string, required) - Block nonce

---

### Masternode RPCs

#### `evoznode list [mode] [filter]`
Get a list of masternodes in different modes.

**Arguments:**
1. `mode` (string, optional, default="json")
   - `addr` - IP addresses
   - `full` - Full info: status, payee, lastpaidtime, lastpaidblock, IP
   - `info` - Info: status, payee, IP
   - `json` - JSON format
   - `lastpaidblock` - Last block paid
   - `lastpaidtime` - Last time paid
   - `owneraddress` - Owner Firo address
   - `payee` - Payout address
   - `pubKeyOperator` - Operator public key
   - `status` - ENABLED/POSE_BANNED
   - `votingaddress` - Voting address
2. `filter` (string, optional) - Filter by outpoint

**Example:**
```bash
firo-cli evoznode list
firo-cli evoznode list json "aXy123"
```

---

#### `evoznode count [mode]`
Get information about number of masternodes.

**Arguments:**
1. `mode` (string, optional) - "total", "enabled", "all"

**Result (no mode):**
```json
{
  "total": 4000,
  "enabled": 3900
}
```

---

#### `evoznode status`
Print masternode status information (if running as masternode).

**Result:**
```json
{
  "outpoint": "txid:n",
  "service": "192.168.1.1:8168",
  "proTxHash": "...",
  "collateralHash": "...",
  "collateralIndex": 0,
  "dmnState": {...},
  "state": "READY",
  "status": "Ready"
}
```

---

#### `evoznode current`
Print info on current masternode winner.

**Result:**
```json
{
  "height": 123456,
  "IP:port": "192.168.1.1:8168",
  "proTxHash": "...",
  "outpoint": "txid:n",
  "payee": "aXy123..."
}
```

---

#### `evoznode winner`
Print info on next masternode winner to vote for.

---

#### `evoznode winners [count] [filter]`
Print list of masternode winners.

**Arguments:**
1. `count` (numeric, optional) - Number of winners
2. `filter` (string, optional) - Filter results

---

#### `evoznsync status`
Returns the masternode sync status.

**Result:**
```json
{
  "AssetID": 999,
  "AssetName": "MASTERNODE_SYNC_FINISHED",
  "AssetStartTime": 1234567890,
  "Attempt": 0,
  "IsBlockchainSynced": true,
  "IsSynced": true,
  "IsFailed": false
}
```

---

### Privacy RPCs - Lelantus

#### `mintlelantus amount`
Mint Lelantus coins from transparent balance.

**Arguments:**
1. `amount` (numeric, required) - Amount to mint in FIRO

**Result:** `"txid"` (string) - The transaction id

---

#### `joinsplit [recipients] [subtractfeefrom]`
Create a Lelantus JoinSplit transaction.

**Arguments:**
1. `recipients` (array, required) - Recipient addresses and amounts
2. `subtractfeefrom` (array, optional) - Indices to subtract fee from

**Example:**
```bash
firo-cli joinsplit "[{\"address\":\"aXy...\",\"amount\":1.0}]"
```

---

#### `listlelantusmints [all]`
List Lelantus mints in wallet.

**Arguments:**
1. `all` (boolean, optional, default=false) - Include used mints

---

#### `resetlelantusmint`
Reset Lelantus mint state for wallet recovery.

---

### Privacy RPCs - Spark

#### `mintspark [outputs]`
Create a Spark mint transaction.

**Arguments:**
1. `outputs` (array, required) - Array of {address, amount, memo}

**Example:**
```bash
firo-cli mintspark "[{\"address\":\"spark1...\",\"amount\":1.0,\"memo\":\"test\"}]"
```

---

#### `spendspark [recipients] [subtractfeefrom] [coincontrol]`
Create a Spark spend transaction.

**Arguments:**
1. `recipients` (array, required) - Recipient addresses and amounts
2. `subtractfeefrom` (array, optional)
3. `coincontrol` (object, optional) - Coin selection options

**Example:**
```bash
firo-cli spendspark "[{\"address\":\"spark1...\",\"amount\":0.5}]"
```

---

#### `getnewsparkaddress`
Generate a new Spark address.

**Result:** `"sparkaddress"` (string) - New Spark address

---

#### `getsparkbalance`
Get total Spark balance.

**Result:**
```json
{
  "availableBalance": 10.5,
  "unconfirmedBalance": 0.5,
  "totalBalance": 11.0
}
```

---

#### `listsparkmints [all]`
List Spark mints in wallet.

**Arguments:**
1. `all` (boolean, optional, default=false) - Include spent

---

#### `listsparkspends`
List Spark spends in wallet.

---

### Mobile RPCs

These RPCs are designed for mobile wallet support (requires `-mobile` flag).

#### `getanonymityset coinGroupId startBlockHash`
Returns Lelantus anonymity set data.

**Arguments:**
1. `coinGroupId` (int, required) - Coin group ID
2. `startBlockHash` (string, required) - Starting block hash (empty for full set)

**Result:**
```json
{
  "blockHash": "base64_encoded",
  "setHash": "base64_encoded",
  "coins": [[coin_data, txhash, tag_or_amount, txhash], ...]
}
```

---

#### `getsparkanonymityset coinGroupId startBlockHash`
Returns Spark anonymity set data.

**Arguments:**
1. `coinGroupId` (int, required) - Coin group ID
2. `startBlockHash` (string, required) - Starting block hash

**Result:**
```json
{
  "blockHash": "base64_encoded",
  "setHash": "base64_encoded",
  "coins": [[serialized_coin, txhash, serial_context], ...]
}
```

---

#### `getusedcoinserials startNumber`
Returns used Lelantus coin serials.

**Arguments:**
1. `startNumber` (int, required) - Starting offset

**Result:**
```json
{
  "serials": ["base64_serial", ...]
}
```

---

#### `getusedcoinstags startNumber`
Returns used Spark coin tags.

**Arguments:**
1. `startNumber` (int, required) - Starting offset

**Result:**
```json
{
  "tags": ["base64_tag", ...]
}
```

---

#### `getlatestcoinid`
Returns the latest Lelantus coin group ID.

**Result:** `n` (numeric) - Latest coin group ID

---

#### `getsparklatestcoinid`
Returns the latest Spark coin group ID.

**Result:** `n` (numeric) - Latest coin group ID

---

#### `getfeerate`
Returns the current minimum fee rate.

**Result:**
```json
{
  "rate": 1000
}
```

---

#### `getmempoolsparktxids`
Returns Spark transaction IDs in mempool.

**Result:** `["base64_txid", ...]`

---

#### `getmempoolsparktxs [txids]`
Returns Spark metadata for transactions.

**Arguments:**
1. `txids` (object, required) - Array of transaction IDs

**Result:**
```json
{
  "base64_txid": {
    "lTags": [...],
    "serial_context": [...],
    "coins": [...],
    "isLocked": true
  }
}
```

---

### Address Index RPCs

Requires `-addressindex` flag.

#### `getaddressbalance [addresses]`
Returns balance for addresses.

**Arguments:**
1. (object, required) - `{"addresses": ["addr1", "addr2"]}`

**Result:**
```json
{
  "balance": 10000000,
  "received": 20000000
}
```

---

#### `getaddressutxos [addresses]`
Returns UTXOs for addresses.

**Arguments:**
1. (object, required) - `{"addresses": ["addr1"]}`

**Result:**
```json
[
  {
    "address": "aXy...",
    "txid": "...",
    "outputIndex": 0,
    "script": "hex...",
    "satoshis": 10000000,
    "height": 123456
  }
]
```

---

#### `getaddresstxids [addresses]`
Returns transaction IDs for addresses.

**Arguments:**
1. (object, required) - `{"addresses": ["addr1"], "start": 0, "end": 100000}`

**Result:** `["txid1", "txid2", ...]`

---

#### `getaddressdeltas [addresses]`
Returns balance changes for addresses.

**Arguments:**
1. (object, required) - `{"addresses": ["addr1"], "start": 0, "end": 100000}`

**Result:**
```json
[
  {
    "satoshis": 10000000,
    "txid": "...",
    "index": 0,
    "blockindex": 1,
    "height": 123456,
    "address": "aXy..."
  }
]
```

---

#### `getaddressmempool [addresses]`
Returns mempool deltas for addresses.

**Arguments:**
1. (object, required) - `{"addresses": ["addr1"]}`

---

## Privacy Protocols

### Lelantus Protocol

Lelantus is a privacy protocol that provides anonymous transactions without trusted setup. It uses:

- **One-out-of-many proofs** for anonymity
- **Range proofs** to ensure valid amounts
- **Serial numbers** to prevent double-spending

#### Key Components

**PublicCoin** (`src/liblelantus/coin.h`)
```cpp
class PublicCoin {
    GroupElement value;       // Pedersen commitment
    // Getters
    const GroupElement& getValue() const;
    bool operator==(const PublicCoin& other) const;
};
```

**PrivateCoin** (`src/liblelantus/coin.h`)
```cpp
class PrivateCoin {
    const Params* params;
    PublicCoin publicCoin;
    Scalar serialNumber;      // Unique identifier
    Scalar randomness;        // Blinding factor
    uint64_t v;              // Value
    // Methods
    const Scalar& getSerialNumber() const;
    const Scalar& getRandomness() const;
    uint64_t getV() const;
};
```

**JoinSplit** (`src/liblelantus/joinsplit.h`)
- Combines multiple input coins
- Produces new output coins
- Proves spend authorization without revealing which coins are spent

```cpp
class JoinSplit {
    // Create a JoinSplit transaction
    JoinSplit(
        const Params* p,
        const std::vector<std::pair<PrivateCoin, uint32_t>>& Cin,
        const std::map<uint32_t, std::vector<PublicCoin>>& anonymity_sets,
        const Scalar& Vout,
        const std::vector<PrivateCoin>& Cout,
        uint64_t fee,
        const uint256& txHash
    );
    
    // Verify the JoinSplit
    bool Verify(
        const std::map<uint32_t, std::vector<PublicCoin>>& anonymity_sets,
        const std::vector<PublicCoin>& Cout,
        uint64_t Vout,
        const uint256& txHash
    ) const;
};
```

---

### Spark Protocol

Spark is Firo's latest privacy protocol with improved features:

- **Stealth addresses** for recipient privacy
- **Better scalability** than Lelantus
- **Flexible denominations**

#### Key Components

**SpendKey** (`src/libspark/keys.h`)
```cpp
class SpendKey {
    SpendKey(const Params* params);
    SpendKey(const Params* params, const Scalar& r_);
    
    const Scalar& get_s1() const;
    const Scalar& get_s2() const;
    const Scalar& get_r() const;
};
```

**FullViewKey** (`src/libspark/keys.h`)
```cpp
class FullViewKey {
    FullViewKey(const SpendKey& spend_key);
    
    const Scalar& get_s1() const;
    const Scalar& get_s2() const;
    const GroupElement& get_D() const;
    const GroupElement& get_P2() const;
};
```

**IncomingViewKey** (`src/libspark/keys.h`)
```cpp
class IncomingViewKey {
    IncomingViewKey(const FullViewKey& full_view_key);
    
    const Scalar& get_s1() const;
    const GroupElement& get_P2() const;
    uint64_t get_diversifier(const std::vector<unsigned char>& d) const;
};
```

**Address** (`src/libspark/keys.h`)
```cpp
class Address {
    Address(const IncomingViewKey& incoming_view_key, uint64_t i);
    
    std::string encode(unsigned char network) const;
    unsigned char decode(const std::string& str);
    
    const std::vector<unsigned char>& get_d() const;
    const GroupElement& get_Q1() const;
    const GroupElement& get_Q2() const;
};
```

**Coin** (`src/libspark/coin.h`)
```cpp
class Coin {
    GroupElement S;     // Serial commitment
    GroupElement K;     // Recovery key
    GroupElement C;     // Value commitment
    // Encrypted data
    std::vector<unsigned char> r_;
    
    // Methods for coin recovery and verification
};
```

**SpendTransaction** (`src/libspark/spend_transaction.h`)
```cpp
class SpendTransaction {
    SpendTransaction(
        const Params* params,
        const FullViewKey& full_view_key,
        const SpendKey& spend_key,
        const std::vector<InputCoinData>& inputs,
        const std::unordered_map<uint64_t, CoverSetData>& cover_set_data,
        const std::unordered_map<uint64_t, std::vector<Coin>>& cover_sets,
        uint64_t f,
        uint64_t vout,
        const std::vector<OutputCoinData>& outputs
    );
    
    uint64_t getFee();
    const std::vector<GroupElement>& getUsedLTags() const;
    const std::vector<Coin>& getOutCoins();
    
    static bool verify(
        const Params* params,
        const std::vector<SpendTransaction>& transactions,
        const std::unordered_map<uint64_t, std::vector<Coin>>& cover_sets
    );
};
```

#### Spark Address Format

Spark addresses use Bech32 encoding:
- **Mainnet prefix:** `sp`
- **Testnet prefix:** `st`

Example: `sp1qw508d6qejxtdg4y5r3zarvary0c5xw7k...`

---

## LLMQ and ChainLocks

### ChainLocks

ChainLocks provide instant finality and 51% attack protection.

**CChainLockSig** (`src/llmq/quorums_chainlocks.h`)
```cpp
class CChainLockSig {
    int32_t nHeight;      // Block height
    uint256 blockHash;    // Block hash
    CBLSSignature sig;    // BLS signature from quorum
};
```

**CChainLocksHandler** (`src/llmq/quorums_chainlocks.h`)
```cpp
class CChainLocksHandler {
    // Check if block has ChainLock
    bool HasChainLock(int nHeight, const uint256& blockHash);
    
    // Check for conflicting ChainLock
    bool HasConflictingChainLock(int nHeight, const uint256& blockHash);
    
    // Check if transaction is safe for mining
    bool IsTxSafeForMining(const uint256& txid);
    
    // Process new ChainLock
    void ProcessNewChainLock(NodeId from, const CChainLockSig& clsig, const uint256& hash);
};
```

### InstantSend

Provides instant transaction confirmation.

**CInstantSendLock** (`src/llmq/quorums_instantsend.h`)
```cpp
class CInstantSendLock {
    std::vector<COutPoint> inputs;
    uint256 txid;
    CBLSSignature sig;
};
```

**CInstantSendManager** (`src/llmq/quorums_instantsend.h`)
```cpp
class CInstantSendManager {
    // Check if transaction is locked
    bool IsLocked(const uint256& txHash);
    
    // Get InstantSend lock
    CInstantSendLockPtr GetConflictingLock(const CTransaction& tx);
};
```

---

## Masternode System

### Deterministic Masternodes

Masternodes provide network services and participate in governance.

**CDeterministicMN** (`src/evo/deterministicmns.h`)
```cpp
class CDeterministicMN {
    uint256 proTxHash;                    // ProRegTx hash
    COutPoint collateralOutpoint;         // Collateral outpoint
    uint16_t nOperatorReward;             // Operator reward share
    CDeterministicMNState* pdmnState;     // Current state
};
```

**CDeterministicMNState** (`src/evo/deterministicmns.h`)
```cpp
class CDeterministicMNState {
    int nRegisteredHeight;
    int nLastPaidHeight;
    int nPoSePenalty;
    int nPoSeRevivedHeight;
    int nPoSeBanHeight;
    uint16_t nRevocationReason;
    uint256 confirmedHash;
    CService addr;                        // IP address and port
    CKeyID keyIDOwner;
    CBLSPublicKey pubKeyOperator;
    CKeyID keyIDVoting;
    CScript scriptPayout;
    CScript scriptOperatorPayout;
};
```

### ProRegTx (Masternode Registration)

```cpp
class CProRegTx {
    uint16_t nVersion;
    uint16_t nType;
    uint16_t nMode;
    COutPoint collateralOutpoint;
    CService addr;
    CKeyID keyIDOwner;
    CBLSPublicKey pubKeyOperator;
    CKeyID keyIDVoting;
    uint16_t nOperatorReward;
    CScript scriptPayout;
    uint256 inputsHash;
    std::vector<unsigned char> vchSig;    // Owner signature
};
```

---

## Core Components

### Transaction Types

Firo supports multiple transaction types:

| Type | Value | Description |
|------|-------|-------------|
| `TRANSACTION_NORMAL` | 0 | Standard transaction |
| `TRANSACTION_PROVIDER_REGISTER` | 1 | Masternode registration |
| `TRANSACTION_PROVIDER_UPDATE_SERVICE` | 2 | Update masternode service |
| `TRANSACTION_PROVIDER_UPDATE_REGISTRAR` | 3 | Update masternode registrar |
| `TRANSACTION_PROVIDER_UPDATE_REVOKE` | 4 | Revoke masternode |
| `TRANSACTION_COINBASE` | 5 | Coinbase special transaction |
| `TRANSACTION_LELANTUS` | 8 | Lelantus transaction |
| `TRANSACTION_SPARK` | 9 | Spark transaction |

### CWallet

The wallet provides key management and transaction handling.

**Key Methods:**
```cpp
class CWallet {
    // Generate new key
    bool GetKeyFromPool(CPubKey& result);
    
    // Get balance
    CAmount GetBalance() const;
    CAmount GetUnconfirmedBalance() const;
    CAmount GetImmatureBalance() const;
    
    // Transactions
    bool CreateTransaction(const std::vector<CRecipient>& vecSend, CWalletTx& wtxNew, 
                          CReserveKey& reservekey, CAmount& nFeeRet, 
                          std::string& strFailReason, const CCoinControl* coinControl);
    bool CommitTransaction(CWalletTx& wtxNew, CReserveKey& reservekey, CConnman* connman);
    
    // Privacy operations
    bool MintAndStoreLelantus(CAmount nValue, std::vector<CLelantusMintMeta>& mints);
    bool JoinSplitLelantus(const std::vector<CRecipient>& vecSend, CWalletTx& wtxNew);
    
    // Spark operations
    std::pair<CAmount, CAmount> GetSparkBalance() const;
    bool CreateSparkMintTransactions(const std::vector<spark::MintedCoinData>& outputs, 
                                     std::vector<std::pair<CWalletTx, CAmount>>& wtxAndFee);
};
```

### Script Types

```cpp
enum txnouttype {
    TX_NONSTANDARD,           // Unrecognized script
    TX_PUBKEY,                // Pay to public key
    TX_PUBKEYHASH,           // Pay to public key hash (P2PKH)
    TX_SCRIPTHASH,           // Pay to script hash (P2SH)
    TX_MULTISIG,             // Multisignature
    TX_NULL_DATA,            // OP_RETURN
    TX_WITNESS_V0_SCRIPTHASH, // P2WSH
    TX_WITNESS_V0_KEYHASH,   // P2WPKH
    TX_ZEROCOINMINT,         // Zerocoin mint (deprecated)
    TX_LELANTUSMINT,         // Lelantus mint
    TX_LELANTUSJMINT,        // Lelantus JMint
    TX_SPARKMINT,            // Spark mint
    TX_SPARKSMINT,           // Spark SMint
};
```

---

## Examples

### Example 1: Basic Wallet Operations

```bash
# Create new address
firo-cli getnewaddress

# Check balance
firo-cli getbalance

# Send coins
firo-cli sendtoaddress "aXy123..." 1.0

# List transactions
firo-cli listtransactions
```

### Example 2: Spark Privacy Operations

```bash
# Generate Spark address
firo-cli getnewsparkaddress

# Mint to Spark (anonymize coins)
firo-cli mintspark "[{\"address\":\"spark1...\",\"amount\":10.0,\"memo\":\"savings\"}]"

# Check Spark balance
firo-cli getsparkbalance

# Send from Spark (private transaction)
firo-cli spendspark "[{\"address\":\"spark1...\",\"amount\":5.0}]"
```

### Example 3: Masternode Operations

```bash
# List all masternodes
firo-cli evoznode list

# Get masternode count
firo-cli evoznode count

# Check sync status
firo-cli evoznsync status

# Get current winner
firo-cli evoznode current
```

### Example 4: Mobile Wallet Integration

```python
import requests
import base64

# Get anonymity set for Spark
def get_spark_anonymity_set(coin_group_id, start_block_hash=""):
    result = rpc_call("getsparkanonymityset", [str(coin_group_id), start_block_hash])
    return {
        "blockHash": base64.b64decode(result["blockHash"]),
        "setHash": base64.b64decode(result["setHash"]),
        "coins": result["coins"]
    }

# Get used coin tags
def get_used_tags(start_number):
    result = rpc_call("getusedcoinstags", [str(start_number)])
    return [base64.b64decode(tag) for tag in result["tags"]]

# Check if transaction is locked
def get_mempool_spark_txs(txids):
    return rpc_call("getmempoolsparktxs", [{"txids": txids}])
```

### Example 5: Address Index Queries

```bash
# Get balance for address
firo-cli getaddressbalance '{"addresses": ["aXy123..."]}'

# Get UTXOs
firo-cli getaddressutxos '{"addresses": ["aXy123..."]}'

# Get transaction history
firo-cli getaddresstxids '{"addresses": ["aXy123..."], "start": 0, "end": 500000}'
```

### Example 6: Mining Pool Integration

```python
# Get block template
template = rpc_call("getblocktemplate", [{"rules": ["segwit"]}])

# For ProgPOW mining, use the pprpcheader
header_hash = template["pprpcheader"]
epoch = template["pprpcepoch"]

# Submit solution
result = rpc_call("pprpcsb", [header_hash, mix_hash, nonce])
```

---

## Error Codes

| Code | Name | Description |
|------|------|-------------|
| -1 | `RPC_MISC_ERROR` | General error |
| -3 | `RPC_TYPE_ERROR` | Invalid type |
| -4 | `RPC_WALLET_ERROR` | Wallet error |
| -5 | `RPC_INVALID_ADDRESS_OR_KEY` | Invalid address or key |
| -6 | `RPC_WALLET_INSUFFICIENT_FUNDS` | Insufficient funds |
| -8 | `RPC_INVALID_PARAMETER` | Invalid parameter |
| -12 | `RPC_WALLET_KEYPOOL_RAN_OUT` | Keypool exhausted |
| -13 | `RPC_WALLET_UNLOCK_NEEDED` | Wallet locked |
| -14 | `RPC_WALLET_PASSPHRASE_INCORRECT` | Wrong passphrase |
| -17 | `RPC_WALLET_ALREADY_UNLOCKED` | Already unlocked |
| -25 | `RPC_VERIFY_ERROR` | Verification failed |
| -26 | `RPC_VERIFY_REJECTED` | Transaction rejected |
| -27 | `RPC_VERIFY_ALREADY_IN_CHAIN` | Already in blockchain |

---

## Configuration Options

### Network Options

| Option | Default | Description |
|--------|---------|-------------|
| `-testnet` | false | Use testnet |
| `-regtest` | false | Use regtest |
| `-port=<port>` | 8168 | P2P port |
| `-rpcport=<port>` | 8888 | RPC port |
| `-maxconnections=<n>` | 125 | Maximum connections |

### Wallet Options

| Option | Default | Description |
|--------|---------|-------------|
| `-disablewallet` | false | Disable wallet |
| `-wallet=<file>` | wallet.dat | Wallet filename |
| `-rescan` | false | Rescan blockchain |
| `-zapwallettxes` | 0 | Clear wallet transactions |

### Privacy Options

| Option | Default | Description |
|--------|---------|-------------|
| `-enablelelantus` | true | Enable Lelantus |
| `-enablespark` | true | Enable Spark |

### Index Options

| Option | Default | Description |
|--------|---------|-------------|
| `-addressindex` | false | Enable address index |
| `-txindex` | false | Enable transaction index |
| `-timestampindex` | false | Enable timestamp index |
| `-spentindex` | false | Enable spent index |

### Mobile Support

| Option | Default | Description |
|--------|---------|-------------|
| `-mobile` | false | Enable mobile RPCs |

---

## See Also

- [Build Instructions](build-unix.md)
- [Developer Notes](developer-notes.md)
- [Release Notes](release-notes.md)
- [ZMQ Documentation](zmq.md)
