#!/usr/bin/env python3
# blocktools.py - utilities for manipulating blocks and transactions
# Copyright (c) 2015-2016 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.

from .mininode import *
from .script import CScript, OP_TRUE, OP_CHECKSIG, OP_RETURN

# Create a block (with regtest difficulty)
def create_block(hashprev, coinbase, nTime=None):
    block = CBlock()
    if nTime is None:
        import time
        block.nTime = int(time.time()+600)
    else:
        block.nTime = nTime
    block.hashPrevBlock = hashprev
    block.nBits = 0x207fffff # Will break after a difficulty adjustment...
    block.vtx.append(coinbase)
    block.hashMerkleRoot = block.calc_merkle_root()
    block.calc_sha256()
    return block

# From BIP141
WITNESS_COMMITMENT_HEADER = b"\xaa\x21\xa9\xed"

# According to BIP141, blocks with witness rules active must commit to the
# hash of all in-block transactions including witness.
def add_witness_commitment(block, nonce=0):
    # First calculate the merkle root of the block's
    # transactions, with witnesses.
    witness_nonce = nonce
    witness_root = block.calc_witness_merkle_root()
    witness_commitment = uint256_from_str(hash256(ser_uint256(witness_root)+ser_uint256(witness_nonce)))
    # witness_nonce should go to coinbase witness.
    block.vtx[0].wit.vtxinwit = [CTxInWitness()]
    block.vtx[0].wit.vtxinwit[0].scriptWitness.stack = [ser_uint256(witness_nonce)]

    # witness commitment is the last OP_RETURN output in coinbase
    output_data = WITNESS_COMMITMENT_HEADER + ser_uint256(witness_commitment)
    block.vtx[0].vout.append(CTxOut(0, CScript([OP_RETURN, output_data])))
    block.vtx[0].rehash()
    block.hashMerkleRoot = block.calc_merkle_root()
    block.rehash()


def serialize_script_num(value):
    r = bytearray(0)
    if value == 0:
        return r
    neg = value < 0
    absvalue = -value if neg else value
    while (absvalue):
        r.append(int(absvalue & 0xff))
        absvalue >>= 8
    if r[-1] & 0x80:
        r.append(0x80 if neg else 0)
    elif neg:
        r[-1] |= 0x80
    return r

def get_halvings(height):
    return int(height/1500)

# Create a coinbase transaction, assuming no miner fees.
# If pubkey is passed in, the coinbase output will be a P2PK output;
# otherwise an anyone-can-spend output.
def create_coinbase(height, pubkey = None, dip4_activated=False):
    coinbase = CTransaction()
    coinbase.vin.append(CTxIn(COutPoint(0, 0xffffffff), 
                ser_string(serialize_script_num(height)), 0xffffffff))
    coinbaseoutput = CTxOut()
    coinbaseoutput.nValue = 50 * COIN
    halvings = get_halvings(height)
    coinbaseoutput.nValue >>= halvings
    if (pubkey != None):
        coinbaseoutput.scriptPubKey = CScript([pubkey, OP_CHECKSIG])
    else:
        coinbaseoutput.scriptPubKey = CScript([OP_TRUE])
    coinbase.vout = fill_founders_rewards(coinbaseoutput, halvings)
    if dip4_activated:
        coinbase.nVersion = 3
        coinbase.nType = 5
        cbtx_payload = CCbTx(2, height, 0, 0)
        coinbase.vExtraPayload = cbtx_payload.serialize()
    coinbase.calc_sha256()
    return coinbase

def fill_founders_rewards(coinbaseOutput, halvings):
    founderReward = 1 * COIN >> halvings
    coinbaseOutput.nValue -= 7 * founderReward
    fr1 = CTxOut()
    fr1.scriptPubKey = CScript(bytes.fromhex('76a914296134d2415bf1f2b518b3f673816d7e603b160088ac'))
    fr1.nValue = founderReward
    fr2 = CTxOut()
    fr2.scriptPubKey = CScript(bytes.fromhex('76a914e1e1dc06a889c1b6d3eb00eef7a96f6a7cfb884888ac'))
    fr2.nValue = founderReward
    fr3 = CTxOut()
    fr3.scriptPubKey = CScript(bytes.fromhex('76a914ab03ecfddee6330497be894d16c29ae341c123aa88ac'))
    fr3.nValue = founderReward
    fr4 = CTxOut()
    fr4.scriptPubKey = CScript(bytes.fromhex('76a9144281a58a1d5b2d3285e00cb45a8492debbdad4c588ac'))
    fr4.nValue = 3 * founderReward
    fr5 = CTxOut()
    fr5.scriptPubKey = CScript(bytes.fromhex('76a9141fd264c0bb53bd9fef18e2248ddf1383d6e811ae88ac'))
    fr5.nValue = founderReward
    return [coinbaseOutput, fr1, fr2, fr3, fr4, fr5]

def get_founders_rewards(height):
    founderReward = float(1 * 1000 >> get_halvings(height)) / 1000
    return {
        'TDk19wPKYq91i18qmY6U9FeTdTxwPeSveo': founderReward,
        'TWZZcDGkNixTAMtRBqzZkkMHbq1G6vUTk5': founderReward,
        'TRZTFdNCKCKbLMQV8cZDkQN9Vwuuq4gDzT': founderReward,
        'TG2ruj59E5b1u9G3F7HQVs6pCcVDBxrQve': 3 * founderReward,
        'TCsTzQZKVn4fao8jDmB9zQBk9YQNEZ3XfS': founderReward,
    }

# Create a transaction.
# If the scriptPubKey is not specified, make it anyone-can-spend.
def create_transaction(prevtx, n, sig, value, scriptPubKey=CScript()):
    tx = CTransaction()
    assert(n < len(prevtx.vout))
    tx.vin.append(CTxIn(COutPoint(prevtx.sha256, n), sig, 0xffffffff))
    tx.vout.append(CTxOut(value, scriptPubKey))
    tx.calc_sha256()
    return tx

def get_legacy_sigopcount_block(block, fAccurate=True):
    count = 0
    for tx in block.vtx:
        count += get_legacy_sigopcount_tx(tx, fAccurate)
    return count

def get_legacy_sigopcount_tx(tx, fAccurate=True):
    count = 0
    for i in tx.vout:
        count += i.scriptPubKey.GetSigOpCount(fAccurate)
    for j in tx.vin:
        # scriptSig might be of type bytes, so convert to CScript for the moment
        count += CScript(j.scriptSig).GetSigOpCount(fAccurate)
    return count

def get_masternode_payment(nHeight, blockValue):
    if blockValue >= 28 / COIN:
        return 15 * COIN
    if blockValue >= 14 / COIN:
        return 7.5 * COIN
