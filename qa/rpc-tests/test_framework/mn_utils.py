from .util import *

class Masternode(object):
    pass

def prepare_mn(node, idx, alias):
    mn = Masternode()
    mn.idx = idx
    mn.alias = alias
    mn.is_protx = True
    mn.p2p_port = p2p_port(mn.idx)
    blsKey = node.bls('generate')
    mn.fundsAddr = node.getnewaddress()
    mn.ownerAddr = node.getnewaddress()
    mn.operatorAddr = blsKey['public']
    mn.votingAddr = mn.ownerAddr
    mn.blsMnkey = blsKey['secret']
    return mn

def start_mn(testcase, mn):
    while len(testcase.nodes) <= mn.idx:
        testcase.nodes.append(None)
    if hasattr(testcase, 'extra_args') and len(testcase.extra_args) > mn.idx:
        extra_args = testcase.extra_args[mn.idx] + ['-znode=1', '-znodeblsprivkey=%s' % mn.blsMnkey]
    else:
        extra_args = ['-znode=1', '-znodeblsprivkey=%s' % mn.blsMnkey]
    n = start_node(mn.idx, testcase.options.tmpdir, extra_args, redirect_stderr=True)
    testcase.nodes[mn.idx] = n
    for i in range(0, testcase.num_nodes):
        if i < len(testcase.nodes) and testcase.nodes[i] is not None and i != mn.idx:
            connect_nodes_bi(testcase.nodes, mn.idx, i)
    mn.node = testcase.nodes[mn.idx]
    testcase.sync_all()
    testcase.force_finish_mnsync(mn.node)

def create_mn_collateral(node, mn):
    mn.collateral_address = node.getnewaddress()
    mn.collateral_txid = node.sendtoaddress(mn.collateral_address, 1000)
    mn.collateral_vout = -1
    node.generate(1)

    rawtx = node.getrawtransaction(mn.collateral_txid, 1)
    for txout in rawtx['vout']:
        if txout['value'] == Decimal(1000):
            mn.collateral_vout = txout['n']
            break
    assert(mn.collateral_vout != -1)

# register a protx MN and also fund it (using collateral inside ProRegTx)
def register_fund_mn(node, mn):
    node.sendtoaddress(mn.fundsAddr, 1000.001)
    mn.collateral_address = node.getnewaddress()
    mn.rewards_address = node.getnewaddress()

    mn.protx_hash = node.protx('register_fund', mn.collateral_address, '127.0.0.1:%d' % mn.p2p_port, mn.ownerAddr, mn.operatorAddr, mn.votingAddr, 0, mn.rewards_address, mn.fundsAddr)
    mn.collateral_txid = mn.protx_hash
    mn.collateral_vout = -1

    rawtx = node.getrawtransaction(mn.collateral_txid, 1)
    for txout in rawtx['vout']:
        if txout['value'] == Decimal(1000):
            mn.collateral_vout = txout['n']
            break
    assert(mn.collateral_vout != -1)

# create a protx MN which refers to an existing collateral
def register_mn(node, mn):
    node.sendtoaddress(mn.fundsAddr, 0.001)
    mn.rewards_address = node.getnewaddress()

    mn.protx_hash = node.protx('register', mn.collateral_txid, mn.collateral_vout, '127.0.0.1:%d' % mn.p2p_port, mn.ownerAddr, mn.operatorAddr, mn.votingAddr, 0, mn.rewards_address, mn.fundsAddr)
    node.generate(1)



