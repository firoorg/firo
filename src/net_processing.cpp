// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "net_processing.h"

#include "addrman.h"
#include "arith_uint256.h"
#include "blockencodings.h"
#include "chainparams.h"
#include "consensus/validation.h"
#include "hash.h"
#include "init.h"
#include "validation.h"
#include "merkleblock.h"
#include "net.h"
#include "netmessagemaker.h"
#include "netbase.h"
#include "policy/fees.h"
#include "policy/policy.h"
#include "primitives/block.h"
#include "primitives/transaction.h"
#include "random.h"
#include "tinyformat.h"
#include "txmempool.h"
#include "ui_interface.h"
#include "util.h"
#include "utilmoneystr.h"
#include "utilstrencodings.h"
#include "validationinterface.h"

#include "masternode-payments.h"
#include "masternode-sync.h"

#include "evo/deterministicmns.h"
#include "evo/mnauth.h"
#include "evo/simplifiedmns.h"
#include "llmq/quorums_blockprocessor.h"
#include "llmq/quorums_commitment.h"
#include "llmq/quorums_chainlocks.h"
#include "llmq/quorums_dkgsessionmgr.h"
#include "llmq/quorums_init.h"
#include "llmq/quorums_instantsend.h"
#include "llmq/quorums_signing.h"
#include "llmq/quorums_signing_shares.h"

#include <boost/thread.hpp>

#if defined(NDEBUG)
# error "Bitcoin cannot be compiled without assertions."
#endif

std::atomic<int64_t> nTimeBestReceived(0); // Used only to inform the wallet of when we last received a block

struct IteratorComparator
{
    template<typename I>
    bool operator()(const I& a, const I& b) const
    {
        return &(*a) < &(*b);
    }
};

struct COrphanTx {
    // When modifying, adapt the copy of this definition in tests/DoS_tests.
    CTransactionRef tx;
    NodeId fromPeer;
    int64_t nTimeExpire;
};
std::map<uint256, COrphanTx> mapOrphanTransactions GUARDED_BY(cs_main);
std::map<COutPoint, std::set<std::map<uint256, COrphanTx>::iterator, IteratorComparator>> mapOrphanTransactionsByPrev GUARDED_BY(cs_main);
void EraseOrphansFor(NodeId peer) EXCLUSIVE_LOCKS_REQUIRED(cs_main);

static size_t vExtraTxnForCompactIt = 0;
static std::vector<std::pair<uint256, CTransactionRef>> vExtraTxnForCompact GUARDED_BY(cs_main);

static const uint64_t RANDOMIZER_ID_ADDRESS_RELAY = 0x3cac0035b5866b90ULL; // SHA256("main address relay")[0:8]

// Internal stuff
namespace {
    /** Number of nodes with fSyncStarted. */
    int nSyncStarted = 0;

    /**
     * Sources of received blocks, saved to be able to send them reject
     * messages or ban them when processing happens afterwards. Protected by
     * cs_main.
     * Set mapBlockSource[hash].second to false if the node should not be
     * punished if the block is invalid.
     */
    std::map<uint256, std::pair<NodeId, bool>> mapBlockSource;

    /**
     * Filter for transactions that were recently rejected by
     * AcceptToMemoryPool. These are not rerequested until the chain tip
     * changes, at which point the entire filter is reset. Protected by
     * cs_main.
     *
     * Without this filter we'd be re-requesting txs from each of our peers,
     * increasing bandwidth consumption considerably. For instance, with 100
     * peers, half of which relay a tx we don't accept, that might be a 50x
     * bandwidth increase. A flooding attacker attempting to roll-over the
     * filter using minimum-sized, 60byte, transactions might manage to send
     * 1000/sec if we have fast peers, so we pick 120,000 to give our peers a
     * two minute window to send invs to us.
     *
     * Decreasing the false positive rate is fairly cheap, so we pick one in a
     * million to make it highly unlikely for users to have issues with this
     * filter.
     *
     * Memory used: 1.3 MB
     */
    std::unique_ptr<CRollingBloomFilter> recentRejects;
    uint256 hashRecentRejectsChainTip;

    /** Blocks that are in flight, and that are in the queue to be downloaded. Protected by cs_main. */
    struct QueuedBlock {
        uint256 hash;
        const CBlockIndex* pindex;                               //!< Optional.
        bool fValidatedHeaders;                                  //!< Whether this block has validated headers at the time of request.
        std::unique_ptr<PartiallyDownloadedBlock> partialBlock;  //!< Optional, used for CMPCTBLOCK downloads
    };
    std::map<uint256, std::pair<NodeId, std::list<QueuedBlock>::iterator> > mapBlocksInFlight;

    /** Stack of nodes which we have set to announce using compact blocks */
    std::list<NodeId> lNodesAnnouncingHeaderAndIDs;

    /** Number of preferable block download peers. */
    int nPreferredDownload = 0;

    /** Number of peers from which we're downloading blocks. */
    int nPeersWithValidatedDownloads = 0;

    /** Relay map, protected by cs_main. */
    typedef std::map<uint256, CTransactionRef> MapRelay;
    MapRelay mapRelay;
    /** Expiration-time ordered list of (expire time, relay map entry) pairs, protected by cs_main). */
    std::deque<std::pair<int64_t, MapRelay::iterator>> vRelayExpiration;
} // anon namespace

//////////////////////////////////////////////////////////////////////////////
//
// Registration of network node signals.
//

namespace {

struct CBlockReject {
    unsigned char chRejectCode;
    std::string strRejectReason;
    uint256 hashBlock;
};

/**
 * Maintain validation-specific state about nodes, protected by cs_main, instead
 * by CNode's own locks. This simplifies asynchronous operation, where
 * processing of incoming data is done after the ProcessMessage call returns,
 * and we're no longer holding the node's locks.
 */
struct CNodeState {
    //! The peer's address
    const CService address;
    //! Whether we have a fully established connection.
    bool fCurrentlyConnected;
    //! Accumulated misbehaviour score for this peer.
    int nMisbehavior;
    //! Whether this peer should be disconnected and banned (unless whitelisted).
    bool fShouldBan;
    //! String name of this peer (debugging/logging purposes).
    const std::string name;
    //! List of asynchronously-determined block rejections to notify this peer about.
    std::vector<CBlockReject> rejects;
    //! The best known block we know this peer has announced.
    const CBlockIndex *pindexBestKnownBlock;
    //! The hash of the last unknown block this peer has announced.
    uint256 hashLastUnknownBlock;
    //! The last full block we both have.
    const CBlockIndex *pindexLastCommonBlock;
    //! The best header we have sent our peer.
    const CBlockIndex *pindexBestHeaderSent;
    //! Length of current-streak of unconnecting headers announcements
    int nUnconnectingHeaders;
    //! Whether we've started headers synchronization with this peer.
    bool fSyncStarted;
    //! Since when we're stalling block download progress (in microseconds), or 0.
    int64_t nStallingSince;
    std::list<QueuedBlock> vBlocksInFlight;
    //! When the first entry in vBlocksInFlight started downloading. Don't care when vBlocksInFlight is empty.
    int64_t nDownloadingSince;
    int nBlocksInFlight;
    int nBlocksInFlightValidHeaders;
    //! Whether we consider this a preferred download peer.
    bool fPreferredDownload;
    //! Whether this peer wants invs or headers (when possible) for block announcements.
    bool fPreferHeaders;
    //! Whether this peer wants invs or cmpctblocks (when possible) for block announcements.
    bool fPreferHeaderAndIDs;
    /**
      * Whether this peer will send us cmpctblocks if we request them.
      * This is not used to gate request logic, as we really only care about fSupportsDesiredCmpctVersion,
      * but is used as a flag to "lock in" the version of compact blocks (fWantsCmpctWitness) we send.
      */
    bool fProvidesHeaderAndIDs;
    //! Whether this peer can give us witnesses
    bool fHaveWitness;
    //! Whether this peer wants witnesses in cmpctblocks/blocktxns
    bool fWantsCmpctWitness;
    /**
     * If we've announced NODE_WITNESS to this peer: whether the peer sends witnesses in cmpctblocks/blocktxns,
     * otherwise: whether this peer sends non-witnesses in cmpctblocks/blocktxns.
     */
    bool fSupportsDesiredCmpctVersion;

    CNodeState(CAddress addrIn, std::string addrNameIn) : address(addrIn), name(addrNameIn) {
        fCurrentlyConnected = false;
        nMisbehavior = 0;
        fShouldBan = false;
        pindexBestKnownBlock = NULL;
        hashLastUnknownBlock.SetNull();
        pindexLastCommonBlock = NULL;
        pindexBestHeaderSent = NULL;
        nUnconnectingHeaders = 0;
        fSyncStarted = false;
        nStallingSince = 0;
        nDownloadingSince = 0;
        nBlocksInFlight = 0;
        nBlocksInFlightValidHeaders = 0;
        fPreferredDownload = false;
        fPreferHeaders = false;
        fPreferHeaderAndIDs = false;
        fProvidesHeaderAndIDs = false;
        fHaveWitness = false;
        fWantsCmpctWitness = false;
        fSupportsDesiredCmpctVersion = false;
    }
};

/** Map maintaining per-node state. Requires cs_main. */
std::map<NodeId, CNodeState> mapNodeState;

// Requires cs_main.
CNodeState *State(NodeId pnode) {
    std::map<NodeId, CNodeState>::iterator it = mapNodeState.find(pnode);
    if (it == mapNodeState.end())
        return NULL;
    return &it->second;
}

void UpdatePreferredDownload(CNode* node, CNodeState* state)
{
    nPreferredDownload -= state->fPreferredDownload;

    // Whether this node should be marked as a preferred download node.
    state->fPreferredDownload = (!node->fInbound || node->fWhitelisted) && !node->fOneShot && !node->fClient;

    nPreferredDownload += state->fPreferredDownload;
}

void PushNodeVersion(CNode *pnode, CConnman& connman, int64_t nTime)
{
    ServiceFlags nLocalNodeServices = pnode->GetLocalServices();
    uint64_t nonce = pnode->GetLocalNonce();
    int nNodeStartingHeight = pnode->GetMyStartingHeight();
    NodeId nodeid = pnode->GetId();
    CAddress addr = pnode->addr;

    CAddress addrYou = (addr.IsRoutable() && !IsProxy(addr) ? addr : CAddress(CService(), addr.nServices));
    CAddress addrMe = CAddress(CService(), nLocalNodeServices);

    uint256 mnauthChallenge;
    GetRandBytes(mnauthChallenge.begin(), mnauthChallenge.size());
    {
        LOCK(pnode->cs_mnauth);
        pnode->sentMNAuthChallenge = mnauthChallenge;
    }

    connman.PushMessage(pnode, CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::VERSION, PROTOCOL_VERSION, (uint64_t)nLocalNodeServices, nTime, addrYou, addrMe,
            nonce, strSubVersion, nNodeStartingHeight, ::fRelayTxes, mnauthChallenge));

    if (fLogIPs)
        LogPrint("net", "send version message: version %d, blocks=%d, us=%s, them=%s, peer=%d\n", PROTOCOL_VERSION, nNodeStartingHeight, addrMe.ToString(), addrYou.ToString(), nodeid);
    else
        LogPrint("net", "send version message: version %d, blocks=%d, us=%s, peer=%d\n", PROTOCOL_VERSION, nNodeStartingHeight, addrMe.ToString(), nodeid);
}

void InitializeNode(CNode *pnode, CConnman& connman) {
    CAddress addr = pnode->addr;
    std::string addrName = pnode->GetAddrName();
    NodeId nodeid = pnode->GetId();
    {
        LOCK(cs_main);
        mapNodeState.emplace_hint(mapNodeState.end(), std::piecewise_construct, std::forward_as_tuple(nodeid), std::forward_as_tuple(addr, std::move(addrName)));
    }
    if(!pnode->fInbound)
        PushNodeVersion(pnode, connman, GetTime());
}

void FinalizeNode(NodeId nodeid, bool& fUpdateConnectionTime) {
    fUpdateConnectionTime = false;
    LOCK(cs_main);
    CNodeState *state = State(nodeid);

    if (state->fSyncStarted)
        nSyncStarted--;

    if (state->nMisbehavior == 0 && state->fCurrentlyConnected) {
        fUpdateConnectionTime = true;
    }

    BOOST_FOREACH(const QueuedBlock& entry, state->vBlocksInFlight) {
        mapBlocksInFlight.erase(entry.hash);
    }
    EraseOrphansFor(nodeid);
    nPreferredDownload -= state->fPreferredDownload;
    nPeersWithValidatedDownloads -= (state->nBlocksInFlightValidHeaders != 0);
    assert(nPeersWithValidatedDownloads >= 0);

    mapNodeState.erase(nodeid);

    if (mapNodeState.empty()) {
        // Do a consistency check after the last peer is removed.
        assert(mapBlocksInFlight.empty());
        assert(nPreferredDownload == 0);
        assert(nPeersWithValidatedDownloads == 0);
    }
}

// Requires cs_main.
// Returns a bool indicating whether we requested this block.
// Also used if a block was /not/ received and timed out or started with another peer
bool MarkBlockAsReceived(const uint256& hash) {
    std::map<uint256, std::pair<NodeId, std::list<QueuedBlock>::iterator> >::iterator itInFlight = mapBlocksInFlight.find(hash);
    if (itInFlight != mapBlocksInFlight.end()) {
        CNodeState *state = State(itInFlight->second.first);
        state->nBlocksInFlightValidHeaders -= itInFlight->second.second->fValidatedHeaders;
        if (state->nBlocksInFlightValidHeaders == 0 && itInFlight->second.second->fValidatedHeaders) {
            // Last validated block on the queue was received.
            nPeersWithValidatedDownloads--;
        }
        if (state->vBlocksInFlight.begin() == itInFlight->second.second) {
            // First block on the queue was received, update the start download time for the next one
            state->nDownloadingSince = std::max(state->nDownloadingSince, GetTimeMicros());
        }
        state->vBlocksInFlight.erase(itInFlight->second.second);
        state->nBlocksInFlight--;
        state->nStallingSince = 0;
        mapBlocksInFlight.erase(itInFlight);
        return true;
    }
    return false;
}

// Requires cs_main.
// returns false, still setting pit, if the block was already in flight from the same peer
// pit will only be valid as long as the same cs_main lock is being held
bool MarkBlockAsInFlight(NodeId nodeid, const uint256& hash, const Consensus::Params& consensusParams, const CBlockIndex* pindex = NULL, std::list<QueuedBlock>::iterator** pit = NULL) {
    CNodeState *state = State(nodeid);
    assert(state != NULL);

    // Short-circuit most stuff in case its from the same node
    std::map<uint256, std::pair<NodeId, std::list<QueuedBlock>::iterator> >::iterator itInFlight = mapBlocksInFlight.find(hash);
    if (itInFlight != mapBlocksInFlight.end() && itInFlight->second.first == nodeid) {
        *pit = &itInFlight->second.second;
        return false;
    }

    // Make sure it's not listed somewhere already.
    MarkBlockAsReceived(hash);

    std::list<QueuedBlock>::iterator it = state->vBlocksInFlight.insert(state->vBlocksInFlight.end(),
            {hash, pindex, pindex != NULL, std::unique_ptr<PartiallyDownloadedBlock>(pit ? new PartiallyDownloadedBlock(&mempool) : NULL)});
    state->nBlocksInFlight++;
    state->nBlocksInFlightValidHeaders += it->fValidatedHeaders;
    if (state->nBlocksInFlight == 1) {
        // We're starting a block download (batch) from this peer.
        state->nDownloadingSince = GetTimeMicros();
    }
    if (state->nBlocksInFlightValidHeaders == 1 && pindex != NULL) {
        nPeersWithValidatedDownloads++;
    }
    itInFlight = mapBlocksInFlight.insert(std::make_pair(hash, std::make_pair(nodeid, it))).first;
    if (pit)
        *pit = &itInFlight->second.second;
    return true;
}

/** Check whether the last unknown block a peer advertised is not yet known. */
void ProcessBlockAvailability(NodeId nodeid) {
    CNodeState *state = State(nodeid);
    assert(state != NULL);

    if (!state->hashLastUnknownBlock.IsNull()) {
        BlockMap::iterator itOld = mapBlockIndex.find(state->hashLastUnknownBlock);
        if (itOld != mapBlockIndex.end() && itOld->second->nChainWork > 0) {
            if (state->pindexBestKnownBlock == NULL || itOld->second->nChainWork >= state->pindexBestKnownBlock->nChainWork)
                state->pindexBestKnownBlock = itOld->second;
            state->hashLastUnknownBlock.SetNull();
        }
    }
}

/** Update tracking information about which blocks a peer is assumed to have. */
void UpdateBlockAvailability(NodeId nodeid, const uint256 &hash) {
    CNodeState *state = State(nodeid);
    assert(state != NULL);

    ProcessBlockAvailability(nodeid);

    BlockMap::iterator it = mapBlockIndex.find(hash);
    if (it != mapBlockIndex.end() && it->second->nChainWork > 0) {
        // An actually better block was announced.
        if (state->pindexBestKnownBlock == NULL || it->second->nChainWork >= state->pindexBestKnownBlock->nChainWork)
            state->pindexBestKnownBlock = it->second;
    } else {
        // An unknown block was announced; just assume that the latest one is the best one.
        state->hashLastUnknownBlock = hash;
    }
}

void MaybeSetPeerAsAnnouncingHeaderAndIDs(NodeId nodeid, CConnman& connman) {
    AssertLockHeld(cs_main);
    CNodeState* nodestate = State(nodeid);
    if (!nodestate || !nodestate->fSupportsDesiredCmpctVersion) {
        // Never ask from peers who can't provide witnesses.
        return;
    }
    if (nodestate->fProvidesHeaderAndIDs) {
        for (std::list<NodeId>::iterator it = lNodesAnnouncingHeaderAndIDs.begin(); it != lNodesAnnouncingHeaderAndIDs.end(); it++) {
            if (*it == nodeid) {
                lNodesAnnouncingHeaderAndIDs.erase(it);
                lNodesAnnouncingHeaderAndIDs.push_back(nodeid);
                return;
            }
        }
        connman.ForNode(nodeid, [&connman](CNode* pfrom){
            bool fAnnounceUsingCMPCTBLOCK = false;
            uint64_t nCMPCTBLOCKVersion = (pfrom->GetLocalServices() & NODE_WITNESS) ? 2 : 1;
            if (lNodesAnnouncingHeaderAndIDs.size() >= 3) {
                // As per BIP152, we only get 3 of our peers to announce
                // blocks using compact encodings.
                connman.ForNode(lNodesAnnouncingHeaderAndIDs.front(), [&connman, fAnnounceUsingCMPCTBLOCK, nCMPCTBLOCKVersion](CNode* pnodeStop){
                    connman.PushMessage(pnodeStop, CNetMsgMaker(pnodeStop->GetSendVersion()).Make(NetMsgType::SENDCMPCT, fAnnounceUsingCMPCTBLOCK, nCMPCTBLOCKVersion));
                    return true;
                });
                lNodesAnnouncingHeaderAndIDs.pop_front();
            }
            fAnnounceUsingCMPCTBLOCK = true;
            connman.PushMessage(pfrom, CNetMsgMaker(pfrom->GetSendVersion()).Make(NetMsgType::SENDCMPCT, fAnnounceUsingCMPCTBLOCK, nCMPCTBLOCKVersion));
            lNodesAnnouncingHeaderAndIDs.push_back(pfrom->GetId());
            return true;
        });
    }
}

// Requires cs_main
bool CanDirectFetch(const Consensus::Params &consensusParams)
{
    return chainActive.Tip()->GetBlockTime() > GetAdjustedTime() - consensusParams.nPowTargetSpacing * 20;
}

// Requires cs_main
bool PeerHasHeader(CNodeState *state, const CBlockIndex *pindex)
{
    if (state->pindexBestKnownBlock && pindex == state->pindexBestKnownBlock->GetAncestor(pindex->nHeight))
        return true;
    if (state->pindexBestHeaderSent && pindex == state->pindexBestHeaderSent->GetAncestor(pindex->nHeight))
        return true;
    return false;
}

/** Find the last common ancestor two blocks have.
 *  Both pa and pb must be non-NULL. */
const CBlockIndex* LastCommonAncestor(const CBlockIndex* pa, const CBlockIndex* pb) {
    if (pa->nHeight > pb->nHeight) {
        pa = pa->GetAncestor(pb->nHeight);
    } else if (pb->nHeight > pa->nHeight) {
        pb = pb->GetAncestor(pa->nHeight);
    }

    while (pa != pb && pa && pb) {
        pa = pa->pprev;
        pb = pb->pprev;
    }

    // Eventually all chain branches meet at the genesis block.
    assert(pa == pb);
    return pa;
}

/** Update pindexLastCommonBlock and add not-in-flight missing successors to vBlocks, until it has
 *  at most count entries. */
void FindNextBlocksToDownload(NodeId nodeid, unsigned int count, std::vector<const CBlockIndex*>& vBlocks, NodeId& nodeStaller, const Consensus::Params& consensusParams) {
    if (count == 0)
        return;

    vBlocks.reserve(vBlocks.size() + count);
    CNodeState *state = State(nodeid);
    assert(state != NULL);

    // Make sure pindexBestKnownBlock is up to date, we'll need it.
    ProcessBlockAvailability(nodeid);

    if (state->pindexBestKnownBlock == NULL || state->pindexBestKnownBlock->nChainWork < chainActive.Tip()->nChainWork) {
        // This peer has nothing interesting.
        return;
    }

    if (state->pindexLastCommonBlock == NULL) {
        // Bootstrap quickly by guessing a parent of our best tip is the forking point.
        // Guessing wrong in either direction is not a problem.
        state->pindexLastCommonBlock = chainActive[std::min(state->pindexBestKnownBlock->nHeight, chainActive.Height())];
    }

    // If the peer reorganized, our previous pindexLastCommonBlock may not be an ancestor
    // of its current tip anymore. Go back enough to fix that.
    state->pindexLastCommonBlock = LastCommonAncestor(state->pindexLastCommonBlock, state->pindexBestKnownBlock);
    if (state->pindexLastCommonBlock == state->pindexBestKnownBlock)
        return;

    std::vector<const CBlockIndex*> vToFetch;
    const CBlockIndex *pindexWalk = state->pindexLastCommonBlock;
    // Never fetch further than the best block we know the peer has, or more than BLOCK_DOWNLOAD_WINDOW + 1 beyond the last
    // linked block we have in common with this peer. The +1 is so we can detect stalling, namely if we would be able to
    // download that next block if the window were 1 larger.
    int nWindowEnd = state->pindexLastCommonBlock->nHeight + BLOCK_DOWNLOAD_WINDOW;
    int nMaxHeight = std::min<int>(state->pindexBestKnownBlock->nHeight, nWindowEnd + 1);
    NodeId waitingfor = -1;
    while (pindexWalk->nHeight < nMaxHeight) {
        // Read up to 128 (or more, if more blocks than that are needed) successors of pindexWalk (towards
        // pindexBestKnownBlock) into vToFetch. We fetch 128, because CBlockIndex::GetAncestor may be as expensive
        // as iterating over ~100 CBlockIndex* entries anyway.
        int nToFetch = std::min(nMaxHeight - pindexWalk->nHeight, std::max<int>(count - vBlocks.size(), 128));
        vToFetch.resize(nToFetch);
        pindexWalk = state->pindexBestKnownBlock->GetAncestor(pindexWalk->nHeight + nToFetch);
        vToFetch[nToFetch - 1] = pindexWalk;
        for (unsigned int i = nToFetch - 1; i > 0; i--) {
            vToFetch[i - 1] = vToFetch[i]->pprev;
        }

        // Iterate over those blocks in vToFetch (in forward direction), adding the ones that
        // are not yet downloaded and not in flight to vBlocks. In the mean time, update
        // pindexLastCommonBlock as long as all ancestors are already downloaded, or if it's
        // already part of our chain (and therefore don't need it even if pruned).
        BOOST_FOREACH(const CBlockIndex* pindex, vToFetch) {
            if (!pindex->IsValid(BLOCK_VALID_TREE)) {
                // We consider the chain that this peer is on invalid.
                return;
            }
            if (!State(nodeid)->fHaveWitness && IsWitnessEnabled(pindex->pprev, consensusParams)) {
                // We wouldn't download this block or its descendants from this peer.
                return;
            }
            if (pindex->nStatus & BLOCK_HAVE_DATA || chainActive.Contains(pindex)) {
                if (pindex->nChainTx)
                    state->pindexLastCommonBlock = pindex;
            } else if (mapBlocksInFlight.count(pindex->GetBlockHash()) == 0) {
                // The block is not already downloaded, and not yet in flight.
                if (pindex->nHeight > nWindowEnd) {
                    // We reached the end of the window.
                    if (vBlocks.size() == 0 && waitingfor != nodeid) {
                        // We aren't able to fetch anything, but we would be if the download window was one larger.
                        nodeStaller = waitingfor;
                    }
                    return;
                }
                vBlocks.push_back(pindex);
                if (vBlocks.size() == count) {
                    return;
                }
            } else if (waitingfor == -1) {
                // This is the first already-in-flight block.
                waitingfor = mapBlocksInFlight[pindex->GetBlockHash()].first;
            }
        }
    }
}

} // anon namespace

bool GetNodeStateStats(NodeId nodeid, CNodeStateStats &stats) {
    LOCK(cs_main);
    CNodeState *state = State(nodeid);
    if (state == NULL)
        return false;
    stats.nMisbehavior = state->nMisbehavior;
    stats.nSyncHeight = state->pindexBestKnownBlock ? state->pindexBestKnownBlock->nHeight : -1;
    stats.nCommonHeight = state->pindexLastCommonBlock ? state->pindexLastCommonBlock->nHeight : -1;
    BOOST_FOREACH(const QueuedBlock& queue, state->vBlocksInFlight) {
        if (queue.pindex)
            stats.vHeightInFlight.push_back(queue.pindex->nHeight);
    }
    return true;
}

void RegisterNodeSignals(CNodeSignals& nodeSignals)
{
    nodeSignals.ProcessMessages.connect(&ProcessMessages);
    nodeSignals.SendMessages.connect(&SendMessages);
    nodeSignals.InitializeNode.connect(&InitializeNode);
    nodeSignals.FinalizeNode.connect(&FinalizeNode);
}

void UnregisterNodeSignals(CNodeSignals& nodeSignals)
{
    nodeSignals.ProcessMessages.disconnect(&ProcessMessages);
    nodeSignals.SendMessages.disconnect(&SendMessages);
    nodeSignals.InitializeNode.disconnect(&InitializeNode);
    nodeSignals.FinalizeNode.disconnect(&FinalizeNode);
}

//////////////////////////////////////////////////////////////////////////////
//
// mapOrphanTransactions
//

void AddToCompactExtraTransactions(const CTransactionRef& tx)
{
    LOCK(cs_main);

    size_t max_extra_txn = GetArg("-blockreconstructionextratxn", DEFAULT_BLOCK_RECONSTRUCTION_EXTRA_TXN);
    if (max_extra_txn <= 0)
        return;
    if (!vExtraTxnForCompact.size())
        vExtraTxnForCompact.resize(max_extra_txn);
    vExtraTxnForCompact[vExtraTxnForCompactIt] = std::make_pair(tx->GetWitnessHash(), tx);
    vExtraTxnForCompactIt = (vExtraTxnForCompactIt + 1) % max_extra_txn;
}

bool AddOrphanTx(const CTransactionRef& tx, NodeId peer) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    const uint256& hash = tx->GetHash();
    if (mapOrphanTransactions.count(hash))
        return false;

    // Ignore big transactions, to avoid a
    // send-big-orphans memory exhaustion attack. If a peer has a legitimate
    // large transaction with a missing parent then we assume
    // it will rebroadcast it later, after the parent transaction(s)
    // have been mined or received.
    // 100 orphans, each of which is at most 99,999 bytes big is
    // at most 10 megabytes of orphans and somewhat more byprev index (in the worst case):
    unsigned int sz = GetTransactionWeight(*tx);
    if (sz >= MAX_NEW_TX_WEIGHT)
    {
        LogPrint("mempool", "ignoring large orphan tx (size: %u, hash: %s)\n", sz, hash.ToString());
        return false;
    }

    auto ret = mapOrphanTransactions.emplace(hash, COrphanTx{tx, peer, GetTime() + ORPHAN_TX_EXPIRE_TIME});
    assert(ret.second);
    BOOST_FOREACH(const CTxIn& txin, tx->vin) {
        mapOrphanTransactionsByPrev[txin.prevout].insert(ret.first);
    }

    AddToCompactExtraTransactions(tx);

    LogPrint("mempool", "stored orphan tx %s (mapsz %u outsz %u)\n", hash.ToString(),
             mapOrphanTransactions.size(), mapOrphanTransactionsByPrev.size());
    return true;
}

int static EraseOrphanTx(uint256 hash) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    std::map<uint256, COrphanTx>::iterator it = mapOrphanTransactions.find(hash);
    if (it == mapOrphanTransactions.end())
        return 0;
    BOOST_FOREACH(const CTxIn& txin, it->second.tx->vin)
    {
        auto itPrev = mapOrphanTransactionsByPrev.find(txin.prevout);
        if (itPrev == mapOrphanTransactionsByPrev.end())
            continue;
        itPrev->second.erase(it);
        if (itPrev->second.empty())
            mapOrphanTransactionsByPrev.erase(itPrev);
    }
    mapOrphanTransactions.erase(it);
    return 1;
}

void EraseOrphansFor(NodeId peer)
{
    int nErased = 0;
    std::map<uint256, COrphanTx>::iterator iter = mapOrphanTransactions.begin();
    while (iter != mapOrphanTransactions.end())
    {
        std::map<uint256, COrphanTx>::iterator maybeErase = iter++; // increment to avoid iterator becoming invalid
        if (maybeErase->second.fromPeer == peer)
        {
            nErased += EraseOrphanTx(maybeErase->second.tx->GetHash());
        }
    }
    if (nErased > 0) LogPrint("mempool", "Erased %d orphan tx from peer=%d\n", nErased, peer);
}


unsigned int LimitOrphanTxSize(unsigned int nMaxOrphans) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    unsigned int nEvicted = 0;
    static int64_t nNextSweep;
    int64_t nNow = GetTime();
    if (nNextSweep <= nNow) {
        // Sweep out expired orphan pool entries:
        int nErased = 0;
        int64_t nMinExpTime = nNow + ORPHAN_TX_EXPIRE_TIME - ORPHAN_TX_EXPIRE_INTERVAL;
        std::map<uint256, COrphanTx>::iterator iter = mapOrphanTransactions.begin();
        while (iter != mapOrphanTransactions.end())
        {
            std::map<uint256, COrphanTx>::iterator maybeErase = iter++;
            if (maybeErase->second.nTimeExpire <= nNow) {
                nErased += EraseOrphanTx(maybeErase->second.tx->GetHash());
            } else {
                nMinExpTime = std::min(maybeErase->second.nTimeExpire, nMinExpTime);
            }
        }
        // Sweep again 5 minutes after the next entry that expires in order to batch the linear scan.
        nNextSweep = nMinExpTime + ORPHAN_TX_EXPIRE_INTERVAL;
        if (nErased > 0) LogPrint("mempool", "Erased %d orphan tx due to expiration\n", nErased);
    }
    while (mapOrphanTransactions.size() > nMaxOrphans)
    {
        // Evict a random orphan:
        uint256 randomhash = GetRandHash();
        std::map<uint256, COrphanTx>::iterator it = mapOrphanTransactions.lower_bound(randomhash);
        if (it == mapOrphanTransactions.end())
            it = mapOrphanTransactions.begin();
        EraseOrphanTx(it->first);
        ++nEvicted;
    }
    return nEvicted;
}

// Requires cs_main.
void Misbehaving(NodeId pnode, int howmuch)
{
    if (howmuch == 0)
        return;

    CNodeState *state = State(pnode);
    if (state == NULL)
        return;

    state->nMisbehavior += howmuch;
    int banscore = GetArg("-banscore", DEFAULT_BANSCORE_THRESHOLD);
    if (state->nMisbehavior >= banscore && state->nMisbehavior - howmuch < banscore)
    {
        LogPrintf("%s: %s peer=%d (%d -> %d) BAN THRESHOLD EXCEEDED\n", __func__, state->name, pnode, state->nMisbehavior-howmuch, state->nMisbehavior);
        state->fShouldBan = true;
    } else
        LogPrintf("%s: %s peer=%d (%d -> %d)\n", __func__, state->name, pnode, state->nMisbehavior-howmuch, state->nMisbehavior);
}

// Requires cs_main.
bool IsBanned(NodeId pnode)
{
    CNodeState *state = State(pnode);
    if (state == NULL)
        return false;
    if (state->fShouldBan) {
        return true;
    }
    return false;
}







//////////////////////////////////////////////////////////////////////////////
//
// blockchain -> download logic notification
//

PeerLogicValidation::PeerLogicValidation(CConnman* connmanIn) : connman(connmanIn) {
    // Initialize global variables that cannot be constructed at startup.
    recentRejects.reset(new CRollingBloomFilter(120000, 0.000001));
}

void PeerLogicValidation::SyncTransaction(const CTransaction& tx, const CBlockIndex* pindex, int nPosInBlock) {
    if (nPosInBlock == CMainSignals::SYNC_TRANSACTION_NOT_IN_BLOCK)
        return;

    LOCK(cs_main);

    std::vector<uint256> vOrphanErase;
    // Which orphan pool entries must we evict?
    for (size_t j = 0; j < tx.vin.size(); j++) {
        auto itByPrev = mapOrphanTransactionsByPrev.find(tx.vin[j].prevout);
        if (itByPrev == mapOrphanTransactionsByPrev.end()) continue;
        for (auto mi = itByPrev->second.begin(); mi != itByPrev->second.end(); ++mi) {
            const CTransaction& orphanTx = *(*mi)->second.tx;
            const uint256& orphanHash = orphanTx.GetHash();
            vOrphanErase.push_back(orphanHash);
        }
    }

    // Erase orphan transactions include or precluded by this block
    if (vOrphanErase.size()) {
        int nErased = 0;
        BOOST_FOREACH(uint256 &orphanHash, vOrphanErase) {
            nErased += EraseOrphanTx(orphanHash);
        }
        LogPrint("mempool", "Erased %d orphan tx included or conflicted by block\n", nErased);
    }
}

static CCriticalSection cs_most_recent_block;
static std::shared_ptr<const CBlock> most_recent_block;
static std::shared_ptr<const CBlockHeaderAndShortTxIDs> most_recent_compact_block;
static uint256 most_recent_block_hash;

void PeerLogicValidation::NewPoWValidBlock(const CBlockIndex *pindex, const std::shared_ptr<const CBlock>& pblock) {
    std::shared_ptr<const CBlockHeaderAndShortTxIDs> pcmpctblock = std::make_shared<const CBlockHeaderAndShortTxIDs> (*pblock, true);
    const CNetMsgMaker msgMaker(PROTOCOL_VERSION);

    LOCK(cs_main);

    static int nHighestFastAnnounce = 0;
    if (pindex->nHeight <= nHighestFastAnnounce)
        return;
    nHighestFastAnnounce = pindex->nHeight;

    bool fWitnessEnabled = IsWitnessEnabled(pindex->pprev, Params().GetConsensus());
    uint256 hashBlock(pblock->GetHash());

    {
        LOCK(cs_most_recent_block);
        most_recent_block_hash = hashBlock;
        most_recent_block = pblock;
        most_recent_compact_block = pcmpctblock;
    }

    connman->ForEachNode([this, &pcmpctblock, pindex, &msgMaker, fWitnessEnabled, &hashBlock](CNode* pnode) {
        // TODO: Avoid the repeated-serialization here
        if (pnode->nVersion < INVALID_CB_NO_BAN_VERSION || pnode->fDisconnect)
            return;
        ProcessBlockAvailability(pnode->GetId());
        CNodeState &state = *State(pnode->GetId());
        // If the peer has, or we announced to them the previous block already,
        // but we don't think they have this one, go ahead and announce it
        if (state.fPreferHeaderAndIDs && (!fWitnessEnabled || state.fWantsCmpctWitness) &&
                !PeerHasHeader(&state, pindex) && PeerHasHeader(&state, pindex->pprev)) {

            LogPrint("net", "%s sending header-and-ids %s to peer=%d\n", "PeerLogicValidation::NewPoWValidBlock",
                    hashBlock.ToString(), pnode->id);
            connman->PushMessage(pnode, msgMaker.Make(NetMsgType::CMPCTBLOCK, *pcmpctblock));
            state.pindexBestHeaderSent = pindex;
        }
    });
}

void PeerLogicValidation::UpdatedBlockTip(const CBlockIndex *pindexNew, const CBlockIndex *pindexFork, bool fInitialDownload) {
    const int nNewHeight = pindexNew->nHeight;
    connman->SetBestHeight(nNewHeight);

    if (!fInitialDownload) {
        // Find the hashes of all blocks that weren't previously in the best chain.
        std::vector<uint256> vHashes;
        const CBlockIndex *pindexToAnnounce = pindexNew;
        while (pindexToAnnounce != pindexFork) {
            vHashes.push_back(pindexToAnnounce->GetBlockHash());
            pindexToAnnounce = pindexToAnnounce->pprev;
            if (vHashes.size() == MAX_BLOCKS_TO_ANNOUNCE) {
                // Limit announcements in case of a huge reorganization.
                // Rely on the peer's synchronization mechanism in that case.
                break;
            }
        }
        // Relay inventory, but don't relay old inventory during initial block download.
        connman->ForEachNode([nNewHeight, &vHashes](CNode* pnode) {
            if (nNewHeight > (pnode->nStartingHeight != -1 ? pnode->nStartingHeight - 2000 : 0)) {
                BOOST_REVERSE_FOREACH(const uint256& hash, vHashes) {
                    pnode->PushBlockHash(hash);
                }
            }
        });
        connman->WakeMessageHandler();
    }

    nTimeBestReceived = GetTime();
}

void PeerLogicValidation::BlockChecked(const CBlock& block, const CValidationState& state) {
    LOCK(cs_main);

    const uint256 hash(block.GetHash());
    std::map<uint256, std::pair<NodeId, bool>>::iterator it = mapBlockSource.find(hash);

    int nDoS = 0;
    if (state.IsInvalid(nDoS)) {
        if (it != mapBlockSource.end() && State(it->second.first)) {
            assert (state.GetRejectCode() < REJECT_INTERNAL); // Blocks are never rejected with internal reject codes
            CBlockReject reject = {(unsigned char)state.GetRejectCode(), state.GetRejectReason().substr(0, MAX_REJECT_MESSAGE_LENGTH), hash};
            State(it->second.first)->rejects.push_back(reject);
            if (nDoS > 0 && it->second.second)
                Misbehaving(it->second.first, nDoS);
        }
    }
    // Check that:
    // 1. The block is valid
    // 2. We're not in initial block download
    // 3. This is currently the best block we're aware of. We haven't updated
    //    the tip yet so we have no way to check this directly here. Instead we
    //    just check that there are currently no other blocks in flight.
    else if (state.IsValid() &&
             !IsInitialBlockDownload() &&
             mapBlocksInFlight.count(hash) == mapBlocksInFlight.size()) {
        if (it != mapBlockSource.end()) {
            MaybeSetPeerAsAnnouncingHeaderAndIDs(it->second.first, *connman);
        }
    }
    if (it != mapBlockSource.end())
        mapBlockSource.erase(it);
}

//////////////////////////////////////////////////////////////////////////////
//
// Messages
//


bool static AlreadyHave(const CInv& inv) EXCLUSIVE_LOCKS_REQUIRED(cs_main)
{
    switch (inv.type)
    {
    case MSG_TX:
    case MSG_WITNESS_TX:
        {
            assert(recentRejects);
            if (chainActive.Tip()->GetBlockHash() != hashRecentRejectsChainTip)
            {
                // If the chain tip has changed previously rejected transactions
                // might be now valid, e.g. due to a nLockTime'd tx becoming valid,
                // or a double-spend. Reset the rejects filter and give those
                // txs a second chance.
                hashRecentRejectsChainTip = chainActive.Tip()->GetBlockHash();
                recentRejects->reset();
            }

            return (recentRejects->contains(inv.hash) && !llmq::quorumInstantSendManager->IsLocked(inv.hash)) ||
                   mempool.exists(inv.hash) ||
                   mapOrphanTransactions.count(inv.hash) ||
                   pcoinsTip->HaveCoinInCache(COutPoint(inv.hash, 0)) || // Best effort: only try output 0 and 1
                   pcoinsTip->HaveCoinInCache(COutPoint(inv.hash, 1));
        }
    case MSG_BLOCK:
    case MSG_WITNESS_BLOCK:
        return mapBlockIndex.count(inv.hash);

    case MSG_DANDELION_TX:
    case MSG_DANDELION_WITNESS_TX:
        // Do not use AlreadyHave for Dandelion transactions
        // If accidentally used, returns false so tx is requested
        return false;

        /*
            Firo Related Inventory Messages

        --

        We shouldn't update the sync times for each of the messages when we already have it.
        We're going to be asking many nodes upfront for the full inventory list, so we'll get duplicates of these.
        We want to only update the time on new hits, so that we can time out appropriately if needed.
    */
    case MSG_QUORUM_FINAL_COMMITMENT:
        return llmq::quorumBlockProcessor->HasMinableCommitment(inv.hash);
    case MSG_QUORUM_CONTRIB:
    case MSG_QUORUM_COMPLAINT:
    case MSG_QUORUM_JUSTIFICATION:
    case MSG_QUORUM_PREMATURE_COMMITMENT:
        return llmq::quorumDKGSessionManager->AlreadyHave(inv);
    case MSG_QUORUM_RECOVERED_SIG:
        return llmq::quorumSigningManager->AlreadyHave(inv);
    case MSG_CLSIG:
        return llmq::chainLocksHandler->AlreadyHave(inv);
    case MSG_ISLOCK:
        return llmq::quorumInstantSendManager->AlreadyHave(inv);
    }
    // Don't know what it is, just say we already got one
    return true;
}

static void RelayAddress(const CAddress& addr, bool fReachable, CConnman& connman)
{
    unsigned int nRelayNodes = fReachable ? 2 : 1; // limited relaying of addresses outside our network(s)

    // Relay to a limited number of other nodes
    // Use deterministic randomness to send to the same nodes for 24 hours
    // at a time so the addrKnowns of the chosen nodes prevent repeats
    uint64_t hashAddr = addr.GetHash();
    const CSipHasher hasher = connman.GetDeterministicRandomizer(RANDOMIZER_ID_ADDRESS_RELAY).Write(hashAddr << 32).Write((GetTime() + hashAddr) / (24*60*60));
    FastRandomContext insecure_rand;

    std::array<std::pair<uint64_t, CNode*>,2> best{{{0, nullptr}, {0, nullptr}}};
    assert(nRelayNodes <= best.size());

    auto sortfunc = [&best, &hasher, nRelayNodes](CNode* pnode) {
        if (pnode->nVersion >= CADDR_TIME_VERSION) {
            uint64_t hashKey = CSipHasher(hasher).Write(pnode->id).Finalize();
            for (unsigned int i = 0; i < nRelayNodes; i++) {
                 if (hashKey > best[i].first) {
                     std::copy(best.begin() + i, best.begin() + nRelayNodes - 1, best.begin() + i + 1);
                     best[i] = std::make_pair(hashKey, pnode);
                     break;
                 }
            }
        }
    };

    auto pushfunc = [&addr, &best, nRelayNodes, &insecure_rand] {
        for (unsigned int i = 0; i < nRelayNodes && best[i].first != 0; i++) {
            best[i].second->PushAddress(addr, insecure_rand);
        }
    };

    connman.ForEachNodeThen(std::move(sortfunc), std::move(pushfunc));
}

void static ProcessGetData(CNode* pfrom, const Consensus::Params& consensusParams, CConnman& connman, const std::atomic<bool>& interruptMsgProc)
{
    std::deque<CInv>::iterator it = pfrom->vRecvGetData.begin();
    std::vector<CInv> vNotFound;
    const CNetMsgMaker msgMaker(pfrom->GetSendVersion());
    LOCK(cs_main);

    while (it != pfrom->vRecvGetData.end()) {
        // Don't bother if send buffer is too full to respond anyway
        if (pfrom->fPauseSend)
            break;

        const CInv &inv = *it;
        {
            if (interruptMsgProc)
                return;

            it++;

            if (inv.type == MSG_BLOCK || inv.type == MSG_FILTERED_BLOCK || inv.type == MSG_CMPCT_BLOCK || inv.type == MSG_WITNESS_BLOCK)
            {
                bool send = false;
                BlockMap::iterator mi = mapBlockIndex.find(inv.hash);
                if (mi != mapBlockIndex.end())
                {
                    if (mi->second->nChainTx && !mi->second->IsValid(BLOCK_VALID_SCRIPTS) &&
                            mi->second->IsValid(BLOCK_VALID_TREE)) {
                        // If we have the block and all of its parents, but have not yet validated it,
                        // we might be in the middle of connecting it (ie in the unlock of cs_main
                        // before ActivateBestChain but after AcceptBlock).
                        // In this case, we need to run ActivateBestChain prior to checking the relay
                        // conditions below.
                        std::shared_ptr<const CBlock> a_recent_block;
                        {
                            LOCK(cs_most_recent_block);
                            a_recent_block = most_recent_block;
                        }
                        CValidationState dummy;
                        ActivateBestChain(dummy, Params(), a_recent_block);
                    }
                    if (chainActive.Contains(mi->second)) {
                        send = true;
                    } else {
                        static const int nOneMonth = 30 * 24 * 60 * 60;
                        // To prevent fingerprinting attacks, only send blocks outside of the active
                        // chain if they are valid, and no more than a month older (both in time, and in
                        // best equivalent proof of work) than the best header chain we know about.
                        send = mi->second->IsValid(BLOCK_VALID_SCRIPTS) && (pindexBestHeader != NULL) &&
                            (pindexBestHeader->GetBlockTime() - mi->second->GetBlockTime() < nOneMonth) &&
                            (GetBlockProofEquivalentTime(*pindexBestHeader, *mi->second, *pindexBestHeader, consensusParams) < nOneMonth);
                        if (!send) {
                            LogPrintf("%s: ignoring request from peer=%i for old block that isn't in the main chain\n", __func__, pfrom->GetId());
                        }
                    }
                }
                // disconnect node in case we have reached the outbound limit for serving historical blocks
                // never disconnect whitelisted nodes
                static const int nOneWeek = 7 * 24 * 60 * 60; // assume > 1 week = historical
                if (send && connman.OutboundTargetReached(true) && ( ((pindexBestHeader != NULL) && (pindexBestHeader->GetBlockTime() - mi->second->GetBlockTime() > nOneWeek)) || inv.type == MSG_FILTERED_BLOCK) && !pfrom->fWhitelisted)
                {
                    LogPrint("net", "historical block serving limit reached, disconnect peer=%d\n", pfrom->GetId());

                    //disconnect node
                    pfrom->fDisconnect = true;
                    send = false;
                }
                // Pruned nodes may have deleted the block, so check whether
                // it's available before trying to send.
                if (send && (mi->second->nStatus & BLOCK_HAVE_DATA))
                {
                    // Send block from disk
                    CBlock block;
                    if (!ReadBlockFromDisk(block, (*mi).second, consensusParams))
                        assert(!"cannot load block from disk");
                    // Strip MTP data if past specific point of time
                    if (!block.IsProgPow() && block.IsMTP() && GetTime() >= consensusParams.nMTPStripDataTime) {
                        if (pfrom->nVersion >= MTPDATA_STRIPPED_VERSION) {
                            if (block.mtpHashData)
                                block.mtpHashData->StripMTPData();
                        }
                        else {
                            // node is not ready for a block with stripped MTP data. Skip the block if MTP
                            // data has already been stripped locally
                            if (!block.mtpHashData || block.mtpHashData->IsMTPDataStripped())
                                continue;
                        }
                    }

                    if (inv.type == MSG_BLOCK)
                        connman.PushMessage(pfrom, msgMaker.Make(SERIALIZE_TRANSACTION_NO_WITNESS, NetMsgType::BLOCK, block));
                    else if (inv.type == MSG_WITNESS_BLOCK)
                        connman.PushMessage(pfrom, msgMaker.Make(NetMsgType::BLOCK, block));
                    else if (inv.type == MSG_FILTERED_BLOCK)
                    {
                        bool sendMerkleBlock = false;
                        CMerkleBlock merkleBlock;
                        {
                            LOCK(pfrom->cs_filter);
                            if (pfrom->pfilter) {
                                sendMerkleBlock = true;
                                merkleBlock = CMerkleBlock(block, *pfrom->pfilter);
                            }
                        }
                        if (sendMerkleBlock) {
                            connman.PushMessage(pfrom, msgMaker.Make(NetMsgType::MERKLEBLOCK, merkleBlock));
                            // CMerkleBlock just contains hashes, so also push any transactions in the block the client did not see
                            // This avoids hurting performance by pointlessly requiring a round-trip
                            // Note that there is currently no way for a node to request any single transactions we didn't send here -
                            // they must either disconnect and retry or request the full block.
                            // Thus, the protocol spec specified allows for us to provide duplicate txn here,
                            // however we MUST always provide at least what the remote peer needs
                            typedef std::pair<unsigned int, uint256> PairType;
                            BOOST_FOREACH(PairType& pair, merkleBlock.vMatchedTxn)
                                connman.PushMessage(pfrom, msgMaker.Make(SERIALIZE_TRANSACTION_NO_WITNESS, NetMsgType::TX, *block.vtx[pair.first]));
                        }
                        // else
                            // no response
                    }
                    else if (inv.type == MSG_CMPCT_BLOCK)
                    {
                        // If a peer is asking for old blocks, we're almost guaranteed
                        // they won't have a useful mempool to match against a compact block,
                        // and we don't feel like constructing the object for them, so
                        // instead we respond with the full, non-compact block.
                        bool fPeerWantsWitness = State(pfrom->GetId())->fWantsCmpctWitness;
                        int nSendFlags = fPeerWantsWitness ? 0 : SERIALIZE_TRANSACTION_NO_WITNESS;
                        if (CanDirectFetch(consensusParams) && mi->second->nHeight >= chainActive.Height() - MAX_CMPCTBLOCK_DEPTH) {
                            CBlockHeaderAndShortTxIDs cmpctblock(block, fPeerWantsWitness);
                            connman.PushMessage(pfrom, msgMaker.Make(nSendFlags, NetMsgType::CMPCTBLOCK, cmpctblock));
                        } else
                            connman.PushMessage(pfrom, msgMaker.Make(nSendFlags, NetMsgType::BLOCK, block));
                    }

                    // Trigger the peer node to send a getblocks request for the next batch of inventory
                    if (inv.hash == pfrom->hashContinue)
                    {
                        // Bypass PushInventory, this must send even if redundant,
                        // and we want it right after the last block so they don't
                        // wait for other stuff first.
                        std::vector<CInv> vInv;
                        vInv.push_back(CInv(MSG_BLOCK, chainActive.Tip()->GetBlockHash()));
                        connman.PushMessage(pfrom, msgMaker.Make(NetMsgType::INV, vInv));
                        pfrom->hashContinue.SetNull();
                    }
                }
            }
            else if (inv.type == MSG_TX || inv.type == MSG_WITNESS_TX ||
                    inv.type == MSG_DANDELION_TX || inv.type == MSG_DANDELION_WITNESS_TX)
            {
                // Send stream from relay memory
                bool push = false;
                if (inv.type == MSG_TX || inv.type == MSG_WITNESS_TX) {
                    auto mi = mapRelay.find(inv.hash);
                    int nSendFlags = (inv.type == MSG_TX ? SERIALIZE_TRANSACTION_NO_WITNESS : 0);
                    if (mi != mapRelay.end()) {
                        connman.PushMessage(pfrom, msgMaker.Make(nSendFlags, NetMsgType::TX, *mi->second));
                        push = true;
                    } else if (pfrom->timeLastMempoolReq) {
                        auto txinfo = mempool.info(inv.hash);
                        // To protect privacy, do not answer getdata using the mempool when
                        // that TX couldn't have been INVed in reply to a MEMPOOL request.
                        if (txinfo.tx && txinfo.nTime <= pfrom->timeLastMempoolReq) {
                            connman.PushMessage(pfrom, msgMaker.Make(nSendFlags, NetMsgType::TX, *txinfo.tx));
                            push = true;
                        }
                    }
                }
                else if (inv.type == MSG_DANDELION_TX || inv.type == MSG_DANDELION_WITNESS_TX) {
                    int nSendFlags = (
                            inv.type == MSG_DANDELION_TX ?
                            SERIALIZE_TRANSACTION_NO_WITNESS : 0);
                    auto txinfo = txpools.getStemTxPool().info(inv.hash);
                    uint256 dandelionServiceDiscoveryHash;
                    dandelionServiceDiscoveryHash.SetHex(
                            "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
                    if (txinfo.tx && !CNode::isDandelionInbound(pfrom) &&
                            pfrom->setDandelionInventoryKnown.count(inv.hash) != 0) {                                
                        connman.PushMessage(pfrom, msgMaker.Make(nSendFlags, NetMsgType::DANDELIONTX, *txinfo.tx));
                        push = true;
                    } else if (inv.hash == dandelionServiceDiscoveryHash &&
                               pfrom->setDandelionInventoryKnown.count(inv.hash) != 0) {
                        pfrom->fSupportsDandelion = true;
                        push = true;
                    }
                }
                if (!push) {
                    vNotFound.push_back(inv);
                }
            }
            else
            {
                // Send stream from relay memory
                bool pushed = false;
                {
                    CDataStream ss(SER_NETWORK, PROTOCOL_VERSION);
                    auto mi = mapRelay.find(inv.hash);
                    if (mi != mapRelay.end()) {
                        ss << (*mi).second;
                        pushed = true;
                    }
                    if(pushed) {
                        connman.PushMessage(pfrom, msgMaker.Make(inv.GetCommand().c_str(), ss));
                    }
                }

                if (!pushed && (inv.type == MSG_QUORUM_FINAL_COMMITMENT)) {
                    llmq::CFinalCommitment o;
                    if (llmq::quorumBlockProcessor->GetMinableCommitmentByHash(inv.hash, o)) {
                        connman.PushMessage(pfrom, msgMaker.Make(NetMsgType::QFCOMMITMENT, o));
                        pushed = true;
                    }
                }

                if (!pushed && (inv.type == MSG_QUORUM_CONTRIB)) {
                    llmq::CDKGContribution o;
                    if (llmq::quorumDKGSessionManager->GetContribution(inv.hash, o)) {
                        connman.PushMessage(pfrom, msgMaker.Make(NetMsgType::QCONTRIB, o));
                        pushed = true;
                    }
                }
                if (!pushed && (inv.type == MSG_QUORUM_COMPLAINT)) {
                    llmq::CDKGComplaint o;
                    if (llmq::quorumDKGSessionManager->GetComplaint(inv.hash, o)) {
                        connman.PushMessage(pfrom, msgMaker.Make(NetMsgType::QCOMPLAINT, o));
                        pushed = true;
                    }
                }
                if (!pushed && (inv.type == MSG_QUORUM_JUSTIFICATION)) {
                    llmq::CDKGJustification o;
                    if (llmq::quorumDKGSessionManager->GetJustification(inv.hash, o)) {
                        connman.PushMessage(pfrom, msgMaker.Make(NetMsgType::QJUSTIFICATION, o));
                        pushed = true;
                    }
                }
                if (!pushed && (inv.type == MSG_QUORUM_PREMATURE_COMMITMENT)) {
                    llmq::CDKGPrematureCommitment o;
                    if (llmq::quorumDKGSessionManager->GetPrematureCommitment(inv.hash, o)) {
                        connman.PushMessage(pfrom, msgMaker.Make(NetMsgType::QPCOMMITMENT, o));
                        pushed = true;
                    }
                }
                if (!pushed && (inv.type == MSG_QUORUM_RECOVERED_SIG)) {
                    llmq::CRecoveredSig o;
                    if (llmq::quorumSigningManager->GetRecoveredSigForGetData(inv.hash, o)) {
                        connman.PushMessage(pfrom, msgMaker.Make(NetMsgType::QSIGREC, o));
                        pushed = true;
                    }
                }

                if (!pushed && (inv.type == MSG_CLSIG)) {
                    llmq::CChainLockSig o;
                    if (llmq::chainLocksHandler->GetChainLockByHash(inv.hash, o)) {
                        connman.PushMessage(pfrom, msgMaker.Make(NetMsgType::CLSIG, o));
                        pushed = true;
                    }
                }

                if (!pushed && (inv.type == MSG_ISLOCK)) {
                    llmq::CInstantSendLock o;
                    if (llmq::quorumInstantSendManager->GetInstantSendLockByHash(inv.hash, o)) {
                        connman.PushMessage(pfrom, msgMaker.Make(NetMsgType::ISLOCK, o));
                        pushed = true;
                    }
                }
                if (!pushed)
                    vNotFound.push_back(inv);
            }


            // Track requests for our stuff.
            GetMainSignals().Inventory(inv.hash);

            if (inv.type == MSG_BLOCK || inv.type == MSG_FILTERED_BLOCK || inv.type == MSG_CMPCT_BLOCK || inv.type == MSG_WITNESS_BLOCK)
                break;
        }
    }

    pfrom->vRecvGetData.erase(pfrom->vRecvGetData.begin(), it);

    if (!vNotFound.empty()) {
        // Let the peer know that we didn't find what it asked for, so it doesn't
        // have to wait around forever. Currently only SPV clients actually care
        // about this message: it's needed when they are recursively walking the
        // dependencies of relevant unconfirmed transactions. SPV clients want to
        // do that because they want to know about (and store and rebroadcast and
        // risk analyze) the dependencies of transactions relevant to them, without
        // having to download the entire memory pool.
        connman.PushMessage(pfrom, msgMaker.Make(NetMsgType::NOTFOUND, vNotFound));
    }
}

uint32_t GetFetchFlags(CNode* pfrom, const CBlockIndex* pprev, const Consensus::Params& chainparams) {
    uint32_t nFetchFlags = 0;
    if ((pfrom->GetLocalServices() & NODE_WITNESS) && State(pfrom->GetId())->fHaveWitness) {
        nFetchFlags |= MSG_WITNESS_FLAG;
    }
    return nFetchFlags;
}

inline void static SendBlockTransactions(const CBlock& block, const BlockTransactionsRequest& req, CNode* pfrom, CConnman& connman) {
    BlockTransactions resp(req);
    for (size_t i = 0; i < req.indexes.size(); i++) {
        if (req.indexes[i] >= block.vtx.size()) {
            LOCK(cs_main);
            Misbehaving(pfrom->GetId(), 100);
            LogPrintf("Peer %d sent us a getblocktxn with out-of-bounds tx indices", pfrom->id);
            return;
        }
        resp.txn[i] = block.vtx[req.indexes[i]];
    }
    LOCK(cs_main);
    const CNetMsgMaker msgMaker(pfrom->GetSendVersion());
    int nSendFlags = State(pfrom->GetId())->fWantsCmpctWitness ? 0 : SERIALIZE_TRANSACTION_NO_WITNESS;
    connman.PushMessage(pfrom, msgMaker.Make(nSendFlags, NetMsgType::BLOCKTXN, resp));
}

bool static ProcessMessage(CNode* pfrom, const std::string& strCommand, CDataStream& vRecv, int64_t nTimeReceived, const CChainParams& chainparams, CConnman& connman, const std::atomic<bool>& interruptMsgProc)
{
    LogPrint("net", "received: %s (%u bytes) peer=%d\n", SanitizeString(strCommand), vRecv.size(), pfrom->id);
    if (IsArgSet("-dropmessagestest") && GetRand(GetArg("-dropmessagestest", 0)) == 0)
    {
        LogPrintf("dropmessagestest DROPPING RECV MESSAGE\n");
        return true;
    }


    if (!(pfrom->GetLocalServices() & NODE_BLOOM) &&
              (strCommand == NetMsgType::FILTERLOAD ||
               strCommand == NetMsgType::FILTERADD))
    {
        if (pfrom->nVersion >= NO_BLOOM_VERSION) {
            LOCK(cs_main);
            Misbehaving(pfrom->GetId(), 100);
            return false;
        } else {
            pfrom->fDisconnect = true;
            return false;
        }
    }

    {
        LOCK(cs_main);
        CNode::CheckDandelionEmbargoes();
    }

    if (strCommand == NetMsgType::REJECT)
    {
        if (fDebug) {
            try {
                std::string strMsg; unsigned char ccode; std::string strReason;
                vRecv >> LIMITED_STRING(strMsg, CMessageHeader::COMMAND_SIZE) >> ccode >> LIMITED_STRING(strReason, MAX_REJECT_MESSAGE_LENGTH);

                std::ostringstream ss;
                ss << strMsg << " code " << itostr(ccode) << ": " << strReason;

                if (strMsg == NetMsgType::BLOCK || strMsg == NetMsgType::TX)
                {
                    uint256 hash;
                    vRecv >> hash;
                    ss << ": hash " << hash.ToString();
                }
                LogPrint("net", "Reject %s\n", SanitizeString(ss.str()));
            } catch (const std::ios_base::failure&) {
                // Avoid feedback loops by preventing reject messages from triggering a new reject message.
                LogPrint("net", "Unparseable reject message received\n");
            }
        }
    }

    else if (strCommand == NetMsgType::VERSION)
    {
        // Each connection can only send one version message
        if (pfrom->nVersion != 0)
        {
            connman.PushMessage(pfrom, CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::REJECT, strCommand, REJECT_DUPLICATE, std::string("Duplicate version message")));
            LOCK(cs_main);
            Misbehaving(pfrom->GetId(), 1);
            return false;
        }

        int64_t nTime;
        CAddress addrMe;
        CAddress addrFrom;
        uint64_t nNonce = 1;
        uint64_t nServiceInt;
        ServiceFlags nServices;
        int nVersion;
        int nSendVersion;
        std::string strSubVer;
        std::string cleanSubVer;
        int nStartingHeight = -1;
        bool fRelay = true;

        vRecv >> nVersion >> nServiceInt >> nTime >> addrMe;
        nSendVersion = std::min(nVersion, PROTOCOL_VERSION);
        nServices = ServiceFlags(nServiceInt);
        if (!pfrom->fInbound)
        {
            connman.SetServices(pfrom->addr, nServices);
        }
        if (pfrom->nServicesExpected & ~nServices)
        {
            LogPrint("net", "peer=%d does not offer the expected services (%08x offered, %08x expected); disconnecting\n", pfrom->id, nServices, pfrom->nServicesExpected);
            connman.PushMessage(pfrom, CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::REJECT, strCommand, REJECT_NONSTANDARD,
                               strprintf("Expected to offer services %08x", pfrom->nServicesExpected)));
            pfrom->fDisconnect = true;
            return false;
        }

        if (nVersion < MIN_PEER_PROTO_VERSION)
        {
            // disconnect from peers older than this proto version
            LogPrintf("peer=%d using obsolete version %i; disconnecting\n", pfrom->id, nVersion);
            connman.PushMessage(pfrom, CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::REJECT, strCommand, REJECT_OBSOLETE,
                               strprintf("Version must be %d or greater", MIN_PEER_PROTO_VERSION)));
            pfrom->fDisconnect = true;
            return false;
        }

        if (nVersion == 10300)
            nVersion = 300;
        if (!vRecv.empty())
            vRecv >> addrFrom >> nNonce;
        if (!vRecv.empty()) {
            vRecv >> LIMITED_STRING(strSubVer, MAX_SUBVERSION_LENGTH);
            cleanSubVer = SanitizeString(strSubVer);
            int parsedVersion[4] = {0, 0, 0, 0};
            if (sscanf(cleanSubVer.c_str(), "/Satoshi:%2d.%2d.%2d.%2d/",
                    &parsedVersion[0], &parsedVersion[1], &parsedVersion[2], &parsedVersion[3]) >= 2) {
                int peerClientVersion = parsedVersion[0]*1000000 + parsedVersion[1]*10000 + parsedVersion[2]*100 + parsedVersion[3];
                if (peerClientVersion < MIN_FIRO_CLIENT_VERSION) {
                    connman.PushMessage(pfrom, CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::REJECT, strCommand, REJECT_OBSOLETE, "This version is banned from the network"));
                    pfrom->fDisconnect = 1;
                    LOCK(cs_main);
                    Misbehaving(pfrom->GetId(), 100);
                    return false;
                }
            }
        }
        if (!vRecv.empty()) {
            vRecv >> nStartingHeight;
        }
        if (!vRecv.empty())
            vRecv >> fRelay;

        if (!vRecv.empty()) {
            LOCK(pfrom->cs_mnauth);
            vRecv >> pfrom->receivedMNAuthChallenge;
        }
        // Disconnect if we connected to ourself
        if (pfrom->fInbound && !connman.CheckIncomingNonce(nNonce))
        {
            LogPrintf("connected to self at %s, disconnecting\n", pfrom->addr.ToString());
            pfrom->fDisconnect = true;
            return true;
        }

        if (pfrom->fInbound && addrMe.IsRoutable())
        {
            SeenLocal(addrMe);
        }

        // Be shy and don't send version until we hear
        if (pfrom->fInbound)
            PushNodeVersion(pfrom, connman, GetAdjustedTime());

        connman.PushMessage(pfrom, CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::VERACK));

        pfrom->nServices = nServices;
        pfrom->SetAddrLocal(addrMe);
        {
            LOCK(pfrom->cs_SubVer);
            pfrom->strSubVer = strSubVer;
            pfrom->cleanSubVer = cleanSubVer;
        }
        pfrom->nStartingHeight = nStartingHeight;
        pfrom->fClient = !(nServices & NODE_NETWORK);
        {
            LOCK(pfrom->cs_filter);
            pfrom->fRelayTxes = fRelay; // set to true after we get the first filter* message
        }

        // Change version
        pfrom->SetSendVersion(nSendVersion);
        pfrom->nVersion = nVersion;

        if((nServices & NODE_WITNESS))
        {
            LOCK(cs_main);
            State(pfrom->GetId())->fHaveWitness = true;
        }

        // Potentially mark this peer as a preferred download peer.
        {
        LOCK(cs_main);
        UpdatePreferredDownload(pfrom, State(pfrom->GetId()));
        }

        if (!pfrom->fInbound)
        {
            // Advertise our address
            if (fListen && !IsInitialBlockDownload())
            {
                CAddress addr = GetLocalAddress(&pfrom->addr, pfrom->GetLocalServices());
                FastRandomContext insecure_rand;
                if (addr.IsRoutable())
                {
                    LogPrint("net", "ProcessMessages: advertising address %s\n", addr.ToString());
                    pfrom->PushAddress(addr, insecure_rand);
                } else if (IsPeerAddrLocalGood(pfrom)) {
                    addr.SetIP(addrMe);
                    LogPrint("net", "ProcessMessages: advertising address %s\n", addr.ToString());
                    pfrom->PushAddress(addr, insecure_rand);
                }
            }

            // Get recent addresses
            if (pfrom->fOneShot || pfrom->nVersion >= CADDR_TIME_VERSION || connman.GetAddressCount() < 1000)
            {
                connman.PushMessage(pfrom, CNetMsgMaker(nSendVersion).Make(NetMsgType::GETADDR));
                pfrom->fGetAddr = true;

                // When requesting a getaddr, accept an additional MAX_ADDR_TO_SEND addresses in response
                // (bypassing the MAX_ADDR_PROCESSING_TOKEN_BUCKET limit).
                pfrom->nAddrTokenBucket += MAX_ADDR_TO_SEND;
            }
            connman.MarkAddressGood(pfrom->addr);
        }

        std::string remoteAddr;
        if (fLogIPs)
            remoteAddr = ", peeraddr=" + pfrom->addr.ToString();

        LogPrintf("receive version message: %s: version %d, blocks=%d, us=%s, peer=%d%s\n",
                  cleanSubVer, pfrom->nVersion,
                  pfrom->nStartingHeight, addrMe.ToString(), pfrom->id,
                  remoteAddr);

        int64_t nTimeOffset = nTime - GetTime();
        pfrom->nTimeOffset = nTimeOffset;
        AddTimeData(pfrom->addr, nTimeOffset);

        // If the peer is old enough to have the old alert system, send it the final alert.
        if (pfrom->nVersion <= 70012) {
            CDataStream finalAlert(ParseHex("60010000000000000000000000ffffff7f00000000ffffff7ffeffff7f01ffffff7f00000000ffffff7f00ffffff7f002f555247454e543a20416c657274206b657920636f6d70726f6d697365642c2075706772616465207265717569726564004630440220653febd6410f470f6bae11cad19c48413becb1ac2c17f908fd0fd53bdc3abd5202206d0e9c96fe88d4a0f01ed9dedae2b6f9e00da94cad0fecaae66ecf689bf71b50"), SER_NETWORK, PROTOCOL_VERSION);
            connman.PushMessage(pfrom, CNetMsgMaker(nSendVersion).Make("alert", finalAlert));
        }

        // Feeler connections exist only to verify if address is online.
        if (pfrom->fFeeler) {
            assert(pfrom->fInbound == false);
            pfrom->fDisconnect = true;
        }
        return true;
    }


    else if (pfrom->nVersion == 0)
    {
        // Must have a version message before anything else
        LOCK(cs_main);
        Misbehaving(pfrom->GetId(), 1);
        return false;
    }

    // At this point, the outgoing message serialization version can't change.
    const CNetMsgMaker msgMaker(pfrom->GetSendVersion());

    if (strCommand == NetMsgType::VERACK)
    {
        pfrom->SetRecvVersion(std::min(pfrom->nVersion.load(), PROTOCOL_VERSION));

        if (!pfrom->fInbound) {
            // Mark this node as currently connected, so we update its timestamp later.
            LOCK(cs_main);
            State(pfrom->GetId())->fCurrentlyConnected = true;
        }

        if (pfrom->nVersion >= LLMQS_PROTO_VERSION) {
            CMNAuth::PushMNAUTH(pfrom, connman);
        }

        if (pfrom->nVersion >= SENDHEADERS_VERSION) {
            // Tell our peer we prefer to receive headers rather than inv's
            // We send this to non-NODE NETWORK peers as well, because even
            // non-NODE NETWORK peers can announce blocks (such as pruning
            // nodes)
            connman.PushMessage(pfrom, msgMaker.Make(NetMsgType::SENDHEADERS));
        }
        if (pfrom->nVersion >= SHORT_IDS_BLOCKS_VERSION) {
            // Tell our peer we are willing to provide version 1 or 2 cmpctblocks
            // However, we do not request new block announcements using
            // cmpctblock messages.
            // We send this to non-NODE NETWORK peers as well, because
            // they may wish to request compact blocks from us
            bool fAnnounceUsingCMPCTBLOCK = false;
            uint64_t nCMPCTBLOCKVersion = 2;
            if (pfrom->GetLocalServices() & NODE_WITNESS)
                connman.PushMessage(pfrom, msgMaker.Make(NetMsgType::SENDCMPCT, fAnnounceUsingCMPCTBLOCK, nCMPCTBLOCKVersion));
            nCMPCTBLOCKVersion = 1;
            connman.PushMessage(pfrom, msgMaker.Make(NetMsgType::SENDCMPCT, fAnnounceUsingCMPCTBLOCK, nCMPCTBLOCKVersion));
        }

        if (pfrom->nVersion >= LLMQS_PROTO_VERSION) {
            // Tell our peer that we're interested in plain LLMQ recovered signatures.
            // Otherwise the peer would only announce/send messages resulting from QRECSIG,
            // e.g. InstantSend locks or ChainLocks. SPV nodes should not send this message
            // as they are usually only interested in the higher level messages
            connman.PushMessage(pfrom, msgMaker.Make(NetMsgType::QSENDRECSIGS, true));
        }

        if (GetBoolArg("-watchquorums", llmq::DEFAULT_WATCH_QUORUMS)) {
            connman.PushMessage(pfrom, msgMaker.Make(NetMsgType::QWATCH));
        }

        pfrom->fSuccessfullyConnected = true;
    }

    else if (!pfrom->fSuccessfullyConnected)
    {
        // Must have a verack message before anything else
        LOCK(cs_main);
        Misbehaving(pfrom->GetId(), 1);
        return false;
    }

    else if (strCommand == NetMsgType::ADDR)
    {
        std::vector<CAddress> vAddr;
        vRecv >> vAddr;

        // Don't want addr from older versions unless seeding
        if (pfrom->nVersion < CADDR_TIME_VERSION && connman.GetAddressCount() > 1000)
            return true;
        if (vAddr.size() > 1000)
        {
            LOCK(cs_main);
            Misbehaving(pfrom->GetId(), 20);
            return error("message addr size() = %u", vAddr.size());
        }

        // Store the new addresses
        std::vector<CAddress> vAddrOk;
        int64_t nNow = GetAdjustedTime();
        int64_t nSince = nNow - 10 * 60;

        // track rate limiting within this message
        uint64_t nProcessedAddrs = 0;
        uint64_t nRatelimitedAddrs = 0;

        // Update/increment addr rate limiting bucket.
        const uint64_t nCurrentTime = GetMockableTimeMicros();
        if (pfrom->nAddrTokenBucket < MAX_ADDR_PROCESSING_TOKEN_BUCKET) {
          const uint64_t nTimeElapsed = std::max(nCurrentTime - pfrom->nAddrTokenTimestamp, uint64_t(0));
          const double nIncrement = nTimeElapsed * MAX_ADDR_RATE_PER_SECOND / 1e6;
          pfrom->nAddrTokenBucket = std::min<double>(pfrom->nAddrTokenBucket + nIncrement, MAX_ADDR_PROCESSING_TOKEN_BUCKET);
        }
        pfrom->nAddrTokenTimestamp = nCurrentTime;

        // Randomize entries before processing, to prevent an attacker to
        // determine which entries will make it through the rate limit
        std::shuffle(vAddr.begin(), vAddr.end(), FastRandomContext());

        BOOST_FOREACH(CAddress& addr, vAddr)
        {
            if (interruptMsgProc)
                return true;

            // apply rate limiting
            if (!pfrom->fWhitelisted) {
              if (pfrom->nAddrTokenBucket < 1.0) {
                nRatelimitedAddrs++;
                continue;
              }
              pfrom->nAddrTokenBucket -= 1.0;
            }

            nProcessedAddrs++;

            if ((addr.nServices & REQUIRED_SERVICES) != REQUIRED_SERVICES)
                continue;

            if (addr.nTime <= 100000000 || addr.nTime > nNow + 10 * 60)
                addr.nTime = nNow - 5 * 24 * 60 * 60;
            pfrom->AddAddressKnown(addr);
            bool fReachable = IsReachable(addr);
            if (addr.nTime > nSince && !pfrom->fGetAddr && vAddr.size() <= 10 && addr.IsRoutable())
            {
                // Relay to a limited number of other nodes
                RelayAddress(addr, fReachable, connman);
            }
            // Do not store addresses outside our network
            if (fReachable)
                vAddrOk.push_back(addr);
        }

        pfrom->nProcessedAddrs += nProcessedAddrs;
        pfrom->nRatelimitedAddrs += nRatelimitedAddrs;

        LogPrint("net", "Received addr: %u addresses (%u processed, %u rate-limited) peer=%d\n",
                 vAddr.size(), nProcessedAddrs, nRatelimitedAddrs, pfrom->GetId());

        connman.AddNewAddresses(vAddrOk, pfrom->addr, 2 * 60 * 60);
        if (vAddr.size() < 1000)
            pfrom->fGetAddr = false;
        if (pfrom->fOneShot)
            pfrom->fDisconnect = true;
    }

    else if (strCommand == NetMsgType::SENDHEADERS)
    {
        LOCK(cs_main);
        State(pfrom->GetId())->fPreferHeaders = true;
    }

    else if (strCommand == NetMsgType::SENDCMPCT)
    {
        bool fAnnounceUsingCMPCTBLOCK = false;
        uint64_t nCMPCTBLOCKVersion = 0;
        vRecv >> fAnnounceUsingCMPCTBLOCK >> nCMPCTBLOCKVersion;
        if (nCMPCTBLOCKVersion == 1 || ((pfrom->GetLocalServices() & NODE_WITNESS) && nCMPCTBLOCKVersion == 2)) {
            LOCK(cs_main);
            // fProvidesHeaderAndIDs is used to "lock in" version of compact blocks we send (fWantsCmpctWitness)
            if (!State(pfrom->GetId())->fProvidesHeaderAndIDs) {
                State(pfrom->GetId())->fProvidesHeaderAndIDs = true;
                State(pfrom->GetId())->fWantsCmpctWitness = nCMPCTBLOCKVersion == 2;
            }
            if (State(pfrom->GetId())->fWantsCmpctWitness == (nCMPCTBLOCKVersion == 2)) // ignore later version announces
                State(pfrom->GetId())->fPreferHeaderAndIDs = fAnnounceUsingCMPCTBLOCK;
            if (!State(pfrom->GetId())->fSupportsDesiredCmpctVersion) {
                if (pfrom->GetLocalServices() & NODE_WITNESS)
                    State(pfrom->GetId())->fSupportsDesiredCmpctVersion = (nCMPCTBLOCKVersion == 2);
                else
                    State(pfrom->GetId())->fSupportsDesiredCmpctVersion = (nCMPCTBLOCKVersion == 1);
            }
        }
    }

    else if (strCommand == NetMsgType::QSENDRECSIGS) {
        bool b;
        vRecv >> b;
        pfrom->fSendRecSigs = b;
    }

    else if (strCommand == NetMsgType::INV)
    {
        std::vector<CInv> vInv;
        vRecv >> vInv;
        if (vInv.size() > MAX_INV_SZ)
        {
            LOCK(cs_main);
            Misbehaving(pfrom->GetId(), 20);
            return error("message inv size() = %u", vInv.size());
        }

        bool fBlocksOnly = !fRelayTxes;

        // Allow whitelisted peers to send data other than blocks in blocks only mode if whitelistrelay is true
        if (pfrom->fWhitelisted && GetBoolArg("-whitelistrelay", DEFAULT_WHITELISTRELAY))
            fBlocksOnly = false;

        LOCK(cs_main);

        uint32_t nFetchFlags = GetFetchFlags(pfrom, chainActive.Tip(), chainparams.GetConsensus());

        std::vector<CInv> vToFetch;

        for (unsigned int nInv = 0; nInv < vInv.size(); nInv++)
        {
            CInv &inv = vInv[nInv];

            if (interruptMsgProc)
                return true;

            bool fAlreadyHave = AlreadyHave(inv);
            LogPrint("net", "got inv: %s  %s peer=%d\n", inv.ToString(), fAlreadyHave ? "have" : "new", pfrom->id);

            if (inv.type == MSG_TX) {
                inv.type |= nFetchFlags;
            }

            if (inv.type == MSG_BLOCK) {
                UpdateBlockAvailability(pfrom->GetId(), inv.hash);
                if (!fAlreadyHave && !fImporting && !fReindex && !mapBlocksInFlight.count(inv.hash)) {
                    // We used to request the full block here, but since headers-announcements are now the
                    // primary method of announcement on the network, and since, in the case that a node
                    // fell back to inv we probably have a reorg which we should get the headers for first,
                    // we now only provide a getheaders response here. When we receive the headers, we will
                    // then ask for the blocks we need.
                    connman.PushMessage(pfrom, msgMaker.Make(NetMsgType::GETHEADERS, chainActive.GetLocator(pindexBestHeader), inv.hash));
                    LogPrint("net", "getheaders (%d) %s to peer=%d\n", pindexBestHeader->nHeight, inv.hash.ToString(), pfrom->id);
                }
            }

            else if (inv.type == MSG_DANDELION_TX) {
                auto result = pfrom->setDandelionInventoryKnown.insert(inv.hash);
                fAlreadyHave = !result.second;
                uint256 dandelionServiceDiscoveryHash;
                dandelionServiceDiscoveryHash.SetHex(
                    "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
                if (fBlocksOnly) {
                    LogPrint("net", "transaction (%s) inv sent in violation of protocol peer=%d\n",
                             inv.hash.ToString(), pfrom->GetId());
                } else if ((!fAlreadyHave && !fImporting && !fReindex &&
                            !IsInitialBlockDownload() &&
                            CNode::isDandelionInbound(pfrom)) ||
                            inv.hash == dandelionServiceDiscoveryHash) {
                    pfrom->AskFor(inv);
                }
            }

            else
            {
                pfrom->AddInventoryKnown(inv);
                if (fBlocksOnly)
                    LogPrint("net", "transaction (%s) inv sent in violation of protocol peer=%d\n", inv.hash.ToString(), pfrom->id);
                else if (!fAlreadyHave && !fImporting && !fReindex && !IsInitialBlockDownload()) {
                    int64_t doubleRequestDelay = 2 * 60 * 1000000;
                    // some messages need to be re-requested faster when the first announcing peer did not answer to GETDATA
                    switch (inv.type) {
                        case MSG_QUORUM_RECOVERED_SIG:
                            doubleRequestDelay = 15 * 1000000;
                            break;
                        case MSG_CLSIG:
                            doubleRequestDelay = 5 * 1000000;
                            break;
                        case MSG_ISLOCK:
                            doubleRequestDelay = 10 * 1000000;
                            break;
                    }
                    pfrom->AskFor(inv, doubleRequestDelay);
                }
            }
        }

        if (!vToFetch.empty())
            connman.PushMessage(pfrom, msgMaker.Make(NetMsgType::GETDATA, vToFetch));
    }


    else if (strCommand == NetMsgType::GETDATA)
    {
        std::vector<CInv> vInv;
        vRecv >> vInv;
        if (vInv.size() > MAX_INV_SZ)
        {
            LOCK(cs_main);
            Misbehaving(pfrom->GetId(), 20);
            return error("message getdata size() = %u", vInv.size());
        }

        if (fDebug || (vInv.size() != 1))
            LogPrint("net", "received getdata (%u invsz) peer=%d\n", vInv.size(), pfrom->id);

        if ((fDebug && vInv.size() > 0) || (vInv.size() == 1))
            LogPrint("net", "received getdata for: %s peer=%d\n", vInv[0].ToString(), pfrom->id);

        pfrom->vRecvGetData.insert(pfrom->vRecvGetData.end(), vInv.begin(), vInv.end());
        ProcessGetData(pfrom, chainparams.GetConsensus(), connman, interruptMsgProc);
    }


    else if (strCommand == NetMsgType::GETBLOCKS)
    {
        CBlockLocator locator;
        uint256 hashStop;
        vRecv >> locator >> hashStop;

        // We might have announced the currently-being-connected tip using a
        // compact block, which resulted in the peer sending a getblocks
        // request, which we would otherwise respond to without the new block.
        // To avoid this situation we simply verify that we are on our best
        // known chain now. This is super overkill, but we handle it better
        // for getheaders requests, and there are no known nodes which support
        // compact blocks but still use getblocks to request blocks.
        {
            std::shared_ptr<const CBlock> a_recent_block;
            {
                LOCK(cs_most_recent_block);
                a_recent_block = most_recent_block;
            }
            CValidationState dummy;
            ActivateBestChain(dummy, Params(), a_recent_block);
        }

        LOCK(cs_main);

        // Find the last block the caller has in the main chain
        const CBlockIndex* pindex = FindForkInGlobalIndex(chainActive, locator);

        // Send the rest of the chain
        if (pindex)
            pindex = chainActive.Next(pindex);
        int nLimit = 500;
        LogPrint("net", "getblocks %d to %s limit %d from peer=%d\n", (pindex ? pindex->nHeight : -1), hashStop.IsNull() ? "end" : hashStop.ToString(), nLimit, pfrom->id);
        for (; pindex; pindex = chainActive.Next(pindex))
        {
            if (pindex->GetBlockHash() == hashStop)
            {
                LogPrint("net", "  getblocks stopping at %d %s\n", pindex->nHeight, pindex->GetBlockHash().ToString());
                break;
            }
            // If pruning, don't inv blocks unless we have on disk and are likely to still have
            // for some reasonable time window (1 hour) that block relay might require.
            const int nPrunedBlocksLikelyToHave = MIN_BLOCKS_TO_KEEP - 3600 / chainparams.GetConsensus().nPowTargetSpacing;
            if (fPruneMode && (!(pindex->nStatus & BLOCK_HAVE_DATA) || pindex->nHeight <= chainActive.Tip()->nHeight - nPrunedBlocksLikelyToHave))
            {
                LogPrint("net", " getblocks stopping, pruned or too old block at %d %s\n", pindex->nHeight, pindex->GetBlockHash().ToString());
                break;
            }
            pfrom->PushInventory(CInv(MSG_BLOCK, pindex->GetBlockHash()));
            if (--nLimit <= 0)
            {
                // When this block is requested, we'll send an inv that'll
                // trigger the peer to getblocks the next batch of inventory.
                LogPrint("net", "  getblocks stopping at limit %d %s\n", pindex->nHeight, pindex->GetBlockHash().ToString());
                pfrom->hashContinue = pindex->GetBlockHash();
                break;
            }
        }
    }


    else if (strCommand == NetMsgType::GETBLOCKTXN)
    {
        BlockTransactionsRequest req;
        vRecv >> req;

        std::shared_ptr<const CBlock> recent_block;
        {
            LOCK(cs_most_recent_block);
            if (most_recent_block_hash == req.blockhash)
                recent_block = most_recent_block;
            // Unlock cs_most_recent_block to avoid cs_main lock inversion
        }
        if (recent_block) {
            SendBlockTransactions(*recent_block, req, pfrom, connman);
            return true;
        }

        LOCK(cs_main);

        BlockMap::iterator it = mapBlockIndex.find(req.blockhash);
        if (it == mapBlockIndex.end() || !(it->second->nStatus & BLOCK_HAVE_DATA)) {
            LogPrintf("Peer %d sent us a getblocktxn for a block we don't have", pfrom->id);
            return true;
        }

        if (it->second->nHeight < chainActive.Height() - MAX_BLOCKTXN_DEPTH) {
            // If an older block is requested (should never happen in practice,
            // but can happen in tests) send a block response instead of a
            // blocktxn response. Sending a full block response instead of a
            // small blocktxn response is preferable in the case where a peer
            // might maliciously send lots of getblocktxn requests to trigger
            // expensive disk reads, because it will require the peer to
            // actually receive all the data read from disk over the network.
            LogPrint("net", "Peer %d sent us a getblocktxn for a block > %i deep", pfrom->id, MAX_BLOCKTXN_DEPTH);
            CInv inv;
            inv.type = State(pfrom->GetId())->fWantsCmpctWitness ? MSG_WITNESS_BLOCK : MSG_BLOCK;
            inv.hash = req.blockhash;
            pfrom->vRecvGetData.push_back(inv);
            ProcessGetData(pfrom, chainparams.GetConsensus(), connman, interruptMsgProc);
            return true;
        }

        CBlock block;
        bool ret = ReadBlockFromDisk(block, it->second, chainparams.GetConsensus());
        assert(ret);

        SendBlockTransactions(block, req, pfrom, connman);
    }


    else if (strCommand == NetMsgType::GETHEADERS)
    {
        CBlockLocator locator;
        uint256 hashStop;
        vRecv >> locator >> hashStop;

        LOCK(cs_main);
        if (IsInitialBlockDownload() && !pfrom->fWhitelisted) {
            LogPrint("net", "Ignoring getheaders from peer=%d because node is in initial block download\n", pfrom->id);
            return true;
        }

        CNodeState *nodestate = State(pfrom->GetId());
        const CBlockIndex* pindex = NULL;
        if (locator.IsNull())
        {
            // If locator is null, return the hashStop block
            BlockMap::iterator mi = mapBlockIndex.find(hashStop);
            if (mi == mapBlockIndex.end())
                return true;
            pindex = (*mi).second;
        }
        else
        {
            // Find the last block the caller has in the main chain
            pindex = FindForkInGlobalIndex(chainActive, locator);
            if (pindex)
                pindex = chainActive.Next(pindex);
        }

        // we must use CBlocks, as CBlockHeaders won't include the 0x00 nTx count at the end
        std::vector<CBlock> vHeaders;
        int nLimit = MAX_HEADERS_RESULTS;
        LogPrint("net", "getheaders %d to %s from peer=%d\n", (pindex ? pindex->nHeight : -1), hashStop.IsNull() ? "end" : hashStop.ToString(), pfrom->id);
        for (; pindex; pindex = chainActive.Next(pindex))
        {
            vHeaders.push_back(pindex->GetBlockHeader());
            if (--nLimit <= 0 || pindex->GetBlockHash() == hashStop)
                break;
        }
        // pindex can be NULL either if we sent chainActive.Tip() OR
        // if our peer has chainActive.Tip() (and thus we are sending an empty
        // headers message). In both cases it's safe to update
        // pindexBestHeaderSent to be our tip.
        //
        // It is important that we simply reset the BestHeaderSent value here,
        // and not max(BestHeaderSent, newHeaderSent). We might have announced
        // the currently-being-connected tip using a compact block, which
        // resulted in the peer sending a headers request, which we respond to
        // without the new block. By resetting the BestHeaderSent, we ensure we
        // will re-announce the new block via headers (or compact blocks again)
        // in the SendMessages logic.
        nodestate->pindexBestHeaderSent = pindex ? pindex : chainActive.Tip();
        connman.PushMessage(pfrom, msgMaker.Make(NetMsgType::HEADERS, vHeaders));
    }


    else if (strCommand == NetMsgType::TX)
    {
        // Stop processing the transaction early if
        // We are in blocks only mode and peer is either not whitelisted or whitelistrelay is off
        if (!fRelayTxes && (!pfrom->fWhitelisted || !GetBoolArg("-whitelistrelay", DEFAULT_WHITELISTRELAY)))
        {
            LogPrint("net", "transaction sent in violation of protocol peer=%d\n", pfrom->id);
            return true;
        }

        std::deque<COutPoint> vWorkQueue;
        std::vector<uint256> vEraseQueue;

        FIRO_UNUSED int nInvType = MSG_TX;
        CTransactionRef ptx;

        // Read data and assign inv type
        vRecv >> ptx;

        const CTransaction& tx = *ptx;

        CInv inv(MSG_TX, tx.GetHash());
        pfrom->AddInventoryKnown(inv);

        LOCK(cs_main);

        bool fMissingInputs = false;
        FIRO_UNUSED bool fMissingInputsSigma = false;
        CValidationState state;
        CValidationState dummyState; // Dummy state for Dandelion stempool

        pfrom->setAskFor.erase(inv.hash);
        mapAlreadyAskedFor.erase(inv.hash);

        std::list<CTransactionRef> lRemovedTxn;

        if (!AlreadyHave(inv) && AcceptToMemoryPool(mempool, state, ptx, true, &fMissingInputs, &lRemovedTxn, false, 0, true)) {
            LogPrintf("Transaction %s received and added to the mempool.\n", tx.GetHash().ToString());

            // Changes to mempool should also be made to Dandelion stempool.
            AcceptToMemoryPool(
                txpools.getStemTxPool(),
                dummyState,
                ptx,
                true, /* fLimitFree */
                &fMissingInputs, /* pfMissingInputs */
                nullptr,
                false, /* fOverrideMempoolLimit */
                0, /* nAbsurdFee */
                true, /* isCheckWalletTransaction */
                false /* markFiroSpendTransactionSerial */
            );

            if (CNode::isTxDandelionEmbargoed(tx.GetHash())) {
                CNode::removeDandelionEmbargo(tx.GetHash());
            }

            mempool.check(pcoinsTip);
            connman.RelayTransaction(tx);
            for (unsigned int i = 0; i < tx.vout.size(); i++) {
                vWorkQueue.emplace_back(inv.hash, i);
            }

            pfrom->nLastTXTime = GetTime();

            LogPrint("mempool", "AcceptToMemoryPool: peer=%d: accepted %s (poolsz %u txn, %u kB)\n",
                pfrom->id,
                tx.GetHash().ToString(),
                mempool.size(), mempool.DynamicMemoryUsage() / 1000);

            // Recursively process any orphan transactions that depended on this one
            std::set<NodeId> setMisbehaving;
            while (!vWorkQueue.empty()) {
                auto itByPrev = mapOrphanTransactionsByPrev.find(vWorkQueue.front());
                vWorkQueue.pop_front();
                if (itByPrev == mapOrphanTransactionsByPrev.end())
                    continue;
                for (auto mi = itByPrev->second.begin();
                     mi != itByPrev->second.end();
                     ++mi)
                {
                    const CTransactionRef& porphanTx = (*mi)->second.tx;
                    const CTransaction& orphanTx = *porphanTx;
                    const uint256& orphanHash = orphanTx.GetHash();
                    NodeId fromPeer = (*mi)->second.fromPeer;
                    bool fMissingInputs2 = false;
                    // Use a dummy CValidationState so someone can't setup nodes to counter-DoS based on orphan
                    // resolution (that is, feeding people an invalid transaction based on LegitTxX in order to get
                    // anyone relaying LegitTxX banned)
                    CValidationState stateDummy;
                    CValidationState stateDummyDandelion;


                    if (setMisbehaving.count(fromPeer))
                        continue;
                    if (AcceptToMemoryPool(mempool, stateDummy, porphanTx, true, &fMissingInputs2, &lRemovedTxn, false, 0, true)) {
                        LogPrint("mempool", "   accepted orphan tx %s\n", orphanHash.ToString());

                        // Changes to mempool should also be made to Dandelion stempool
                        AcceptToMemoryPool(
                            txpools.getStemTxPool(),
                            stateDummyDandelion,
                            porphanTx,
                            true, /* fLimitFree */
                            &fMissingInputs2,  /* pfMissingInputs */
                            nullptr,
                            false, /* fOverrideMempoolLimit */
                            0, /* nAbsurdFee */
                            true, /* isCheckWalletTransaction */
                            false /* markFiroSpendTransactionSerial */
                        );

                        connman.RelayTransaction(orphanTx);
                        for (unsigned int i = 0; i < orphanTx.vout.size(); i++) {
                            vWorkQueue.emplace_back(orphanHash, i);
                        }
                        vEraseQueue.push_back(orphanHash);
                    }
                    else if (!fMissingInputs2)
                    {
                        int nDos = 0;
                        if (stateDummy.IsInvalid(nDos) && nDos > 0)
                        {
                            // Punish peer that gave us an invalid orphan tx
                            Misbehaving(fromPeer, nDos);
                            setMisbehaving.insert(fromPeer);
                            LogPrint("mempool", "   invalid orphan tx %s\n", orphanHash.ToString());
                        }
                        // Has inputs but not accepted to mempool
                        // Probably non-standard or insufficient fee/priority
                        LogPrint("mempool", "   removed orphan tx %s\n", orphanHash.ToString());
                        vEraseQueue.push_back(orphanHash);
                        if (!orphanTx.HasWitness() && !stateDummy.CorruptionPossible()) {
                            // Do not use rejection cache for witness transactions or
                            // witness-stripped transactions, as they can have been malleated.
                            // See https://github.com/bitcoin/bitcoin/issues/8279 for details.
                            assert(recentRejects);
                            recentRejects->insert(orphanHash);
                        }
                    }
                    mempool.check(pcoinsTip);
                }
            }

            BOOST_FOREACH(uint256 hash, vEraseQueue)
                EraseOrphanTx(hash);
        }
        else if (fMissingInputs)
        {
            bool fRejectedParents = false; // It may be the case that the orphans parents have all been rejected
            BOOST_FOREACH(const CTxIn& txin, tx.vin) {
                if (recentRejects->contains(txin.prevout.hash)) {
                    fRejectedParents = true;
                    break;
                }
            }
            if (!fRejectedParents) {
                uint32_t nFetchFlags = GetFetchFlags(pfrom, chainActive.Tip(), chainparams.GetConsensus());
                BOOST_FOREACH(const CTxIn& txin, tx.vin) {
                    CInv _inv(MSG_TX | nFetchFlags, txin.prevout.hash);
                    pfrom->AddInventoryKnown(_inv);
                    if (!AlreadyHave(_inv)) pfrom->AskFor(_inv);
                }
                AddOrphanTx(ptx, pfrom->GetId());

                // DoS prevention: do not allow mapOrphanTransactions to grow unbounded
                unsigned int nMaxOrphanTx = (unsigned int)std::max((int64_t)0, GetArg("-maxorphantx", DEFAULT_MAX_ORPHAN_TRANSACTIONS));
                unsigned int nEvicted = LimitOrphanTxSize(nMaxOrphanTx);
                if (nEvicted > 0)
                    LogPrint("mempool", "mapOrphan overflow, removed %u tx\n", nEvicted);
            } else {
                LogPrint("mempool", "not keeping orphan with rejected parents %s\n",tx.GetHash().ToString());
                // We will continue to reject this tx since it has rejected
                // parents so avoid re-requesting it from other peers.
                recentRejects->insert(tx.GetHash());
            }
        } else {
            if (!tx.HasWitness() && !state.CorruptionPossible()) {
                // Do not use rejection cache for witness transactions or
                // witness-stripped transactions, as they can have been malleated.
                // See https://github.com/bitcoin/bitcoin/issues/8279 for details.
                assert(recentRejects);
                recentRejects->insert(tx.GetHash());
                if (RecursiveDynamicUsage(*ptx) < 100000) {
                    AddToCompactExtraTransactions(ptx);
                }
            } else if (tx.HasWitness() && RecursiveDynamicUsage(*ptx) < 100000) {
                AddToCompactExtraTransactions(ptx);
            }

            if (pfrom->fWhitelisted && GetBoolArg("-whitelistforcerelay", DEFAULT_WHITELISTFORCERELAY)) {
                // Always relay transactions received from whitelisted peers, even
                // if they were already in the mempool or rejected from it due
                // to policy, allowing the node to function as a gateway for
                // nodes hidden behind it.
                //
                // Never relay transactions that we would assign a non-zero DoS
                // score for, as we expect peers to do the same with us in that
                // case.
                int nDoS = 0;
                if (!state.IsInvalid(nDoS) || nDoS == 0) {
                    LogPrintf("Force relaying tx %s from whitelisted peer=%d\n", tx.GetHash().ToString(), pfrom->id);
                    connman.RelayTransaction(tx);
                } else {
                    LogPrintf("Not relaying invalid transaction %s from whitelisted peer=%d (%s)\n", tx.GetHash().ToString(), pfrom->id, FormatStateMessage(state));
                }
            }
        }

        for (const CTransactionRef& removedTx : lRemovedTxn)
            AddToCompactExtraTransactions(removedTx);

        int nDoS = 0;
        if (state.IsInvalid(nDoS))
        {
            LogPrint("mempoolrej", "%s from peer=%d was not accepted: %s\n", tx.GetHash().ToString(),
                pfrom->id,
                FormatStateMessage(state));
            if (state.GetRejectCode() < REJECT_INTERNAL) // Never send AcceptToMemoryPool's internal codes over P2P
                connman.PushMessage(pfrom, msgMaker.Make(NetMsgType::REJECT, strCommand, (unsigned char)state.GetRejectCode(),
                                   state.GetRejectReason().substr(0, MAX_REJECT_MESSAGE_LENGTH), inv.hash));
            if (nDoS > 0) {
                Misbehaving(pfrom->GetId(), nDoS);
            }
        }
    }


    else if (strCommand == NetMsgType::DANDELIONTX)
    {
        CValidationState state;
        CTransactionRef ptx;
        vRecv >> ptx;
        const CTransaction &tx = *ptx;

        bool fMissingInputs = false;
        std::list<CTransaction> lRemovedTxn;
        CInv inv(MSG_DANDELION_TX, tx.GetHash());
        LOCK(cs_main);
        if (CNode::isDandelionInbound(pfrom)) {
            if (!txpools.getStemTxPool().exists(inv.hash)) {
                bool ret = AcceptToMemoryPool(
                    txpools.getStemTxPool(),
                    state,
                    ptx,
                    true, // fLimitFree
                    &fMissingInputs,
                    nullptr, //&lRemovedTxn,
                    false, /* fOverrideMempoolLimit */
                    0, /* nAbsurdFee */
                    false, /* isCheckWalletTransaction */
                    false /* markFiroSpendTransactionSerial */
                    );
                if (ret) {
                    LogPrint("mempool",
                             "AcceptToStemPool: peer=%d: accepted %s (poolsz %u txn, %u kB)\n",
                             pfrom->GetId(),
                             tx.GetHash().ToString(),
                             txpools.getStemTxPool().size(),
                             txpools.getStemTxPool().DynamicMemoryUsage() / 1000);
                    int64_t nCurrTime = GetTimeMicros();
                    const auto& consensus = Params().GetConsensus();
                    int64_t nEmbargo = 1000000 * consensus.nDandelionEmbargoMinimum +
                        PoissonNextSend(nCurrTime, consensus.nDandelionEmbargoAvgAdd);
                    pfrom->insertDandelionEmbargo(tx.GetHash(), nEmbargo);
               }
                int nDoS = 0;
                if (state.IsInvalid(nDoS)) {
                    LogPrint(
                        "mempool-reject",
                        "%s from peer=%d was not accepted: %s\n",
                        tx.GetHash().ToString(),
                        pfrom->GetId(),
                        FormatStateMessage(state));
                    // Never send AcceptToMemoryPool's internal codes over P2P
                    if (state.GetRejectCode() > 0 &&
                        state.GetRejectCode() < REJECT_INTERNAL) {
                        connman.PushMessage(pfrom, msgMaker.Make(NetMsgType::REJECT, strCommand, (unsigned char) state.GetRejectCode(),
                            state.GetRejectReason().substr(0, MAX_REJECT_MESSAGE_LENGTH), inv.hash));
                    }
                    if (nDoS > 0) {
                        Misbehaving(pfrom->GetId(), nDoS);
                    }
                }
            }
            // If the transaction already was in the stempool,
            // Or we just successfully added it there, relay it.
            // It will either get relayed to one Dandelion destination, or fluff phase will start.
            if (txpools.getStemTxPool().exists(inv.hash)) {
                CNode::RelayDandelionTransaction(tx, pfrom);
            }
        }
    }
    

    else if (strCommand == NetMsgType::CMPCTBLOCK && !fImporting && !fReindex) // Ignore blocks received while importing
    {
        CBlockHeaderAndShortTxIDs cmpctblock;
        vRecv >> cmpctblock;

        {
        LOCK(cs_main);

        if (mapBlockIndex.find(cmpctblock.header.hashPrevBlock) == mapBlockIndex.end()) {
            // Doesn't connect (or is genesis), instead of DoSing in AcceptBlockHeader, request deeper headers
            if (!IsInitialBlockDownload())
                connman.PushMessage(pfrom, msgMaker.Make(NetMsgType::GETHEADERS, chainActive.GetLocator(pindexBestHeader), uint256()));
            return true;
        }
        }

        const CBlockIndex *pindex = NULL;
        CValidationState state;
        if (!ProcessNewBlockHeaders({cmpctblock.header}, state, chainparams, &pindex)) {
            int nDoS;
            if (state.IsInvalid(nDoS)) {
                if (nDoS > 0) {
                    LOCK(cs_main);
                    Misbehaving(pfrom->GetId(), nDoS);
                }
                LogPrintf("Peer %d sent us invalid header via cmpctblock\n", pfrom->id);
                return true;
            }
        }

        // When we succeed in decoding a block's txids from a cmpctblock
        // message we typically jump to the BLOCKTXN handling code, with a
        // dummy (empty) BLOCKTXN message, to re-use the logic there in
        // completing processing of the putative block (without cs_main).
        bool fProcessBLOCKTXN = false;
        CDataStream blockTxnMsg(SER_NETWORK, PROTOCOL_VERSION);

        // If we end up treating this as a plain headers message, call that as well
        // without cs_main.
        bool fRevertToHeaderProcessing = false;
        CDataStream vHeadersMsg(SER_NETWORK, PROTOCOL_VERSION);

        // Keep a CBlock for "optimistic" compactblock reconstructions (see
        // below)
        std::shared_ptr<CBlock> pblock = std::make_shared<CBlock>();
        bool fBlockReconstructed = false;

        {
        LOCK(cs_main);
        // If AcceptBlockHeader returned true, it set pindex
        assert(pindex);
        UpdateBlockAvailability(pfrom->GetId(), pindex->GetBlockHash());

        std::map<uint256, std::pair<NodeId, std::list<QueuedBlock>::iterator> >::iterator blockInFlightIt = mapBlocksInFlight.find(pindex->GetBlockHash());
        bool fAlreadyInFlight = blockInFlightIt != mapBlocksInFlight.end();

        if (pindex->nStatus & BLOCK_HAVE_DATA) // Nothing to do here
            return true;

        if (pindex->nChainWork <= chainActive.Tip()->nChainWork || // We know something better
                pindex->nTx != 0) { // We had this block at some point, but pruned it
            if (fAlreadyInFlight) {
                // We requested this block for some reason, but our mempool will probably be useless
                // so we just grab the block via normal getdata
                std::vector<CInv> vInv(1);
                vInv[0] = CInv(MSG_BLOCK | GetFetchFlags(pfrom, pindex->pprev, chainparams.GetConsensus()), cmpctblock.header.GetHash());
                connman.PushMessage(pfrom, msgMaker.Make(NetMsgType::GETDATA, vInv));
            }
            return true;
        }

        // If we're not close to tip yet, give up and let parallel block fetch work its magic
        if (!fAlreadyInFlight && !CanDirectFetch(chainparams.GetConsensus()))
            return true;

        CNodeState *nodestate = State(pfrom->GetId());

        if (IsWitnessEnabled(pindex->pprev, chainparams.GetConsensus()) && !nodestate->fSupportsDesiredCmpctVersion) {
            // Don't bother trying to process compact blocks from v1 peers
            // after segwit activates.
            return true;
        }

        // We want to be a bit conservative just to be extra careful about DoS
        // possibilities in compact block processing...
        if (pindex->nHeight <= chainActive.Height() + 2) {
            if ((!fAlreadyInFlight && nodestate->nBlocksInFlight < MAX_BLOCKS_IN_TRANSIT_PER_PEER) ||
                 (fAlreadyInFlight && blockInFlightIt->second.first == pfrom->GetId())) {
                std::list<QueuedBlock>::iterator* queuedBlockIt = NULL;
                if (!MarkBlockAsInFlight(pfrom->GetId(), pindex->GetBlockHash(), chainparams.GetConsensus(), pindex, &queuedBlockIt)) {
                    if (!(*queuedBlockIt)->partialBlock)
                        (*queuedBlockIt)->partialBlock.reset(new PartiallyDownloadedBlock(&mempool));
                    else {
                        // The block was already in flight using compact blocks from the same peer
                        LogPrint("net", "Peer sent us compact block we were already syncing!\n");
                        return true;
                    }
                }

                PartiallyDownloadedBlock& partialBlock = *(*queuedBlockIt)->partialBlock;
                ReadStatus status = partialBlock.InitData(cmpctblock, vExtraTxnForCompact);
                if (status == READ_STATUS_INVALID) {
                    MarkBlockAsReceived(pindex->GetBlockHash()); // Reset in-flight state in case of whitelist
                    Misbehaving(pfrom->GetId(), 100);
                    LogPrintf("Peer %d sent us invalid compact block\n", pfrom->id);
                    return true;
                } else if (status == READ_STATUS_FAILED) {
                    // Duplicate txindexes, the block is now in-flight, so just request it
                    std::vector<CInv> vInv(1);
                    vInv[0] = CInv(MSG_BLOCK | GetFetchFlags(pfrom, pindex->pprev, chainparams.GetConsensus()), cmpctblock.header.GetHash());
                    connman.PushMessage(pfrom, msgMaker.Make(NetMsgType::GETDATA, vInv));
                    return true;
                }

                BlockTransactionsRequest req;
                for (size_t i = 0; i < cmpctblock.BlockTxCount(); i++) {
                    if (!partialBlock.IsTxAvailable(i))
                        req.indexes.push_back(i);
                }
                if (req.indexes.empty()) {
                    // Dirty hack to jump to BLOCKTXN code (TODO: move message handling into their own functions)
                    BlockTransactions txn;
                    txn.blockhash = cmpctblock.header.GetHash();
                    blockTxnMsg << txn;
                    fProcessBLOCKTXN = true;
                } else {
                    req.blockhash = pindex->GetBlockHash();
                    connman.PushMessage(pfrom, msgMaker.Make(NetMsgType::GETBLOCKTXN, req));
                }
            } else {
                // This block is either already in flight from a different
                // peer, or this peer has too many blocks outstanding to
                // download from.
                // Optimistically try to reconstruct anyway since we might be
                // able to without any round trips.
                PartiallyDownloadedBlock tempBlock(&mempool);
                ReadStatus status = tempBlock.InitData(cmpctblock, vExtraTxnForCompact);
                if (status != READ_STATUS_OK) {
                    // TODO: don't ignore failures
                    return true;
                }
                std::vector<CTransactionRef> dummy;
                status = tempBlock.FillBlock(*pblock, dummy);
                if (status == READ_STATUS_OK) {
                    fBlockReconstructed = true;
                }
            }
        } else {
            if (fAlreadyInFlight) {
                // We requested this block, but its far into the future, so our
                // mempool will probably be useless - request the block normally
                std::vector<CInv> vInv(1);
                vInv[0] = CInv(MSG_BLOCK | GetFetchFlags(pfrom, pindex->pprev, chainparams.GetConsensus()), cmpctblock.header.GetHash());
                connman.PushMessage(pfrom, msgMaker.Make(NetMsgType::GETDATA, vInv));
                return true;
            } else {
                // If this was an announce-cmpctblock, we want the same treatment as a header message
                // Dirty hack to process as if it were just a headers message (TODO: move message handling into their own functions)
                std::vector<CBlock> headers;
                headers.push_back(cmpctblock.header);
                vHeadersMsg << headers;
                fRevertToHeaderProcessing = true;
            }
        }
        } // cs_main

        if (fProcessBLOCKTXN)
            return ProcessMessage(pfrom, NetMsgType::BLOCKTXN, blockTxnMsg, nTimeReceived, chainparams, connman, interruptMsgProc);

        if (fRevertToHeaderProcessing)
            return ProcessMessage(pfrom, NetMsgType::HEADERS, vHeadersMsg, nTimeReceived, chainparams, connman, interruptMsgProc);

        if (fBlockReconstructed) {
            // If we got here, we were able to optimistically reconstruct a
            // block that is in flight from some other peer.
            {
                LOCK(cs_main);
                mapBlockSource.emplace(pblock->GetHash(), std::make_pair(pfrom->GetId(), false));
            }
            bool fNewBlock = false;
            ProcessNewBlock(chainparams, pblock, true, &fNewBlock);
            if (fNewBlock)
                pfrom->nLastBlockTime = GetTime();

            LOCK(cs_main); // hold cs_main for CBlockIndex::IsValid()
            if (pindex->IsValid(BLOCK_VALID_TRANSACTIONS)) {
                // Clear download state for this block, which is in
                // process from some other peer.  We do this after calling
                // ProcessNewBlock so that a malleated cmpctblock announcement
                // can't be used to interfere with block relay.
                MarkBlockAsReceived(pblock->GetHash());
            }
        }

    }

    else if (strCommand == NetMsgType::BLOCKTXN && !fImporting && !fReindex) // Ignore blocks received while importing
    {
        BlockTransactions resp;
        vRecv >> resp;

        std::shared_ptr<CBlock> pblock = std::make_shared<CBlock>();
        bool fBlockRead = false;
        {
            LOCK(cs_main);

            std::map<uint256, std::pair<NodeId, std::list<QueuedBlock>::iterator> >::iterator it = mapBlocksInFlight.find(resp.blockhash);
            if (it == mapBlocksInFlight.end() || !it->second.second->partialBlock ||
                    it->second.first != pfrom->GetId()) {
                LogPrint("net", "Peer %d sent us block transactions for block we weren't expecting\n", pfrom->id);
                return true;
            }

            PartiallyDownloadedBlock& partialBlock = *it->second.second->partialBlock;
            ReadStatus status = partialBlock.FillBlock(*pblock, resp.txn);
            if (status == READ_STATUS_INVALID) {
                MarkBlockAsReceived(resp.blockhash); // Reset in-flight state in case of whitelist
                Misbehaving(pfrom->GetId(), 100);
                LogPrintf("Peer %d sent us invalid compact block/non-matching block transactions\n", pfrom->id);
                return true;
            } else if (status == READ_STATUS_FAILED) {
                // Might have collided, fall back to getdata now :(
                std::vector<CInv> invs;
                invs.push_back(CInv(MSG_BLOCK | GetFetchFlags(pfrom, chainActive.Tip(), chainparams.GetConsensus()), resp.blockhash));
                connman.PushMessage(pfrom, msgMaker.Make(NetMsgType::GETDATA, invs));
            } else {
                // Block is either okay, or possibly we received
                // READ_STATUS_CHECKBLOCK_FAILED.
                // Note that CheckBlock can only fail for one of a few reasons:
                // 1. bad-proof-of-work (impossible here, because we've already
                //    accepted the header)
                // 2. merkleroot doesn't match the transactions given (already
                //    caught in FillBlock with READ_STATUS_FAILED, so
                //    impossible here)
                // 3. the block is otherwise invalid (eg invalid coinbase,
                //    block is too big, too many legacy sigops, etc).
                // So if CheckBlock failed, #3 is the only possibility.
                // Under BIP 152, we don't DoS-ban unless proof of work is
                // invalid (we don't require all the stateless checks to have
                // been run).  This is handled below, so just treat this as
                // though the block was successfully read, and rely on the
                // handling in ProcessNewBlock to ensure the block index is
                // updated, reject messages go out, etc.
                MarkBlockAsReceived(resp.blockhash); // it is now an empty pointer
                fBlockRead = true;
                // mapBlockSource is only used for sending reject messages and DoS scores,
                // so the race between here and cs_main in ProcessNewBlock is fine.
                // BIP 152 permits peers to relay compact blocks after validating
                // the header only; we should not punish peers if the block turns
                // out to be invalid.
                mapBlockSource.emplace(resp.blockhash, std::make_pair(pfrom->GetId(), false));
            }
        } // Don't hold cs_main when we call into ProcessNewBlock
        if (fBlockRead) {
            bool fNewBlock = false;
            // Since we requested this block (it was in mapBlocksInFlight), force it to be processed,
            // even if it would not be a candidate for new tip (missing previous block, chain not long enough, etc)

            ProcessNewBlock(chainparams, pblock, true, &fNewBlock);
            if (fNewBlock)
                pfrom->nLastBlockTime = GetTime();
        }
    }


    else if (strCommand == NetMsgType::HEADERS && !fImporting && !fReindex) // Ignore headers received while importing
    {
        std::vector<CBlockHeader> headers;

        // Bypass the normal CBlock deserialization, as we don't want to risk deserializing 2000 full blocks.
        unsigned int nCount = ReadCompactSize(vRecv);
        if (nCount > MAX_HEADERS_RESULTS) {
            LOCK(cs_main);
            Misbehaving(pfrom->GetId(), 20);
            return error("headers message size = %u", nCount);
        }
        headers.resize(nCount);
        for (unsigned int n = 0; n < nCount; n++) {
            headers[n].SerializationOp(vRecv, CBlockHeader::CReadBlockHeader());
            ReadCompactSize(vRecv); // ignore tx count; assume it is 0.
        }

        if (nCount == 0) {
            // Nothing interesting. Stop asking this peers for more headers.
            return true;
        }

        const CBlockIndex *pindexLast = NULL;
        {
        LOCK(cs_main);
        CNodeState *nodestate = State(pfrom->GetId());

        // If this looks like it could be a block announcement (nCount <
        // MAX_BLOCKS_TO_ANNOUNCE), use special logic for handling headers that
        // don't connect:
        // - Send a getheaders message in response to try to connect the chain.
        // - The peer can send up to MAX_UNCONNECTING_HEADERS in a row that
        //   don't connect before giving DoS points
        // - Once a headers message is received that is valid and does connect,
        //   nUnconnectingHeaders gets reset back to 0.
        if (mapBlockIndex.find(headers[0].hashPrevBlock) == mapBlockIndex.end() && nCount < MAX_BLOCKS_TO_ANNOUNCE) {
            nodestate->nUnconnectingHeaders++;
            connman.PushMessage(pfrom, msgMaker.Make(NetMsgType::GETHEADERS, chainActive.GetLocator(pindexBestHeader), uint256()));
            LogPrint("net", "received header %s: missing prev block %s, sending getheaders (%d) to end (peer=%d, nUnconnectingHeaders=%d)\n",
                    headers[0].GetHash().ToString(),
                    headers[0].hashPrevBlock.ToString(),
                    pindexBestHeader->nHeight,
                    pfrom->id, nodestate->nUnconnectingHeaders);
            // Set hashLastUnknownBlock for this peer, so that if we
            // eventually get the headers - even from a different peer -
            // we can use this peer to download.
            UpdateBlockAvailability(pfrom->GetId(), headers.back().GetHash());

            if (nodestate->nUnconnectingHeaders % MAX_UNCONNECTING_HEADERS == 0) {
                Misbehaving(pfrom->GetId(), 20);
            }
            return true;
        }

        uint256 hashLastBlock;
        for (const CBlockHeader& header : headers) {
            if (!hashLastBlock.IsNull() && header.hashPrevBlock != hashLastBlock) {
                Misbehaving(pfrom->GetId(), 20);
                return error("non-continuous headers sequence");
            }
            hashLastBlock = header.GetHash();
        }
        }

        CValidationState state;
        if (!ProcessNewBlockHeaders(headers, state, chainparams, &pindexLast)) {
            int nDoS;
            if (state.IsInvalid(nDoS)) {
                if (nDoS > 0) {
                    LOCK(cs_main);
                    Misbehaving(pfrom->GetId(), nDoS);
                }
                return error("invalid header received");
            }
        }

        {
        LOCK(cs_main);
        CNodeState *nodestate = State(pfrom->GetId());
        if (nodestate->nUnconnectingHeaders > 0) {
            LogPrint("net", "peer=%d: resetting nUnconnectingHeaders (%d -> 0)\n", pfrom->id, nodestate->nUnconnectingHeaders);
        }
        nodestate->nUnconnectingHeaders = 0;

        assert(pindexLast);
        UpdateBlockAvailability(pfrom->GetId(), pindexLast->GetBlockHash());

        if (nCount == MAX_HEADERS_RESULTS) {
            // Headers message had its maximum size; the peer may have more headers.
            // TODO: optimize: if pindexLast is an ancestor of chainActive.Tip or pindexBestHeader, continue
            // from there instead.
            LogPrint("net", "more getheaders (%d) to end to peer=%d (startheight:%d)\n", pindexLast->nHeight, pfrom->id, pfrom->nStartingHeight);
            connman.PushMessage(pfrom, msgMaker.Make(NetMsgType::GETHEADERS, chainActive.GetLocator(pindexLast), uint256()));
        }

        bool fCanDirectFetch = CanDirectFetch(chainparams.GetConsensus());
        // If this set of headers is valid and ends in a block with at least as
        // much work as our tip, download as much as possible.
        if (fCanDirectFetch && pindexLast->IsValid(BLOCK_VALID_TREE) && chainActive.Tip()->nChainWork <= pindexLast->nChainWork) {
            std::vector<const CBlockIndex*> vToFetch;
            const CBlockIndex *pindexWalk = pindexLast;
            // Calculate all the blocks we'd need to switch to pindexLast, up to a limit.
            while (pindexWalk && !chainActive.Contains(pindexWalk) && vToFetch.size() <= MAX_BLOCKS_IN_TRANSIT_PER_PEER) {
                if (!(pindexWalk->nStatus & BLOCK_HAVE_DATA) &&
                        !mapBlocksInFlight.count(pindexWalk->GetBlockHash()) &&
                        (!IsWitnessEnabled(pindexWalk->pprev, chainparams.GetConsensus()) || State(pfrom->GetId())->fHaveWitness)) {
                    // We don't have this block, and it's not yet in flight.
                    vToFetch.push_back(pindexWalk);
                }
                pindexWalk = pindexWalk->pprev;
            }
            // If pindexWalk still isn't on our main chain, we're looking at a
            // very large reorg at a time we think we're close to caught up to
            // the main chain -- this shouldn't really happen.  Bail out on the
            // direct fetch and rely on parallel download instead.
            if (!chainActive.Contains(pindexWalk)) {
                LogPrint("net", "Large reorg, won't direct fetch to %s (%d)\n",
                        pindexLast->GetBlockHash().ToString(),
                        pindexLast->nHeight);
            } else {
                std::vector<CInv> vGetData;
                // Download as much as possible, from earliest to latest.
                BOOST_REVERSE_FOREACH(const CBlockIndex *pindex, vToFetch) {
                    if (nodestate->nBlocksInFlight >= MAX_BLOCKS_IN_TRANSIT_PER_PEER) {
                        // Can't download any more from this peer
                        break;
                    }
                    uint32_t nFetchFlags = GetFetchFlags(pfrom, pindex->pprev, chainparams.GetConsensus());
                    vGetData.push_back(CInv(MSG_BLOCK | nFetchFlags, pindex->GetBlockHash()));
                    MarkBlockAsInFlight(pfrom->GetId(), pindex->GetBlockHash(), chainparams.GetConsensus(), pindex);
                    LogPrint("net", "Requesting block %s from  peer=%d\n",
                            pindex->GetBlockHash().ToString(), pfrom->id);
                }
                if (vGetData.size() > 1) {
                    LogPrint("net", "Downloading blocks toward %s (%d) via headers direct fetch\n",
                            pindexLast->GetBlockHash().ToString(), pindexLast->nHeight);
                }
                if (vGetData.size() > 0) {
                    if (nodestate->fSupportsDesiredCmpctVersion && vGetData.size() == 1 && mapBlocksInFlight.size() == 1 && pindexLast->pprev->IsValid(BLOCK_VALID_CHAIN)) {
                        // In any case, we want to download using a compact block, not a regular one
                        vGetData[0] = CInv(MSG_CMPCT_BLOCK, vGetData[0].hash);
                    }
                    connman.PushMessage(pfrom, msgMaker.Make(NetMsgType::GETDATA, vGetData));
                }
            }
        }
        }
    }

    else if (strCommand == NetMsgType::BLOCK && !fImporting && !fReindex) // Ignore blocks received while importing
    {
        std::shared_ptr<CBlock> pblock = std::make_shared<CBlock>();
        vRecv >> *pblock;

        if (pblock->IsMTP() && !pblock->IsProgPow() && pblock->mtpHashData && GetTime() >= chainparams.GetConsensus().nMTPStripDataTime)
        {
            // we don't need MTP data anymore
            pblock->mtpHashData->StripMTPData();
        }

        LogPrint("net", "received block %s peer=%d\n", pblock->GetHash().ToString(), pfrom->id);

        // Process all blocks from whitelisted peers, even if not requested,
        // unless we're still syncing with the network.
        // Such an unrequested block may still be processed, subject to the
        // conditions in AcceptBlock().
        bool forceProcessing = pfrom->fWhitelisted && !IsInitialBlockDownload();
        const uint256 hash(pblock->GetHash());
        {
            LOCK(cs_main);
            // Also always process if we requested the block explicitly, as we may
            // need it even though it is not a candidate for a new best tip.
            forceProcessing |= MarkBlockAsReceived(hash);
            // mapBlockSource is only used for sending reject messages and DoS scores,
            // so the race between here and cs_main in ProcessNewBlock is fine.
            mapBlockSource.emplace(hash, std::make_pair(pfrom->GetId(), true));
        }
        bool fNewBlock = false;
        ProcessNewBlock(chainparams, pblock, forceProcessing, &fNewBlock);
        if (fNewBlock)
            pfrom->nLastBlockTime = GetTime();
    }


    else if (strCommand == NetMsgType::GETADDR)
    {
        // This asymmetric behavior for inbound and outbound connections was introduced
        // to prevent a fingerprinting attack: an attacker can send specific fake addresses
        // to users' AddrMan and later request them by sending getaddr messages.
        // Making nodes which are behind NAT and can only make outgoing connections ignore
        // the getaddr message mitigates the attack.
        if (!pfrom->fInbound) {
            LogPrint("net", "Ignoring \"getaddr\" from outbound connection. peer=%d\n", pfrom->id);
            return true;
        }

        // Only send one GetAddr response per connection to reduce resource waste
        //  and discourage addr stamping of INV announcements.
        if (pfrom->fSentAddr) {
            LogPrint("net", "Ignoring repeated \"getaddr\". peer=%d\n", pfrom->id);
            return true;
        }
        pfrom->fSentAddr = true;

        pfrom->vAddrToSend.clear();
        std::vector<CAddress> vAddr = connman.GetAddresses();
        FastRandomContext insecure_rand;
        BOOST_FOREACH(const CAddress &addr, vAddr)
            pfrom->PushAddress(addr, insecure_rand);
    }


    else if (strCommand == NetMsgType::MEMPOOL)
    {
        if (!(pfrom->GetLocalServices() & NODE_BLOOM) && !pfrom->fWhitelisted)
        {
            LogPrint("net", "mempool request with bloom filters disabled, disconnect peer=%d\n", pfrom->GetId());
            pfrom->fDisconnect = true;
            return true;
        }

        if (connman.OutboundTargetReached(false) && !pfrom->fWhitelisted)
        {
            LogPrint("net", "mempool request with bandwidth limit reached, disconnect peer=%d\n", pfrom->GetId());
            pfrom->fDisconnect = true;
            return true;
        }

        LOCK(pfrom->cs_inventory);
        pfrom->fSendMempool = true;
    }


    else if (strCommand == NetMsgType::PING)
    {
        if (pfrom->nVersion > BIP0031_VERSION)
        {
            uint64_t nonce = 0;
            vRecv >> nonce;
            // Echo the message back with the nonce. This allows for two useful features:
            //
            // 1) A remote node can quickly check if the connection is operational
            // 2) Remote nodes can measure the latency of the network thread. If this node
            //    is overloaded it won't respond to pings quickly and the remote node can
            //    avoid sending us more work, like chain download requests.
            //
            // The nonce stops the remote getting confused between different pings: without
            // it, if the remote node sends a ping once per second and this node takes 5
            // seconds to respond to each, the 5th ping the remote sends would appear to
            // return very quickly.
            connman.PushMessage(pfrom, msgMaker.Make(NetMsgType::PONG, nonce));
        }
    }


    else if (strCommand == NetMsgType::PONG)
    {
        int64_t pingUsecEnd = nTimeReceived;
        uint64_t nonce = 0;
        size_t nAvail = vRecv.in_avail();
        bool bPingFinished = false;
        std::string sProblem;

        if (nAvail >= sizeof(nonce)) {
            vRecv >> nonce;

            // Only process pong message if there is an outstanding ping (old ping without nonce should never pong)
            if (pfrom->nPingNonceSent != 0) {
                if (nonce == pfrom->nPingNonceSent) {
                    // Matching pong received, this ping is no longer outstanding
                    bPingFinished = true;
                    int64_t pingUsecTime = pingUsecEnd - pfrom->nPingUsecStart;
                    if (pingUsecTime > 0) {
                        // Successful ping time measurement, replace previous
                        pfrom->nPingUsecTime = pingUsecTime;
                        pfrom->nMinPingUsecTime = std::min(pfrom->nMinPingUsecTime.load(), pingUsecTime);
                    } else {
                        // This should never happen
                        sProblem = "Timing mishap";
                    }
                } else {
                    // Nonce mismatches are normal when pings are overlapping
                    sProblem = "Nonce mismatch";
                    if (nonce == 0) {
                        // This is most likely a bug in another implementation somewhere; cancel this ping
                        bPingFinished = true;
                        sProblem = "Nonce zero";
                    }
                }
            } else {
                sProblem = "Unsolicited pong without ping";
            }
        } else {
            // This is most likely a bug in another implementation somewhere; cancel this ping
            bPingFinished = true;
            sProblem = "Short payload";
        }

        if (!(sProblem.empty())) {
            LogPrint("net", "pong peer=%d: %s, %x expected, %x received, %u bytes\n",
                pfrom->id,
                sProblem,
                pfrom->nPingNonceSent,
                nonce,
                nAvail);
        }
        if (bPingFinished) {
            pfrom->nPingNonceSent = 0;
        }
    }


    else if (strCommand == NetMsgType::FILTERLOAD)
    {
        CBloomFilter filter;
        vRecv >> filter;

        if (!filter.IsWithinSizeConstraints())
        {
            // There is no excuse for sending a too-large filter
            LOCK(cs_main);
            Misbehaving(pfrom->GetId(), 100);
        }
        else
        {
            LOCK(pfrom->cs_filter);
            delete pfrom->pfilter;
            pfrom->pfilter = new CBloomFilter(filter);
            pfrom->pfilter->UpdateEmptyFull();
            pfrom->fRelayTxes = true;
        }
    }


    else if (strCommand == NetMsgType::FILTERADD)
    {
        std::vector<unsigned char> vData;
        vRecv >> vData;

        // Nodes must NEVER send a data item > 520 bytes (the max size for a script data object,
        // and thus, the maximum size any matched object can have) in a filteradd message
        bool bad = false;
        if (vData.size() > MAX_SCRIPT_ELEMENT_SIZE) {
            bad = true;
        } else {
            LOCK(pfrom->cs_filter);
            if (pfrom->pfilter) {
                pfrom->pfilter->insert(vData);
            } else {
                bad = true;
            }
        }
        if (bad) {
            LOCK(cs_main);
            Misbehaving(pfrom->GetId(), 100);
        }
    }


    else if (strCommand == NetMsgType::FILTERCLEAR)
    {
        LOCK(pfrom->cs_filter);
        if (pfrom->GetLocalServices() & NODE_BLOOM) {
            delete pfrom->pfilter;
            pfrom->pfilter = new CBloomFilter();
        }
        pfrom->fRelayTxes = true;
    }

    else if (strCommand == NetMsgType::FEEFILTER) {
        CAmount newFeeFilter = 0;
        vRecv >> newFeeFilter;
        if (MoneyRange(newFeeFilter)) {
            {
                LOCK(pfrom->cs_feeFilter);
                pfrom->minFeeFilter = newFeeFilter;
            }
            LogPrint("net", "received: feefilter of %s from peer=%d\n", CFeeRate(newFeeFilter).ToString(), pfrom->id);
        }
    }

    else if (strCommand == NetMsgType::GETMNLISTDIFF) {
        CGetSimplifiedMNListDiff cmd;
        vRecv >> cmd;

        LOCK(cs_main);

        CSimplifiedMNListDiff mnListDiff;
        std::string strError;
        if (BuildSimplifiedMNListDiff(cmd.baseBlockHash, cmd.blockHash, mnListDiff, strError)) {
            connman.PushMessage(pfrom, msgMaker.Make(NetMsgType::MNLISTDIFF, mnListDiff));
        } else {
            LogPrint("net", "getmnlistdiff failed for baseBlockHash=%s, blockHash=%s. error=%s\n", cmd.baseBlockHash.ToString(), cmd.blockHash.ToString(), strError);
            Misbehaving(pfrom->id, 1);
        }
    }


    else if (strCommand == NetMsgType::MNLISTDIFF) {
        // we have never requested this
        LOCK(cs_main);
        Misbehaving(pfrom->id, 100);
        LogPrint("net", "received not-requested mnlistdiff. peer=%d\n", pfrom->id);
    }

    else if (strCommand == NetMsgType::NOTFOUND) {
        // We do not care about the NOTFOUND message, but logging an Unknown Command
        // message would be undesirable as we transmit it ourselves.
    }

    else {
        bool found = false;
        const std::vector <std::string> &allMessages = getAllNetMessageTypes();
        BOOST_FOREACH(const std::string msg, allMessages) {
            if (msg == strCommand) {
                found = true;
                break;
            }
        }

        if (found) {
            // TODO: remove this temporary solution
            std::string command = strCommand;

            // these functions must be called in transition window
            CMNAuth::ProcessMessage(pfrom, strCommand, vRecv, connman);

            masternodeSync.ProcessMessage(pfrom, strCommand, vRecv);
            llmq::quorumBlockProcessor->ProcessMessage(pfrom, strCommand, vRecv, connman);
            llmq::quorumDKGSessionManager->ProcessMessage(pfrom, strCommand, vRecv, connman);
            llmq::quorumSigSharesManager->ProcessMessage(pfrom, strCommand, vRecv, connman);
            llmq::quorumSigningManager->ProcessMessage(pfrom, strCommand, vRecv, connman);
            llmq::chainLocksHandler->ProcessMessage(pfrom, strCommand, vRecv, connman);
            llmq::quorumInstantSendManager->ProcessMessage(pfrom, strCommand, vRecv, connman);
        } else {
            // Ignore unknown commands for extensibility
            LogPrint("net", "Unknown command \"%s\" from peer=%d\n", SanitizeString(strCommand), pfrom->id);
        }
    }



    return true;
}

static bool SendRejectsAndCheckIfBanned(CNode* pnode, CConnman& connman)
{
    AssertLockHeld(cs_main);
    CNodeState &state = *State(pnode->GetId());

    BOOST_FOREACH(const CBlockReject& reject, state.rejects) {
        connman.PushMessage(pnode, CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::REJECT, (std::string)NetMsgType::BLOCK, reject.chRejectCode, reject.strRejectReason, reject.hashBlock));
    }
    state.rejects.clear();

    if (state.fShouldBan) {
        state.fShouldBan = false;
        if (pnode->fWhitelisted)
            LogPrintf("Warning: not punishing whitelisted peer %s!\n", pnode->addr.ToString());
        else if (pnode->fAddnode)
            LogPrintf("Warning: not punishing addnoded peer %s!\n", pnode->addr.ToString());
        else {
            pnode->fDisconnect = true;
            if (pnode->addr.IsLocal())
                LogPrintf("Warning: not banning local peer %s!\n", pnode->addr.ToString());
            else
            {
                connman.Ban(pnode->addr, BanReasonNodeMisbehaving);
            }
        }
        return true;
    }
    return false;
}

bool ProcessMessages(CNode* pfrom, CConnman& connman, const std::atomic<bool>& interruptMsgProc)
{
    const CChainParams& chainparams = Params();
    //
    // Message format
    //  (4) message start
    //  (12) command
    //  (4) size
    //  (4) checksum
    //  (x) data
    //
    bool fMoreWork = false;

    if (!pfrom->vRecvGetData.empty())
        ProcessGetData(pfrom, chainparams.GetConsensus(), connman, interruptMsgProc);

    if (pfrom->fDisconnect)
        return false;

    // this maintains the order of responses
    if (!pfrom->vRecvGetData.empty()) return true;

        // Don't bother if send buffer is too full to respond anyway
        if (pfrom->fPauseSend)
            return false;

        std::list<CNetMessage> msgs;
        {
            LOCK(pfrom->cs_vProcessMsg);
            if (pfrom->vProcessMsg.empty())
                return false;
            // Just take one message
            msgs.splice(msgs.begin(), pfrom->vProcessMsg, pfrom->vProcessMsg.begin());
            pfrom->nProcessQueueSize -= msgs.front().vRecv.size() + CMessageHeader::HEADER_SIZE;
            pfrom->fPauseRecv = pfrom->nProcessQueueSize > connman.GetReceiveFloodSize();
            fMoreWork = !pfrom->vProcessMsg.empty();
        }
        CNetMessage& msg(msgs.front());

        msg.SetVersion(pfrom->GetRecvVersion());
        // Scan for message start
        if (memcmp(msg.hdr.pchMessageStart, chainparams.MessageStart(), CMessageHeader::MESSAGE_START_SIZE) != 0) {
            LogPrintf("PROCESSMESSAGE: INVALID MESSAGESTART %s peer=%d\n", SanitizeString(msg.hdr.GetCommand()), pfrom->id);
            pfrom->fDisconnect = true;
            return false;
        }

        // Read header
        CMessageHeader& hdr = msg.hdr;
        if (!hdr.IsValid(chainparams.MessageStart()))
        {
            LogPrintf("PROCESSMESSAGE: ERRORS IN HEADER %s peer=%d\n", SanitizeString(hdr.GetCommand()), pfrom->id);
            return fMoreWork;
        }
        std::string strCommand = hdr.GetCommand();

        // Message size
        unsigned int nMessageSize = hdr.nMessageSize;

        // Checksum
        CDataStream& vRecv = msg.vRecv;
        const uint256& hash = msg.GetMessageHash();
        if (memcmp(hash.begin(), hdr.pchChecksum, CMessageHeader::CHECKSUM_SIZE) != 0)
        {
            LogPrintf("%s(%s, %u bytes): CHECKSUM ERROR expected %s was %s\n", __func__,
               SanitizeString(strCommand), nMessageSize,
               HexStr(hash.begin(), hash.begin()+CMessageHeader::CHECKSUM_SIZE),
               HexStr(hdr.pchChecksum, hdr.pchChecksum+CMessageHeader::CHECKSUM_SIZE));
            return fMoreWork;
        }

        // Process message
        bool fRet = false;
        try
        {
            fRet = ProcessMessage(pfrom, strCommand, vRecv, msg.nTime, chainparams, connman, interruptMsgProc);
            if (interruptMsgProc)
                return false;
            if (!pfrom->vRecvGetData.empty())
                fMoreWork = true;
        }
        catch (const std::ios_base::failure& e)
        {
            connman.PushMessage(pfrom, CNetMsgMaker(INIT_PROTO_VERSION).Make(NetMsgType::REJECT, strCommand, REJECT_MALFORMED, std::string("error parsing message")));
            if (strstr(e.what(), "end of data"))
            {
                // Allow exceptions from under-length message on vRecv
                LogPrintf("%s(%s, %u bytes): Exception '%s' caught, normally caused by a message being shorter than its stated length\n", __func__, SanitizeString(strCommand), nMessageSize, e.what());
            }
            else if (strstr(e.what(), "size too large"))
            {
                // Allow exceptions from over-long size
                LogPrintf("%s(%s, %u bytes): Exception '%s' caught\n", __func__, SanitizeString(strCommand), nMessageSize, e.what());
            }
            else if (strstr(e.what(), "non-canonical ReadCompactSize()"))
            {
                // Allow exceptions from non-canonical encoding
                LogPrintf("%s(%s, %u bytes): Exception '%s' caught\n", __func__, SanitizeString(strCommand), nMessageSize, e.what());
            }
            else
            {
                PrintExceptionContinue(std::current_exception(), "ProcessMessages()");
            }
        }
        catch (...) {
            PrintExceptionContinue(std::current_exception(), "ProcessMessages()");
        }

        if (!fRet) {
            LogPrintf("%s(%s, %u bytes) FAILED peer=%d\n", __func__, SanitizeString(strCommand), nMessageSize, pfrom->id);
        }

        LOCK(cs_main);
        SendRejectsAndCheckIfBanned(pfrom, connman);

    return fMoreWork;
}

class CompareInvMempoolOrder
{
    CTxMemPool *mp;
public:
    CompareInvMempoolOrder(CTxMemPool *_mempool)
    {
        mp = _mempool;
    }

    bool operator()(std::set<uint256>::iterator a, std::set<uint256>::iterator b)
    {
        /* As std::make_heap produces a max-heap, we want the entries with the
         * fewest ancestors/highest fee to sort later. */
        return mp->CompareDepthAndScore(*b, *a);
    }
};

bool SendMessages(CNode* pto, CConnman& connman, const std::atomic<bool>& interruptMsgProc)
{
    const Consensus::Params& consensusParams = Params().GetConsensus();
    {
        // Don't send anything until the version handshake is complete
        if (!pto->fSuccessfullyConnected || pto->fDisconnect)
            return true;

        // If we get here, the outgoing message serialization version is set and can't change.
        const CNetMsgMaker msgMaker(pto->GetSendVersion());

        //
        // Message: ping
        //
        bool pingSend = false;
        if (pto->fPingQueued) {
            // RPC ping request by user
            pingSend = true;
        }
        if (pto->nPingNonceSent == 0 && pto->nPingUsecStart + PING_INTERVAL * 1000000 < GetTimeMicros()) {
            // Ping automatically sent as a latency probe & keepalive.
            pingSend = true;
        }
        if (pingSend) {
            uint64_t nonce = 0;
            while (nonce == 0) {
                GetRandBytes((unsigned char*)&nonce, sizeof(nonce));
            }
            pto->fPingQueued = false;
            pto->nPingUsecStart = GetTimeMicros();
            if (pto->nVersion > BIP0031_VERSION) {
                pto->nPingNonceSent = nonce;
                connman.PushMessage(pto, msgMaker.Make(NetMsgType::PING, nonce));
            } else {
                // Peer is too old to support ping command with nonce, pong will never arrive.
                pto->nPingNonceSent = 0;
                connman.PushMessage(pto, msgMaker.Make(NetMsgType::PING));
            }
        }

        TRY_LOCK(cs_main, lockMain); // Acquire cs_main for IsInitialBlockDownload() and CNodeState()
        if (!lockMain)
            return true;

        if (SendRejectsAndCheckIfBanned(pto, connman))
            return true;
        CNodeState &state = *State(pto->GetId());

        // Address refresh broadcast
        int64_t nNow = GetTimeMicros();
        if (!IsInitialBlockDownload() && pto->nNextLocalAddrSend < nNow) {
            AdvertiseLocal(pto);
            pto->nNextLocalAddrSend = PoissonNextSend(nNow, AVG_LOCAL_ADDRESS_BROADCAST_INTERVAL);
        }

        //
        // Message: addr
        //
        if (pto->nNextAddrSend < nNow) {
            pto->nNextAddrSend = PoissonNextSend(nNow, AVG_ADDRESS_BROADCAST_INTERVAL);
            std::vector<CAddress> vAddr;
            vAddr.reserve(pto->vAddrToSend.size());
            BOOST_FOREACH(const CAddress& addr, pto->vAddrToSend)
            {
                if (!pto->addrKnown.contains(addr.GetKey()))
                {
                    pto->addrKnown.insert(addr.GetKey());
                    vAddr.push_back(addr);
                    // receiver rejects addr messages larger than 1000
                    if (vAddr.size() >= 1000)
                    {
                        connman.PushMessage(pto, msgMaker.Make(NetMsgType::ADDR, vAddr));
                        vAddr.clear();
                    }
                }
            }
            pto->vAddrToSend.clear();
            if (!vAddr.empty())
                connman.PushMessage(pto, msgMaker.Make(NetMsgType::ADDR, vAddr));
            // we only send the big addr message once
            if (pto->vAddrToSend.capacity() > 40)
                pto->vAddrToSend.shrink_to_fit();
        }

        // Start block sync
        if (pindexBestHeader == NULL)
            pindexBestHeader = chainActive.Tip();
        bool fFetch = state.fPreferredDownload || (nPreferredDownload == 0 && !pto->fClient && !pto->fOneShot); // Download if this is a nice peer, or we have no nice peers and this one might do.
        if (!state.fSyncStarted && !pto->fClient && !fImporting && !fReindex) {
            // Only actively request headers from a single peer, unless we're close to today.
            if ((nSyncStarted == 0 && fFetch) || pindexBestHeader->GetBlockTime() > GetAdjustedTime() - 24 * 60 * 60) {
                state.fSyncStarted = true;
                nSyncStarted++;
                const CBlockIndex *pindexStart = pindexBestHeader;
                /* If possible, start at the block preceding the currently
                   best known header.  This ensures that we always get a
                   non-empty list of headers back as long as the peer
                   is up-to-date.  With a non-empty response, we can initialise
                   the peer's known best block.  This wouldn't be possible
                   if we requested starting at pindexBestHeader and
                   got back an empty response.  */
                if (pindexStart->pprev)
                    pindexStart = pindexStart->pprev;
                LogPrint("net", "initial getheaders (%d) to peer=%d (startheight:%d)\n", pindexStart->nHeight, pto->id, pto->nStartingHeight);
                connman.PushMessage(pto, msgMaker.Make(NetMsgType::GETHEADERS, chainActive.GetLocator(pindexStart), uint256()));
            }
        }

        // Resend wallet transactions that haven't gotten in a block yet
        // Except during reindex, importing and IBD, when old wallet
        // transactions become unconfirmed and spams other nodes.
        if (!fReindex && !fImporting && !IsInitialBlockDownload())
        {
            GetMainSignals().Broadcast(nTimeBestReceived, &connman);
        }

        //
        // Try sending block announcements via headers
        //
        {
            // If we have less than MAX_BLOCKS_TO_ANNOUNCE in our
            // list of block hashes we're relaying, and our peer wants
            // headers announcements, then find the first header
            // not yet known to our peer but would connect, and send.
            // If no header would connect, or if we have too many
            // blocks, or if the peer doesn't want headers, just
            // add all to the inv queue.
            LOCK(pto->cs_inventory);
            std::vector<CBlock> vHeaders;
            bool fRevertToInv = ((!state.fPreferHeaders &&
                                 (!state.fPreferHeaderAndIDs || pto->vBlockHashesToAnnounce.size() > 1)) ||
                                pto->vBlockHashesToAnnounce.size() > MAX_BLOCKS_TO_ANNOUNCE);
            const CBlockIndex *pBestIndex = NULL; // last header queued for delivery
            ProcessBlockAvailability(pto->id); // ensure pindexBestKnownBlock is up-to-date

            if (!fRevertToInv) {
                bool fFoundStartingHeader = false;
                // Try to find first header that our peer doesn't have, and
                // then send all headers past that one.  If we come across any
                // headers that aren't on chainActive, give up.
                BOOST_FOREACH(const uint256 &hash, pto->vBlockHashesToAnnounce) {
                    BlockMap::iterator mi = mapBlockIndex.find(hash);
                    assert(mi != mapBlockIndex.end());
                    const CBlockIndex *pindex = mi->second;
                    if (chainActive[pindex->nHeight] != pindex) {
                        // Bail out if we reorged away from this block
                        fRevertToInv = true;
                        break;
                    }
                    if (pBestIndex != NULL && pindex->pprev != pBestIndex) {
                        // This means that the list of blocks to announce don't
                        // connect to each other.
                        // This shouldn't really be possible to hit during
                        // regular operation (because reorgs should take us to
                        // a chain that has some block not on the prior chain,
                        // which should be caught by the prior check), but one
                        // way this could happen is by using invalidateblock /
                        // reconsiderblock repeatedly on the tip, causing it to
                        // be added multiple times to vBlockHashesToAnnounce.
                        // Robustly deal with this rare situation by reverting
                        // to an inv.
                        fRevertToInv = true;
                        break;
                    }
                    pBestIndex = pindex;
                    if (fFoundStartingHeader) {
                        // add this to the headers message
                        vHeaders.push_back(pindex->GetBlockHeader());
                    } else if (PeerHasHeader(&state, pindex)) {
                        continue; // keep looking for the first new block
                    } else if (pindex->pprev == NULL || PeerHasHeader(&state, pindex->pprev)) {
                        // Peer doesn't have this header but they do have the prior one.
                        // Start sending headers.
                        fFoundStartingHeader = true;
                        vHeaders.push_back(pindex->GetBlockHeader());
                    } else {
                        // Peer doesn't have this header or the prior one -- nothing will
                        // connect, so bail out.
                        fRevertToInv = true;
                        break;
                    }
                }
            }
            if (!fRevertToInv && !vHeaders.empty()) {
                if (vHeaders.size() == 1 && state.fPreferHeaderAndIDs) {
                    // We only send up to 1 block as header-and-ids, as otherwise
                    // probably means we're doing an initial-ish-sync or they're slow
                    LogPrint("net", "%s sending header-and-ids %s to peer=%d\n", __func__,
                            vHeaders.front().GetHash().ToString(), pto->id);

                    int nSendFlags = state.fWantsCmpctWitness ? 0 : SERIALIZE_TRANSACTION_NO_WITNESS;

                    bool fGotBlockFromCache = false;
                    {
                        LOCK(cs_most_recent_block);
                        if (most_recent_block_hash == pBestIndex->GetBlockHash()) {
                            if (state.fWantsCmpctWitness)
                                connman.PushMessage(pto, msgMaker.Make(nSendFlags, NetMsgType::CMPCTBLOCK, *most_recent_compact_block));
                            else {
                                CBlockHeaderAndShortTxIDs cmpctblock(*most_recent_block, state.fWantsCmpctWitness);
                                connman.PushMessage(pto, msgMaker.Make(nSendFlags, NetMsgType::CMPCTBLOCK, cmpctblock));
                            }
                            fGotBlockFromCache = true;
                        }
                    }
                    if (!fGotBlockFromCache) {
                        CBlock block;
                        bool ret = ReadBlockFromDisk(block, pBestIndex, consensusParams);
                        assert(ret);
                        CBlockHeaderAndShortTxIDs cmpctblock(block, state.fWantsCmpctWitness);
                        connman.PushMessage(pto, msgMaker.Make(nSendFlags, NetMsgType::CMPCTBLOCK, cmpctblock));
                    }
                    state.pindexBestHeaderSent = pBestIndex;
                } else if (state.fPreferHeaders) {
                    if (vHeaders.size() > 1) {
                        LogPrint("net", "%s: %u headers, range (%s, %s), to peer=%d\n", __func__,
                                vHeaders.size(),
                                vHeaders.front().GetHash().ToString(),
                                vHeaders.back().GetHash().ToString(), pto->id);
                    } else {
                        LogPrint("net", "%s: sending header %s to peer=%d\n", __func__,
                                vHeaders.front().GetHash().ToString(), pto->id);
                    }
                    connman.PushMessage(pto, msgMaker.Make(NetMsgType::HEADERS, vHeaders));
                    state.pindexBestHeaderSent = pBestIndex;
                } else
                    fRevertToInv = true;
            }
            if (fRevertToInv) {
                // If falling back to using an inv, just try to inv the tip.
                // The last entry in vBlockHashesToAnnounce was our tip at some point
                // in the past.
                if (!pto->vBlockHashesToAnnounce.empty()) {
                    const uint256 &hashToAnnounce = pto->vBlockHashesToAnnounce.back();
                    BlockMap::iterator mi = mapBlockIndex.find(hashToAnnounce);
                    assert(mi != mapBlockIndex.end());
                    const CBlockIndex *pindex = mi->second;

                    // Warn if we're announcing a block that is not on the main chain.
                    // This should be very rare and could be optimized out.
                    // Just log for now.
                    if (chainActive[pindex->nHeight] != pindex) {
                        LogPrint("net", "Announcing block %s not on main chain (tip=%s)\n",
                            hashToAnnounce.ToString(), chainActive.Tip()->GetBlockHash().ToString());
                    }

                    // If the peer's chain has this block, don't inv it back.
                    if (!PeerHasHeader(&state, pindex)) {
                        pto->PushInventory(CInv(MSG_BLOCK, hashToAnnounce));
                        LogPrint("net", "%s: sending inv peer=%d hash=%s\n", __func__,
                            pto->id, hashToAnnounce.ToString());
                    }
                }
            }
            pto->vBlockHashesToAnnounce.clear();
        }

        //
        // Message: inventory
        //
        std::vector<CInv> vInv;
        {
            LOCK(pto->cs_inventory);
            vInv.reserve(std::max<size_t>(pto->vInventoryBlockToSend.size(), INVENTORY_BROADCAST_MAX));

            // Add blocks
            BOOST_FOREACH(const uint256& hash, pto->vInventoryBlockToSend) {
                vInv.push_back(CInv(MSG_BLOCK, hash));
                if (vInv.size() == MAX_INV_SZ) {
                    connman.PushMessage(pto, msgMaker.Make(NetMsgType::INV, vInv));
                    vInv.clear();
                }
            }
            pto->vInventoryBlockToSend.clear();

            // Add Dandelion transactions
            for (const uint256& hash : pto->vInventoryDandelionTxToSend) {
                pto->setDandelionInventoryKnown.insert(hash);
                uint256 dandelionServiceDiscoveryHash;
                dandelionServiceDiscoveryHash.SetHex(
                    "0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
                if (!pto->fSupportsDandelion && hash != dandelionServiceDiscoveryHash) {
                    //LogPrintf("Pushing transaction MSG_TX %s to %s.",
                    //          hash.ToString(), pto->addr.ToString());
                    vInv.push_back(CInv(MSG_TX, hash));
                } else {
                    vInv.push_back(CInv(MSG_DANDELION_TX, hash));
                }
                if (vInv.size() == MAX_INV_SZ) {
                        connman.PushMessage(pto, msgMaker.Make(NetMsgType::INV, vInv));
                    vInv.clear();
                }
            }
            pto->vInventoryDandelionTxToSend.clear();

            // Check whether periodic sends should happen
            bool fSendTrickle = pto->fWhitelisted;
            if (pto->nNextInvSend < nNow) {
                fSendTrickle = true;
                // Use half the delay for outbound peers, as there is less privacy concern for them.
                pto->nNextInvSend = PoissonNextSend(nNow, INVENTORY_BROADCAST_INTERVAL >> !pto->fInbound);
            }

            // Time to send but the peer has requested we not relay transactions.
            if (fSendTrickle) {
                LOCK(pto->cs_filter);
                if (!pto->fRelayTxes) pto->setInventoryTxToSend.clear();
            }

            // Respond to BIP35 mempool requests
            if (fSendTrickle && pto->fSendMempool) {
                auto vtxinfo = mempool.infoAll();
                pto->fSendMempool = false;
                CAmount filterrate = 0;
                {
                    LOCK(pto->cs_feeFilter);
                    filterrate = pto->minFeeFilter;
                }

                LOCK(pto->cs_filter);

                for (const auto& txinfo : vtxinfo) {
                    const uint256& hash = txinfo.tx->GetHash();
                    CInv inv(MSG_TX, hash);
                    pto->setInventoryTxToSend.erase(hash);
                    if (filterrate) {
                        if (txinfo.feeRate.GetFeePerK() < filterrate)
                            continue;
                    }
                    if (pto->pfilter) {
                        if (!pto->pfilter->IsRelevantAndUpdate(*txinfo.tx)) continue;
                    }
                    pto->filterInventoryKnown.insert(hash);
                    vInv.push_back(inv);
                    if (vInv.size() == MAX_INV_SZ) {
                        connman.PushMessage(pto, msgMaker.Make(NetMsgType::INV, vInv));
                        vInv.clear();
                    }
                }
                pto->timeLastMempoolReq = GetTime();
            }

            // Determine transactions to relay
            if (fSendTrickle) {
                // Produce a vector with all candidates for sending
                std::vector<std::set<uint256>::iterator> vInvTx;
                vInvTx.reserve(pto->setInventoryTxToSend.size());
                for (std::set<uint256>::iterator it = pto->setInventoryTxToSend.begin(); it != pto->setInventoryTxToSend.end(); it++) {
                    vInvTx.push_back(it);
                }
                CAmount filterrate = 0;
                {
                    LOCK(pto->cs_feeFilter);
                    filterrate = pto->minFeeFilter;
                }
                // Topologically and fee-rate sort the inventory we send for privacy and priority reasons.
                // A heap is used so that not all items need sorting if only a few are being sent.
                CompareInvMempoolOrder compareInvMempoolOrder(&mempool);
                std::make_heap(vInvTx.begin(), vInvTx.end(), compareInvMempoolOrder);
                // No reason to drain out at many times the network's capacity,
                // especially since we have many peers and some will draw much shorter delays.
                unsigned int nRelayedTransactions = 0;
                LOCK(pto->cs_filter);
                while (!vInvTx.empty() && nRelayedTransactions < INVENTORY_BROADCAST_MAX) {
                    // Fetch the top element from the heap
                    std::pop_heap(vInvTx.begin(), vInvTx.end(), compareInvMempoolOrder);
                    std::set<uint256>::iterator it = vInvTx.back();
                    vInvTx.pop_back();
                    uint256 hash = *it;
                    // Remove it from the to-be-sent set
                    pto->setInventoryTxToSend.erase(it);
                    // Check if not in the filter already
                    if (pto->filterInventoryKnown.contains(hash)) {
                        continue;
                    }
                    // Not in the mempool anymore? don't bother sending it.
                    auto txinfo = mempool.info(hash);
                    if (!txinfo.tx) {
                        continue;
                    }
                    if (filterrate && txinfo.feeRate.GetFeePerK() < filterrate) {
                        continue;
                    }
                    if (pto->pfilter && !pto->pfilter->IsRelevantAndUpdate(*txinfo.tx)) continue;
                    // Send
                    vInv.push_back(CInv(MSG_TX, hash));
                    nRelayedTransactions++;
                    {
                        // Expire old relay messages
                        while (!vRelayExpiration.empty() && vRelayExpiration.front().first < nNow)
                        {
                            mapRelay.erase(vRelayExpiration.front().second);
                            vRelayExpiration.pop_front();
                        }

                        auto ret = mapRelay.insert(std::make_pair(hash, std::move(txinfo.tx)));
                        if (ret.second) {
                            vRelayExpiration.push_back(std::make_pair(nNow + 15 * 60 * 1000000, ret.first));
                        }
                    }
                    if (vInv.size() == MAX_INV_SZ) {
                        connman.PushMessage(pto, msgMaker.Make(NetMsgType::INV, vInv));
                        vInv.clear();
                    }
                    pto->filterInventoryKnown.insert(hash);
                }
            }

            // Send non-tx/non-block inventory items
            for (const auto& inv : pto->vInventoryOtherToSend) {
                if (pto->filterInventoryKnown.contains(inv.hash)) {
                    continue;
                }
                vInv.push_back(inv);
                pto->filterInventoryKnown.insert(inv.hash);
                if (vInv.size() == MAX_INV_SZ) {
                    connman.PushMessage(pto, msgMaker.Make(NetMsgType::INV, vInv));
                    vInv.clear();
                }
            }
            pto->vInventoryOtherToSend.clear();
        }
        if (!vInv.empty())
            connman.PushMessage(pto, msgMaker.Make(NetMsgType::INV, vInv));

        // Detect whether we're stalling
        nNow = GetTimeMicros();
        if (state.nStallingSince && state.nStallingSince < nNow - 1000000 * BLOCK_STALLING_TIMEOUT) {
            // Stalling only triggers when the block download window cannot move. During normal steady state,
            // the download window should be much larger than the to-be-downloaded set of blocks, so disconnection
            // should only happen during initial block download.
            LogPrintf("Peer=%d is stalling block download, disconnecting\n", pto->id);
            pto->fDisconnect = true;
            return true;
        }
        // In case there is a block that has been in flight from this peer for 2 + 0.5 * N times the block interval
        // (with N the number of peers from which we're downloading validated blocks), disconnect due to timeout.
        // We compensate for other peers to prevent killing off peers due to our own downstream link
        // being saturated. We only count validated in-flight blocks so peers can't advertise non-existing block hashes
        // to unreasonably increase our timeout.
        if (state.vBlocksInFlight.size() > 0) {
            QueuedBlock &queuedBlock = state.vBlocksInFlight.front();
            int nOtherPeersWithValidatedDownloads = nPeersWithValidatedDownloads - (state.nBlocksInFlightValidHeaders > 0);
            if (nNow > state.nDownloadingSince + consensusParams.nPowTargetSpacing * (BLOCK_DOWNLOAD_TIMEOUT_BASE + BLOCK_DOWNLOAD_TIMEOUT_PER_PEER * nOtherPeersWithValidatedDownloads)) {
                LogPrintf("Timeout downloading block %s from peer=%d, disconnecting\n", queuedBlock.hash.ToString(), pto->id);
                pto->fDisconnect = true;
                return true;
            }
        }

        //
        // Message: getdata (blocks)
        //
        std::vector<CInv> vGetData;
        if (!pto->fClient && (fFetch || !IsInitialBlockDownload()) && state.nBlocksInFlight < MAX_BLOCKS_IN_TRANSIT_PER_PEER) {
            std::vector<const CBlockIndex*> vToDownload;
            NodeId staller = -1;
            FindNextBlocksToDownload(pto->GetId(), MAX_BLOCKS_IN_TRANSIT_PER_PEER - state.nBlocksInFlight, vToDownload, staller, consensusParams);
            BOOST_FOREACH(const CBlockIndex *pindex, vToDownload) {
                uint32_t nFetchFlags = GetFetchFlags(pto, pindex->pprev, consensusParams);
                vGetData.push_back(CInv(MSG_BLOCK | nFetchFlags, pindex->GetBlockHash()));
                MarkBlockAsInFlight(pto->GetId(), pindex->GetBlockHash(), consensusParams, pindex);
                LogPrint("net", "Requesting block %s (%d) peer=%d\n", pindex->GetBlockHash().ToString(),
                    pindex->nHeight, pto->id);
            }
            if (state.nBlocksInFlight == 0 && staller != -1) {
                if (State(staller)->nStallingSince == 0) {
                    State(staller)->nStallingSince = nNow;
                    LogPrint("net", "Stall started peer=%d\n", staller);
                }
            }
        }

        //
        // Message: getdata (non-blocks)
        //
        std::sort(pto->vecAskFor.begin(), pto->vecAskFor.end());
        auto it = pto->vecAskFor.begin();
        while (it != pto->vecAskFor.end() && it->first <= nNow)
        {
            const CInv& inv = it->second;
            if (!AlreadyHave(inv))
            {
                LogPrint("net", "SendMessages -- GETDATA -- requesting inv = %s peer=%d\n", inv.ToString(), pto->id);
                vGetData.push_back(inv);
                if (vGetData.size() >= 1000)
                {
                    connman.PushMessage(pto, msgMaker.Make(NetMsgType::GETDATA, vGetData));
                    LogPrint("net", "SendMessages -- GETDATA -- pushed size = %lu peer=%d\n", vGetData.size(), pto->id);
                    vGetData.clear();
                }
            } else {
                //If we're not going to ask, don't expect a response.
                LogPrint("net", "SendMessages -- GETDATA -- already have inv = %s peer=%d\n", inv.ToString(), pto->id);
                pto->setAskFor.erase(inv.hash);
            }
            ++it;
        }
        pto->vecAskFor.erase(pto->vecAskFor.begin(), it);
        if (!vGetData.empty()) {
            connman.PushMessage(pto, msgMaker.Make(NetMsgType::GETDATA, vGetData));
            LogPrint("net", "SendMessages -- GETDATA -- pushed size = %lu peer=%d\n", vGetData.size(), pto->id);
        }

        //
        // Message: feefilter
        //
        // We don't want white listed peers to filter txs to us if we have -whitelistforcerelay
        if (pto->nVersion >= FEEFILTER_VERSION && GetBoolArg("-feefilter", DEFAULT_FEEFILTER) &&
            !(pto->fWhitelisted && GetBoolArg("-whitelistforcerelay", DEFAULT_WHITELISTFORCERELAY))) {
            CAmount currentFilter = mempool.GetMinFee(GetArg("-maxmempool", DEFAULT_MAX_MEMPOOL_SIZE) * 1000000).GetFeePerK();
            int64_t timeNow = GetTimeMicros();
            if (timeNow > pto->nextSendTimeFeeFilter) {
                static CFeeRate default_feerate(DEFAULT_MIN_RELAY_TX_FEE);
                static FeeFilterRounder filterRounder(default_feerate);
                CAmount filterToSend = filterRounder.round(currentFilter);
                // If we don't allow free transactions, then we always have a fee filter of at least minRelayTxFee
                if (GetArg("-limitfreerelay", DEFAULT_LIMITFREERELAY) <= 0)
                    filterToSend = std::max(filterToSend, ::minRelayTxFee.GetFeePerK());
                if (filterToSend != pto->lastSentFeeFilter) {
                    connman.PushMessage(pto, msgMaker.Make(NetMsgType::FEEFILTER, filterToSend));
                    pto->lastSentFeeFilter = filterToSend;
                }
                pto->nextSendTimeFeeFilter = PoissonNextSend(timeNow, AVG_FEEFILTER_BROADCAST_INTERVAL);
            }
            // If the fee filter has changed substantially and it's still more than MAX_FEEFILTER_CHANGE_DELAY
            // until scheduled broadcast, then move the broadcast to within MAX_FEEFILTER_CHANGE_DELAY.
            else if (timeNow + MAX_FEEFILTER_CHANGE_DELAY * 1000000 < pto->nextSendTimeFeeFilter &&
                     (currentFilter < 3 * pto->lastSentFeeFilter / 4 || currentFilter > 4 * pto->lastSentFeeFilter / 3)) {
                pto->nextSendTimeFeeFilter = timeNow + GetRandInt(MAX_FEEFILTER_CHANGE_DELAY) * 1000000;
            }
        }
    }
    return true;
}

class CNetProcessingCleanup
{
public:
    CNetProcessingCleanup() {}
    ~CNetProcessingCleanup() {
        // orphan transactions
        mapOrphanTransactions.clear();
        mapOrphanTransactionsByPrev.clear();
    }
} instance_of_cnetprocessingcleanup;
