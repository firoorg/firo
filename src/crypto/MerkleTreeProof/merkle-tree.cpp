#include "merkle-tree.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include "blake2/blake2.h"

std::ostream& operator<<(std::ostream& os, const MerkleTree::Buffer& buffer)
{
    for (   MerkleTree::Buffer::const_iterator it = buffer.begin();
            it != buffer.end();
            ++it) {
        os << std::hex << std::setw(2) << std::setfill('0') << *it;
    }
    return os;
}

MerkleTree::MerkleTree(const Elements& elements, bool preserveOrder)
    : preserveOrder_(preserveOrder)
{
    if (elements.empty()) {
        throw std::runtime_error("Empty elements list");
    }

    for (   Elements::const_iterator it = elements.begin();
            it != elements.end();
            ++it) {
        if (it->empty()) {
            continue; // ignore empty elements
        }
        if (it->size() != MERKLE_TREE_ELEMENT_SIZE_B) {
            std::ostringstream oss;
            oss << "Element size is " << it->size() << ", it must be "
                << MERKLE_TREE_ELEMENT_SIZE_B;
            throw std::runtime_error(oss.str());
        }
        if (!preserveOrder_) {
            // Check that this element has not been pushed yet
            if (std::find(elements_.begin(), elements_.end(), *it)
                    != elements_.end()) {
                continue; // ignore duplicates
            }
        }
        elements_.push_back(*it);
    } // for each element

    if (!preserveOrder_) {
        std::sort(elements_.begin(), elements_.end()); // sort elements
    }

    getLayers();
}

MerkleTree::~MerkleTree()
{
}

MerkleTree::Buffer MerkleTree::hash(const Buffer& data)
{
    blake2b_state state;
    blake2b_init(&state, MERKLE_TREE_ELEMENT_SIZE_B);
    for (Buffer::const_iterator it = data.begin(); it != data.end(); ++it) {
        blake2b_4r_update(&state, &(*it), sizeof(*it));
    }
    uint8_t digest[MERKLE_TREE_ELEMENT_SIZE_B];
    blake2b_4r_final(&state, digest, sizeof(digest));
    return Buffer(digest, digest + sizeof(digest));
}

MerkleTree::Buffer MerkleTree::combinedHash(const Buffer& first,
        const Buffer& second, bool preserveOrder)
{
    Buffer buffer;
    buffer.reserve(first.size() + second.size());
    if (preserveOrder || (first > second)) {
        std::copy(first.begin(), first.end(), std::back_inserter(buffer));
        std::copy(second.begin(), second.end(), std::back_inserter(buffer));
    } else {
        std::copy(second.begin(), second.end(), std::back_inserter(buffer));
        std::copy(first.begin(), first.end(), std::back_inserter(buffer));
    }
    return hash(buffer);
}

MerkleTree::Buffer MerkleTree::merkleRoot(const Elements& elements,
        bool preserveOrder)
{
    return MerkleTree(elements, preserveOrder).getRoot();
}

MerkleTree::Elements MerkleTree::getProof(const Buffer& element) const
{
    bool found = false;
    size_t index;
    for (size_t i = 0; (i < elements_.size()) && !found; ++i) {
        if (elements_[i] == element) {
            found = true;
            index = i;
        }
    }
    if (!found) {
        throw std::runtime_error("Element not found");
    }
    return getProof(index);
}

std::string MerkleTree::getProofHex(const Buffer& element) const
{
    return elementsToHex(getProof(element));
}

MerkleTree::Elements MerkleTree::getProofOrdered(const Buffer& element,
        size_t index) const
{
    if (index == 0) {
        throw std::runtime_error("Index is zero");
    }
    index--;
    if ((index >= elements_.size()) || (elements_[index] != element)) {
        throw std::runtime_error("Index does not point to element");
    }
    return getProof(index);
}

std::string MerkleTree::getProofOrderedHex(const Buffer& element,
        size_t index) const
{
    return elementsToHex(getProofOrdered(element, index));
}

bool MerkleTree::checkProof(const Elements& proof, const Buffer& root,
        const Buffer& element)
{
    Buffer tempHash = element;
    for (   Elements::const_iterator it = proof.begin();
            it != proof.end();
            ++it) {
        tempHash = combinedHash(tempHash, *it, false);
    }
    return tempHash == root;
}

// Fabrice: This function seems buggy to me, rewrote it below
#if 0
bool MerkleTree::checkProofOrdered(const Elements& proof,
        const Buffer& root, const Buffer& element, size_t index)
{
    Buffer tempHash = element;
    for (size_t i = 0; i < proof.size(); ++i) {
        size_t remaining = proof.size() - i;

        // We don't assume that the tree is padded to a power of 2. If the
        // index is odd, then the proof starts with a hash at a higher layer,
        // so we have to adjust the index to be the index at that layer.
        while ((remaining > 0) && (index & 1) && (index > (1u << remaining))) {
            index = index / 2;
        }

        if (index & 1) {
            tempHash = combinedHash(tempHash, proof[i], true);
        } else {
            tempHash = combinedHash(proof[i], tempHash, true);
        }
        index = index / 2;
    }
    return tempHash == root;
}
#endif

bool MerkleTree::checkProofOrdered(const Elements& proof,
        const Buffer& root, const Buffer& element, size_t index)
{
    --index; // `index` argument starts at 1
    Buffer tempHash = element;
    for (size_t i = 0; i < proof.size(); ++i) {
        size_t remaining = proof.size() - i;

        // We don't assume that the tree is padded to a power of 2. If the
        // index is even and the last one of the layer, then the proof starts
        // with a hash at a higher layer, so we have to adjust the index to be
        // the index at that layer.
        while (((index & 1) == 0) && (index >= (1u << remaining))) {
            index = index / 2;
        }

        if (index & 1) {
            tempHash = combinedHash(proof[i], tempHash, true);
        } else {
            tempHash = combinedHash(tempHash, proof[i], true);
        }
        index = index / 2;
    }
    return tempHash == root;
}

void MerkleTree::getLayers()
{
    layers_.clear();

    // The first layer is the elements themselves
    layers_.push_back(elements_);

    if (elements_.empty()) {
        return; // nothing left to do
    }

    // For subsequent layers, combine each pair of hashes in the previous
    // layer to build the current layer. Repeat until the current layer has
    // only one hash (this will be the root of the tree).
    while (layers_.back().size() > 1) {
        getNextLayer();
    }
}

void MerkleTree::getNextLayer()
{
    const Elements& previous_layer = layers_.back();

    // Create a new empty layer
    layers_.push_back(Elements());
    Elements& current_layer = layers_.back();

    // For each pair of elements in the previous layer
    // NB: If there is an odd number of elements, we ignore the last one for now
    for (size_t i = 0; i < (previous_layer.size() / 2); ++i) {
        current_layer.push_back(combinedHash(previous_layer[2*i],
                    previous_layer[2*i + 1], preserveOrder_));
    }

    // If there is an odd one out at the end, process it
    // NB: It's on its own, so we don't combine it with anything
    if (previous_layer.size() & 1) {
        current_layer.push_back(previous_layer.back());
    }
}

MerkleTree::Elements MerkleTree::getProof(size_t index) const
{
    Elements proof;
    for (   Layers::const_iterator it = layers_.begin();
            it != layers_.end();
            ++it) {
        Buffer pair;
        if (getPair(*it, index, pair)) {
            proof.push_back(pair);
        }
        index = index / 2; // point to correct hash in next layer
    } // for each layer
    return proof;
}

bool MerkleTree::getPair(const Elements& layer, size_t index, Buffer& pair)
{
    size_t pairIndex;
    if (index & 1) {
        pairIndex = index - 1;
    } else {
        pairIndex = index + 1;
    }
    if (pairIndex >= layer.size()) {
        return false;
    }
    pair = layer[pairIndex];
    return true;
}

std::string MerkleTree::elementsToHex(const Elements& elements)
{
    std::ostringstream oss;
    oss << "0x";
    for (   Elements::const_iterator it = elements.begin();
            it != elements.end();
            ++it) {
        oss << *it;
    }
    return oss.str();
}


