#ifndef MERKLE_TREE_HPP_
#define MERKLE_TREE_HPP_

extern "C" {
#include <stdint.h>
}

#include <vector>
#include <deque>
#include <string>
#include <stdexcept>

/** Size of a hash, in bytes
 *
 * We are using Blake2b with an output of 128 bits, which is 16 bytes.
 */
#define MERKLE_TREE_ELEMENT_SIZE_B 16

class MerkleTree
{
public :
    /** Buffer type
     *
     * This represents a single hash in the Merkle Tree and must have a
     * length of `MERKLE_TREE_ELEMENT_SIZE_B`.
     *
     * \see MERKLE_TREE_ELEMENT_SIZE_B
     */
    typedef std::vector<uint8_t> Buffer;

    /** List of elements
     *
     * This is a list of hashes. 'Element' is another name for 'hash' in the
     * context of a Merkle Tree.
     */
    typedef std::deque<Buffer> Elements;

    /** Constructor
     *
     * If `preserveOrder` is set to `true`, the `elements` will be used in
     * the order they are presented, and without any transformations. If set
     * to `false`, the `elements` will be sorted and duplicates will be removed
     * before the Merkle Tree is built.
     *
     * \param elements      [in] Elements to add to the Merkle Tree
     *                           There must be at least one element
     * \param preserveOrder [in] Whether to preserve the elements order
     *
     * \throw `std::runtime_error` if `elements` is empty
     *
     * \throw `std::runtime_error` if `elements` contains an element which is
     *        not of the right size, \see MERKLE_TREE_ELEMENT_SIZE_B.
     */
    MerkleTree(const Elements& elements, bool preserveOrder = false);

    /** Destructor */
    virtual ~MerkleTree();

    /** Compute a hash
     *
     * \param data [in] Data to hash (can be any size)
     *
     * \return The computed hash of `data`
     */
    static Buffer hash(const Buffer& data);

    /** Combine two hashes into one
     *
     * \param first         [in] First hash (i.e. the one on the left)
     * \param second        [in] Second hash (i.e. the one on the right)
     * \param preserveOrder [in] Whether to preserve the order
     *
     * \return The hash of the combined two hashes
     */
    static Buffer combinedHash(const Buffer& first, const Buffer& second,
            bool preserveOrder);

    /** Get the root hash of the Merkle Tree */
    Buffer getRoot() const
    {
        return layers_.back()[0];
    }

    /** Compute a root hash given a set of hashes
     *
     * This function builds a temporary Merkle Tree and extracts its root
     * hash. The temporary Merkle Tree will be built using the passed
     * arguments.
     *
     * \param elements      [in] Set of hashes used to build the Merkle Tree
     * \param preserveOrder [in] Whether to preserve the order of `elements`
     *
     * \return The root hash of a Merkle Tree that would be build using the
     *         given `elements`
     *
     * \throw `std::runtime_error` if `elements` is empty
     *
     * \throw `std::runtime_error` if `elements` contains an element which is
     *        not of the right size, \see MERKLE_TREE_ELEMENT_SIZE_B.
     */
    static Buffer merkleRoot(const Elements& elements,
            bool preserveOrder = false);

    /** Get proof for a given Merkle Tree element
     *
     * This function returns a list of hashes, starting from the hash of the
     * paired element of `element`, up to the top-level hash.
     *
     * \param element [in] Element to get the proof for
     *
     * \return The list of hashes from lowest to root
     *
     * \throw `std::runtime_error` if `element` is not in the base layer of
     *        the Merkle Tree
     */
    Elements getProof(const Buffer& element) const;

    /** Get proof in string form for a given Merkle Tree element
     *
     * This function is similar to `getProof()` but will return the proof in
     * hexadecimal string form.
     *
     * \param element [in] Element to get the proof for
     *
     * \return The list of hashes from lowest to root, in hex form
     *
     * \throw `std::runtime_error` if `element` is not in the base layer of
     *        the Merkle Tree
     */
    std::string getProofHex(const Buffer& element) const;

    /** Get proof for a given element of a Merkle Tree with preserved order
     *
     * This function returns a list of hashes, starting from the hash of the
     * paired element of `element`, up to the top-level hash. This function
     * should be used on a Merkle Tree with preserved order.
     *
     * \param element [in] Element to get the proof for
     * \param index   [in] Index of above element; this is necessary to
     *                     distinguish potential duplicates
     *
     * **IMPORTANT NOTE**: `index` starts at 1, not at 0; so the first element
     *                     has an index of 1, the second element an index of
     *                     2, etc.
     *
     * \throw `std::runtime_error` if `index` does not point to `element`
     */
    Elements getProofOrdered(const Buffer& element, size_t index) const;

    /** Get proof in string form for a given element of a Merkle Tree with preserved order
     *
     * This function is similar to `getProofOrdered()`, but it will return the
     * proof in hexadecimal string form.
     *
     * \param element [in] Element to get the proof for
     * \param index   [in] Index of above element; this is necessary to
     *                     distinguish potential duplicates
     *
     * **IMPORTANT NOTE**: `index` starts at 1, not at 0; so the first element
     *                     has an index of 1, the second element an index of
     *                     2, etc.
     *
     * \throw `std::runtime_error` if `index` does not point to `element`
     */
    std::string getProofOrderedHex(const Buffer& element, size_t index) const;

    /** Check the given proof for the given element
     *
     * This function will check that the given proof is valid for the given
     * `element`.
     *
     * \param proof   [in] Proof to check
     * \param root    [in] Root hash of the Merke Tree
     * \param element [in] Element for which the proof is checked
     *
     * \return `true` if `proof` is valid, `false` if not
     */
    static bool checkProof(const Elements& proof, const Buffer& root,
            const Buffer& element);

    /** Check the given proof for the given element in a Merkle Tree with order preserved
     *
     * This function will check that the given proof is valid for the given
     * `element`. This function should be used only on Merkle Trees where
     * `preserveOrder` was set to `true`.
     *
     * \param proof   [in] Proof to check
     * \param root    [in] Root hash of the Merke Tree
     * \param element [in] Element for which the proof is checked
     * \param index   [in] Index of above element; this is necessary to
     *                     distinguish potential duplicates
     *
     * **IMPORTANT NOTE**: `index` starts at 1, not at 0; so the first element
     *                     has an index of 1, the second element an index of
     *                     2, etc.
     *
     * \return `true` if `proof` is valid, `false` if not
     */
    static bool checkProofOrdered(const Elements& proof, const Buffer& root,
            const Buffer& element, size_t index);

private :
    /** Layers data structure
     *
     * This data structure represents the various layers of the Merkle Tree.
     * The first layer is the initial list of hashes, the 2nd layer is the
     * combination of the hashes of the first layer, etc. until the last layer
     * which is the top-level hash, aka the root. The last layer has a length
     * of one.
     */
    typedef std::deque<Elements> Layers;

    bool     preserveOrder_; /**< Whether to preserve the initial order */
    Elements elements_;      /**< Leaves of the Merkle Tree */
    Layers   layers_;        /**< The various layers of the Merkle Tree */

    /** Build the Merkle Tree layers */
    void getLayers();

    /** Build the next Merkle Tree layer */
    void getNextLayer();

    /** Get proof given the index of the element
     *
     * \param index [in] Index of the element to get the proof for
     *
     * \return The list of hashes that make up the proof
     */
    Elements getProof(size_t index) const;

    /** Get the peer of an element
     *
     * \param layer [in]  Layer to search
     * \param index [in]  Index of element in layer
     * \param pair  [out] Peer element
     *
     * \return `true` if OK, `false` if no peer element (this can happen if
     *         the `layer` has an odd number of elements, and you are asking
     *         for the last one, which obviously has no peer)
     */
    static bool getPair(const Elements& layer, size_t index, Buffer& pair);

    /** Converts a list of hashes into a hexadecimal string */
    static std::string elementsToHex(const Elements& elements);
};

#endif // MERKLE_TREE_HPP_
