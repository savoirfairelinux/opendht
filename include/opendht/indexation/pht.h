#pragma once

#include <string>
#include <vector>
#include <memory>
#include <map>
#include <functional>
#include <stdexcept>
#include <bitset>
#include <iostream>
#include <sstream>

#include "../value.h"
#include "../dhtrunner.h"
#include "../infohash.h"

namespace dht {
namespace indexation {

/*!
 * @class   Prefix
 * @brief   A blob structure which prefixes a Key in the PHT.
 * @details
 * Since the PHT structure is a "trie", every node in this structure have a
 * label which is defined by the path from the root of the trie to the node. If
 * the node in question is a leaf, *the label is a prefix of all the keys
 * contained in the leaf*.
 */
struct Prefix {
    Prefix() {}
    Prefix(InfoHash h) : size_(h.size() * 8), content_(h.begin(), h.end()) {}
    Prefix(const Blob& d) : size_(d.size()*8), content_(d) {}
    Prefix(const Prefix& p, size_t first) :
        size_(std::min(first, p.content_.size()*8)),
        content_(Blob(p.content_.begin(), p.content_.begin()+size_/8))
    {
        auto rem = size_ % 8;
        if (rem)
            content_.push_back(p.content_[size_/8] & (0xFF << (8 - rem)));
    }

    Prefix getPrefix(ssize_t len) const {
        if ((size_t)std::abs(len) > size_)
            throw std::out_of_range("len larger than prefix size.");
        if (len < 0)
            len += size_;
        return Prefix(*this, len);
    }

    /**
     * Method for getting the state of the bit at the position pos.
     * @param pos : Pos of the needed bit
     * @return : true if the bit is at 1
     *           false otherwise
     */
    bool isActiveBit(size_t pos) const {
        return ((this->content_[pos / 8] >> (7 - (pos % 8)) ) & 1) == 1;
    }

    Prefix getFullSize() { return Prefix(*this, content_.size()*8); }

    /**
     * This methods gets the prefix of its sibling in the PHT structure.
     *
     * @return The prefix of this sibling.
     */
    Prefix getSibling() const {
        Prefix copy = *this;
        if (size_) {
            size_t last_bit =  (8 - size_) % 8;
            copy.content_.back() ^= (1 << last_bit);
        }
        return copy;
    }

    InfoHash hash() const {
        Blob copy(content_);
        copy.push_back(size_);
        return InfoHash::get(copy);
    }

    std::string toString() const {
        std::stringstream ss;
        auto bn = size_ % 8;
        auto n = size_ / 8;
        for (size_t i = 0; i<n; i++)
            ss << std::bitset<8>(content_[i]);
        if (bn)
            for (unsigned b=0; b<bn; b++)
                ss << (char)((content_[n] & (1 << (7 - b))) ? '1':'0');
        return ss.str();
    }

    static inline unsigned commonBits(const Prefix& p1, const Prefix& p2) {
        unsigned i, j;
        uint8_t x;
        auto longest_prefix_size = std::min(p1.size_, p2.size_);

        for (i = 0; i < longest_prefix_size; i++) {
            if (p1.content_.data()[i] != p2.content_.data()[i])
                break;
        }

        if (i == longest_prefix_size)
            return 8*longest_prefix_size;

        x = p1.content_.data()[i] ^ p2.content_.data()[i];

        j = 0;
        while ((x & 0x80) == 0) {
            x <<= 1;
            j++;
        }

        return 8 * i + j;
    }

    size_t size_ {0};
    Blob content_ {};
};

using Value = std::pair<InfoHash, dht::Value::Id>;

class Pht {
    static constexpr const char* INVALID_KEY = "Key does not match the PHT key spec.";

    /* Prefixes the user_type for all dht values put on the DHT */
    static constexpr const char* INDEX_PREFIX = "index.pht.";

public:
    /* This is the maximum number of entries per node. This parameter is
     * critical and influences the traffic a lot during a lookup operation.
     */
    static constexpr const size_t MAX_NODE_ENTRY_COUNT {16};

    /* A key for a an index entry */
    using Key = std::map<std::string, Blob>;
    /* Specifications of the keys. It defines the number, the length and the
     * serialization order of fields. */
    using KeySpec = std::map<std::string, size_t>;

    using LookupCallback = std::function<void(std::vector<std::shared_ptr<Value>>& values, Prefix p)>;
    typedef void (*LookupCallbackRaw)(std::vector<std::shared_ptr<Value>>* values, Prefix* p, void *user_data);
    static LookupCallback
    bindLookupCb(LookupCallbackRaw raw_cb, void* user_data) {
        if (not raw_cb) return {};
        return [=](std::vector<std::shared_ptr<Value>>& values, Prefix p) {
            raw_cb((std::vector<std::shared_ptr<Value>>*) &values, (Prefix*) &p, user_data);
        };
    }
    using LookupCallbackSimple = std::function<void(std::vector<std::shared_ptr<Value>>& values)>;
    typedef void (*LookupCallbackSimpleRaw)(std::vector<std::shared_ptr<Value>>* values, void *user_data);
    static LookupCallbackSimple
    bindLookupCbSimple(LookupCallbackSimpleRaw raw_cb, void* user_data) {
        if (not raw_cb) return {};
        return [=](std::vector<std::shared_ptr<Value>>& values) {
            raw_cb((std::vector<std::shared_ptr<Value>>*) &values, user_data);
        };
    }

    Pht(std::string name, KeySpec k_spec, std::shared_ptr<DhtRunner> dht)
        : name_(INDEX_PREFIX + name), canary_(name_ + ".canary"), keySpec_(k_spec), dht_(dht)
    {
        if (k_spec.size() != 1)
            throw std::invalid_argument("PHT only supports unidimensional data.");
    }
    virtual ~Pht () { }

    /**
     * Lookup a key for a value.
     */
    void lookup(Key k, LookupCallback cb = {}, DoneCallbackSimple done_cb = {}, bool exact_match = true);
    void lookup(Key k, LookupCallbackSimple cb = {}, DoneCallbackSimple done_cb = {}, bool exact_match = true)
    {
        lookup(k, [=](std::vector<std::shared_ptr<Value>>& values, Prefix) { cb(values); }, done_cb, exact_match);
    }
    /**
     * Adds an entry into the index.
     */
    void insert(Key k, Value v, DoneCallbackSimple cb = {});

private:
    class Cache {
    public:
        /**
         * Insert all needed node into the tree according to a prefix
         * @param p : Prefix that we need to insert
         */
        void insert(const Prefix& p);

        /**
         * Lookup into the tree to return the maximum prefix length in the cache tree
         *
         * @param p : Prefix that we are looking for
         * @return  : The size of the longest prefix known in the cache between 0 and p.size_
         */
        int lookup(const Prefix& p);

    private:
        static constexpr const size_t MAX_ELEMENT {1024};
        static constexpr const std::chrono::minutes NODE_EXPIRE_TIME {5};

        struct Node {
            time_point last_reply;           /* Made the assocation between leaves and leaves multimap */
            std::shared_ptr<Node> parent;    /* Share_ptr to the parent, it allow the self destruction of tree */
            std::weak_ptr<Node> left_child;  /* Left child, for bit equal to 1 */
            std::weak_ptr<Node> right_child; /* Right child, for bit equal to 0 */
        };

        std::weak_ptr<Node> root_;                         /* Root of the tree */

        /**
         * This mutlimap contains all prefix insert in the tree in time order
         * We could then delete the last one if there is too much node
         * The tree will self destroy is branch ( thanks to share_ptr )
         */
        std::multimap<time_point, std::shared_ptr<Node>> leaves_;
    };

    /**
     * Performs a step in the lookup operation. Each steps are performed
     * asynchronously.
     */
    void lookupStep(Prefix k, std::shared_ptr<int> lo, std::shared_ptr<int> hi,
            std::shared_ptr<std::vector<std::shared_ptr<Value>>> vals, LookupCallback cb,
            DoneCallbackSimple done_cb, std::shared_ptr<unsigned> max_common_prefix_len,
            int start = -1, bool all_values = false);

    /**
     * Linearizes the key into a unidimensional key. A pht only takes
     * unidimensional key.
     *
     * @param Key  The initial key.
     *
     * @return the prefix of the linearized key.
     */
    virtual Prefix linearize(Key k) const {
        if (not validKey(k)) { throw std::invalid_argument(INVALID_KEY); }
        return Blob {k.begin()->second.begin(), k.begin()->second.begin() + keySpec_.begin()->second};
    };

    /**
     * Tells if the key is valid according to the key spec.
     */
    bool validKey(const Key& k) const {
        return k.size() == keySpec_.size() and
            std::equal(k.begin(), k.end(), keySpec_.begin(),
                [&](const Key::value_type& key, const KeySpec::value_type& key_spec) {
                    return key.first == key_spec.first;
                }
            );
    }

    /**
     * Updates the canary token on the node responsible for the specified
     * Prefix.
     */
    void updateCanary(Prefix p);

    const std::string name_;
    const std::string canary_;
    const KeySpec keySpec_;
    Cache cache_;
    std::shared_ptr<DhtRunner> dht_;
};

} /* indexation  */
} /* dht */

