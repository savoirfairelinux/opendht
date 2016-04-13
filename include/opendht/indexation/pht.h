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
    bool isActivBit(size_t pos) const {
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

struct IndexEntry : public dht::Value::Serializable<IndexEntry> {
    static const ValueType TYPE;

    virtual void unpackValue(const dht::Value& v) {
        Serializable<IndexEntry>::unpackValue(v);
        name = v.user_type;
    }

    virtual dht::Value packValue() const {
        auto pack = Serializable<IndexEntry>::packValue();
        pack.user_type = name;
        return pack;
    }

    Blob prefix;
    Value value;
    std::string name;
    MSGPACK_DEFINE_MAP(prefix, value);
};

class Pht {
    static constexpr const char* INDEX_PREFIX = "index.pht.";

public:
    /* This is the maximum number of entries per node. This parameter is
     * critical and influences the traffic a lot during a lookup operation.
     */
    static constexpr const size_t MAX_NODE_ENTRY_COUNT {16};

    using Key = std::map<std::string, Prefix>;

    using LookupCallback = std::function<void(std::vector<std::shared_ptr<Value>>& values, Prefix p)>;
    typedef void (*LookupCallbackRaw)(std::vector<std::shared_ptr<Value>>* values, Prefix* p, void *user_data);
    static LookupCallback
    bindLookupCb(LookupCallbackRaw raw_cb, void* user_data) {
        if (not raw_cb) return {};
        return [=](std::vector<std::shared_ptr<Value>>& values, Prefix p) {
            raw_cb((std::vector<std::shared_ptr<Value>>*) &values, (Prefix*) &p, user_data);
        };
    }

    Pht(std::string name, std::shared_ptr<DhtRunner> dht)
        : name_(INDEX_PREFIX + name), canary_(name_ + ".canary"), dht_(dht) { }
    virtual ~Pht () { }

    /**
     * Lookup a key for a value.
     */
    void lookup(Key k, LookupCallback cb = {}, Dht::DoneCallbackSimple doneCb = {}, bool exact_match = true);
    /**
     * Adds an entry into the index.
     */
    void insert(Key k, Value v, Dht::DoneCallbackSimple cb = {});

private:
    class Cache {
    public:
        /**
         * Insert all needed node into the tree according to a prefix
         * @param p : Prefix that we need to insert
         */
        void insert(const Prefix& p) {
            size_t i = 0;
            auto now = clock::now();

            std::shared_ptr<Node> curr_node;

            while ( ( leaves_.size() > 0 && leaves_.begin()->first + NODE_EXPIRE_TIME < now )
                    || leaves_.size() > MAX_ELEMENT ) {

                leaves_.erase(leaves_.begin());
            }

            if ( !(curr_node = root_.lock()) ) {

                /* Root does not exist, need to create one*/
                curr_node = std::make_shared<Node>();
                root_ = curr_node;
            }

            curr_node->last_reply = now;

            /* Iterate through all bit of the Blob */
            for ( i = 0; i < p.size_; i++ ) {

                /* According to the bit define which node is the next one */
                auto& next = ( p.isActivBit(i) ) ? curr_node->right_child : curr_node->left_child;

                /**
                 * If lock, node exists
                 * else create it
                 */
                if (auto n = next.lock()) {
                    curr_node = std::move(n);
                } else {
                    /* Create the next node if doesn't exist*/
                    auto tmp_curr_node = std::make_shared<Node>();
                    tmp_curr_node->parent = curr_node;
                    next = tmp_curr_node;
                    curr_node = std::move(tmp_curr_node);
                }

                curr_node->last_reply = now;
            }

            /* Insert the leaf (curr_node) into the multimap */
            leaves_.emplace(std::move(now), std::move(curr_node) );
        }

        /**
         * Lookup into the tree to return the maximum prefix length in the cache tree
         *
         * @param p : Prefix that we are looking for
         * @return  : The size of the longest prefix known in the cache between 0 and p.size_
         */
        int lookup(const Prefix& p) {
            int pos = 0;
            auto now = clock::now(), last_node_time = now;

            /* Before lookup remove the useless one [i.e. too old] */
            while ( leaves_.size() > 0 &&  leaves_.begin()->first + NODE_EXPIRE_TIME < now ) {
                leaves_.erase(leaves_.begin());
            }

            auto next = root_;
            std::shared_ptr<Node> curr_node;

            while ( auto n = next.lock() ) {
                /* Safe since pos is equal to 0 until here */
                if ( (unsigned) pos >= p.size_ ) break;

                curr_node = n;
                last_node_time = curr_node->last_reply;
                curr_node->last_reply = now;

                /* Get the Prefix bit by bit, starting from left */
                next = ( p.isActivBit(pos) ) ? curr_node->right_child : curr_node->left_child;

                ++pos;
            }

            if ( pos > 0 ) {
                auto to_erase = leaves_.find(last_node_time);
                if ( to_erase != leaves_.end() )
                    leaves_.erase( to_erase );

                leaves_.emplace( std::move(now), std::move(curr_node) );
            }

            return --pos;
        }


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
     * Linearizes the key into a unidimensional key. A pht only takes
     * unidimensional key.
     *
     * @param Key  The initial key.
     *
     * @return return The linearized key.
     */
    static Prefix linearize(Key k) {
        if (k.size() != 1) { throw std::invalid_argument("PHT only supports unidimensional data."); }
        return k.begin()->second;
    };

    /**
     * Performs a step in the lookup operation. Each steps are performed
     * asynchronously.
     */
    void lookupStep(Prefix k, std::shared_ptr<int> lo, std::shared_ptr<int> hi,
            std::shared_ptr<std::vector<std::shared_ptr<Value>>> vals, LookupCallback cb,
            Dht::DoneCallbackSimple done_cb, std::shared_ptr<unsigned> max_common_prefix_len,
            int start = -1, bool all_values = false);

    /**
     * Updates the canary token on the node responsible for the specified
     * Prefix.
     */
    void updateCanary(Prefix p);

    const std::string name_;
    const std::string canary_;
    Cache cache_;
    std::shared_ptr<DhtRunner> dht_;
};

} /* indexation  */
} /* dht */

