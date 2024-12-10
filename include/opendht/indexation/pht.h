/*
 *  Copyright (C) 2014-2020 Savoir-faire Linux Inc.
 *  Author(s) : Adrien Béraud <adrien.beraud@savoirfairelinux.com>
 *              Simon Désaulniers <simon.desaulniers@savoirfairelinux.com>
 *              Nicolas Reynaud <nicolas.reynaud@savoirfairelinux.com>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

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
struct OPENDHT_PUBLIC Prefix {
    Prefix() {}
    Prefix(InfoHash h) : size_(h.size() * 8), content_(h.begin(), h.end()) { }
    Prefix(const Blob& d, const Blob& f={}) : size_(d.size()*8), flags_(f), content_(d) { }

    Prefix(const Prefix& p, size_t first) :
        size_(std::min(first, p.content_.size()*8)),
        content_(Blob(p.content_.begin(), p.content_.begin()+size_/8))
    {

        auto rem = size_ % 8;
        if ( not p.flags_.empty() ) {
            flags_ = Blob(p.flags_.begin(), p.flags_.begin()+size_/8);
            if (rem)
                flags_.push_back(p.flags_[size_/8] & (0xFF << (8 - rem)));
        }

        if (rem)
            content_.push_back(p.content_[size_/8] & (0xFF << (8 - rem)));
    }

    /**
     * Get a sub prefix of the Prefix
     *
     * @param len lenght of the prefix to get, could be negative
     *            if len is negativ then you will get the prefix
     *            of size of the previous prefix minus len
     *
     * @return Sub-prefix of size len or if len is negative sub-prefix of size
     *         of prefix minus len
     *
     * @throw out_of_range if len is larger than size of the content
     */
    Prefix getPrefix(ssize_t len) const {
        if ((size_t)std::abs(len) >= content_.size() * 8)
            throw std::out_of_range("len larger than prefix size.");
        if (len < 0)
            len += size_;

        return Prefix(*this, len);
    }

    /**
     * Flags are considered as active if flag is empty or if the flag
     * at pos 'pos' is active
ee     *
     * @see isActiveBit in private function
     */
    bool isFlagActive(size_t pos) const {
        return flags_.empty() or isActiveBit(flags_, pos);
    }

    /**
     * @see isActiveBit in private function
     */
    bool isContentBitActive(size_t pos) const {
        return isActiveBit(content_, pos);
    }

    Prefix getFullSize() { return Prefix(*this, content_.size()*8); }

    /**
     * This methods gets the prefix of its sibling in the PHT structure.
     *
     * @return The prefix of this sibling.
     */
    Prefix getSibling() const {
        Prefix copy = *this;
        if ( size_ )
            copy.swapContentBit(size_ - 1);

        return copy;
    }

    InfoHash hash() const {
        Blob copy(content_);
        copy.push_back(size_);
        return InfoHash::get(copy);
    }

    /**
     * This method count total of bit in common between 2 prefix
     *
     * @param p1 first prefix to compared
     * @param p2 second prefix to compared
     * @return Lenght of the larger common prefix between both
     */
    static inline unsigned commonBits(const Prefix& p1, const Prefix& p2) {
        unsigned i, j;
        uint8_t x;
        auto longest_prefix_size = std::min(p1.size_, p2.size_);

        for (i = 0; i < longest_prefix_size; i++) {
            if (p1.content_.data()[i] != p2.content_.data()[i]
                or not p1.isFlagActive(i)
                or not p2.isFlagActive(i) ) {

                    break;
            }
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

    /**
     * @see doc of swap private function
     */
    void swapContentBit(size_t bit) {
        swapBit(content_, bit);
    }

    /**
     * @see doc of swap private function
     */
    void swapFlagBit(size_t bit) {
        swapBit(flags_, bit);
    }

    /**
     * @see doc of addPadding private function
     */
    void addPaddingContent(size_t size) {
        content_ = addPadding(content_, size);
    }

    void updateFlags() {
        /* Fill first known bit */
        auto csize = size_ - flags_.size() * 8;
        while(csize >= 8) {
            flags_.push_back(0xFF);
            csize -= 8;
        }

        /* if needed fill remaining bit */
        if ( csize )
            flags_.push_back(0xFF << (8 - csize));

        /* Complet vector space missing */
        for ( auto i = flags_.size(); i < content_.size(); i++ )
            flags_.push_back(0xFF);
    }

    std::string toString() const;

    size_t size_ {0};

    /* Will contain flags according to content_.
       If flags_[i] == 0, then content_[i] is unknown
       else if flags_[i] == 1, then content_[i] is known */
    Blob flags_ {};
    Blob content_ {};

private:

    /**
     * Add a padding to the input blob
     *
     * @param toP  : Prefix where to add a padding
     * @param size : Final size of the prefix with padding
     *
     * @return Copy of the input Blob but with a padding
     */
    Blob addPadding(Blob toP, size_t size) {
        Blob copy = toP;
        for ( auto i = copy.size(); i < size; i++ )
            copy.push_back(0);

        swapBit(copy, size_ + 1);
        return copy;
    }

    /**
     * Check if the bit a pos 'pos' is active, i.e. equal to 1
     *
     * @param b   : Blob to check
     * @param pos : Position to check
     *
     * @return true if the bit is equal to 1, false otherwise
     *
     * @throw out_of_range if bit is superior to blob size * 8
     */
    bool isActiveBit(const Blob &b, size_t pos) const {
        if ( pos >= content_.size() * 8 )
            throw std::out_of_range("Can't detect active bit at pos, pos larger than prefix size or empty prefix");

        return ((b[pos / 8] >> (7 - (pos % 8)) ) & 1) == 1;
    }

    /**
     * Swap bit at position bit [from 0 to 1 and vice-versa]
     *
     * @param b   : Blob to swap
     * @param bit : Bit to swap on b
     *
     * @return the input prefix with the bit at pos 'bit' swapped
     *
     * @throw out_of_range if bit is superior to blob size * 8
     */
    void swapBit(Blob &b, size_t bit) {
        if ( bit >= b.size() * 8 )
            throw std::out_of_range("bit larger than prefix size.");

        size_t offset_bit = (8 - bit) % 8;
        b[bit / 8] ^= (1 << offset_bit);
    }
};

using Value = std::pair<InfoHash, dht::Value::Id>;
struct OPENDHT_PUBLIC IndexEntry : public dht::Value::Serializable<IndexEntry> {
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
    MSGPACK_DEFINE_MAP(prefix, value)
};

class OPENDHT_PUBLIC Pht {
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
    using LookupCallback = std::function<void(std::vector<std::shared_ptr<Value>>& values, const Prefix& p)>;

    typedef void (*LookupCallbackRaw)(std::vector<std::shared_ptr<Value>>* values, Prefix* p, void *user_data);
    static LookupCallback
    bindLookupCb(LookupCallbackRaw raw_cb, void* user_data) {
        if (not raw_cb) return {};
        return [=](std::vector<std::shared_ptr<Value>>& values, const Prefix& p) {
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
        : name_(INDEX_PREFIX + name), canary_(name_ + ".canary"), keySpec_(k_spec), dht_(dht) {}

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
     * Wrapper function which call the private one.
     *
     * @param k : Key to insert [i.e map of string, blob]
     * @param v : Value to insert
     * @param done_cb : Callbakc which going to be call when all the insert is done
     */
    void insert(Key k, Value v, DoneCallbackSimple done_cb = {}) {
        Prefix p = linearize(k);

        auto lo = std::make_shared<int>(0);
        auto hi = std::make_shared<int>(p.size_);

        IndexEntry entry;
        entry.value = v;
        entry.prefix = p.content_;
        entry.name = name_;

        Pht::insert(p, entry, lo, hi, clock::now(), true, done_cb);
    }

private:

    /**
     * Insert function which really insert onto the pht
     *
     * @param kp          : Prefix to insert (linearize the the key)
     * @param entry       : Entry created from the value
     * @param lo          : Lowest point to start in the prefix
     * @param hi          : Highest point to end in the prefix
     * @param time_p      : Timepoint to use for the insertion into the dht (must be < now)
     * @param check_split : If this flag is true then the algoritm will not use the merge algorithm
     * @param done_cb     : Callback to call when the insert is done
     */

    void insert(const Prefix& kp, IndexEntry entry, std::shared_ptr<int> lo, std::shared_ptr<int> hi, time_point time_p,
                bool check_split, DoneCallbackSimple done_cb = {});

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
         *
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

    /* Callback used for insert value by using the pht */
    using RealInsertCallback = std::function<void(const Prefix& p, IndexEntry entry)>;
    using LookupCallbackWrapper = std::function<void(std::vector<std::shared_ptr<IndexEntry>>& values, const Prefix& p)>;

    /**
     * Performs a step in the lookup operation. Each steps are performed
     * asynchronously.
     *
     * @param k          : Prefix on which the lookup is performed
     * @param lo         : lowest bound on the prefix (where to start)
     * @param hi         : highest bound on the prefix (where to stop)
     * @param vals       : Shared ptr to a vector of IndexEntry (going to contains all values found)
     * @param cb         : Callback to use at the end of the lookupStep (call on the value of vals)
     * @param done_cb    : Callback at the end of the lookupStep
     * @param max_common_prefix_len: used in the inexacte lookup match case, indicate the longest common prefix found
     * @param start      : If start is set then lo and hi will be ignore for the first step, if the step fail lo and hi will be used
     * @param all_values : If all value is true then all value met during the lookupstep will be in the vector vals
     */
    void lookupStep(Prefix k, std::shared_ptr<int> lo, std::shared_ptr<int> hi,
            std::shared_ptr<std::vector<std::shared_ptr<IndexEntry>>> vals,
            LookupCallbackWrapper cb, DoneCallbackSimple done_cb,
            std::shared_ptr<unsigned> max_common_prefix_len,
            int start = -1, bool all_values = false);

    /**
     * Apply the zcurve algorithm on the list of input prefix
     *
     * @param all_prefix : Vector of prefix to interleave
     *
     * @return The output prefix where all flags and content are interleaves
     */
    Prefix zcurve(const std::vector<Prefix>& all_prefix) const;

    /**
     * Linearizes the key into a unidimensional key. A pht only takes
     * unidimensional key.
     *
     * @param Key  The initial key.
     *
     * @return the prefix of the linearized key.
     */
    virtual Prefix linearize(Key k) const;

    /**
     * Looking where to put the data cause if there is free space on the node
     * above then this node will became the real leave.
     *
     * @param p       Share_ptr on the Prefix to check
     * @param entry   The entry to put at the prefix p
     * @param end_cb  Callback to use at the end of counting
     */
    void getRealPrefix(const std::shared_ptr<Prefix>& p, IndexEntry entry, RealInsertCallback end_cb );

    /**
     * Looking where to put the data cause if there is free space on the node
     * above then this node will became the real leave.
     *
     * @param p       Share_ptr on the Prefix to check
     * @param entry   The entry to put at the prefix p
     * @param end_cb  Callback to use at the end of counting
     */
    void checkPhtUpdate(Prefix p, IndexEntry entry, time_point time_p);

    /**
     * Search for the split location by comparing 'compared' to all values in vals.
     *
     * @param compared : Value which going to be compared
     * @param vals     : The vector of values to compare with comapred
     * @return position compared diverge from all others
     */
    static size_t findSplitLocation(const Prefix& compared, const std::vector<std::shared_ptr<IndexEntry>>& vals) {
        for ( size_t i = 0; i < compared.content_.size() * 8 - 1; i++ )
            for ( auto const& v : vals)
                if ( Prefix(v->prefix).isContentBitActive(i) != compared.isContentBitActive(i) )
                    return i + 1;
        return compared.content_.size() * 8 - 1;
    }

    /**
     * Put canary from the split point until the last known canary and add the prefix at the good place
     *
     * @param insert : Prefix to insertm but also prefix which going to check where we need to split
     * @param vals   : Vector of vals for the comparaison
     * @param entry  : Entry to put on the pht
     * @param end_cb : Callback to apply to the insert prefi (here does the insert)
     */
    void split(const Prefix& insert, const std::vector<std::shared_ptr<IndexEntry>>& vals, IndexEntry entry, RealInsertCallback end_cb);

    /**
     * Tells if the key is valid according to the key spec.
     */
    bool validKey(const Key& k) const {
        return k.size() == keySpec_.size() and
            std::equal(k.begin(), k.end(), keySpec_.begin(),
                [&](const Key::value_type& key, const KeySpec::value_type& key_spec) {
                    return key.first == key_spec.first and key.second.size() <= key_spec.second;
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

