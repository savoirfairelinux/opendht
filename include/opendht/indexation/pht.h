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

#include "opendht.h"

namespace dht {
namespace indexation {

struct Prefix {
    Prefix() {}
    Prefix(InfoHash h) : size_(h.size() * 8), content_(h.begin(), h.end()) {}
    Prefix(const Blob& d) : size_(d.size()*8), content_(d) {}
    Prefix(const Prefix& p, size_t first) : size_(first), content_(p.content_.begin(), p.content_.begin()+first/8) {
       auto rem = first % 8;
       if (rem)
           content_.push_back(p.content_[first/8] & (0xFF << (7 - rem)));
    }

    Prefix getPrefix(ssize_t len) const {
        if ((size_t)std::abs(len) > size_)
            throw std::out_of_range("len larger than prefix size.");
        if (len < 0)
            len += size_;
        return Prefix(*this, len);
    }
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

    size_t size_ {0};
    Blob content_ {};
};

using Value = std::pair<InfoHash, dht::Value::Id>;

struct IndexEntry : public dht::Value::Serializable<IndexEntry> {
    const ValueType& getType() const {
        return ValueType::USER_DATA;
    }

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
    static constexpr const size_t MAX_NODE_ENTRY_COUNT {128};

public:
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
    void lookup(Key k, LookupCallback cb = {}, Dht::DoneCallbackSimple doneCb = {});
    /**
     * Adds an entry into the index.
     */
    void insert(Key k, Value v, Dht::DoneCallbackSimple cb = {});

private:
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
    void lookupStep(Prefix k, std::shared_ptr<int> lo,
                       std::shared_ptr<int> hi,
                       std::shared_ptr<std::vector<std::shared_ptr<Value>>> vals,
                       LookupCallback cb, Dht::DoneCallbackSimple done_cb);

    /**
     * Updates the canary token on the node responsible for the specified
     * Prefix.
     */
    void updateCanary(Prefix p);

    const std::string name_;
    const std::string canary_;

    std::shared_ptr<DhtRunner> dht_;
};

} /* indexation  */
} /* dht */

