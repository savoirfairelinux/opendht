/*
 *  Copyright (C) 2014-2017 Savoir-faire Linux Inc.
 *  Author : Adrien Béraud <adrien.beraud@savoirfairelinux.com>
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

#include "def.h"

#include <msgpack.hpp>

#ifndef _WIN32
#include <netinet/in.h>
#include <netdb.h>
#ifdef __ANDROID__
typedef uint16_t in_port_t;
#endif
#else
#include <iso646.h>
#include <ws2tcpip.h>
typedef uint16_t sa_family_t;
typedef uint16_t in_port_t;
#endif

#include <iostream>
#include <iomanip>
#include <array>
#include <vector>
#include <algorithm>
#include <stdexcept>
#include <sstream>
#include <cstring>


// bytes
#define HASH_LEN 20u

namespace dht {

using byte = uint8_t;

template <size_t N>
class OPENDHT_PUBLIC Hash
{
public:
    Hash() {
        data_.fill(0);
    }
    Hash(const msgpack::object& o) {
        msgpack_unpack(o);
    }
    byte* data() {
        return data_.data();
    }
    const byte* data() const {
        return data_.data();
    }
    constexpr size_t size() const { return data_.size(); }
    explicit operator bool() const { return std::any_of(data_.begin(), data_.end(), [](byte _b) { return _b != 0; }); }
    bool operator==(Hash const& _c) const { return data_ == _c.data_; }
    bool operator!=(Hash const& _c) const { return data_ != _c.data_; }
    bool operator<(Hash const& _c) const { for (unsigned i = 0; i < N; ++i) if (data_[i] < _c.data_[i]) return true; else if (data_[i] > _c.data_[i]) return false; return false; }
    bool operator>=(Hash const& _c) const { return !operator<(_c); }
    bool operator<=(Hash const& _c) const { return operator==(_c) || operator<(_c); }
    bool operator>(Hash const& _c) const { return !operator<=(_c); }
    template <typename Packer>
    void msgpack_pack(Packer& pk) const
    {
        pk.pack_bin(N);
        pk.pack_bin_body((char*)data_.data(), N);
    }
    void msgpack_unpack(msgpack::object o) {
        if (o.type != msgpack::type::BIN or o.via.bin.size != N)
            throw msgpack::type_error();
        std::copy_n(o.via.bin.ptr, N, data_.data());
    }

    template <size_t M>
    OPENDHT_PUBLIC friend std::ostream& operator<< (std::ostream& s, const Hash<M>& h);

    template <size_t M>
    OPENDHT_PUBLIC friend std::istream& operator>> (std::istream& s, Hash<M>& h);

    std::string toString() const {
        std::stringstream ss;
        ss << *this;
        return ss.str();
    }

private:
    std::array<byte, N> data_;
};

template <size_t N>
std::ostream& operator<< (std::ostream& s, const Hash<N>& h)
{
    s << std::hex;
    for (unsigned i=0; i<h.size(); i++)
        s << std::setfill('0') << std::setw(2) << (unsigned)h.data_[i];
    s << std::dec;
    return s;
}

template <size_t N>
std::istream& operator>> (std::istream& s, Hash<N>& h)
{
    std::array<char, h.size()*2> dat;
    s.exceptions(std::istream::eofbit | std::istream::failbit);
    s.read(&(*dat.begin()), dat.size());
    for (size_t i = 0; i < h.size(); i++) {
        unsigned res = 0;
        sscanf(dat.data() + 2*i, "%02x", &res);
        h[i] = res;
    }
    return s;
}

using h256 = Hash<32>;
using PkId = h256;

/**
 * Represents an InfoHash.
 * An InfoHash is a byte array of HASH_LEN bytes.
 * InfoHashes identify nodes and values in the Dht.
 */
class OPENDHT_PUBLIC InfoHash final : public std::array<uint8_t, HASH_LEN> {
public:
    constexpr InfoHash() : std::array<uint8_t, HASH_LEN>() {}
    constexpr InfoHash(const std::array<uint8_t, HASH_LEN>& h) : std::array<uint8_t, HASH_LEN>(h) {}
    InfoHash(const uint8_t* h, size_t h_len) : std::array<uint8_t, HASH_LEN>() {
        if (h_len < HASH_LEN)
            fill(0);
        else
            std::copy_n(h, HASH_LEN, begin());
    }

    /**
     * Constructor from an hexadecimal string (without "0x").
     * hex must be at least 2.HASH_LEN characters long.
     * If too long, only the first 2.HASH_LEN characters are read.
     */
    explicit InfoHash(const std::string& hex);

    InfoHash(const msgpack::object& o) {
        msgpack_unpack(o);
    }

    /**
     * Find the lowest 1 bit in an id.
     * Result will allways be lower than 8*HASH_LEN
     */
    inline unsigned lowbit() const {
        int i, j;
        for(i = HASH_LEN-1; i >= 0; i--)
            if((*this)[i] != 0)
                break;
        if(i < 0)
            return -1;
        for(j = 7; j >= 0; j--)
            if(((*this)[i] & (0x80 >> j)) != 0)
                break;
        return 8 * i + j;
    }

    /**
     * Forget about the ``XOR-metric''.  An id is just a path from the
     * root of the tree, so bits are numbered from the start.
     */
    static inline int cmp(const InfoHash& id1, const InfoHash& id2) {
        return std::memcmp(id1.data(), id2.data(), HASH_LEN);
    }

    /** Find how many bits two ids have in common. */
    static inline unsigned
    commonBits(const InfoHash& id1, const InfoHash& id2)
    {
        unsigned i, j;
        uint8_t x;
        for(i = 0; i < HASH_LEN; i++) {
            if(id1[i] != id2[i])
                break;
        }

        if(i == HASH_LEN)
            return 8*HASH_LEN;

        x = id1[i] ^ id2[i];

        j = 0;
        while((x & 0x80) == 0) {
            x <<= 1;
            j++;
        }

        return 8 * i + j;
    }

    /** Determine whether id1 or id2 is closer to this */
    int
    xorCmp(const InfoHash& id1, const InfoHash& id2) const
    {
        for(unsigned i = 0; i < HASH_LEN; i++) {
            uint8_t xor1, xor2;
            if(id1[i] == id2[i])
                continue;
            xor1 = id1[i] ^ (*this)[i];
            xor2 = id2[i] ^ (*this)[i];
            if(xor1 < xor2)
                return -1;
            else
                return 1;
        }
        return 0;
    }

    bool
    getBit(unsigned nbit) const
    {
        auto& num = *(cbegin()+(nbit/8));
        unsigned bit = 7 - (nbit % 8);
        return (num >> bit) & 1;
    }

    void
    setBit(unsigned nbit, bool b)
    {
        auto& num = (*this)[nbit/8];
        unsigned bit = 7 - (nbit % 8);
        num ^= (-b ^ num) & (1 << bit);
    }

    double toFloat() const {
        using D = size_t;
        double v = 0.;
        for (size_t i = 0; i < std::min<size_t>(HASH_LEN, sizeof(D)-1); i++)
            v += *(cbegin()+i) / (double)((D)1 << 8*(i+1));
        return v;
    }

    bool
    operator<(const InfoHash& o) const {
        for(unsigned i = 0; i < HASH_LEN; i++) {
            if((*this)[i] != o[i])
                return (*this)[i] < o[i];
        }
        return false;
    }

    static inline InfoHash get(const std::string& data) {
        return get((const uint8_t*)data.data(), data.size());
    }

    static inline InfoHash get(const std::vector<uint8_t>& data) {
        return get(data.data(), data.size());
    }

    /**
     * Computes the hash from a given data buffer of size data_len.
     */
    static InfoHash get(const uint8_t* data, size_t data_len);

    static InfoHash getRandom();

    OPENDHT_PUBLIC friend std::ostream& operator<< (std::ostream& s, const InfoHash& h);
    OPENDHT_PUBLIC friend std::istream& operator>> (std::istream& s, InfoHash& h);

    const char* to_c_str() const;

    std::string toString() const;

    template <typename Packer>
    void msgpack_pack(Packer& pk) const
    {
        pk.pack_bin(HASH_LEN);
        pk.pack_bin_body((char*)data(), HASH_LEN);
    }

    void msgpack_unpack(msgpack::object o) {
        if (o.type != msgpack::type::BIN or o.via.bin.size != HASH_LEN)
            throw msgpack::type_error();
        std::copy_n(o.via.bin.ptr, HASH_LEN, data());
    }

};

static constexpr const InfoHash zeroes {};

struct OPENDHT_PUBLIC NodeExport {
    InfoHash id;
    sockaddr_storage ss;
    socklen_t sslen;

    template <typename Packer>
    void msgpack_pack(Packer& pk) const
    {
        pk.pack_map(2);
        pk.pack(std::string("id"));
        pk.pack(id);
        pk.pack(std::string("addr"));
        pk.pack_bin(sslen);
        pk.pack_bin_body((char*)&ss, sslen);
    }

    void msgpack_unpack(msgpack::object o);

    OPENDHT_PUBLIC friend std::ostream& operator<< (std::ostream& s, const InfoHash& h);
};

}
