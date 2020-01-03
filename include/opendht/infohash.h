/*
 *  Copyright (C) 2014-2020 Savoir-faire Linux Inc.
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
#include "rng.h"

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

namespace dht {

using byte = uint8_t;

namespace crypto {
    OPENDHT_PUBLIC void hash(const uint8_t* data, size_t data_length, uint8_t* hash, size_t hash_length);
}

/**
 * Represents an InfoHash.
 * An InfoHash is a byte array of HASH_LEN bytes.
 * InfoHashes identify nodes and values in the Dht.
 */
template <size_t N>
class OPENDHT_PUBLIC Hash {
public:
    using T = std::array<uint8_t, N>;
    typedef typename T::iterator iterator;
    typedef typename T::const_iterator const_iterator;

    Hash () noexcept {
        data_.fill(0);
    }
    Hash (const uint8_t* h, size_t data_len) {
        if (data_len < N)
            data_.fill(0);
        else
            std::copy_n(h, N, data_.begin());
    }
    /**
     * Constructor from an hexadecimal string (without "0x").
     * hex must be at least 2.HASH_LEN characters long.
     * If too long, only the first 2.HASH_LEN characters are read.
     */
    explicit Hash(const std::string& hex);

    Hash(const msgpack::object& o) {
        msgpack_unpack(o);
    }

    static constexpr size_t size() noexcept { return N; }
    const uint8_t* data() const { return data_.data(); }
    uint8_t* data() { return data_.data(); }
    iterator begin() { return data_.begin(); }
    const_iterator cbegin() const { return data_.cbegin(); }
    iterator end() { return data_.end(); }
    const_iterator cend() const { return data_.cend(); }

    bool operator==(const Hash& h) const {
        auto a = reinterpret_cast<const uint32_t*>(data_.data());
        auto b = reinterpret_cast<const uint32_t*>(h.data_.data());
        constexpr unsigned n = N / sizeof(uint32_t);
        for (unsigned i=0; i < n; i++)
            if (a[i] != b[i])
                return false;
        return true;
    }
    bool operator!=(const Hash& h) const { return !(*this == h); }

    bool operator<(const Hash& o) const {
        for(unsigned i = 0; i < N; i++) {
            if(data_[i] != o.data_[i])
                return data_[i] < o.data_[i];
        }
        return false;
    }

    explicit operator bool() const {
        auto a = reinterpret_cast<const uint32_t*>(data_.data());
        auto b = reinterpret_cast<const uint32_t*>(data_.data() + N);
        for (; a != b; a++) {
            if (*a)
                return true;
        }
        return false;
    }

    uint8_t& operator[](size_t index) { return data_[index]; }
    const uint8_t& operator[](size_t index) const { return data_[index]; }

    /**
     * Find the lowest 1 bit in an id.
     * Result will allways be lower than 8*N
     */
    inline int lowbit() const {
        int i, j;
        for(i = N-1; i >= 0; i--)
            if(data_[i] != 0)
                break;
        if(i < 0)
            return -1;
        for(j = 7; j >= 0; j--)
            if((data_[i] & (0x80 >> j)) != 0)
                break;
        return 8 * i + j;
    }

    /**
     * Forget about the ``XOR-metric''.  An id is just a path from the
     * root of the tree, so bits are numbered from the start.
     */
    static inline int cmp(const Hash& id1, const Hash& id2) {
        return std::memcmp(id1.data_.data(), id2.data_.data(), N);
    }

    /** Find how many bits two ids have in common. */
    static inline unsigned
    commonBits(const Hash& id1, const Hash& id2)
    {
        unsigned i, j;
        uint8_t x;
        for(i = 0; i < N; i++) {
            if(id1.data_[i] != id2.data_[i])
                break;
        }

        if(i == N)
            return 8*N;

        x = id1.data_[i] ^ id2.data_[i];

        j = 0;
        while((x & 0x80) == 0) {
            x <<= 1;
            j++;
        }

        return 8 * i + j;
    }

    /** Determine whether id1 or id2 is closer to this */
    int
    xorCmp(const Hash& id1, const Hash& id2) const
    {
        for(unsigned i = 0; i < N; i++) {
            uint8_t xor1, xor2;
            if(id1.data_[i] == id2.data_[i])
                continue;
            xor1 = id1.data_[i] ^ data_[i];
            xor2 = id2.data_[i] ^ data_[i];
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
        auto& num = *(data_.cbegin()+(nbit/8));
        unsigned bit = 7 - (nbit % 8);
        return (num >> bit) & 1;
    }

    void
    setBit(unsigned nbit, bool b)
    {
        auto& num = data_[nbit/8];
        unsigned bit = 7 - (nbit % 8);
        num ^= (-b ^ num) & (1 << bit);
    }

    double toFloat() const {
        using D = size_t;
        double v = 0.;
        for (size_t i = 0; i < std::min<size_t>(N, sizeof(D)-1); i++)
            v += *(data_.cbegin()+i) / (double)((D)1 << 8*(i+1));
        return v;
    }

    static inline Hash get(const std::string& data) {
        return get((const uint8_t*)data.data(), data.size());
    }

    static inline Hash get(const std::vector<uint8_t>& data) {
        return get(data.data(), data.size());
    }

    /**
     * Computes the hash from a given data buffer of size data_len.
     */
    static Hash get(const uint8_t* data, size_t data_len)
    {
        Hash ret;
        crypto::hash(data, data_len, ret.data(), N);
        return ret;
    }

    static Hash getRandom();

    template <size_t M>
    OPENDHT_PUBLIC friend std::ostream& operator<< (std::ostream& s, const Hash<M>& h);

    template <size_t M>
    OPENDHT_PUBLIC friend std::istream& operator>> (std::istream& s, Hash<M>& h);

    const char* to_c_str() const;

    std::string toString() const;

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
private:
    T data_;
    void fromString(const char*);
};

#define HASH_LEN 20u
using InfoHash = Hash<HASH_LEN>;
using h256 = Hash<32>;
using PkId = h256;

template <size_t N>
std::ostream& operator<< (std::ostream& s, const Hash<N>& h)
{
    s.write(h.to_c_str(), N*2);
    return s;
}

template <size_t N>
std::istream& operator>> (std::istream& s, Hash<N>& h)
{
    std::array<char, h.size()*2> dat;
    s.exceptions(std::istream::eofbit | std::istream::failbit);
    s.read(&(*dat.begin()), dat.size());
    fromString(dat.data());
    return s;
}

template <size_t N>
Hash<N>::Hash(const std::string& hex) {
    if (hex.size() < 2*N)
        data_.fill(0);
    else
        fromString(hex.c_str());
}

template <size_t N>
void
Hash<N>::fromString(const char* in) {
    auto hex2bin = [](char c) -> uint8_t {
        if      (c >= 'a' and c <= 'f') return 10 + c - 'a';
        else if (c >= 'A' and c <= 'F') return 10 + c - 'A';
        else if (c >= '0' and c <= '9') return c - '0';
        else throw std::domain_error("not an hex character");
    };
    try {
        for (size_t i=0; i<N; i++)
            data_[i] = (hex2bin(in[2*i]) << 4) | hex2bin(in[2*i+1]);
    } catch (const std::domain_error&) {
        data_.fill(0);
    }
}

template <size_t N>
Hash<N>
Hash<N>::getRandom()
{
    Hash h;
    crypto::random_device rdev;
    std::uniform_int_distribution<uint32_t> rand_int;
    auto a = reinterpret_cast<uint32_t*>(h.data());
    auto b = reinterpret_cast<uint32_t*>(h.data() + h.size());
    std::generate(a, b, std::bind(rand_int, std::ref(rdev)));
    return h;
}

struct HexMap : public std::array<std::array<char, 2>, 256> {
    HexMap() {
        for (size_t i=0; i<size(); i++) {
            auto& e = (*this)[i];
            e[0] = hex_digits[(i >> 4) & 0x0F];
            e[1] = hex_digits[i & 0x0F];
        }
    }
private:
    static constexpr const char* hex_digits = "0123456789abcdef";
};

OPENDHT_PUBLIC extern const HexMap hex_map;

template <size_t N>
const char*
Hash<N>::to_c_str() const
{
    thread_local std::array<char, N*2+1> buf;
    for (size_t i=0; i<N; i++) {
        auto b = buf.data()+i*2;
        const auto& m = hex_map[data_[i]];
        *((uint16_t*)b) = *((uint16_t*)&m);
    }
    return buf.data();
}

template <size_t N>
std::string
Hash<N>::toString() const
{
    return std::string(to_c_str(), N*2);
}

const InfoHash zeroes {};

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

    OPENDHT_PUBLIC friend std::ostream& operator<< (std::ostream& s, const NodeExport& h);
};

}
