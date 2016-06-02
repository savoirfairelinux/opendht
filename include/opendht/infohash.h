/*
 *  Copyright (C) 2014-2016 Savoir-faire Linux Inc.
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
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301 USA.
 */

#pragma once

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
#include <cstring>


// bytes
#define HASH_LEN 20u

namespace dht {

/**
 * Represents an InfoHash.
 * An InfoHash is a byte array of HASH_LEN bytes.
 * InfoHashes identify nodes and values in the Dht.
 */
class InfoHash final : public std::array<uint8_t, HASH_LEN> {
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
#ifdef WIN32_NATIVE
    static inline int cmp(const InfoHash& __restrict id1, const InfoHash& __restrict id2) {
#else
    static inline int cmp(const InfoHash& __restrict__ id1, const InfoHash& __restrict__ id2) {
#endif
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

    double
    toFloat() const
    {
        double v = 0.;
        for (unsigned i = 0; i < std::min<size_t>(HASH_LEN, sizeof(unsigned)-1); i++)
            v += *(cbegin()+i)/(double)(1<<(8*(i+1)));
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

    friend std::ostream& operator<< (std::ostream& s, const InfoHash& h);

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

struct NodeExport {
    InfoHash id;
    sockaddr_storage ss;
    socklen_t sslen;
};

}
