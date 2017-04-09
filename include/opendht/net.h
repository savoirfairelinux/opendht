/*
 *  Copyright (C) 2014-2017 Savoir-faire Linux Inc.
 *  Author(s) : Adrien Béraud <adrien.beraud@savoirfairelinux.com>
 *              Simon Désaulniers <simon.desaulniers@savoirfairelinux.com>
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

#include <array>
#include <cstdint>

namespace dht {
namespace net {

struct TransPrefix : public std::array<uint8_t, 2> {
    TransPrefix(const std::string& str) : std::array<uint8_t, 2>({{(uint8_t)str[0], (uint8_t)str[1]}}) {}
    static const TransPrefix PING;
    static const TransPrefix FIND_NODE;
    static const TransPrefix GET_VALUES;
    static const TransPrefix ANNOUNCE_VALUES;
    static const TransPrefix REFRESH;
    static const TransPrefix LISTEN;
};

/* Transaction-ids are 4-bytes long, with the first two bytes identifying
 * the kind of request, and the remaining two a sequence number in
 * host order.
 */
struct TransId final : public std::array<uint8_t, 4> {
    static const constexpr uint16_t INVALID {0};

    TransId() { std::fill_n(begin(), 4, 0); }
    TransId(const std::array<char, 4>& o) { std::copy(o.begin(), o.end(), begin()); }
    TransId(const TransPrefix prefix, uint16_t seqno = 0) {
        std::copy_n(prefix.begin(), prefix.size(), begin());
        *reinterpret_cast<uint16_t*>(data()+prefix.size()) = seqno;
    }

    TransId(const char* q, size_t l) : array<uint8_t, 4>() {
        if (l > 4) {
            length = 0;
        } else {
            std::copy_n(q, l, begin());
            length = l;
        }
    }

    uint16_t getTid() const {
        return *reinterpret_cast<const uint16_t*>(&(*this)[2]);
    }

    uint32_t toInt() const {
        return *reinterpret_cast<const uint32_t*>(&(*this)[0]);
    }

    bool matches(const TransPrefix prefix, uint16_t* tid = nullptr) const {
        if (std::equal(begin(), begin()+2, prefix.begin())) {
            if (tid)
                *tid = getTid();
            return true;
        } else
            return false;
    }

    unsigned length {4};
};

} /* namespace net */
} /* dht */
