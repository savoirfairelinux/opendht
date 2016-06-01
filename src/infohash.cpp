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

#include "infohash.h"
#include "rng.h"

extern "C" {
#include <gnutls/gnutls.h>
}

#include <functional>
#include <sstream>
#include <cstdio>

namespace dht {

InfoHash::InfoHash(const std::string& hex) {
    if (hex.size() < 2*HASH_LEN) {
        fill(0);
        return;
    }
    const auto p = (const char*)hex.data();
    for (size_t i = 0; i < HASH_LEN; i++) {
        unsigned res = 0;
        sscanf(p + 2*i, "%02x", &res);
        (*this)[i] = res;
    }
}

InfoHash
InfoHash::get(const uint8_t* data, size_t data_len)
{
    InfoHash h;
    size_t s = h.size();
    const gnutls_datum_t gnudata = {(uint8_t*)data, (unsigned)data_len};
    const gnutls_digest_algorithm_t algo =  (HASH_LEN == 64) ? GNUTLS_DIG_SHA512 : (
                                            (HASH_LEN == 32) ? GNUTLS_DIG_SHA256 : (
                                            (HASH_LEN == 20) ? GNUTLS_DIG_SHA1   :
                                            GNUTLS_DIG_NULL ));
    static_assert(algo != GNUTLS_DIG_NULL, "Can't find hash function to use.");
    int rc = gnutls_fingerprint(algo, &gnudata, h.data(), &s);
    if (rc == 0 && s == HASH_LEN)
        return h;
    throw std::string("Error while hashing");
}

InfoHash
InfoHash::getRandom()
{
    InfoHash h;
    crypto::random_device rdev;
#ifdef _WIN32
    static std::uniform_int_distribution<int> rand_byte{ 0, std::numeric_limits<uint8_t>::max() };
#else
    static std::uniform_int_distribution<uint8_t> rand_byte;
#endif
    std::generate(h.begin(), h.end(), std::bind(rand_byte, std::ref(rdev)));
    return h;
}

std::string
InfoHash::toString() const
{
    std::stringstream ss;
    ss << *this;
    return ss.str();
}

std::ostream& operator<< (std::ostream& s, const InfoHash& h)
{
    s << std::hex;
    for (unsigned i=0; i<HASH_LEN; i++)
        s << std::setfill('0') << std::setw(2) << (unsigned)h[i];
    s << std::dec;
    return s;
}

}
