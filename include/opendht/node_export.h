// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
#pragma once

#include "def.h"
#include "infohash.h"
#include "sockaddr.h"

#include <string_view>

namespace dht {
using namespace std::literals;

struct OPENDHT_PUBLIC NodeExport
{
    InfoHash id;
    SockAddr addr;

    template<typename Packer>
    void msgpack_pack(Packer& pk) const
    {
        pk.pack_map(2);
        pk.pack("id"sv);
        pk.pack(id);
        pk.pack("addr"sv);
        pk.pack_bin(addr.getLength());
        pk.pack_bin_body((const char*) addr.get(), (size_t) addr.getLength());
    }

    void msgpack_unpack(msgpack::object o);

    OPENDHT_PUBLIC friend std::ostream& operator<<(std::ostream& s, const NodeExport& h);
};

} // namespace dht
