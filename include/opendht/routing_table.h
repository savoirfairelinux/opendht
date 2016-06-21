/*
 *  Copyright (C) 2014-2016 Savoir-faire Linux Inc.
 *  Author(s) : Adrien Béraud <adrien.beraud@savoirfairelinux.com>
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

#include "node.h"

namespace dht {

static constexpr unsigned TARGET_NODES {8};

struct Bucket {
    Bucket() : cached() {}
    Bucket(sa_family_t af, const InfoHash& f = {}, time_point t = time_point::min())
        : af(af), first(f), time(t), cached() {}
    sa_family_t af {0};
    InfoHash first {};
    time_point time {time_point::min()};             /* time of last reply in this bucket */
    std::list<std::shared_ptr<Node>> nodes {};
    std::shared_ptr<Node> cached;                    /* the address of a likely candidate */

    /** Return a random node in a bucket. */
    std::shared_ptr<Node> randomNode();
};

class RoutingTable : public std::list<Bucket> {
public:
    using std::list<Bucket>::list;

    InfoHash middle(const RoutingTable::const_iterator&) const;

    std::vector<std::shared_ptr<Node>> findClosestNodes(const InfoHash id, time_point now, size_t count = TARGET_NODES) const;

    RoutingTable::iterator findBucket(const InfoHash& id);
    RoutingTable::const_iterator findBucket(const InfoHash& id) const;

    /**
     * Return true if the id is in the bucket's range.
     */
    inline bool contains(const RoutingTable::const_iterator& bucket, const InfoHash& id) const {
        return InfoHash::cmp(bucket->first, id) <= 0
            && (std::next(bucket) == end() || InfoHash::cmp(id, std::next(bucket)->first) < 0);
    }

    /**
     * Return true if the table has no bucket ore one empty buket.
     */
    inline bool isEmpty() const {
        return empty() || (size() == 1 && front().nodes.empty());
    }

    /**
     * Return a random id in the bucket's range.
     */
    InfoHash randomId(const RoutingTable::const_iterator& bucket) const;

    unsigned depth(const RoutingTable::const_iterator& bucket) const;

    /**
     * Split a bucket in two equal parts.
     */
    bool split(const RoutingTable::iterator& b);
};

}
