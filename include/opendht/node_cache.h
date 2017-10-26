/*
 *  Copyright (C) 2014-2017 Savoir-faire Linux Inc.
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
 *  along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#pragma once

#include "node.h"

#include <list>
#include <memory>

namespace dht {

struct NodeCache {
    Sp<Node> getNode(const InfoHash& id, sa_family_t family);
    Sp<Node> getNode(const InfoHash& id, const SockAddr&, time_point now, bool confirmed, bool client=false);
    std::vector<Sp<Node>> getCachedNodes(const InfoHash& id, sa_family_t sa_f, size_t count) const;

    /**
     * Reset the connectivity state of every node,
     * Giving them a new chance if they where expired.
     * To use in case of connectivity change etc.
     */
    void clearBadNodes(sa_family_t family = 0);

    ~NodeCache();

private:
    class NodeMap : public std::map<InfoHash, std::weak_ptr<Node>> {
    public:
        Sp<Node> getNode(const InfoHash& id);
        Sp<Node> getNode(const InfoHash& id, const SockAddr&, time_point now, bool confirmed, bool client);
        void clearBadNodes();
        void setExpired();
    };

    const NodeMap& cache(sa_family_t af) const { return af == AF_INET ? cache_4 : cache_6; }
    NodeMap& cache(sa_family_t af) { return af == AF_INET ? cache_4 : cache_6; }
    NodeMap cache_4;
    NodeMap cache_6;
};

}
