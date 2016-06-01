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

#include <list>
#include <memory>

namespace dht {

struct NodeCache {
    std::shared_ptr<Node> getNode(const InfoHash& id, sa_family_t family);
    std::shared_ptr<Node> getNode(const InfoHash& id, const sockaddr* sa, socklen_t sa_len, time_point now, int confirmed);

    /**
     * Reset the connectivity state of every node,
     * Giving them a new chance if they where expired.
     * To use in case of connectivity change etc.
     */
    void clearBadNodes(sa_family_t family = 0);

private:
    class NodeMap : public std::map<InfoHash, std::weak_ptr<Node>> {
    public:
        std::shared_ptr<Node> getNode(const InfoHash& id);
        std::shared_ptr<Node> getNode(const InfoHash& id, const sockaddr* sa, socklen_t sa_len, time_point now, int confirmed);
        void clearBadNodes();
    };

    NodeMap cache_4;
    NodeMap cache_6;
};

}
