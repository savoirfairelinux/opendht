/*
 *  Copyright (C) 2014-2016 Savoir-faire Linux Inc.
 *  Author(s) : Adrien Béraud <adrien.beraud@savoirfairelinux.com>
 *              Simon Désaulniers <sim.desaulniers@gmail.com>
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

#include "utils.h"
#include "infohash.h"

#include <arpa/inet.h>

namespace dht {

struct NodeExport {
    InfoHash id;
    sockaddr_storage ss;
    socklen_t sslen;
};

struct Node {
    InfoHash id {};
    sockaddr_storage ss;
    socklen_t sslen {0};
    time_point time {time_point::min()};            /* last time eared about */
    time_point reply_time {time_point::min()};      /* time of last correct reply received */
    time_point pinged_time {time_point::min()};     /* time of last message sent */
    unsigned pinged {0};           /* how many requests we sent since last reply */

    Node() : ss() {
        std::fill_n((uint8_t*)&ss, sizeof(ss), 0);
    }
    Node(const InfoHash& id, const sockaddr* sa, socklen_t salen)
        : id(id), ss(), sslen(salen) {
            std::copy_n((const uint8_t*)sa, salen, (uint8_t*)&ss);
            if ((unsigned)salen < sizeof(ss))
                std::fill_n((uint8_t*)&ss+salen, sizeof(ss)-salen, 0);
        }
    InfoHash getId() const {
        return id;
    }
    std::pair<const sockaddr*, socklen_t> getAddr() const {
        return {(const sockaddr*)&ss, sslen};
    }
    std::string getAddrStr() const {
        return print_addr(ss, sslen);
    }
    bool isExpired(time_point now) const;
    bool isExpired() const { return isExpired(clock::now()); }
    bool isGood(time_point now) const;
    bool isMessagePending(time_point now) const;
    NodeExport exportNode() const { return NodeExport {id, ss, sslen}; }
    sa_family_t getFamily() const { return ss.ss_family; }

    void update(const sockaddr* sa, socklen_t salen);

    /** To be called when a message was sent to the node */
    void requested(time_point now);

    /** To be called when a message was received from the node.
      Answer should be true if the message was an aswer to a request we made*/
    void received(time_point now, bool answer);

    friend std::ostream& operator<< (std::ostream& s, const Node& h);

    static constexpr const std::chrono::minutes NODE_GOOD_TIME {120};

    /* The time after which we consider a node to be expirable. */
    static constexpr const std::chrono::minutes NODE_EXPIRE_TIME {10};

    /* Time for a request to timeout */
    static constexpr const std::chrono::seconds MAX_RESPONSE_TIME {3};
};

}
