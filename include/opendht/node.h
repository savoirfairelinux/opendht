/*
Copyright (C) 2009-2014 Juliusz Chroboczek
Copyright (C) 2014-2016 Savoir-faire Linux Inc.

Author(s) : Adrien Béraud <adrien.beraud@savoirfairelinux.com>,
            Simon Désaulniers <sim.desaulniers@gmail.com>

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
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
