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

#include "infohash.h" // includes socket structures
#include "utils.h"
#include "sockaddr.h"
#include "uv_utils.h"

#include <list>

namespace dht {

namespace net {
struct Request;
} /* namespace net */

struct Node {
    InfoHash id;
    SockAddr addr;
    Sp<TcpSocket> sock;

    time_point time {time_point::min()};            /* last time eared about */
    time_point reply_time {time_point::min()};      /* time of last correct reply received */

    Node(const InfoHash& id, const sockaddr* sa, socklen_t salen)
        : id(id), addr(sa, salen) {}
    Node(const InfoHash& id, const SockAddr& addr, const Sp<TcpSocket>& s = {}) : id(id), addr(addr), sock(s) {}
    ~Node() {
        if (sock)
            sock->close();
    }

    InfoHash getId() const {
        return id;
    }
    std::pair<const sockaddr*, socklen_t> getAddr() const {
        return {(const sockaddr*)&addr.first, addr.second};
    }
    std::string getAddrStr() const {
        return addr.toString();
    }

    /**
     * Makes notice about an additionnal authentication error with this node. Up
     * to MAX_AUTH_ERRORS errors are accepted in order to let the node recover.
     * Upon this limit, the node expires.
     */
    void authError() {
        if (++auth_errors > MAX_AUTH_ERRORS)
            setExpired();
    }
    void authSuccess() { auth_errors = 0; }

    bool isExpired() const { return expired_; }
    bool isGood(time_point now) const;
    bool isPendingMessage() const;
    size_t getPendingMessageCount() const;

    NodeExport exportNode() const { return NodeExport {id, addr.first, addr.second}; }
    sa_family_t getFamily() const { return addr.getFamily(); }

    void update(const SockAddr&, const Sp<TcpSocket>&);

    bool canStream() const {
        return sock and not sock->isClosed() and sock->canWrite();
    }

    void requested(Sp<net::Request>& req);
    void received(time_point now, Sp<net::Request> req);

    void setExpired();

    /**
     * Resets the state of the node so it's not expired anymore.
     */
    void reset() { expired_ = false; reply_time = time_point::min(); }

    std::string toString() const;

    OPENDHT_PUBLIC friend std::ostream& operator<< (std::ostream& s, const Node& h);

    static constexpr const std::chrono::minutes NODE_GOOD_TIME {120};

    /* The time after which we consider a node to be expirable. */
    static constexpr const std::chrono::minutes NODE_EXPIRE_TIME {10};

    /* Time for a request to timeout */
    static constexpr const std::chrono::seconds MAX_RESPONSE_TIME {1};

private:
    /* Number of times we accept authentication errors from this node. */
    static const constexpr unsigned MAX_AUTH_ERRORS {3};

    std::list<std::weak_ptr<net::Request>> requests_ {};
    unsigned auth_errors {0};
    bool expired_ {false};

    void clearPendingQueue() {
        requests_.remove_if([](std::weak_ptr<net::Request>& w) {
            return w.expired();
        });
    }
};

}
