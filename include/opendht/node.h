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
#include "net.h"

#include <list>
#include <map>

namespace dht {

struct Node;
namespace net {
struct Request;
struct Socket;
struct RequestAnswer;
using SocketCb = std::function<void(const Sp<Node>&, RequestAnswer&&)>;
} /* namespace net */

struct Node {
    const InfoHash id;
    SockAddr addr;
    bool is_client {false};

    time_point time {time_point::min()};            /* last time eared about */
    time_point reply_time {time_point::min()};      /* time of last correct reply received */

    Node(const InfoHash& id, const SockAddr& addr, bool client=false);
    Node(const InfoHash& id, const sockaddr* sa, socklen_t salen)
        : Node(id, SockAddr(sa, salen)) {}

    InfoHash getId() const {
        return id;
    }
    std::pair<const sockaddr*, socklen_t> getAddr() const {
        return {addr.get(), addr.getLength()};
    }
    std::string getAddrStr() const {
        return addr.toString();
    }
    bool isClient() const { return is_client; }

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

    NodeExport exportNode() const {
        NodeExport ne;
        ne.id = id;
        ne.sslen = addr.getLength();
        std::memcpy(&ne.ss, addr.get(), ne.sslen);
        return ne;
    }
    sa_family_t getFamily() const { return addr.getFamily(); }

    void update(const SockAddr&);

    void requested(const Sp<net::Request>& req);
    void received(time_point now, const Sp<net::Request>& req);
    Sp<net::Request> getRequest(const net::TransId& tid);
    void cancelRequest(const Sp<net::Request>& req);

    void setExpired();

    /**
     * Opens a socket on which a node will be able allowed to write for further
     * additionnal updates following the response to a previous request.
     *
     * @param node  The node which will be allowed to write on this socket.
     * @param cb    The callback to execute once updates arrive on the socket.
     *
     * @return the socket.
     */
    Sp<net::Socket> openSocket(const net::TransId& id, net::SocketCb&& cb);

    Sp<net::Socket> getSocket(const net::TransId& id) const;

    /**
     * Closes a socket so that no further data will be red on that socket.
     *
     * @param socket  The socket to close.
     */
    void closeSocket(const Sp<net::Socket>& socket);

    /**
     * Resets the state of the node so it's not expired anymore.
     */
    void reset() { expired_ = false; reply_time = time_point::min(); }

    /**
     * Generates a new request id, skipping the invalid id.
     *
     * @return the new id.
     */
    uint16_t getNewTid() {
        ++transaction_id;
        return transaction_id == net::TransId::INVALID ? ++transaction_id : transaction_id;
    }

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

    std::map<net::TransId, Sp<net::Request>> requests_ {};
    std::map<net::TransId, Sp<net::Socket>> sockets_ {};

    unsigned auth_errors {0};
    bool expired_ {false};
    uint16_t transaction_id {1};
    using TransactionDist = std::uniform_int_distribution<decltype(transaction_id)>;
};

}
