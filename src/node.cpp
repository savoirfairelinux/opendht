/*
 *  Copyright (C) 2014-2020 Savoir-faire Linux Inc.
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


#include "node.h"
#include "request.h"
#include "rng.h"

#include <sstream>

namespace dht {

constexpr std::chrono::minutes Node::NODE_EXPIRE_TIME;
constexpr std::chrono::minutes Node::NODE_GOOD_TIME;
constexpr std::chrono::seconds Node::MAX_RESPONSE_TIME;

Node::Node(const InfoHash& id, const SockAddr& addr, std::mt19937_64& rd, bool client)
: id(id), addr(addr), is_client(client), sockets_()
{
    transaction_id = std::uniform_int_distribution<Tid>{1}(rd);
}

Node::Node(const InfoHash& id, SockAddr&& addr, std::mt19937_64& rd, bool client)
: id(id), addr(std::move(addr)), is_client(client), sockets_()
{
    transaction_id = std::uniform_int_distribution<Tid>{1}(rd);
}

/* This is our definition of a known-good node. */
bool
Node::isGood(time_point now) const
{
    return not expired_ &&
        reply_time >= now - NODE_GOOD_TIME &&
        time >= now - NODE_EXPIRE_TIME;
}

bool
Node::isPendingMessage() const
{
    for (const auto& r : requests_) {
        if (r.second->pending())
            return true;
    }
    return false;
}

size_t
Node::getPendingMessageCount() const
{
    size_t count {0};
    for (const auto& r : requests_) {
        if (r.second->pending())
            count++;
    }
    return count;
}

void
Node::update(const SockAddr& new_addr)
{
    addr = new_addr;
}

/** To be called when a message was sent to the node */
void
Node::requested(const Sp<net::Request>& req)
{
    auto e = requests_.emplace(req->getTid(), req);
    if (not e.second and req != e.first->second) {
        // Should not happen !
        // Try to handle this scenario as well as we can
        e.first->second->setExpired();
        e.first->second = req;
    }
}

/** To be called when a message was received from the node.
 Req should be true if the message was an aswer to a request we made*/
void
Node::received(time_point now, const Sp<net::Request>& req)
{
    time = now;
    expired_ = false;
    if (req) {
        reply_time = now;
        requests_.erase(req->getTid());
    }
}

Sp<net::Request>
Node::getRequest(Tid tid)
{
    auto it = requests_.find(tid);
    return it != requests_.end() ? it->second : nullptr;
}

void
Node::cancelRequest(const Sp<net::Request>& req)
{
    if (req) {
        req->cancel();
        closeSocket(req->closeSocket());
        requests_.erase(req->getTid());
    }
}

void
Node::setExpired()
{
    expired_ = true;
    for (auto r : requests_) {
        r.second->setExpired();
    }
    requests_.clear();
    sockets_.clear();
}

Tid
Node::openSocket(SocketCb&& cb)
{
    if (++transaction_id == 0)
        transaction_id = 1;

    auto sock = std::make_shared<Socket>(std::move(cb));
    auto s = sockets_.emplace(transaction_id, std::move(sock));
    if (not s.second)
        s.first->second = std::move(sock);
    return transaction_id;
}

Sp<Socket>
Node::getSocket(Tid id)
{
    auto it = sockets_.find(id);
    return it == sockets_.end() ? nullptr : it->second;
}

void
Node::closeSocket(Tid id)
{
    if (id) {
        sockets_.erase(id);
        //DHT_LOG.w("Closing socket (tid: %d), %lu remaining", socket->id, sockets_.size());
    }
}

std::string
Node::toString() const
{
    std::stringstream ss;
    ss << (*this);
    return ss.str();
}

std::ostream& operator<< (std::ostream& s, const Node& h)
{
    s << h.id << " " << h.addr.toString();
    return s;
}

}
