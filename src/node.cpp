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


#include "node.h"
#include "request.h"

#include <sstream>

namespace dht {

constexpr std::chrono::minutes Node::NODE_EXPIRE_TIME;
constexpr std::chrono::minutes Node::NODE_GOOD_TIME;
constexpr std::chrono::seconds Node::MAX_RESPONSE_TIME;

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
    for (auto w : requests_) {
        if (auto r = w.lock()) {
            if (r->pending())
                return true;
        }
    }
    return false;
}

size_t
Node::getPendingMessageCount() const
{
    size_t count {0};
    for (auto w : requests_) {
        if (auto r = w.lock()) {
            if (r->pending())
                count++;
        }
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
Node::requested(std::shared_ptr<net::Request>& req)
{
    requests_.emplace_back(req);
}

/** To be called when a message was received from the node.
 Req should be true if the message was an aswer to a request we made*/
void
Node::received(time_point now, std::shared_ptr<net::Request> req)
{
    time = now;
    expired_ = false;
    if (req) {
        reply_time = now;
        for (auto it = requests_.begin(); it != requests_.end();) {
            auto r = it->lock();
            if (not r or r == req)
                it = requests_.erase(it);
            else
                ++it;
        }
    }
}

void
Node::setExpired()
{
    expired_ = true;
    for (auto w : requests_) {
        if (auto r = w.lock())
            r->setExpired();
    }
    requests_.clear();
    sockets_.clear();
}


Sp<net::Socket>
Node::openSocket(const net::TransId& tid, net::SocketCb&& cb)
{
    auto s = sockets_.emplace(tid, std::make_shared<net::Socket>(tid, cb));
    //if (not s.second)
    //    DHT_LOG.e(id, "[node %s] socket (tid: %d) already opened!", id.toString().c_str(), tid.toInt());
    //else
    //    DHT_LOG.w("Opened socket (tid: %d), %lu opened", s.first->second->id, sockets_.size());
    return s.first->second;
}


Sp<net::Socket>
Node::getSocket(const net::TransId& tid) const
{
    auto it = sockets_.find(tid);
    return it == sockets_.end() ? nullptr : it->second;
}

void
Node::closeSocket(const Sp<net::Socket>& socket)
{
    if (socket) {
        sockets_.erase(socket->id);
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
