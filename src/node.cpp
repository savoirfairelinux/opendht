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
Node::update(const sockaddr* sa, socklen_t salen)
{
    std::copy_n((const uint8_t*)sa, salen, (uint8_t*)&ss);
    sslen = salen;
}

/** To be called when a message was sent to the node */
void
Node::requested(std::shared_ptr<Request>& req)
{
    requests_.emplace_back(req);
}

/** To be called when a message was received from the node.
 Req should be true if the message was an aswer to a request we made*/
void
Node::received(time_point now, std::shared_ptr<Request> req)
{
    time = now;
    if (req) {
        reply_time = now;
        expired_ = false;
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
    s << h.id << " " << print_addr(h.ss, h.sslen);
    return s;
}

}
