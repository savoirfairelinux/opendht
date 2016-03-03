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

#include "node.h"

namespace dht {

constexpr std::chrono::minutes Node::NODE_EXPIRE_TIME;
constexpr std::chrono::minutes Node::NODE_GOOD_TIME;
constexpr std::chrono::seconds Node::MAX_RESPONSE_TIME;

/* This is our definition of a known-good node. */
bool
Node::isGood(time_point now) const
{
    return
        not isExpired(now) &&
        reply_time >= now - NODE_GOOD_TIME &&
        time >= now - NODE_EXPIRE_TIME;
}

bool
Node::isExpired(time_point now) const
{
    return pinged >= 3 && reply_time < pinged_time && pinged_time + MAX_RESPONSE_TIME < now;
}

bool
Node::isMessagePending(time_point now) const
{
    return reply_time < pinged_time && pinged_time + MAX_RESPONSE_TIME > now;
}

void
Node::update(const sockaddr* sa, socklen_t salen)
{
    std::copy_n((const uint8_t*)sa, salen, (uint8_t*)&ss);
    sslen = salen;
}

/** To be called when a message was sent to the node */
void
Node::requested(time_point now)
{
    pinged++;
    if (reply_time > pinged_time || pinged_time + MAX_RESPONSE_TIME < now)
        pinged_time = now;
}

/** To be called when a message was received from the node.
 Answer should be true if the message was an aswer to a request we made*/
void
Node::received(time_point now, bool answer)
{
    time = now;
    if (answer) {
        pinged = 0;
        reply_time = now;
    }
}

std::ostream& operator<< (std::ostream& s, const Node& h)
{
    s << h.id << " " << print_addr(h.ss, h.sslen);
    return s;
}

}
