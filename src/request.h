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

#pragma once

#include "net.h"
#include "value.h"

namespace dht {
struct Node;
namespace net {

class NetworkEngine;
struct ParsedMessage;

/*!
 * @class   Request
 * @brief   An atomic request destined to a node.
 * @details
 * A request contains data used by the NetworkEngine to process a request
 * desitned to specific node and std::function callbacks to execute when the
 * request is done.
 */
struct Request {
    friend class dht::net::NetworkEngine;

    Sp<Node> node {};             /* the node to whom the request is destined. */
    time_point reply_time {time_point::min()}; /* time when we received the response to the request. */

    enum class State
    {
        PENDING,
        CANCELLED,
        EXPIRED,
        COMPLETED
    };

    bool expired() const { return state_ == State::EXPIRED; }
    bool completed() const { return state_ == State::COMPLETED; }
    bool cancelled() const { return state_ == State::CANCELLED; }
    bool pending() const { return state_ == State::PENDING; }
    bool over() const { return not pending(); }
    State getState() const { return state_; }
    char getStateChar() const {
        switch (state_) {
            case State::PENDING:   return 'f';
            case State::CANCELLED: return 'c';
            case State::EXPIRED:   return 'e';
            case State::COMPLETED: return 'a';
            default:               return '?';
        }
    }

    Request(State state = State::PENDING) : state_(state) {}
    Request(MessageType type, Tid tid,
            Sp<Node> node,
            Blob&& msg,
            std::function<void(const Request&, ParsedMessage&&)> on_done,
            std::function<void(const Request&, bool)> on_expired,
            Tid socket = 0) :
        node(node), tid(tid), type(type), on_done(on_done), on_expired(on_expired), msg(std::move(msg)), socket(socket) { }

    Tid getTid() const { return tid; }
    MessageType getType() const { return type; }

    Tid getSocket() { return socket; }
    Tid closeSocket() { auto ret = socket; socket = 0; return ret; }

    void setExpired() {
        if (pending()) {
            state_ = Request::State::EXPIRED;
            on_expired(*this, true);
            clear();
        }
    }
    void setDone(ParsedMessage&& msg) {
        if (pending()) {
            state_ = Request::State::COMPLETED;
            on_done(*this, std::forward<ParsedMessage>(msg));
            clear();
        }
    }

    void cancel() {
        if (pending()) {
            state_ = State::CANCELLED;
            clear();
        }
    }

private:
    static const constexpr size_t MAX_ATTEMPT_COUNT {3};

    bool isExpired(time_point now) const {
        return pending() and now > last_try + attempt_duration and attempt_count >= Request::MAX_ATTEMPT_COUNT;
    }

    void clear() {
        on_done = {};
        on_expired = {};
        msg = {};
        parts = {};
    }

    const Tid tid {0}; /* the request id. */
    const MessageType type {};
    State state_ {State::PENDING};

    unsigned attempt_count {0};                /* number of attempt to process the request. */
    duration attempt_duration {((duration)Node::MAX_RESPONSE_TIME)/2};
    time_point start {time_point::min()};      /* time when the request is created. */
    time_point last_try {time_point::min()};   /* time of the last attempt to process the request. */

    std::function<void(const Request&, ParsedMessage&&)> on_done {};
    std::function<void(const Request&, bool)> on_expired {};

    Blob msg {};                      /* the serialized message. */
    std::vector<Blob> parts;
    Tid socket;   /* the socket used for further reponses. */
};

} /* namespace net  */
}
