/*
 *  Copyright (C) 2016 Savoir-faire Linux Inc.
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

namespace dht {

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
    friend class dht::NetworkEngine;
    std::shared_ptr<Node> node {};             /* the node to whom the request is destined. */
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

    Request() {}
    Request(uint16_t tid,
            std::shared_ptr<Node> node,
            Blob&& msg,
            std::function<void(const Request& req_status, ParsedMessage&&)> on_done,
            std::function<void(const Request& req_status, bool)> on_expired,
            bool persistent = false) :
        node(node), on_done(on_done), on_expired(on_expired), tid(tid), msg(std::move(msg)), persistent(persistent) { }

    void setExpired() {
        if (pending()) {
            state_ = Request::State::EXPIRED;
            on_expired(*this, true);
            clear();
        }
    }
    void setDone(ParsedMessage&& msg) {
        if (pending() or persistent) {
            state_ = Request::State::COMPLETED;
            on_done(*this, std::forward<ParsedMessage>(msg));
            if (not persistent)
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
        return pending() and now > last_try + Node::MAX_RESPONSE_TIME and attempt_count >= Request::MAX_ATTEMPT_COUNT;
    }

    void clear() {
        on_done = {};
        on_expired = {};
        msg.clear();
    }

    State state_ {State::PENDING};

    unsigned attempt_count {0};                /* number of attempt to process the request. */
    time_point start {time_point::min()};      /* time when the request is created. */
    time_point last_try {time_point::min()};   /* time of the last attempt to process the request. */

    std::function<void(const Request& req_status, ParsedMessage&&)> on_done {};
    std::function<void(const Request& req_status, bool)> on_expired {};

    const uint16_t tid {0};                   /* the request id. */
    Blob msg {};                              /* the serialized message. */
    const bool persistent {false};            /* the request is not erased upon completion. */
};

}
