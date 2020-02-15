/*
 *  Copyright (C) 2014-2020 Savoir-faire Linux Inc.
 *  Author(s) : Paymon <paymon@savoirfairelinux.com>
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

#include "log.h"

#include <functional>
#include <thread>
#include <mutex>
#include <atomic>

struct nl_sock;
struct nl_msg;
struct sockaddr_nl;
struct ucred;

namespace dht {
namespace net {

class OPENDHT_PUBLIC ConnectivityStatus
{
public:
    enum class Event : long unsigned int {
        NONE_EVENT = 0,
        ADDR,
        ROUTE,
        LINK,
        NEIGHT,
        EVENTS_NEW,
        NEWLINK,
        NEWROUTE4,
        NEWROUTE6,
        NEWROUTE,
        NEWADDR4,
        NEWADDR6,
        NEWADDR,
        NEWNEIGH,
        NEIGHTBL,
        IPV4_MROUTE,
        IPV6_MROUTE,
        IP_MROUTE,
        EVENTS_DEL,
        DELLINK,
        DELROUTE4,
        DELROUTE6,
        DELROUTE,
        DELADDR4,
        DELADDR6,
        DELADDR,
        DELNEIGH
    };

    ConnectivityStatus();
    ~ConnectivityStatus();

    using ConnectionEventCb = std::function<void (Event)>;

    void setEventListener    (ConnectionEventCb ucb, Event);
    void removeEventListener (Event);

private:

    std::mutex mtx_;
    std::unique_ptr<dht::Logger> logger_;

    std::map<Event, ConnectionEventCb> event_cbs = {};

    using NlMsgPtr = std::unique_ptr<nl_msg, void(*)(nl_msg *)>;
    NlMsgPtr bye;
    using NlPtr = std::unique_ptr<nl_sock, void(*)(nl_sock *)>;
    NlPtr nlsk;
    static NlPtr nlsk_init ();

    void nlsk_setup         (nl_sock*);
    void nl_event_loop_thrd (nl_sock*);
    void get_neigh_state    (struct nl_msg*);
    int nl_event_cb         (struct nl_msg*);
    void executer           (Event);

    std::atomic_bool stop {false};

    std::thread thrd_;
};

} /* namespace net */
} /* namespace dht */
