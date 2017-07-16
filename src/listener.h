/*
 *  Copyright (C) 2014-2017 Savoir-faire Linux Inc.
 *  Author(s) : Adrien Béraud <adrien.beraud@savoirfairelinux.com>
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

#include "value.h"
#include "utils.h"

namespace dht {

/**
 * Foreign nodes asking for updates about an InfoHash.
 */
struct Listener {
    size_t sid;
    time_point time;
    Query query;

    Listener(size_t sid, time_point t, Query&& q) : sid(sid), time(t), query(std::move(q)) {}

    void refresh(size_t s, time_point t, Query&& q) {
        sid = s;
        time = t;
        query = std::move(q);
    }
};

/**
 * A single "listen" operation data
 */
struct LocalListener {
    Sp<Query> query;
    Value::Filter filter;
    GetCallback get_cb;
};

}
