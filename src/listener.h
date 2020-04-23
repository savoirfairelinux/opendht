/*
 *  Copyright (C) 2014-2020 Savoir-faire Linux Inc.
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
#include "callbacks.h"

namespace dht {

/**
 * Foreign nodes asking for updates about an InfoHash.
 */
struct Listener {
    time_point time;
    Query query;
    int version;

    Listener(time_point t, Query&& q, int version = 0) : time(t), query(std::move(q)), version(version) {}

    void refresh(time_point t, Query&& q) {
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
    ValueCallback get_cb;
};

}
