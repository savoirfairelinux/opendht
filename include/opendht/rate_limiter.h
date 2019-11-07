/*
 *  Copyright (C) 2017-2019 Savoir-faire Linux Inc.
 *  Author : Adrien Béraud <adrien.beraud@savoirfairelinux.com>
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

#include "utils.h"
#include <queue>

namespace dht {

class RateLimiter {
public:
    RateLimiter() = delete;
    RateLimiter(size_t quota) : quota_(quota) {}

    /** Clear outdated records and return current quota usage */
    size_t maintain(const time_point& now) {
        auto limit = now - std::chrono::seconds(1);
        while (not records.empty() and records.front() < limit)
            records.pop();
        return records.size();
    }
    /** Return false if quota is reached, insert record and return true otherwise. */
    bool limit(const time_point& now) {
        if (quota_ == (size_t)-1)
            return true;
        if (maintain(now) >= quota_)
            return false;
        records.emplace(now);
        return true;
    }
    bool empty() const {
        return records.empty();
    }
    size_t quota() const {
        return quota_;
    }
private:
    const size_t quota_;
    std::queue<time_point> records {};
};

}
