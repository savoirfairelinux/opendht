// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
#pragma once

#include "utils.h"
#include <queue>

namespace dht {

class RateLimiter
{
public:
    RateLimiter(size_t quota, const duration& period = std::chrono::seconds(1))
        : quota_(quota)
        , period_(period)
    {}

    /** Clear outdated records and return current quota usage */
    size_t maintain(const time_point& now)
    {
        auto limit = now - period_;
        while (not records.empty() and records.front() < limit)
            records.pop();
        return records.size();
    }
    /** Return false if quota is reached, insert record and return true otherwise. */
    bool limit(const time_point& now)
    {
        if (quota_ == std::numeric_limits<size_t>::max())
            return true;
        if (maintain(now) >= quota_)
            return false;
        records.emplace(now);
        return true;
    }
    bool empty() const { return records.empty(); }

private:
    const size_t quota_;
    const duration period_;
    std::queue<time_point> records {};
};

} // namespace dht
