// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
#pragma once

#include "utils.h"
#include "sockaddr.h"

#include <map>
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
    /** Whether quota remains, without using it */
    bool available(const time_point& now)
    {
        return quota_ == std::numeric_limits<size_t>::max() or maintain(now) < quota_;
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

/**
 * A global quota and a quota per address. IPv6 addresses share the quota of their /64 prefix.
 * Negative quotas are unlimited.
 */
class AddressRateLimiter
{
public:
    AddressRateLimiter(ssize_t quota, ssize_t peerQuota, const duration& period = std::chrono::seconds(1))
        : global_(quota, period)
        , peerQuota_(peerQuota)
        , period_(period)
    {}

    bool limit(const SockAddr& addr, const time_point& now)
    {
        // Checked first so that dropped packets create no per-address record
        if (not global_.available(now))
            return false;
        if (peerQuota_ >= 0) {
            maintain(now);
            auto it = peers_.find(addr);
            if (it == peers_.end())
                it = peers_.emplace(addr, RateLimiter(peerQuota_, period_)).first;
            if (not it->second.limit(now))
                return false;
        }
        return global_.limit(now);
    }
    /** Number of addresses with a record */
    size_t size() const { return peers_.size(); }

private:
    void maintain(const time_point& now)
    {
        if (now < nextMaintenance_)
            return;
        for (auto it = peers_.begin(); it != peers_.end();)
            it = it->second.maintain(now) ? std::next(it) : peers_.erase(it);
        nextMaintenance_ = now + period_;
    }

    RateLimiter global_;
    const ssize_t peerQuota_;
    const duration period_;
    std::map<SockAddr, RateLimiter, SockAddr::ipCmp> peers_ {};
    time_point nextMaintenance_ {time_point::min()};
};

} // namespace dht
