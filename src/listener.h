// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
#pragma once

#include "value.h"
#include "utils.h"
#include "callbacks.h"
#include "network_engine.h"
#include "request.h"

namespace dht {

/**
 * Foreign nodes asking for updates about an InfoHash.
 */
struct Listener
{
    struct Stream
    {
        net::ListenSync sync;
        std::vector<Sp<net::Request>> initialRequests;
        ~Stream()
        {
            for (const auto& request : initialRequests)
                request->cancel();
        }
    };

    time_point time;
    Query query;
    int version;
    std::shared_ptr<Stream> stream;

    Listener(time_point t, Query&& q, int version = 0)
        : time(t)
        , query(std::move(q))
        , version(version)
    {}

    void refresh(time_point t, Query&& q)
    {
        time = t;
        query = std::move(q);
    }
};

/**
 * A single "listen" operation data
 */
struct LocalListener
{
    Sp<Query> query;
    Value::Filter filter;
    ValueCallback get_cb;
};

} // namespace dht
