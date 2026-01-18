// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT
#pragma once

#include "node.h"

#include <list>
#include <memory>

namespace dht {

struct NodeCache
{
    size_t size(sa_family_t family) const { return cache(family).count(); }
    size_t size() const { return size(AF_INET) + size(AF_INET6); }

    Sp<Node> getNode(const InfoHash& id, sa_family_t family);
    Sp<Node> getNode(const InfoHash& id, const SockAddr&, time_point now, bool confirmed, bool client = false);
    std::vector<Sp<Node>> getCachedNodes(const InfoHash& id, sa_family_t sa_f, size_t count) const;

    /**
     * Reset the connectivity state of every node,
     * Giving them a new chance if they where expired.
     * To use in case of connectivity change etc.
     */
    void clearBadNodes(sa_family_t family = 0);

    NodeCache(std::mt19937_64& r)
        : rd(r) {};
    ~NodeCache();

private:
    class NodeMap : private std::map<InfoHash, std::weak_ptr<Node>>
    {
    public:
        Sp<Node> getNode(const InfoHash& id);
        Sp<Node> getNode(
            const InfoHash& id, const SockAddr&, time_point now, bool confirmed, bool client, std::mt19937_64& rd);
        std::vector<Sp<Node>> getCachedNodes(const InfoHash& id, size_t count) const;
        void clearBadNodes();
        void setExpired();
        void cleanup();
        size_t count() const { return size(); }

    private:
        size_t cleanup_counter {0};
    };

    const NodeMap& cache(sa_family_t af) const { return af == AF_INET ? cache_4 : cache_6; }
    NodeMap& cache(sa_family_t af) { return af == AF_INET ? cache_4 : cache_6; }
    NodeMap cache_4;
    NodeMap cache_6;
    std::mt19937_64& rd;
};

} // namespace dht
