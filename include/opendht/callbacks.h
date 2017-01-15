/*
 *  Copyright (C) 2014-2017 Savoir-faire Linux Inc.
 *  Author : Adrien Béraud <adrien.beraud@savoirfairelinux.com>
 *           Simon Désaulniers <simon.desaulniers@savoirfairelinux.com>
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

#pragma once

#include "infohash.h"
#include "value.h"

#include <vector>
#include <memory>
#include <functional>

namespace dht {

struct Node;

/**
 * Current status of a DHT node.
 */
enum class NodeStatus {
    Disconnected, // 0 nodes
    Connecting,   // 1+ nodes
    Connected     // 1+ good nodes
};

struct OPENDHT_PUBLIC NodeStats {
    unsigned good_nodes,
             dubious_nodes,
             cached_nodes,
             incoming_nodes;
    unsigned table_depth;
    unsigned getKnownNodes() const { return good_nodes + dubious_nodes; }
    std::string toString() const;
};

/**
 * Dht configuration.
 */
struct OPENDHT_PUBLIC Config {
    /** DHT node ID */
    InfoHash node_id;

    /**
     * DHT network ID. A node will only talk with other nodes having
     * the same network ID.
     * Network ID 0 (default) represents the main public network.
     */
    NetId network;

    /** For testing purposes only, enables bootstrap mode */
    bool is_bootstrap;

    /** Makes the DHT responsible to maintain its stored values. Consumes more ressources. */
    bool maintain_storage;
};

/**
 * SecureDht configuration.
 */
struct OPENDHT_PUBLIC SecureDhtConfig
{
    Config node_config;
    crypto::Identity id;
};

static constexpr size_t DEFAULT_STORAGE_LIMIT {1024 * 1024 * 64};

using ValuesExport = std::pair<InfoHash, Blob>;

using QueryCallback = std::function<bool(const std::vector<std::shared_ptr<FieldValueIndex>>& fields)>;
using GetCallback = std::function<bool(const std::vector<std::shared_ptr<Value>>& values)>;
using GetCallbackSimple = std::function<bool(std::shared_ptr<Value> value)>;
using ShutdownCallback = std::function<void()>;

using CertificateStoreQuery = std::function<std::vector<std::shared_ptr<crypto::Certificate>>(const InfoHash& pk_id)>;

typedef bool (*GetCallbackRaw)(std::shared_ptr<Value>, void *user_data);

OPENDHT_PUBLIC GetCallbackSimple bindGetCb(GetCallbackRaw raw_cb, void* user_data);
OPENDHT_PUBLIC GetCallback bindGetCb(GetCallbackSimple cb);

using DoneCallback = std::function<void(bool success, const std::vector<std::shared_ptr<Node>>& nodes)>;
typedef void (*DoneCallbackRaw)(bool, std::vector<std::shared_ptr<Node>>*, void *user_data);
typedef void (*ShutdownCallbackRaw)(void *user_data);
typedef void (*DoneCallbackSimpleRaw)(bool, void *user_data);

using DoneCallbackSimple = std::function<void(bool success)>;

OPENDHT_PUBLIC ShutdownCallback bindShutdownCb(ShutdownCallbackRaw shutdown_cb_raw, void* user_data);
OPENDHT_PUBLIC DoneCallback bindDoneCb(DoneCallbackSimple donecb);
OPENDHT_PUBLIC DoneCallback bindDoneCb(DoneCallbackRaw raw_cb, void* user_data);
OPENDHT_PUBLIC DoneCallbackSimple bindDoneCbSimple(DoneCallbackSimpleRaw raw_cb, void* user_data);

}
