/*
 *  Copyright (C) 2014-2020 Savoir-faire Linux Inc.
 *  Authors: Adrien Béraud <adrien.beraud@savoirfairelinux.com>
 *           Simon Désaulniers <simon.desaulniers@savoirfairelinux.com>
 *           Sébastien Blin <sebastien.blin@savoirfairelinux.com>
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

#include "infohash.h"
#include "value.h"

#include <vector>
#include <memory>
#include <functional>
#include <string>

#ifdef OPENDHT_JSONCPP
#include <json/json.h>
#endif

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

inline constexpr const char*
statusToStr(NodeStatus status) {
    return status == NodeStatus::Connected  ? "connected"  : (
           status == NodeStatus::Connecting ? "connecting" :
                                              "disconnected");
}

struct OPENDHT_PUBLIC NodeStats {
    unsigned good_nodes {0},
             dubious_nodes {0},
             cached_nodes {0},
             incoming_nodes {0};
    unsigned table_depth {0};
    unsigned searches {0};
    unsigned node_cache_size {0};
    unsigned getKnownNodes() const { return good_nodes + dubious_nodes; }
    unsigned long getNetworkSizeEstimation() const { return 8 * std::exp2(table_depth); }
    std::string toString() const;

#ifdef OPENDHT_JSONCPP
    /**
     * Build a json object from a NodeStats
     */
    Json::Value toJson() const;
    NodeStats() {};
    explicit NodeStats(const Json::Value& v);
#endif

    MSGPACK_DEFINE_MAP(good_nodes, dubious_nodes, cached_nodes, incoming_nodes, table_depth, searches, node_cache_size)
};

struct OPENDHT_PUBLIC NodeInfo {
    InfoHash id;
    InfoHash node_id;
    NodeStats ipv4 {};
    NodeStats ipv6 {};
    size_t ongoing_ops {0};
    in_port_t bound4 {0};
    in_port_t bound6 {0};

#ifdef OPENDHT_JSONCPP
    /**
     * Build a json object from a NodeStats
     */
    Json::Value toJson() const;
    NodeInfo() {};
    explicit NodeInfo(const Json::Value& v);
#endif

    MSGPACK_DEFINE_MAP(id, node_id, ipv4, ipv6)
};

/**
 * Dht configuration.
 */
struct OPENDHT_PUBLIC Config {
    /** DHT node ID */
    InfoHash node_id {};

    /**
     * DHT network ID. A node will only talk with other nodes having
     * the same network ID.
     * Network ID 0 (default) represents the main public network.
     */
    NetId network {0};

    /** For testing purposes only, enables bootstrap mode */
    bool is_bootstrap {false};

    /** Makes the DHT responsible to maintain its stored values. Consumes more ressources. */
    bool maintain_storage {false};

    /** If set, the dht will load its state from this file on start and save its state in this file on shutdown */
    std::string persist_path {};

    /** If non-0, overrides the default global rate-limit. -1 means no limit. */
    ssize_t max_req_per_sec {0};

    /** If non-0, overrides the default per-IP address rate-limit. -1 means no limit. */
    ssize_t max_peer_req_per_sec {0};

    /* If non-0, overrides the default maximum number of searches. -1 means no limit.  */
    ssize_t max_searches {0};

    /* If non-0, overrides the default maximum store size. -1 means no limit.  */
    ssize_t max_store_size {0};

    /** 
     * Use appropriate bahavior for a public IP, stable node:
     *   - No connectivity change triggered when a search fails
     *   - Larger listen refresh time
     */
    bool public_stable {false};
};

/**
 * SecureDht configuration.
 */
struct OPENDHT_PUBLIC SecureDhtConfig
{
    Config node_config {};
    crypto::Identity id {};

    /** 
     * Cache all encountered public keys and certificates,
     * for use by the certificate store, putEncrypted and putSigned
     */
    bool cert_cache_all {false};
};

static constexpr size_t DEFAULT_STORAGE_LIMIT {1024 * 1024 * 64};

using ValuesExport = std::pair<InfoHash, Blob>;

using QueryCallback = std::function<bool(const std::vector<std::shared_ptr<FieldValueIndex>>& fields)>;
using GetCallback = std::function<bool(const std::vector<std::shared_ptr<Value>>& values)>;
using ValueCallback = std::function<bool(const std::vector<std::shared_ptr<Value>>& values, bool expired)>;
using GetCallbackSimple = std::function<bool(std::shared_ptr<Value> value)>;
using ShutdownCallback = std::function<void()>;

using CertificateStoreQuery = std::function<std::vector<std::shared_ptr<crypto::Certificate>>(const InfoHash& pk_id)>;

typedef bool (*GetCallbackRaw)(std::shared_ptr<Value>, void *user_data);
typedef bool (*ValueCallbackRaw)(std::shared_ptr<Value>, bool expired, void *user_data);

using DoneCallback = std::function<void(bool success, const std::vector<std::shared_ptr<Node>>& nodes)>;
typedef void (*DoneCallbackRaw)(bool, std::vector<std::shared_ptr<Node>>*, void *user_data);
typedef void (*ShutdownCallbackRaw)(void *user_data);
typedef void (*DoneCallbackSimpleRaw)(bool, void *user_data);
typedef bool (*FilterRaw)(const Value&, void *user_data);

using DoneCallbackSimple = std::function<void(bool success)>;

OPENDHT_PUBLIC GetCallbackSimple bindGetCb(const GetCallbackRaw& raw_cb, void* user_data);
OPENDHT_PUBLIC GetCallback bindGetCb(const GetCallbackSimple& cb);
OPENDHT_PUBLIC ValueCallback bindValueCb(const ValueCallbackRaw& raw_cb, void* user_data);
OPENDHT_PUBLIC ShutdownCallback bindShutdownCb(const ShutdownCallbackRaw& shutdown_cb_raw, void* user_data);
OPENDHT_PUBLIC DoneCallback bindDoneCb(DoneCallbackSimple donecb);
OPENDHT_PUBLIC DoneCallback bindDoneCb(const DoneCallbackRaw& raw_cb, void* user_data);
OPENDHT_PUBLIC DoneCallbackSimple bindDoneCbSimple(const DoneCallbackSimpleRaw& raw_cb, void* user_data);
OPENDHT_PUBLIC Value::Filter bindFilterRaw(const FilterRaw& raw_filter, void* user_data);

}
