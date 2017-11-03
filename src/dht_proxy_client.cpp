/*
 *  Copyright (C) 2016 Savoir-faire Linux Inc.
 *  Author : Sébastien Blin <sebastien.blin@savoirfairelinux.com>
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

#if OPENDHT_PROXY_SERVER

#include "dht_proxy_client.h"

#include <chrono>
#include <json/json.h>
#include <restbed>
#include <vector>

#include "dhtrunner.h"

constexpr const char* const HTTP_PROTO {"http://"};

// TODO connectivity changed
// TODO follow listen between non proxified and proxified

namespace dht {

DhtProxyClient::DhtProxyClient(const std::string& serverHost)
: serverHost_(serverHost), scheduler(DHT_LOG)
{
    auto confirm_nodes_time = scheduler.time() + std::chrono::seconds(5);
    nextNodesConfirmation = scheduler.add(confirm_nodes_time, std::bind(&DhtProxyClient::confirmProxy, this));

    getConnectivityStatus();
}

void
DhtProxyClient::confirmProxy()
{
    getConnectivityStatus();
    auto disconnected = statusIpv4_ == NodeStatus::Disconnected && statusIpv6_ == NodeStatus::Disconnected;
    auto time = disconnected ? std::chrono::seconds(5) : std::chrono::seconds(600);
    auto confirm_nodes_time = scheduler.time() + time;
    scheduler.edit(nextNodesConfirmation, confirm_nodes_time);
}

DhtProxyClient::~DhtProxyClient()
{
    cancelAllOperations();
}

void
DhtProxyClient::cancelAllOperations()
{
    for (auto& operation: operations_) {
        if (operation.thread && operation.thread->joinable()) {
            // Close connection to stop operation?
            restbed::Http::close(operation.req);
            operation.thread->join();
        }
    }
}

void
DhtProxyClient::shutdown(ShutdownCallback cb)
{
    cancelAllOperations();
    cb();
}

NodeStatus
DhtProxyClient::getStatus(sa_family_t af) const
{
    switch (af)
    {
    case AF_INET:
        return statusIpv4_;
    case AF_INET6:
        return statusIpv6_;
    default:
        return NodeStatus::Disconnected;
    }
}

bool
DhtProxyClient::isRunning(sa_family_t af) const
{
    switch (af)
    {
    case AF_INET:
        return statusIpv4_ == NodeStatus::Connected;
    case AF_INET6:
        return statusIpv6_ == NodeStatus::Connected;
    default:
        return false;
    }
}


void
DhtProxyClient::get(const InfoHash& key, GetCallback cb, DoneCallback donecb,
                    Value::Filter&& filter, Where&& where)
{
    restbed::Uri uri(HTTP_PROTO + serverHost_ + "/" + key.toString());
    auto req = std::make_shared<restbed::Request>(uri);
    Query query {{}, where};
    auto filterChain = filter.chain(query.where.getFilter());

    Operation o;
    o.req = req;
    o.thread = std::move(std::unique_ptr<std::thread>(
    new std::thread([=](){
        // Try to contact the proxy and set the status to connected when done.
        // will change the connectivity status
        auto ok = std::make_shared<bool>(true);
        auto future = restbed::Http::async(req,
            [=](const std::shared_ptr<restbed::Request>& req,
                const std::shared_ptr<restbed::Response>& reply) {
            auto code = reply->get_status_code();

            if (code == 200) {
                try {
                    while (restbed::Http::is_open(req)) {
                        restbed::Http::fetch("\n", reply);
                        std::string body;
                        reply->get_body(body);
                        reply->set_body(""); // Reset the body for the next fetch

                        Json::Value json;
                        Json::Reader reader;
                        if (reader.parse(body, json)) {
                            auto value = std::make_shared<Value>(json);
                            if (not filterChain or filterChain(*value))
                                cb({value});
                        } else {
                            *ok = false;
                        }
                    }
                } catch (std::runtime_error& e) { }
            } else {
                *ok = false;
            }
        });
        future.wait();
        donecb(*ok, {});
        if (!ok) {
            // Connection failed, update connectivity
            getConnectivityStatus();
        }
    })));
    operations_.emplace_back(std::move(o));
}

void
DhtProxyClient::put(const InfoHash& key, Sp<Value> val, DoneCallback cb, time_point, bool permanent)
{
    restbed::Uri uri(HTTP_PROTO + serverHost_ + "/" + key.toString());
    auto req = std::make_shared<restbed::Request>(uri);
    req->set_method("POST");
    Json::FastWriter writer;
    auto json = val->toJson();
    if (permanent)
        json["permanent"] = true;
    auto body = writer.write(json);
    req->set_body(body);
    req->set_header("Content-Length", std::to_string(body.size()));

    Operation o;
    o.req = req;
    o.thread = std::move(std::unique_ptr<std::thread>(
    new std::thread([=](){
        auto ok = std::make_shared<bool>(true);
        auto future = restbed::Http::async(req,
            [this, val, ok](const std::shared_ptr<restbed::Request>& /*req*/,
                        const std::shared_ptr<restbed::Response>& reply) {
            auto code = reply->get_status_code();

            if (code == 200) {
                restbed::Http::fetch("\n", reply);
                std::string body;
                reply->get_body(body);
                reply->set_body(""); // Reset the body for the next fetch

                Json::Value json;
                Json::Reader reader;
                if (reader.parse(body, json)) {
                    auto value = std::make_shared<Value>(json);
                } else {
                    *ok = false;
                }
            } else {
                *ok = false;
            }
        });
        future.wait();
        cb(*ok, {});
        if (!ok) {
            // Connection failed, update connectivity
            getConnectivityStatus();
        }
    })));
    operations_.emplace_back(std::move(o));
}

NodeStats
DhtProxyClient::getNodesStats(sa_family_t af) const
{
    auto proxyInfos = getProxyInfos();
    NodeStats stats {};
    auto identifier = af == AF_INET6 ? "ipv6" : "ipv4";
    try {
        stats = NodeStats(proxyInfos[identifier]);
    } catch (...) { }
    return stats;
}

Json::Value
DhtProxyClient::getProxyInfos() const
{
    auto result = std::make_shared<Json::Value>();
    restbed::Uri uri(HTTP_PROTO + serverHost_ + "/");
    auto req = std::make_shared<restbed::Request>(uri);

    // Try to contact the proxy and set the status to connected when done.
    // will change the connectivity status
    auto future = restbed::Http::async(req,
        [this, result](const std::shared_ptr<restbed::Request>&,
                       const std::shared_ptr<restbed::Response>& reply) {
        auto code = reply->get_status_code();

        if (code == 200) {
            restbed::Http::fetch("\n", reply);
            std::string body;
            reply->get_body(body);

            Json::Reader reader;
            reader.parse(body, *result);
        }
    });
    future.wait();
    return *result;
}

std::vector<SockAddr>
DhtProxyClient::getPublicAddress(sa_family_t family)
{
    auto proxyInfos = getProxyInfos();
    // json["public_ip"] contains [ipv6:ipv4]:port or ipv4:port
    if (!proxyInfos.isMember("public_ip")) {
        getConnectivityStatus();
        return {};
    }
    auto public_ip = proxyInfos["public_ip"].asString();
    if (public_ip.length() < 2) {
        getConnectivityStatus();
        return {};
    }
    std::string ipv4Address = "";
    std::string ipv6Address = "";
    std::string port = "";
    if (public_ip[0] == '[') {
        // ipv6 complient
        auto endIp = public_ip.find(']');
        if (public_ip.length() > endIp + 2) {
            port = public_ip.substr(endIp + 2);
            auto ips = public_ip.substr(1, endIp - 1);
            auto ipv4And6Separator = ips.find_last_of(':');
            ipv4Address = ips.substr(ipv4And6Separator + 1);
            ipv6Address = ips.substr(0, ipv4And6Separator - 1);
        }
    } else {
        auto endIp = public_ip.find_last_of(':');
        port = public_ip.substr(endIp + 1);
        ipv4Address = public_ip.substr(0, endIp - 1);
    }
    switch (family)
    {
    case AF_INET:
        return DhtRunner::getAddrInfo(ipv4Address, port);
    case AF_INET6:
        return DhtRunner::getAddrInfo(ipv6Address, port);
    default:
        return {};
    }
}

void
DhtProxyClient::getConnectivityStatus()
{
    auto proxyInfos = getProxyInfos();
    // NOTE: json["ipvX"] contains NodeStats::toJson()
    try {
        auto goodIpv4 = static_cast<long>(proxyInfos["ipv4"]["good"].asLargestUInt());
        auto dubiousIpv4 = static_cast<long>(proxyInfos["ipv4"]["dubious"].asLargestUInt());
        if (goodIpv4 + dubiousIpv4 > 0) {
            statusIpv4_ = NodeStatus::Connected;
        }
        auto goodIpv6 = static_cast<long>(proxyInfos["ipv6"]["good"].asLargestUInt());
        auto dubiousIpv6 = static_cast<long>(proxyInfos["ipv6"]["dubious"].asLargestUInt());
        if (goodIpv6 + dubiousIpv6 > 0) {
            statusIpv6_ = NodeStatus::Connected;
        }
        myid = InfoHash(proxyInfos["node_id"].asString());
    } catch (...) {
        statusIpv4_ = NodeStatus::Disconnected;
        statusIpv6_ = NodeStatus::Disconnected;
    }

    // TODO for now, we don't handle connectivity issues. (when the proxy is down, we don't try to reconnect)
}

} // namespace dht

#endif // OPENDHT_PROXY_CLIENT
