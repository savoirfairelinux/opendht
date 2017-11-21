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
#include <signal.h>

#include "dhtrunner.h"

constexpr const char* const HTTP_PROTO {"http://"};

namespace dht {

DhtProxyClient::DhtProxyClient(const std::string& serverHost)
: serverHost_(serverHost), scheduler(DHT_LOG), currentProxyInfos_(new Json::Value())
{
    if (!serverHost_.empty())
        start(serverHost_);
}

void
DhtProxyClient::confirmProxy()
{
    if (serverHost_.empty()) return;
    // Retrieve the connectivity each hours if connected, else every 5 seconds.
    auto disconnected_old_status =  statusIpv4_ == NodeStatus::Disconnected && statusIpv6_ == NodeStatus::Disconnected;
    getConnectivityStatus();
    auto disconnected_new_status = statusIpv4_ == NodeStatus::Disconnected && statusIpv6_ == NodeStatus::Disconnected;
    auto time = disconnected_new_status ? std::chrono::seconds(5) : std::chrono::hours(1);
    if (disconnected_old_status && !disconnected_new_status) {
        restartListeners();
    }
    auto confirm_proxy_time = scheduler.time() + time;
    scheduler.edit(nextProxyConfirmation, confirm_proxy_time);
}

void
DhtProxyClient::start(const std::string& serverHost)
{
    serverHost_ = serverHost;
    if (serverHost_.empty()) return;
    auto confirm_proxy_time = scheduler.time() + std::chrono::seconds(5);
    nextProxyConfirmation = scheduler.add(confirm_proxy_time, std::bind(&DhtProxyClient::confirmProxy, this));
    auto confirm_connectivity = scheduler.time() + std::chrono::seconds(5);
    nextConnectivityConfirmation = scheduler.add(confirm_connectivity, std::bind(&DhtProxyClient::confirmConnectivity, this));

    getConnectivityStatus();
}

void
DhtProxyClient::confirmConnectivity()
{
    // The scheduler must get if the proxy is disconnected
    auto confirm_connectivity = scheduler.time() + std::chrono::seconds(3);
    scheduler.edit(nextConnectivityConfirmation, confirm_connectivity);
}

DhtProxyClient::~DhtProxyClient()
{
    cancelAllOperations();
    cancelAllListeners();
}

void
DhtProxyClient::cancelAllOperations()
{
    for (auto& operation: operations_) {
        if (operation.thread.joinable()) {
            // Close connection to stop operation?
            restbed::Http::close(operation.req);
            operation.thread.join();
        }
    }
}

void
DhtProxyClient::cancelAllListeners()
{
    for (auto& listener: listeners_) {
        if (listener.thread && listener.thread->joinable()) {
            // Close connection to stop listener?
            if (listener.req)
                restbed::Http::close(listener.req);
            listener.thread->join();
        }
    }
}

void
DhtProxyClient::shutdown(ShutdownCallback cb)
{
    cancelAllOperations();
    cancelAllListeners();
    if (cb)
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
    o.thread = std::move(std::thread([=](){
        // Try to contact the proxy and set the status to connected when done.
        // will change the connectivity status
        auto ok = std::make_shared<bool>(true);
        restbed::Http::async(req,
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
                            if ((not filterChain or filterChain(*value)) && cb)
                                cb({value});
                        } else {
                            *ok = false;
                        }
                    }
                } catch (std::runtime_error& e) { }
            } else {
                *ok = false;
            }
        }).wait();
        if (donecb)
            donecb(*ok, {});
        if (!ok) {
            // Connection failed, update connectivity
            getConnectivityStatus();
        }
    }));
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
    o.thread = std::move(std::thread([=](){
        auto ok = std::make_shared<bool>(true);
        restbed::Http::async(req,
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
        }).wait();
        if (cb)
            cb(*ok, {});
        if (!ok) {
            // Connection failed, update connectivity
            getConnectivityStatus();
        }
    }));
    operations_.emplace_back(std::move(o));
}

NodeStats
DhtProxyClient::getNodesStats(sa_family_t af) const
{
    auto proxyInfos = *currentProxyInfos_;
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
    restbed::Uri uri(HTTP_PROTO + serverHost_ + "/");
    auto req = std::make_shared<restbed::Request>(uri);

    // Try to contact the proxy and set the status to connected when done.
    // will change the connectivity status
    restbed::Http::async(req,
        [this](const std::shared_ptr<restbed::Request>&,
                       const std::shared_ptr<restbed::Response>& reply) {
        auto code = reply->get_status_code();

        if (code == 200) {
            restbed::Http::fetch("\n", reply);
            std::string body;
            reply->get_body(body);

            Json::Reader reader;
            try {
                reader.parse(body, *currentProxyInfos_);
            } catch (...) {
                *currentProxyInfos_ = Json::Value();
            }
        } else {
            *currentProxyInfos_ = Json::Value();
        }
    }).wait();
    return *currentProxyInfos_;
}

std::vector<SockAddr>
DhtProxyClient::getPublicAddress(sa_family_t family)
{
    auto proxyInfos = *currentProxyInfos_;
    // json["public_ip"] contains [ipv6:ipv4]:port or ipv4:port
    if (!proxyInfos.isMember("public_ip")) {
        return {};
    }
    auto public_ip = proxyInfos["public_ip"].asString();
    if (public_ip.length() < 2) {
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

size_t
DhtProxyClient::listen(const InfoHash& key, GetCallback cb, Value::Filter&& filter, Where&& where)
{
    restbed::Uri uri(HTTP_PROTO + serverHost_ + "/" + key.toString());
    auto req = std::make_shared<restbed::Request>(uri);
    req->set_method("LISTEN");

    Query query {{}, where};
    auto filterChain = filter.chain(query.where.getFilter());

    Listener l;
    ++listener_token_;
    l.key = key.toString();
    l.token = listener_token_;
    l.req = req;
    l.cb = cb;
    l.filterChain = std::move(filterChain);
    l.thread = std::move(std::unique_ptr<std::thread>(new std::thread([=]()
        {
            auto settings = std::make_shared<restbed::Settings>();
            std::chrono::milliseconds timeout(std::numeric_limits<int>::max());
            settings->set_connection_timeout(timeout); // Avoid the client to close the socket after 5 seconds.

            restbed::Http::async(req,
                [this, filterChain, cb](const std::shared_ptr<restbed::Request>& req,
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
                                if ((not filterChain or filterChain(*value)) && cb)
                                    cb({value});
                            }
                        }
                    } catch (std::runtime_error&) {
                        // NOTE: Http::close() can occurs here. Ignore this.
                    }

                } else {
                    this->statusIpv4_ = NodeStatus::Disconnected;
                    this->statusIpv6_ = NodeStatus::Disconnected;
                }
            }, settings).get();
            getConnectivityStatus();
        })
    ));
    listeners_.emplace_back(std::move(l));
    return listener_token_;
}

bool
DhtProxyClient::cancelListen(const InfoHash&, size_t token)
{
    for (auto it = listeners_.begin(); it != listeners_.end(); ++it) {
        auto& listener = *it;
        if (listener.token == token) {
            if (listener.thread->joinable()) {
                // Close connection to stop listener?
                if (listener.req)
                    restbed::Http::close(listener.req);
                if (listener.thread->joinable())
                    listener.thread->join();
                listeners_.erase(it);
                return true;
            }
        }
    }
    return false;
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
        } else {
            statusIpv4_ = NodeStatus::Disconnected;
        }
        auto goodIpv6 = static_cast<long>(proxyInfos["ipv6"]["good"].asLargestUInt());
        auto dubiousIpv6 = static_cast<long>(proxyInfos["ipv6"]["dubious"].asLargestUInt());
        if (goodIpv6 + dubiousIpv6 > 0) {
            statusIpv6_ = NodeStatus::Connected;
        } else {
            statusIpv6_ = NodeStatus::Disconnected;
        }
        myid = InfoHash(proxyInfos["node_id"].asString());
        if (statusIpv4_ == NodeStatus::Disconnected && statusIpv6_ == NodeStatus::Disconnected) {
            const auto& now = scheduler.time();
            scheduler.edit(nextProxyConfirmation, now);
        }
    } catch (...) {
        statusIpv4_ = NodeStatus::Disconnected;
        statusIpv6_ = NodeStatus::Disconnected;
        const auto& now = scheduler.time();
        scheduler.edit(nextProxyConfirmation, now);
    }
}

void
DhtProxyClient::restartListeners()
{
    for (auto& listener: listeners_) {
        if (listener.thread && listener.thread->joinable())
            listener.thread->join();
        // Redo listen
        auto filterChain = listener.filterChain;
        auto cb = listener.cb;
        restbed::Uri uri(HTTP_PROTO + serverHost_ + "/" + listener.key);
        auto req = std::make_shared<restbed::Request>(uri);
        req->set_method("LISTEN");
        listener.req = req;
        listener.thread = std::move(std::unique_ptr<std::thread>(new std::thread([this, filterChain, cb, req]()
            {
                auto settings = std::make_shared<restbed::Settings>();
                std::chrono::milliseconds timeout(std::numeric_limits<int>::max());
                settings->set_connection_timeout(timeout); // Avoid the client to close the socket after 5 seconds.

                restbed::Http::async(req,
                    [this, filterChain, cb](const std::shared_ptr<restbed::Request>& req,
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
                                    if ((not filterChain or filterChain(*value)) && cb)
                                        cb({value});
                                }
                            }
                        } catch (std::runtime_error&) {
                            // NOTE: Http::close() can occurs here. Ignore this.
                        }

                    } else {
                        this->statusIpv4_ = NodeStatus::Disconnected;
                        this->statusIpv6_ = NodeStatus::Disconnected;
                    }
                }, settings).get();
                getConnectivityStatus();
            })
        ));
    }
}


} // namespace dht

#endif // OPENDHT_PROXY_CLIENT
