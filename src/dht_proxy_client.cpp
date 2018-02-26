/*
 *  Copyright (C) 2016-2018 Savoir-faire Linux Inc.
 *  Author: Sébastien Blin <sebastien.blin@savoirfairelinux.com>
 *          Adrien Béraud <adrien.beraud@savoirfairelinux.com>
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

#if OPENDHT_PROXY_CLIENT

#include "dht_proxy_client.h"

#include <chrono>
#include <json/json.h>
#include <restbed>
#include <vector>

#include "dhtrunner.h"

constexpr const char* const HTTP_PROTO {"http://"};

namespace dht {

DhtProxyClient::DhtProxyClient(std::function<void()> signal, const std::string& serverHost, const std::string& pushClientId)
: serverHost_(serverHost), pushClientId_(pushClientId), scheduler(DHT_LOG), loopSignal_(signal)
{
    if (!serverHost_.empty())
        startProxy();
}

void
DhtProxyClient::confirmProxy()
{
    if (serverHost_.empty()) return;
    getConnectivityStatus();
}

void
DhtProxyClient::startProxy()
{
    if (serverHost_.empty()) return;
    DHT_LOG.WARN("Staring proxy client to %s", serverHost_.c_str());
    nextProxyConfirmation = scheduler.add(scheduler.time(), std::bind(&DhtProxyClient::confirmProxy, this));
}

DhtProxyClient::~DhtProxyClient()
{
    cancelAllOperations();
    cancelAllListeners();
}

void
DhtProxyClient::cancelAllOperations()
{
    std::lock_guard<std::mutex> lock(lockOperations_);
    auto operation = operations_.begin();
    while (operation != operations_.end()) {
        if (operation->thread.joinable()) {
            // Close connection to stop operation?
            restbed::Http::close(operation->req);
            operation->thread.join();
            operation = operations_.erase(operation);
        } else {
            ++operation;
        }
    }
}

void
DhtProxyClient::cancelAllListeners()
{
    std::lock_guard<std::mutex> lock(lockListener_);
    for (auto& listener: listeners_) {
        if (listener.thread.joinable()) {
            // Close connection to stop listener?
            if (listener.req)
                restbed::Http::close(listener.req);
            listener.thread.join();
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
    std::lock_guard<std::mutex> l(lockCurrentProxyInfos_);
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
    std::lock_guard<std::mutex> l(lockCurrentProxyInfos_);
    switch (af)
    {
    case AF_INET:
        return statusIpv4_ != NodeStatus::Disconnected;
    case AF_INET6:
        return statusIpv6_ != NodeStatus::Disconnected;
    default:
        return false;
    }
}

time_point
DhtProxyClient::periodic(const uint8_t*, size_t, const SockAddr&)
{
    // Exec all currently stored callbacks
    scheduler.syncTime();
    if (!callbacks_.empty()) {
        std::lock_guard<std::mutex> lock(lockCallbacks);
        for (auto& callback : callbacks_)
            callback();
        callbacks_.clear();
    }
    // Remove finished operations
    {
        std::lock_guard<std::mutex> lock(lockOperations_);
        auto operation = operations_.begin();
        while (operation != operations_.end()) {
            if (*(operation->finished)) {
                if (operation->thread.joinable()) {
                    // Close connection to stop operation?
                    restbed::Http::close(operation->req);
                    operation->thread.join();
                }
                operation = operations_.erase(operation);
            } else {
                ++operation;
            }
        }
    }
    return scheduler.run();
}

void
DhtProxyClient::get(const InfoHash& key, const GetCallback& cb, DoneCallback donecb, const Value::Filter& filterChain)
{
    restbed::Uri uri(HTTP_PROTO + serverHost_ + "/" + key.toString());
    auto req = std::make_shared<restbed::Request>(uri);

    auto finished = std::make_shared<std::atomic_bool>(false);
    Operation o;
    o.req = req;
    o.finished = finished;
    o.thread = std::thread([=](){
        // Try to contact the proxy and set the status to connected when done.
        // will change the connectivity status
        auto ok = std::make_shared<std::atomic_bool>(true);
        restbed::Http::async(req,
            [=](const std::shared_ptr<restbed::Request>& req,
                const std::shared_ptr<restbed::Response>& reply) {
            auto code = reply->get_status_code();

            if (code == 200) {
                try {
                    while (restbed::Http::is_open(req) and not *finished) {
                        restbed::Http::fetch("\n", reply);
                        if (*finished)
                            break;
                        std::string body;
                        reply->get_body(body);
                        reply->set_body(""); // Reset the body for the next fetch

                        std::string err;
                        Json::Value json;
                        Json::CharReaderBuilder rbuilder;
                        auto* char_data = reinterpret_cast<const char*>(&body[0]);
                        auto reader = std::unique_ptr<Json::CharReader>(rbuilder.newCharReader());
                        if (reader->parse(char_data, char_data + body.size(), &json, &err)) {
                            auto value = std::make_shared<Value>(json);
                            if ((not filterChain or filterChain(*value)) && cb) {
                                std::lock_guard<std::mutex> lock(lockCallbacks);
                                callbacks_.emplace_back([cb, value, finished]() {
                                    if (not cb({value}))
                                        *finished = true;
                                });
                                loopSignal_();
                            }
                        } else {
                            *ok = false;
                        }
                    }
                } catch (std::runtime_error& e) { }
            } else {
                *ok = false;
            }
        }).wait();
        if (donecb) {
            std::lock_guard<std::mutex> lock(lockCallbacks);
            callbacks_.emplace_back([=](){
                donecb(*ok, {});
            });
            loopSignal_();
        }
        if (!ok) {
            // Connection failed, update connectivity
            opFailed();
        }
        *finished = true;
    });
    {
        std::lock_guard<std::mutex> lock(lockOperations_);
        operations_.emplace_back(std::move(o));
    }
}

void
DhtProxyClient::get(const InfoHash& key, GetCallback cb, DoneCallback donecb,
                    Value::Filter&& filter, Where&& where)
{
    Query query {{}, where};
    auto filterChain = filter.chain(query.where.getFilter());
    get(key, cb, donecb, filterChain);
}

void
DhtProxyClient::put(const InfoHash& key, Sp<Value> val, DoneCallback cb, time_point, bool permanent)
{
    restbed::Uri uri(HTTP_PROTO + serverHost_ + "/" + key.toString());
    auto req = std::make_shared<restbed::Request>(uri);
    req->set_method("POST");
    auto json = val->toJson();
    if (permanent)
        json["permanent"] = true;
    Json::StreamWriterBuilder wbuilder;
    wbuilder["commentStyle"] = "None";
    wbuilder["indentation"] = "";
    auto body = Json::writeString(wbuilder, json) + "\n";
    req->set_body(body);
    req->set_header("Content-Length", std::to_string(body.size()));

    auto finished = std::make_shared<std::atomic_bool>(false);
    Operation o;
    o.req = req;
    o.finished = finished;
    o.thread = std::thread([=](){
        auto ok = std::make_shared<std::atomic_bool>(true);
        restbed::Http::async(req,
            [this, ok](const std::shared_ptr<restbed::Request>& /*req*/,
                        const std::shared_ptr<restbed::Response>& reply) {
            auto code = reply->get_status_code();

            if (code == 200) {
                restbed::Http::fetch("\n", reply);
                std::string body;
                reply->get_body(body);
                reply->set_body(""); // Reset the body for the next fetch

                try {
                    std::string err;
                    Json::Value json;
                    Json::CharReaderBuilder rbuilder;
                    auto* char_data = reinterpret_cast<const char*>(&body[0]);
                    auto reader = std::unique_ptr<Json::CharReader>(rbuilder.newCharReader());
                    if (not reader->parse(char_data, char_data + body.size(), &json, &err))
                        *ok = false;
                } catch (...) {
                    *ok = false;
                }
            } else {
                *ok = false;
            }
        }).wait();
        if (cb) {
            std::lock_guard<std::mutex> lock(lockCallbacks);
            callbacks_.emplace_back([=](){
                cb(*ok, {});
            });
            loopSignal_();
        }
        if (!ok) {
            // Connection failed, update connectivity
            opFailed();
        }
        *finished = true;
    });
    {
        std::lock_guard<std::mutex> lock(lockOperations_);
        operations_.emplace_back(std::move(o));
    }
}

NodeStats
DhtProxyClient::getNodesStats(sa_family_t af) const
{
    return af == AF_INET ? stats4_ : stats6_;
}

void
DhtProxyClient::getProxyInfos()
{
    DHT_LOG.DEBUG("Requesting proxy server node information");

    if (ongoingStatusUpdate_.test_and_set())
        return;

    {
        std::lock_guard<std::mutex> l(lockCurrentProxyInfos_);
        if (statusIpv4_ == NodeStatus::Disconnected)
            statusIpv4_ = NodeStatus::Connecting;
        if (statusIpv6_ == NodeStatus::Disconnected)
            statusIpv6_ = NodeStatus::Connecting;
    }

    restbed::Uri uri(HTTP_PROTO + serverHost_ + "/");
    auto req = std::make_shared<restbed::Request>(uri);

    // Try to contact the proxy and set the status to connected when done.
    // will change the connectivity status
    statusThread_ = std::thread([this, req]{
        restbed::Http::async(req,
            [this](const std::shared_ptr<restbed::Request>&,
                           const std::shared_ptr<restbed::Response>& reply) {
            auto code = reply->get_status_code();
            Json::Value proxyInfos;
            if (code == 200) {
                restbed::Http::fetch("\n", reply);
                std::string body;
                reply->get_body(body);

                std::string err;
                Json::CharReaderBuilder rbuilder;
                auto reader = std::unique_ptr<Json::CharReader>(rbuilder.newCharReader());
                try {
                    reader->parse(body.data(), body.data() + body.size(), &proxyInfos, &err);
                } catch (...) {
                }
            }
            onProxyInfos(proxyInfos);
            ongoingStatusUpdate_.clear();
        });
    });
    statusThread_.detach();
}

void
DhtProxyClient::onProxyInfos(const Json::Value& proxyInfos)
{
    std::lock_guard<std::mutex> l(lockCurrentProxyInfos_);

    auto oldStatus = std::max(statusIpv4_, statusIpv6_);

    try {
        myid = InfoHash(proxyInfos["node_id"].asString());

        stats4_ = NodeStats(proxyInfos["ipv4"]);
        if (stats4_.good_nodes)
            statusIpv4_ = NodeStatus::Connected;
        else if (stats4_.dubious_nodes)
            statusIpv4_ = NodeStatus::Connecting;
        else
            statusIpv4_ = NodeStatus::Disconnected;

        stats6_ = NodeStats(proxyInfos["ipv6"]);
        if (stats6_.good_nodes)
            statusIpv6_ = NodeStatus::Connected;
        else if (stats6_.dubious_nodes)
            statusIpv6_ = NodeStatus::Connecting;
        else
            statusIpv6_ = NodeStatus::Disconnected;

        publicAddress_ = parsePublicAddress(proxyInfos["public_ip"]);
    } catch (...) {}

    auto newStatus = std::max(statusIpv4_, statusIpv6_);

    if (newStatus == NodeStatus::Connecting || newStatus == NodeStatus::Connected) {
        if (oldStatus == NodeStatus::Disconnected) {
            restartListeners();
        }
        scheduler.edit(nextProxyConfirmation, scheduler.time() + std::chrono::minutes(15));
    }
    else if (newStatus == NodeStatus::Disconnected) {
        scheduler.edit(nextProxyConfirmation, scheduler.time() + std::chrono::minutes(1));
    }
    loopSignal_();
}

SockAddr
DhtProxyClient::parsePublicAddress(const Json::Value& val)
{
    auto public_ip = val.asString();
    auto endIp = public_ip.find_last_of(':');
    std::string service = public_ip.substr(endIp + 1);
    std::string address = public_ip.substr(0, endIp - 1);
    auto sa = SockAddr::resolve(address, service);
    if (sa.empty()) return {};
    return sa.front().getMappedIPv4();
}

std::vector<SockAddr>
DhtProxyClient::getPublicAddress(sa_family_t family)
{
    std::lock_guard<std::mutex> l(lockCurrentProxyInfos_);
    if (not publicAddress_) return {};
    return publicAddress_.getFamily() == family ? std::vector<SockAddr>{publicAddress_} : std::vector<SockAddr>{};
}

size_t
DhtProxyClient::listen(const InfoHash& key, GetCallback cb, Value::Filter filter, Where where)
{
    restbed::Uri uri(HTTP_PROTO + serverHost_ + "/" + key.toString());
    auto req = std::make_shared<restbed::Request>(uri);
    req->set_method(deviceKey_.empty() ? "LISTEN" : "SUBSCRIBE");

    Query query {{}, where};
    auto filterChain = filter.chain(query.where.getFilter());
    auto pushNotifToken = std::make_shared<unsigned>(0);

    Listener l;
    ++listener_token_;
    l.key = key.toString();
    l.token = listener_token_;
    l.req = req;
    l.cb = cb;
    l.pushNotifToken = pushNotifToken;
    l.filterChain = std::move(filterChain);
    l.thread = std::thread([=]()
        {
            auto settings = std::make_shared<restbed::Settings>();
            if (deviceKey_.empty()) {
                std::chrono::milliseconds timeout(std::numeric_limits<int>::max());
                settings->set_connection_timeout(timeout); // Avoid the client to close the socket after 5 seconds.
            }
#if OPENDHT_PUSH_NOTIFICATIONS
            else
                fillBodyToGetToken(req);
#endif

            struct State {
                std::atomic_bool ok {true};
                std::atomic_bool cancel {false};
            };
            auto state = std::make_shared<State>();
            restbed::Http::async(req,
                [this, filterChain, cb, pushNotifToken, state](const std::shared_ptr<restbed::Request>& req,
                                                               const std::shared_ptr<restbed::Response>& reply) {
                auto code = reply->get_status_code();
                if (code == 200) {
                    try {
                        std::string err;
                        Json::Value json;
                        Json::CharReaderBuilder rbuilder;
                        auto reader = std::unique_ptr<Json::CharReader>(rbuilder.newCharReader());
                        if (!deviceKey_.empty()) {
                            restbed::Http::fetch("\n", reply);
                            if (state->cancel)
                                return;
                            std::string body;
                            reply->get_body(body);

                            auto* char_data = reinterpret_cast<const char*>(&body[0]);
                            if (reader->parse(char_data, char_data + body.size(), &json, &err)) {
                                if (!json.isMember("token")) return;
                                *pushNotifToken = json["token"].asLargestUInt();
                            } else {
                                state->ok = false;
                            }
                        } else {
                            while (restbed::Http::is_open(req) and not state->cancel) {
                                restbed::Http::fetch("\n", reply);
                                if (state->cancel)
                                    break;
                                std::string body;
                                reply->get_body(body);
                                reply->set_body(""); // Reset the body for the next fetch

                                auto* char_data = reinterpret_cast<const char*>(&body[0]);
                                if (reader->parse(char_data, char_data + body.size(), &json, &err)) {
                                    auto value = std::make_shared<Value>(json);
                                    if ((not filterChain or filterChain(*value)) && cb)  {
                                        std::lock_guard<std::mutex> lock(lockCallbacks);
                                        callbacks_.emplace_back([cb, value, state]() {
                                            if (not state->cancel and not cb({value})) {
                                                state->cancel = true;
                                            }
                                        });
                                        loopSignal_();
                                    }
                                } else {
                                    state->ok = false;
                                }
                            }
                        }
                    } catch (std::runtime_error&) {
                        state->ok = false;
                    }
                } else {
                    state->ok = false;
                }
            }, settings).get();
            if (not state->ok) {
                opFailed();
            }
        }
    );
    {
        std::lock_guard<std::mutex> lock(lockListener_);
        listeners_.emplace_back(std::move(l));
    }
    return listener_token_;
}

bool
DhtProxyClient::cancelListen(const InfoHash&, size_t token)
{
    std::lock_guard<std::mutex> lock(lockListener_);
    for (auto it = listeners_.begin(); it != listeners_.end(); ++it) {
        auto& listener = *it;
        if (listener.token == token) {
            if (!deviceKey_.empty()) {
                // First, be sure to have a token
                if (listener.thread.joinable()) {
                    listener.thread.join();
                }
                // UNSUBSCRIBE
                restbed::Uri uri(HTTP_PROTO + serverHost_ + "/" + listener.key);
                auto req = std::make_shared<restbed::Request>(uri);
                req->set_method("UNSUBSCRIBE");
                restbed::Http::async(req,
                    [](const std::shared_ptr<restbed::Request>&,
                       const std::shared_ptr<restbed::Response>&){}
                );
                // And remove
                listeners_.erase(it);
                return true;
            } else {
                // Just stop the request
                if (listener.thread.joinable()) {
                    // Close connection to stop listener?
                    if (listener.req)
                        restbed::Http::close(listener.req);
                    listener.thread.join();
                    listeners_.erase(it);
                    return true;
                }
            }
        }
    }
    return false;
}

void
DhtProxyClient::opFailed()
{
    DHT_LOG.ERR("Proxy request failed");
    {
        std::lock_guard<std::mutex> l(lockCurrentProxyInfos_);
        statusIpv4_ = NodeStatus::Disconnected;
        statusIpv6_ = NodeStatus::Disconnected;
    }
    getConnectivityStatus();
    loopSignal_();
}

void
DhtProxyClient::getConnectivityStatus()
{
    getProxyInfos();
}

void
DhtProxyClient::restartListeners()
{
    std::lock_guard<std::mutex> lock(lockListener_);
    for (auto& listener: listeners_) {
        if (listener.thread.joinable())
            listener.thread.join();
        // Redo listen
        auto filterChain = listener.filterChain;
        auto cb = listener.cb;
        restbed::Uri uri(HTTP_PROTO + serverHost_ + "/" + listener.key);
        auto req = std::make_shared<restbed::Request>(uri);
        req->set_method("LISTEN");
        listener.req = req;
        listener.thread = std::thread([this, filterChain, cb, req]()
            {
                auto settings = std::make_shared<restbed::Settings>();
                std::chrono::milliseconds timeout(std::numeric_limits<int>::max());
                settings->set_connection_timeout(timeout); // Avoid the client to close the socket after 5 seconds.

                auto ok = std::make_shared<std::atomic_bool>(true);
                restbed::Http::async(req,
                    [this, filterChain, cb, ok](const std::shared_ptr<restbed::Request>& req,
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
                                std::string err;
                                Json::CharReaderBuilder rbuilder;
                                auto* char_data = reinterpret_cast<const char*>(&body[0]);
                                auto reader = std::unique_ptr<Json::CharReader>(rbuilder.newCharReader());
                                if (reader->parse(char_data, char_data + body.size(), &json, &err)) {
                                    auto value = std::make_shared<Value>(json);
                                    if ((not filterChain or filterChain(*value)) && cb) {
                                        auto okCb = std::make_shared<std::promise<bool>>();
                                        auto futureCb = okCb->get_future();
                                        {
                                            std::lock_guard<std::mutex> lock(lockCallbacks);
                                            callbacks_.emplace_back([cb, value, okCb](){
                                                okCb->set_value(cb({value}));
                                            });
                                            loopSignal_();
                                        }
                                        futureCb.wait();
                                        if (!futureCb.get()) {
                                            return;
                                        }
                                    }
                                }
                            }
                        } catch (std::runtime_error&) {
                            // NOTE: Http::close() can occurs here. Ignore this.
                        }
                    } else {
                        *ok = false;
                    }
                }, settings).get();
                if (!ok) opFailed();
            }
        );
    }
}

void
DhtProxyClient::pushNotificationReceived(const std::map<std::string, std::string>& notification)
{
#if OPENDHT_PUSH_NOTIFICATIONS
    try {
        auto token = std::stoul(notification.at("token"));
        for (const auto& listener: listeners_) {
            if (*(listener.pushNotifToken) != token)
                continue;
            if (notification.find("timeout") == notification.cend()) {
                // Wake up daemon and get values
                get(InfoHash(listener.key), listener.cb, {}, listener.filterChain);
            } else {
                // A timeout has occured, we need to relaunch the listener
                resubscribe(token);
            }

        }
    } catch (...) {

    }
#endif
}

void
DhtProxyClient::resubscribe(const unsigned token)
{
#if OPENDHT_PUSH_NOTIFICATIONS
    if (deviceKey_.empty()) return;
    for (auto& listener: listeners_) {
        if (*(listener.pushNotifToken) == token) {
            // Subscribe
            restbed::Uri uri(HTTP_PROTO + serverHost_ + "/" + listener.key);
            auto req = std::make_shared<restbed::Request>(uri);
            req->set_method("SUBSCRIBE");

            auto pushNotifToken = std::make_shared<unsigned>(0);

            if (listener.thread.joinable())
                listener.thread.join();
            listener.req = req;
            listener.pushNotifToken = pushNotifToken;
            listener.thread = std::thread([=]()
            {
                fillBodyToGetToken(req);
                auto settings = std::make_shared<restbed::Settings>();
                auto ok = std::make_shared<std::atomic_bool>(true);
                restbed::Http::async(req,
                    [this, pushNotifToken, ok](const std::shared_ptr<restbed::Request>&,
                                               const std::shared_ptr<restbed::Response>& reply) {
                    auto code = reply->get_status_code();
                    if (code == 200) {
                        try {
                            restbed::Http::fetch("\n", reply);
                            std::string body;
                            reply->get_body(body);

                            std::string err;
                            Json::Value json;
                            Json::CharReaderBuilder rbuilder;
                            auto* char_data = reinterpret_cast<const char*>(&body[0]);
                            auto reader = std::unique_ptr<Json::CharReader>(rbuilder.newCharReader());
                            if (reader->parse(char_data, char_data + body.size(), &json, &err)) {
                                if (!json.isMember("token")) return;
                                *pushNotifToken = json["token"].asLargestUInt();
                            }
                        } catch (std::runtime_error&) {
                            // NOTE: Http::close() can occurs here. Ignore this.
                        }
                    } else {
                        *ok = false;
                    }
                }, settings).get();
                if (!ok) opFailed();
            });
        }
    }
#endif
}

#if OPENDHT_PUSH_NOTIFICATIONS
void
DhtProxyClient::fillBodyToGetToken(std::shared_ptr<restbed::Request> req)
{
    // Fill body with
    // {
    //   "key":"device_key",
    //   "callback_id": xxx
    // }
    Json::Value body;
    body["key"] = deviceKey_;
    body["client_id"] = pushClientId_;
    {
        std::lock_guard<std::mutex> lock(lockCallback_);
        callbackId_ += 1;
        body["callback_id"] = callbackId_;
    }
#ifdef __ANDROID__
    body["platform"] = "android";
#endif
#ifdef __APPLE__
    body["platform"] = "apple";
#endif
    Json::StreamWriterBuilder wbuilder;
    wbuilder["commentStyle"] = "None";
    wbuilder["indentation"] = "";
    auto content = Json::writeString(wbuilder, body) + "\n";
    std::replace(content.begin(), content.end(), '\n', ' ');
    req->set_body(content);
    req->set_header("Content-Length", std::to_string(content.size()));
}
#endif // OPENDHT_PUSH_NOTIFICATIONS

} // namespace dht

#endif // OPENDHT_PROXY_CLIENT
