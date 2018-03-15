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
#include "op_cache.h"

constexpr const char* const HTTP_PROTO {"http://"};

namespace dht {

struct DhtProxyClient::Listener
{
    ValueCache cache;
    ValueCallback cb;
    Value::Filter filter;
    Sp<restbed::Request> req;
    std::thread thread;
    unsigned callbackId;
    Sp<bool> isCanceledViaClose;
    Sp<unsigned> pushNotifToken; // NOTE: unused if not using push notifications
    Listener(ValueCache&& c, const Sp<restbed::Request>& r, Value::Filter&& f, unsigned cid)
        : cache(std::move(c)), filter(std::move(f)), req(r), callbackId(cid), isCanceledViaClose(std::make_shared<bool>(false))
    {}
};

struct DhtProxyClient::ProxySearch {
    SearchCache ops {};
    std::map<size_t, Listener> listeners {};
};

DhtProxyClient::DhtProxyClient() : scheduler(DHT_LOG) {}

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
    isDestroying_ = true;
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
    for (auto& s: listeners_) {
        for (auto& l : s.second.listeners)
            if (l.second.thread.joinable()) {
                // Close connection to stop listener?
                if (l.second.req)
                    restbed::Http::close(l.second.req);
                l.second.thread.join();
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
DhtProxyClient::get(const InfoHash& key, GetCallback cb, DoneCallback donecb, Value::Filter&& f, Where&& w)
{
    restbed::Uri uri(HTTP_PROTO + serverHost_ + "/" + key.toString());
    auto req = std::make_shared<restbed::Request>(uri);
    Value::Filter filter = w.empty() ? f : f.chain(w.getFilter());

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
                            if ((not filter or filter(*value)) && cb) {
                                std::lock_guard<std::mutex> lock(lockCallbacks);
                                callbacks_.emplace_back([cb, value, finished]() {
                                    if (not *finished and not cb({value}))
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
DhtProxyClient::listen(const InfoHash& key, ValueCallback cb, Value::Filter filter, Where where) {
    auto it = listeners_.find(key);
    if (it == listeners_.end()) {
        it = listeners_.emplace(key, ProxySearch{}).first;
    }
    auto query = std::make_shared<Query>(Select{}, where);
    auto token = it->second.ops.listen(cb, query, filter, [&](Sp<Query> q, ValueCallback vcb){
        return doListen(key, vcb, filter);
    });
    return token;
}

bool
DhtProxyClient::cancelListen(const InfoHash& key, size_t gtoken) {
    auto it = listeners_.find(key);
    if (it == listeners_.end())
        return false;
    return it->second.ops.cancelListen(gtoken, [&](size_t ltoken){
        doCancelListen(key, ltoken);
    });
}

size_t
DhtProxyClient::doListen(const InfoHash& key, ValueCallback cb, Value::Filter filter/*, Where where*/)
{
    restbed::Uri uri(HTTP_PROTO + serverHost_ + "/" + key.toString());
    auto req = std::make_shared<restbed::Request>(uri);
    req->set_method(deviceKey_.empty() ? "LISTEN" : "SUBSCRIBE");

    std::lock_guard<std::mutex> lock(lockListener_);
    auto search = listeners_.find(key);
    if (search == listeners_.end()) {
        std::cerr << "doListen: search not found" << std::endl;
        return 0;
    }

    auto token = ++listener_token_;
    auto callbackId = ++callbackId_;
    auto l = search->second.listeners.emplace(token, Listener{
        ValueCache(cb), req, std::move(filter), callbackId
    }).first;

    ValueCache& cache = l->second.cache;
    l->second.cb = [this,&cache](const std::vector<Sp<Value>>& values, bool expired) {
        const std::vector<Sp<Value>> new_values_empty;
        std::vector<Value::Id> expired_ids;
        if (expired) {
            expired_ids.reserve(values.size());
            for (const auto& v : values)
                expired_ids.emplace_back(v->id);
        }
        cache.onValues(expired ? new_values_empty : values, std::vector<Value::Id>{}, expired_ids, types, scheduler.time());
        return true;
    };
    std::weak_ptr<bool> isCanceledViaClose(l->second.isCanceledViaClose);
    auto pushNotifToken = std::make_shared<unsigned>(0);
    l->second.pushNotifToken = pushNotifToken;
    l->second.thread = std::thread([=]()
        {
            auto settings = std::make_shared<restbed::Settings>();
            if (deviceKey_.empty()) {
                std::chrono::milliseconds timeout(std::numeric_limits<int>::max());
                settings->set_connection_timeout(timeout); // Avoid the client to close the socket after 5 seconds.
            }
#if OPENDHT_PUSH_NOTIFICATIONS
            else
                fillBodyToGetToken(req, callbackId);
#endif

            struct State {
                std::atomic_bool ok {true};
                std::atomic_bool cancel {false};
            };
            auto state = std::make_shared<State>();
            restbed::Http::async(req,
                [this, filter, cb, pushNotifToken, state](const std::shared_ptr<restbed::Request>& req,
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
                                    if (not filter or filter(*value))  {
                                        std::lock_guard<std::mutex> lock(lockCallbacks);
                                        callbacks_.emplace_back([cb, value, state]() {
                                            if (not state->cancel and not cb({value}, false))
                                                state->cancel = true;
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
            auto isCanceledNormally = isCanceledViaClose.lock();
            if (not state->ok and isCanceledNormally and not *isCanceledNormally) {
                opFailed();
            }
        }
    );
    return token;
}

bool
DhtProxyClient::doCancelListen(const InfoHash& key, size_t ltoken)
{
    std::lock_guard<std::mutex> lock(lockListener_);

    auto search = listeners_.find(key);
    if (search == listeners_.end())
        return false;

    auto it = search->second.listeners.find(ltoken);
    if (it == search->second.listeners.end())
        return false;

    auto& listener = it->second;
    if (!deviceKey_.empty()) {
        // First, be sure to have a token
        if (listener.thread.joinable()) {
            listener.thread.join();
        }
        // UNSUBSCRIBE
        restbed::Uri uri(HTTP_PROTO + serverHost_ + "/" + key.toString());
        auto req = std::make_shared<restbed::Request>(uri);
        req->set_method("UNSUBSCRIBE");
        // fill request body
        Json::Value body;
        body["key"] = deviceKey_;
        body["client_id"] = pushClientId_;
        body["token"] = std::to_string(ltoken);
        body["callback_id"] = listener.callbackId;
        Json::StreamWriterBuilder wbuilder;
        wbuilder["commentStyle"] = "None";
        wbuilder["indentation"] = "";
        auto content = Json::writeString(wbuilder, body) + "\n";
        std::replace(content.begin(), content.end(), '\n', ' ');
        req->set_body(content);
        req->set_header("Content-Length", std::to_string(content.size()));

        restbed::Http::async(req, [](const std::shared_ptr<restbed::Request>&, const std::shared_ptr<restbed::Response>&){});
    } else {
        // Just stop the request
        if (listener.thread.joinable()) {
            // Close connection to stop listener?
            *(listener.isCanceledViaClose) = true;
            if (listener.req)
                restbed::Http::close(listener.req);
            listener.thread.join();
        }
    }
    search->second.listeners.erase(it);
    if (search->second.listeners.empty()) {
        listeners_.erase(search);
    }

    return true;
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
    if (!isDestroying_) getProxyInfos();
}

void
DhtProxyClient::restartListeners()
{
    std::lock_guard<std::mutex> lock(lockListener_);
    for (auto& search: listeners_) {
    for (auto& l: search.second.listeners) {
        auto& listener = l.second;
        if (listener.thread.joinable())
            listener.thread.join();
        // Redo listen
        auto filter = listener.filter;
        auto cb = listener.cb;
        restbed::Uri uri(HTTP_PROTO + serverHost_ + "/" + search.first.toString());
        auto req = std::make_shared<restbed::Request>(uri);
        req->set_method("LISTEN");
        listener.req = req;
        listener.thread = std::thread([this, filter, cb, req]()
            {
                auto settings = std::make_shared<restbed::Settings>();
                std::chrono::milliseconds timeout(std::numeric_limits<int>::max());
                settings->set_connection_timeout(timeout); // Avoid the client to close the socket after 5 seconds.

                auto ok = std::make_shared<std::atomic_bool>(true);
                restbed::Http::async(req,
                    [this, filter, cb, ok](const std::shared_ptr<restbed::Request>& req,
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
                                    if ((not filter or filter(*value)) && cb) {
                                        auto okCb = std::make_shared<std::promise<bool>>();
                                        auto futureCb = okCb->get_future();
                                        {
                                            std::lock_guard<std::mutex> lock(lockCallbacks);
                                            callbacks_.emplace_back([cb, value, okCb](){
                                                okCb->set_value(cb({value}, false));
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
}

void
DhtProxyClient::pushNotificationReceived(const std::map<std::string, std::string>& notification)
{
#if OPENDHT_PUSH_NOTIFICATIONS
    try {
        auto token = std::stoul(notification.at("token"));
        for (auto& search: listeners_) {
            for (auto& list : search.second.listeners) {
                auto& listener = list.second;
                if (*listener.pushNotifToken!= token)
                    continue;
                if (notification.find("timeout") == notification.cend()) {
                    // Wake up daemon and get values
                    auto cb = listener.cb;
                    auto filter = listener.filter;
                    get(search.first, [cb](const std::vector<Sp<Value>>& vals){
                        cb(vals, false);
                        return true;
                    }, DoneCallbackSimple{}, std::move(filter));
                } else {
                    // A timeout has occured, we need to relaunch the listener
                    resubscribe(search.first, listener);
                }
            }
        }
    } catch (const std::exception& e) {
        std::cerr << "pushNotificationReceived: error " << e.what() << std::endl;
    }
#endif
}

void
DhtProxyClient::resubscribe(const InfoHash& key, Listener& listener)
{
#if OPENDHT_PUSH_NOTIFICATIONS
    if (deviceKey_.empty()) return;
    // Subscribe
    restbed::Uri uri(HTTP_PROTO + serverHost_ + "/" + key.toString());
    auto req = std::make_shared<restbed::Request>(uri);
    req->set_method("SUBSCRIBE");

    auto pushNotifToken = std::make_shared<unsigned>(0);

    if (listener.thread.joinable())
        listener.thread.join();
    listener.req = req;
    listener.pushNotifToken = pushNotifToken;
    auto callbackId = listener.callbackId;
    listener.thread = std::thread([=]()
    {
        fillBodyToGetToken(req, callbackId);
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
#endif
}

#if OPENDHT_PUSH_NOTIFICATIONS
void
DhtProxyClient::fillBodyToGetToken(std::shared_ptr<restbed::Request> req, unsigned callbackId)
{
    // Fill body with
    // {
    //   "key":"device_key",
    //   "callback_id": xxx
    // }
    Json::Value body;
    body["key"] = deviceKey_;
    body["client_id"] = pushClientId_;
    body["callback_id"] = callbackId;
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
