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

#include "dhtrunner.h"
#include "op_cache.h"
#include "utils.h"

#include <restbed>
#include <json/json.h>

#include <chrono>
#include <vector>

constexpr const char* const HTTP_PROTO {"http://"};
constexpr const std::chrono::seconds OP_TIMEOUT {1 * 60 * 60 - 60}; // one hour minus margin

namespace dht {

struct DhtProxyClient::Listener
{
    struct State {
        std::atomic_bool ok {true};
        std::atomic_bool cancel {false};
    };
    ValueCache cache;
    Sp<Scheduler::Job> cacheExpirationJob {};
    ValueCallback cb;
    Value::Filter filter;
    Sp<restbed::Request> req;
    std::thread thread;
    unsigned callbackId;
    Sp<State> state;
    Sp<unsigned> pushNotifToken; // NOTE: unused if not using push notifications
    Sp<Scheduler::Job> refreshJob;
    Listener(ValueCache&& c, Sp<Scheduler::Job>&& j, const Sp<restbed::Request>& r, Value::Filter&& f)
        : cache(std::move(c)),
          cacheExpirationJob(std::move(j)),
          filter(std::move(f)),
          req(r)
    {}
};

struct PermanentPut {
    Sp<Value> value;
    Sp<Scheduler::Job> refreshJob;
};

struct DhtProxyClient::ProxySearch {
    SearchCache ops {};
    std::map<size_t, Listener> listeners {};
    std::map<Value::Id, PermanentPut> puts {};
};

DhtProxyClient::DhtProxyClient() {}

DhtProxyClient::DhtProxyClient(std::function<void()> signal, const std::string& serverHost, const std::string& pushClientId)
: serverHost_(serverHost), pushClientId_(pushClientId), loopSignal_(signal)
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
    DHT_LOG.w("Staring proxy client to %s", serverHost_.c_str());
    nextProxyConfirmation = scheduler.add(scheduler.time(), std::bind(&DhtProxyClient::confirmProxy, this));
}

DhtProxyClient::~DhtProxyClient()
{
    isDestroying_ = true;
    cancelAllOperations();
    cancelAllListeners();
    if (statusThread_.joinable())
        statusThread_.join();
}

std::vector<Sp<Value>>
DhtProxyClient::getLocal(const InfoHash& k, Value::Filter filter) const {
    std::lock_guard<std::mutex> lock(searchLock_);
    auto s = searches_.find(k);
    if (s == searches_.end())
        return {};
    return s->second.ops.get(filter);
}

Sp<Value>
DhtProxyClient::getLocalById(const InfoHash& k, Value::Id id) const {
    std::lock_guard<std::mutex> lock(searchLock_);
    auto s = searches_.find(k);
    if (s == searches_.end())
        return {};
    return s->second.ops.get(id);
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
    std::lock_guard<std::mutex> lock(searchLock_);
    DHT_LOG.w("Cancelling all listeners for %zu searches", searches_.size());
    for (auto& s: searches_) {
        s.second.ops.cancelAll([&](size_t token){
            auto l = s.second.listeners.find(token);
            if (l == s.second.listeners.end())
                return;
            if (l->second.thread.joinable()) {
                // Close connection to stop listener?
                l->second.state->cancel = true;
                if (l->second.req)
                    restbed::Http::close(l->second.req);
                l->second.thread.join();
            }
            s.second.listeners.erase(token);
        });
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
    DHT_LOG.d(key, "[search %s]: get", key.to_c_str());
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
DhtProxyClient::put(const InfoHash& key, Sp<Value> val, DoneCallback cb, time_point created, bool permanent)
{
    DHT_LOG.d(key, "[search %s]: put", key.to_c_str());
    scheduler.syncTime();
    if (not val) {
        if (cb) cb(false, {});
        return;
    }
    if (val->id == Value::INVALID_ID) {
        crypto::random_device rdev;
        std::uniform_int_distribution<Value::Id> rand_id {};
        val->id = rand_id(rdev);
    }
    if (permanent) {
        std::lock_guard<std::mutex> lock(searchLock_);
        auto id = val->id;
        auto search = searches_.emplace(key, ProxySearch{}).first;
        auto nextRefresh = scheduler.time() + OP_TIMEOUT;
        search->second.puts.erase(id);
        search->second.puts.emplace(id, PermanentPut {val, scheduler.add(nextRefresh, [this, key, id]{
            auto s = searches_.find(key);
            if (s == searches_.end())
                return;
            auto p = s->second.puts.find(id);
            if (p == s->second.puts.end())
                return;
            const auto& now = scheduler.time();
            doPut(key, p->second.value, {}, now, true);
            scheduler.edit(p->second.refreshJob, now + OP_TIMEOUT);
        })});
    }
    doPut(key, val, std::move(cb), created, permanent);
}

void
DhtProxyClient::doPut(const InfoHash& key, Sp<Value> val, DoneCallback cb, time_point created, bool permanent)
{
    DHT_LOG.d(key, "[search %s] performing put of %s", key.to_c_str(), val->toString().c_str());
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
            [ok](const std::shared_ptr<restbed::Request>& /*req*/,
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

/**
 * Get data currently being put at the given hash.
 */
std::vector<Sp<Value>>
DhtProxyClient::getPut(const InfoHash& key) {
    std::vector<Sp<Value>> ret;
    auto search = searches_.find(key);
    if (search != searches_.end()) {
        ret.reserve(search->second.puts.size());
        for (const auto& put : search->second.puts)
            ret.emplace_back(put.second.value);
    }
    return ret;
}

/**
 * Get data currently being put at the given hash with the given id.
 */
Sp<Value>
DhtProxyClient::getPut(const InfoHash& key, const Value::Id& id) {
    auto search = searches_.find(key);
    if (search == searches_.end())
        return {};
    auto val = search->second.puts.find(id);
    if (val == search->second.puts.end())
        return {};
    return val->second.value;
}

/**
 * Stop any put/announce operation at the given location,
 * for the value with the given id.
 */
bool
DhtProxyClient::cancelPut(const InfoHash& key, const Value::Id& id)
{
    auto search = searches_.find(key);
    if (search == searches_.end())
        return false;
    DHT_LOG.d(key, "[search %s] cancel put", key.to_c_str());
    return search->second.puts.erase(id) > 0;
}

NodeStats
DhtProxyClient::getNodesStats(sa_family_t af) const
{
    return af == AF_INET ? stats4_ : stats6_;
}

void
DhtProxyClient::getProxyInfos()
{
    DHT_LOG.d("Requesting proxy server node information");

    if (ongoingStatusUpdate_.test_and_set())
        return;

    {
        std::lock_guard<std::mutex> l(lockCurrentProxyInfos_);
        if (statusIpv4_ == NodeStatus::Disconnected)
            statusIpv4_ = NodeStatus::Connecting;
        if (statusIpv6_ == NodeStatus::Disconnected)
            statusIpv6_ = NodeStatus::Connecting;
    }

    // A node can have a Ipv4 and a Ipv6. So, we need to retrieve all public ips
    auto serverHost = serverHost_;

    // Try to contact the proxy and set the status to connected when done.
    // will change the connectivity status
    if (statusThread_.joinable())
        statusThread_.join();
    statusThread_ = std::thread([this, serverHost]{
        auto hostAndService = splitPort(serverHost);
        auto resolved_proxies = SockAddr::resolve(hostAndService.first, hostAndService.second);
        for (const auto& resolved_proxy: resolved_proxies) {
            auto server = resolved_proxy.toString();
            if (resolved_proxy.getFamily() == AF_INET6) {
                // HACK restbed seems to not correctly handle directly http://[ipv6]
                // See https://github.com/Corvusoft/restbed/issues/290.
                server = serverHost;
            }
            restbed::Uri uri(HTTP_PROTO + server + "/");
            auto req = std::make_shared<restbed::Request>(uri);
            restbed::Http::async(req,
            [this, resolved_proxy](const std::shared_ptr<restbed::Request>&,
                                   const std::shared_ptr<restbed::Response>& reply)
            {
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
                    onProxyInfos(proxyInfos, resolved_proxy.getFamily());
                }
            });
            ongoingStatusUpdate_.clear();
        }
    });
}

void
DhtProxyClient::onProxyInfos(const Json::Value& proxyInfos, sa_family_t family)
{
    std::lock_guard<std::mutex> l(lockCurrentProxyInfos_);

    DHT_LOG.d("Got proxy infos %s", family == AF_INET ? "IPv4" : "IPv6");

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

        if (family == AF_INET)
            publicAddressV4_ = parsePublicAddress(proxyInfos["public_ip"]);
        else if (family == AF_INET6)
            publicAddressV6_ = parsePublicAddress(proxyInfos["public_ip"]);
    } catch (const std::exception& e) {
        DHT_LOG.w("Error parsing proxy infos: %s", e.what());
    }

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
    auto hostAndService = splitPort(public_ip);
    auto sa = SockAddr::resolve(hostAndService.first);
    if (sa.empty()) return {};
    return sa.front().getMappedIPv4();
}

std::vector<SockAddr>
DhtProxyClient::getPublicAddress(sa_family_t family)
{
    std::lock_guard<std::mutex> l(lockCurrentProxyInfos_);
    std::vector<SockAddr> result;
    if (publicAddressV6_ && family != AF_INET) result.emplace_back(publicAddressV6_);
    if (publicAddressV4_ && family != AF_INET6) result.emplace_back(publicAddressV4_);
    return result;
}

size_t
DhtProxyClient::listen(const InfoHash& key, ValueCallback cb, Value::Filter filter, Where where) {
    DHT_LOG.d(key, "[search %s]: listen", key.to_c_str());
    auto it = searches_.find(key);
    if (it == searches_.end()) {
        it = searches_.emplace(key, ProxySearch{}).first;
    }
    auto query = std::make_shared<Query>(Select{}, where);
    auto token = it->second.ops.listen(cb, query, filter, [&](Sp<Query> q, ValueCallback vcb){
        return doListen(key, vcb, filter);
    });
    return token;
}

bool
DhtProxyClient::cancelListen(const InfoHash& key, size_t gtoken) {
    DHT_LOG.d(key, "[search %s]: cancelListen %zu", key.to_c_str(), gtoken);
    auto it = searches_.find(key);
    if (it == searches_.end())
        return false;
    return it->second.ops.cancelListen(gtoken, [&](size_t ltoken){
        doCancelListen(key, ltoken);
    });
}

size_t
DhtProxyClient::doListen(const InfoHash& key, ValueCallback cb, Value::Filter filter/*, Where where*/)
{
    scheduler.syncTime();
    restbed::Uri uri(HTTP_PROTO + serverHost_ + "/" + key.toString());
    auto req = std::make_shared<restbed::Request>(uri);
    req->set_method(deviceKey_.empty() ? "LISTEN" : "SUBSCRIBE");

    std::lock_guard<std::mutex> lock(searchLock_);
    auto search = searches_.find(key);
    if (search == searches_.end()) {
        DHT_LOG.e(key, "[search %s] listen: search not found", key.to_c_str());
        return 0;
    }
    DHT_LOG.d(key, "[search %s] sending %s", key.to_c_str(), deviceKey_.empty() ? "listen" : "subscribe");

    auto token = ++listener_token_;
    auto l = search->second.listeners.find(token);
    if (l == search->second.listeners.end()) {
        auto f = filter;
        l = search->second.listeners.emplace(token, Listener {
            ValueCache(cb), scheduler.add(time_point::max(), [this, key, token]{
                std::lock_guard<std::mutex> lock(searchLock_);
                auto s = searches_.find(key);
                if (s == searches_.end()) {
                    return;
                }
                auto l = s->second.listeners.find(token);
                if (l == s->second.listeners.end()) {
                    return;
                }
                auto next = l->second.cache.expireValues(scheduler.time());
                scheduler.edit(l->second.cacheExpirationJob, next);
            }), req, std::move(f)
        }).first;
    }

    auto state = std::make_shared<Listener::State>();
    l->second.state = state;
    l->second.cb = [this,key,token,state](const std::vector<Sp<Value>>& values, bool expired) {
        if (state->cancel)
            return false;
        std::lock_guard<std::mutex> lock(searchLock_);
        auto s = searches_.find(key);
        if (s == searches_.end()) {
            return false;
        }
        auto l = s->second.listeners.find(token);
        if (l == s->second.listeners.end()) {
            return false;
        }
        const std::vector<Sp<Value>> new_values_empty;
        std::vector<Value::Id> expired_ids;
        if (expired) {
            expired_ids.reserve(values.size());
            for (const auto& v : values)
                expired_ids.emplace_back(v->id);
        }
        auto next = l->second.cache.onValues(expired ? new_values_empty : values, std::vector<Value::Id>{}, expired_ids, types, scheduler.time());
        scheduler.edit(l->second.cacheExpirationJob, next);
        return true;
    };
    auto pushNotifToken = std::make_shared<unsigned>(0);
    auto vcb = l->second.cb;
    l->second.pushNotifToken = pushNotifToken;
    l->second.thread = std::thread([this,req,filter,vcb,pushNotifToken,state]()
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

            restbed::Http::async(req,
                [this, filter, vcb, pushNotifToken, state](const std::shared_ptr<restbed::Request>& req,
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
                                        callbacks_.emplace_back([vcb, value, state]() {
                                            if (not state->cancel and not vcb({value}, false))
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
            auto& s = *state;
            if (not s.ok and not s.cancel) {
                opFailed();
            }
        }
    );
    return token;
}

bool
DhtProxyClient::doCancelListen(const InfoHash& key, size_t ltoken)
{
    std::lock_guard<std::mutex> lock(searchLock_);

    auto search = searches_.find(key);
    if (search == searches_.end())
        return false;

    auto it = search->second.listeners.find(ltoken);
    if (it == search->second.listeners.end())
        return false;

    DHT_LOG.d(key, "[search %s] cancel listen", key.to_c_str());

    auto& listener = it->second;
    if (not deviceKey_.empty()) {
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
            listener.state->cancel = true;
            if (listener.req)
                restbed::Http::close(listener.req);
            listener.thread.join();
        }
    }
    search->second.listeners.erase(it);
    DHT_LOG.d(key, "[search %s] cancelListen: %zu listener remaining", key.to_c_str(), search->second.listeners.size());
    if (search->second.listeners.empty()) {
        searches_.erase(search);
    }

    return true;
}

void
DhtProxyClient::opFailed()
{
    DHT_LOG.e("Proxy request failed");
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
    if (not deviceKey_.empty()) {
        return;
    }
    DHT_LOG.d("Restarting listeners");
    std::lock_guard<std::mutex> lock(searchLock_);
    for (auto& search: searches_) {
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
        std::lock_guard<std::mutex> lock(searchLock_);
        auto token = std::stoul(notification.at("token"));
        for (auto& search: searches_) {
            for (auto& list : search.second.listeners) {
                auto& listener = list.second;
                if (*listener.pushNotifToken!= token)
                    continue;
                DHT_LOG.d(search.first, "[search %s] handling push notification", search.first.to_c_str());
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
                break;
            }
        }
    } catch (const std::exception& e) {
        DHT_LOG.e("Error handling push notification: %s", e.what());
    }
#endif
}

void
DhtProxyClient::resubscribe(const InfoHash& key, Listener& listener)
{
#if OPENDHT_PUSH_NOTIFICATIONS
    if (deviceKey_.empty()) return;
    DHT_LOG.d(key, "[search %s] resubscribe push listener", key.to_c_str());
    // Subscribe
    restbed::Uri uri(HTTP_PROTO + serverHost_ + "/" + key.toString());
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
            [pushNotifToken, ok](const std::shared_ptr<restbed::Request>&,
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
DhtProxyClient::fillBodyToGetToken(std::shared_ptr<restbed::Request> req, unsigned token)
{
    // Fill body with
    // {
    //   "key":"device_key",
    //   "token": xxx
    // }
    Json::Value body;
    body["key"] = deviceKey_;
    body["client_id"] = pushClientId_;
    if (token > 0)
        body["token"] = token;
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
