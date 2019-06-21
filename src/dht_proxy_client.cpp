/*
 *  Copyright (C) 2016-2019 Savoir-faire Linux Inc.
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

#include "dht_proxy_client.h"

#include "dhtrunner.h"
#include "op_cache.h"
#include "utils.h"

#include <restbed>
#include <json/json.h>

#include <chrono>
#include <vector>

namespace dht {

struct DhtProxyClient::InfoState {
    std::atomic_uint ipv4 {0}, ipv6 {0};
    std::atomic_bool cancel {false};
};

struct DhtProxyClient::ListenState {
    std::atomic_bool ok {true};
    std::atomic_bool cancel {false};
};

struct DhtProxyClient::Listener
{
    OpValueCache cache;
    ValueCallback cb;
    Value::Filter filter;
    Sp<restbed::Request> req;
    std::thread thread;
    unsigned callbackId;
    Sp<ListenState> state;
    Sp<Scheduler::Job> refreshJob;
    Listener(OpValueCache&& c, const Sp<restbed::Request>& r, Value::Filter&& f)
        : cache(std::move(c)), filter(std::move(f)),req(r) {}
};

struct PermanentPut {
    Sp<Value> value;
    Sp<Scheduler::Job> refreshJob;
    Sp<std::atomic_bool> ok;
    PermanentPut(const Sp<Value>& v, Sp<Scheduler::Job>&& j, const Sp<std::atomic_bool>& o)
        : value(v), refreshJob(std::move(j)), ok(o) {}
};

struct DhtProxyClient::ProxySearch {
    SearchCache ops {};
    Sp<Scheduler::Job> opExpirationJob {};
    std::map<size_t, Listener> listeners {};
    std::map<Value::Id, PermanentPut> puts {};
};

DhtProxyClient::DhtProxyClient() {}

DhtProxyClient::DhtProxyClient(std::function<void()> signal, const std::string& serverHost, const std::string& pushClientId, const Logger& l)
: DhtInterface(l), serverHost_(serverHost), pushClientId_(pushClientId), loopSignal_(signal)
{
    if (serverHost_.find("://") == std::string::npos)
        serverHost_ = proxy::HTTP_PROTO + serverHost_;
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
    listenerRestart = std::make_shared<Scheduler::Job>(std::bind(&DhtProxyClient::restartListeners, this));
    loopSignal_();
}

DhtProxyClient::~DhtProxyClient()
{
    isDestroying_ = true;
    cancelAllOperations();
    cancelAllListeners();
    if (infoState_)
        infoState_->cancel = true;
    if (statusThread_.joinable())
        statusThread_.join();
}

std::vector<Sp<Value>>
DhtProxyClient::getLocal(const InfoHash& k, const Value::Filter& filter) const {
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
            if (operation->req) {
                try {
                    restbed::Http::close(operation->req);
                } catch (const std::exception& e) {
                    DHT_LOG.w("Error closing socket: %s", e.what());
                }
                operation->req.reset();
            }
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
                if (l->second.req) {
                    try {
                        restbed::Http::close(l->second.req);
                    } catch (const std::exception& e) {
                        DHT_LOG.w("Error closing socket: %s", e.what());
                    }
                    l->second.req.reset();
                }
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
DhtProxyClient::periodic(const uint8_t*, size_t, SockAddr)
{
    // Exec all currently stored callbacks
    scheduler.syncTime();
    decltype(callbacks_) callbacks;
    {
        std::lock_guard<std::mutex> lock(lockCallbacks);
        callbacks = std::move(callbacks_);
    }
    for (auto& callback : callbacks)
        callback();
    callbacks.clear();

    // Remove finished operations
    {
        std::lock_guard<std::mutex> lock(lockOperations_);
        auto operation = operations_.begin();
        while (operation != operations_.end()) {
            if (*(operation->finished)) {
                if (operation->thread.joinable()) {
                    // Close connection to stop operation?
                    if (operation->req) {
                        try {
                            restbed::Http::close(operation->req);
                        } catch (const std::exception& e) {
                            DHT_LOG.w("Error closing socket: %s", e.what());
                        }
                        operation->req.reset();
                    }
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
    restbed::Uri uri(serverHost_ + "/" + key.toString());
    auto req = std::make_shared<restbed::Request>(uri);
    Value::Filter filter = w.empty() ? f : f.chain(w.getFilter());

    auto finished = std::make_shared<std::atomic_bool>(false);
    Operation o;
    o.req = req;
    o.finished = finished;
    o.thread = std::thread([=](){
        // Try to contact the proxy and set the status to connected when done.
        // will change the connectivity status
        struct GetState{ std::atomic_bool ok {true}; std::atomic_bool stop {false}; };
        auto state = std::make_shared<GetState>();
        try {
            restbed::Http::async(req,
                [=](const std::shared_ptr<restbed::Request>& req,
                    const std::shared_ptr<restbed::Response>& reply) {
                auto code = reply->get_status_code();

                if (code == 200) {
                    try {
                        while (restbed::Http::is_open(req) and not *finished and not state->stop) {
                            restbed::Http::fetch("\n", reply);
                            if (*finished or state->stop)
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
                                if ((not filter or filter(*value)) and cb) {
                                    {
                                        std::lock_guard<std::mutex> lock(lockCallbacks);
                                        callbacks_.emplace_back([cb, value, state]() {
                                            if (not state->stop and not cb({value}))
                                                state->stop = true;
                                        });
                                    }
                                    loopSignal_();
                                }
                            } else {
                                state->ok = false;
                            }
                        }
                    } catch (std::runtime_error& e) { }
                } else {
                    state->ok = false;
                }
            }).wait();
        } catch(const std::exception& e) {
            state->ok = false;
        }
        if (donecb) {
            {
                std::lock_guard<std::mutex> lock(lockCallbacks);
                callbacks_.emplace_back([=](){
                    donecb(state->ok, {});
                    state->stop = true;
                });
            }
            loopSignal_();
        }
        if (!state->ok) {
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
        auto& search = searches_[key];
        auto nextRefresh = scheduler.time() + proxy::OP_TIMEOUT - proxy::OP_MARGIN;
        auto ok = std::make_shared<std::atomic_bool>(false);
        search.puts.erase(id);
        search.puts.emplace(std::piecewise_construct,
            std::forward_as_tuple(id),
            std::forward_as_tuple(val, scheduler.add(nextRefresh, [this, key, id, ok]{
                std::lock_guard<std::mutex> lock(searchLock_);
                auto s = searches_.find(key);
                if (s != searches_.end()) {
                    auto p = s->second.puts.find(id);
                    if (p != s->second.puts.end()) {
                        doPut(key, p->second.value,
                        [ok](bool result, const std::vector<std::shared_ptr<dht::Node> >&){
                            *ok = result;
                        }, time_point::max(), true);
                        scheduler.edit(p->second.refreshJob, scheduler.time() + proxy::OP_TIMEOUT - proxy::OP_MARGIN);
                    }
                }
            }), ok));
    }
    doPut(key, val, std::move(cb), created, permanent);
}

void
DhtProxyClient::doPut(const InfoHash& key, Sp<Value> val, DoneCallback cb, time_point /*created*/, bool permanent)
{
    DHT_LOG.d(key, "[search %s] performing put of %s", key.to_c_str(), val->toString().c_str());
    restbed::Uri uri(serverHost_ + "/" + key.toString());
    auto req = std::make_shared<restbed::Request>(uri);
    req->set_method("POST");

    auto json = val->toJson();
    if (permanent) {
        if (deviceKey_.empty()) {
            json["permanent"] = true;
        } else {
#ifdef OPENDHT_PUSH_NOTIFICATIONS
            Json::Value refresh;
            getPushRequest(refresh);
            json["permanent"] = refresh;
#else
            json["permanent"] = true;
#endif
        }
    }
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
        try {
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
        } catch(const std::exception& e) {
            *ok = false;
        }
        if (cb) {
            {
                std::lock_guard<std::mutex> lock(lockCallbacks);
                callbacks_.emplace_back([=](){
                    cb(*ok, {});
                });
            }
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
DhtProxyClient::getPut(const InfoHash& key) const {
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
DhtProxyClient::getPut(const InfoHash& key, const Value::Id& id) const {
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
    std::lock_guard<std::mutex> l(statusLock_);

    auto infoState = std::make_shared<InfoState>();
    if (infoState_)
        infoState_->cancel = true;
    infoState_ = infoState;

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
    if (statusThread_.joinable()) {
        try {
            statusThread_.detach();
            statusThread_ = {};
        } catch (const std::exception& e) {
            DHT_LOG.e("Error detaching thread: %s", e.what());
        }
    }
    statusThread_ = std::thread([this, serverHost, infoState]{
        try {
            auto endpointStr = serverHost;
            auto protocol = std::string(proxy::HTTP_PROTO);
            auto protocolIdx = serverHost.find("://");
            if (protocolIdx != std::string::npos) {
                protocol = endpointStr.substr(0, protocolIdx + 3);
                endpointStr = endpointStr.substr(protocolIdx + 3);
            }
            auto hostAndService = splitPort(endpointStr);
            auto resolved_proxies = SockAddr::resolve(hostAndService.first, hostAndService.second);
            std::vector<std::future<Sp<restbed::Response>>> reqs;
            reqs.reserve(resolved_proxies.size());
            for (const auto& resolved_proxy: resolved_proxies) {
                auto server = resolved_proxy.toString();
                if (resolved_proxy.getFamily() == AF_INET6) {
                    // HACK restbed seems to not correctly handle directly http://[ipv6]
                    // See https://github.com/Corvusoft/restbed/issues/290.
                    server = endpointStr;
                }
                restbed::Uri uri(protocol + server + "/");
                auto req = std::make_shared<restbed::Request>(uri);
                if (infoState->cancel)
                    return;
                reqs.emplace_back(restbed::Http::async(req,
                    [this, resolved_proxy, infoState](
                                const std::shared_ptr<restbed::Request>&,
                                const std::shared_ptr<restbed::Response>& reply)
                {
                    auto code = reply->get_status_code();
                    Json::Value proxyInfos;
                    if (code == 200) {
                        restbed::Http::fetch("\n", reply);
                        auto& state = *infoState;
                        if (state.cancel) return;
                        std::string body;
                        reply->get_body(body);

                        std::string err;
                        Json::CharReaderBuilder rbuilder;
                        auto reader = std::unique_ptr<Json::CharReader>(rbuilder.newCharReader());
                        try {
                            reader->parse(body.data(), body.data() + body.size(), &proxyInfos, &err);
                        } catch (...) {
                            return;
                        }
                        auto family = resolved_proxy.getFamily();
                        if      (family == AF_INET)  state.ipv4++;
                        else if (family == AF_INET6) state.ipv6++;
                        if (not state.cancel)
                            onProxyInfos(proxyInfos, family);
                    }
                }));
            }
            for (auto& r : reqs)
                r.get();
            reqs.clear();
        } catch (const std::exception& e) {
            DHT_LOG.e("Error sending proxy info request: %s", e.what());
        }
        const auto& state = *infoState;
        if (state.cancel) return;
        if (state.ipv4 == 0) onProxyInfos(Json::Value{}, AF_INET);
        if (state.ipv6 == 0) onProxyInfos(Json::Value{}, AF_INET6);
    });
}

void
DhtProxyClient::onProxyInfos(const Json::Value& proxyInfos, sa_family_t family)
{
    if (isDestroying_)
        return;
    std::lock_guard<std::mutex> l(lockCurrentProxyInfos_);
    auto oldStatus = std::max(statusIpv4_, statusIpv6_);
    auto& status = family == AF_INET ? statusIpv4_ : statusIpv6_;
    if (not proxyInfos.isMember("node_id")) {
        DHT_LOG.e("Proxy info request failed for %s", family == AF_INET ? "IPv4" : "IPv6");
        status = NodeStatus::Disconnected;
    } else {
        DHT_LOG.d("Got proxy reply for %s", family == AF_INET ? "IPv4" : "IPv6");
        try {
            myid = InfoHash(proxyInfos["node_id"].asString());
            stats4_ = NodeStats(proxyInfos["ipv4"]);
            stats6_ = NodeStats(proxyInfos["ipv6"]);
            if (stats4_.good_nodes + stats6_.good_nodes)
                status = NodeStatus::Connected;
            else if (stats4_.dubious_nodes + stats6_.dubious_nodes)
                status = NodeStatus::Connecting;
            else
                status = NodeStatus::Disconnected;

            auto publicIp = parsePublicAddress(proxyInfos["public_ip"]);
            auto publicFamily = publicIp.getFamily();
            if (publicFamily == AF_INET)
                publicAddressV4_ = publicIp;
            else if (publicFamily == AF_INET6)
                publicAddressV6_ = publicIp;
        } catch (const std::exception& e) {
            DHT_LOG.w("Error processing proxy infos: %s", e.what());
        }
    }

    auto newStatus = std::max(statusIpv4_, statusIpv6_);
    if (newStatus == NodeStatus::Connected) {
        if (oldStatus == NodeStatus::Disconnected || oldStatus == NodeStatus::Connecting) {
            scheduler.edit(listenerRestart, scheduler.time());
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
    auto& search = searches_[key];
    auto query = std::make_shared<Query>(Select{}, where);
    auto token = search.ops.listen(cb, query, filter, [this, key, filter](Sp<Query> /*q*/, ValueCallback cb, SyncCallback /*scb*/) -> size_t {
        scheduler.syncTime();
        restbed::Uri uri(serverHost_ + "/" + key.toString());
        std::lock_guard<std::mutex> lock(searchLock_);
        auto search = searches_.find(key);
        if (search == searches_.end()) {
            DHT_LOG.e(key, "[search %s] listen: search not found", key.to_c_str());
            return 0;
        }
        DHT_LOG.d(key, "[search %s] sending %s", key.to_c_str(), deviceKey_.empty() ? "listen" : "subscribe");

        auto req = std::make_shared<restbed::Request>(uri);
        auto token = ++listenerToken_;
        auto l = search->second.listeners.find(token);
        if (l == search->second.listeners.end()) {
            auto f = filter;
            l = search->second.listeners.emplace(std::piecewise_construct,
                    std::forward_as_tuple(token),
                    std::forward_as_tuple(std::move(cb), req, std::move(f))).first;
        } else {
            if (l->second.state)
                l->second.state->cancel = true;
        }

        auto state = std::make_shared<ListenState>();
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
            return l->second.cache.onValue(values, expired);
        };

        auto vcb = l->second.cb;
        l->second.req = req;

        if (not deviceKey_.empty()) {
            // Relaunch push listeners even if a timeout is not received (if the proxy crash for any reason)
            l->second.refreshJob = scheduler.add(scheduler.time() + proxy::OP_TIMEOUT - proxy::OP_MARGIN, [this, key, token, state] {
                if (state->cancel)
                    return;
                std::lock_guard<std::mutex> lock(searchLock_);
                auto s = searches_.find(key);
                if (s != searches_.end()) {
                    auto l = s->second.listeners.find(token);
                    if (l != s->second.listeners.end()) {
                        resubscribe(key, l->second);
                    }
                }
            });
        }
        l->second.thread = std::thread([this, req, vcb, filter, state]() {
            sendListen(req, vcb, filter, state,
                    deviceKey_.empty() ? ListenMethod::LISTEN : ListenMethod::SUBSCRIBE);
        });
        return token;
    });
    return token;
}

bool
DhtProxyClient::cancelListen(const InfoHash& key, size_t gtoken) {
    scheduler.syncTime();
    DHT_LOG.d(key, "[search %s]: cancelListen %zu", key.to_c_str(), gtoken);
    auto it = searches_.find(key);
    if (it == searches_.end())
        return false;
    auto& ops = it->second.ops;
    bool canceled = ops.cancelListen(gtoken, scheduler.time());
    if (not it->second.opExpirationJob) {
        it->second.opExpirationJob = scheduler.add(time_point::max(), [this,key](){
            auto it = searches_.find(key);
            if (it != searches_.end()) {
                auto next = it->second.ops.expire(scheduler.time(), [this,key](size_t ltoken){
                    doCancelListen(key, ltoken);
                });
                if (next != time_point::max()) {
                    scheduler.edit(it->second.opExpirationJob, next);
                }
            }
        });
    }
    scheduler.edit(it->second.opExpirationJob, ops.getExpiration());
    loopSignal_();
    return canceled;
}

void DhtProxyClient::sendListen(const std::shared_ptr<restbed::Request> &req,
                                const ValueCallback &cb,
                                const Value::Filter &filter,
                                const Sp<ListenState> &state,
                                ListenMethod method) {
    auto settings = std::make_shared<restbed::Settings>();
    if (method != ListenMethod::LISTEN) {
        req->set_method("SUBSCRIBE");
    } else {
        std::chrono::milliseconds timeout(std::numeric_limits<int>::max());
        settings->set_connection_timeout(timeout); // Avoid the client to close the socket after 5 seconds.
        req->set_method("LISTEN");
    }
    try {
#ifdef OPENDHT_PUSH_NOTIFICATIONS
        if (method != ListenMethod::LISTEN)
        fillBody(req, method == ListenMethod::RESUBSCRIBE);
    #endif
        restbed::Http::async(req,
              [this, filter, cb, state](const std::shared_ptr<restbed::Request>& req,
                                        const std::shared_ptr<restbed::Response>& reply)
        {
            auto code = reply->get_status_code();
            if (code == 200) {
                try {
                    while (restbed::Http::is_open(req) and not state->cancel) {
                        restbed::Http::fetch("\n", reply);
                        if (state->cancel)
                            break;
                        std::string body;
                        reply->get_body(body);
                        reply->set_body(""); // Reset the body for the next fetch

                        Json::Value json;
                        std::string err;
                        Json::CharReaderBuilder rbuilder;
                        auto reader = std::unique_ptr<Json::CharReader>(rbuilder.newCharReader());
                        if (reader->parse(body.data(), body.data() + body.size(), &json, &err)) {
                            if (json.size() == 0) {
                                // Empty value, it's the end
                                break;
                            }
                            auto expired = json.get("expired", Json::Value(false)).asBool();
                            auto value = std::make_shared<Value>(json);
                            if ((not filter or filter(*value)) and cb) {
                                {
                                    std::lock_guard<std::mutex> lock(lockCallbacks);
                                    callbacks_.emplace_back([cb, value, state, expired]() {
                                        if (not state->cancel and not cb({value}, expired))
                                            state->cancel = true;
                                    });
                                }
                                loopSignal_();
                            }
                        }
                    }
                } catch (const std::exception& e) {
                    if (not state->cancel) {
                        DHT_LOG.w("Listen closed by the proxy server: %s", e.what());
                        state->ok = false;
                    }
                }
            } else {
                state->ok = false;
            }
        }, settings).get();
    } catch (const std::exception& e) {
        state->ok = false;
    }
    auto& s = *state;
    if (not s.ok and not s.cancel)
        opFailed();
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
    listener.state->cancel = true;
    if (not deviceKey_.empty()) {
        // First, be sure to have a token
        if (listener.thread.joinable()) {
            listener.thread.join();
        }
        // UNSUBSCRIBE
        restbed::Uri uri(serverHost_ + "/" + key.toString());
        auto req = std::make_shared<restbed::Request>(uri);
        req->set_method("UNSUBSCRIBE");
        // fill request body
        Json::Value body;
        body["key"] = deviceKey_;
        body["client_id"] = pushClientId_;
        Json::StreamWriterBuilder wbuilder;
        wbuilder["commentStyle"] = "None";
        wbuilder["indentation"] = "";
        auto content = Json::writeString(wbuilder, body) + "\n";
        std::replace(content.begin(), content.end(), '\n', ' ');
        req->set_body(content);
        req->set_header("Content-Length", std::to_string(content.size()));
        try {
            restbed::Http::async(req, [](const std::shared_ptr<restbed::Request>&, const std::shared_ptr<restbed::Response>&){});
        } catch (const std::exception& e) {
            DHT_LOG.w(key, "[search %s] cancelListen: Http::async failed: %s", key.to_c_str(), e.what());
        }
    } else {
        // Just stop the request
        if (listener.thread.joinable()) {
            // Close connection to stop listener
            if (listener.req) {
                try {
                    restbed::Http::close(listener.req);
                } catch (const std::exception& e) {
                    DHT_LOG.w("Error closing socket: %s", e.what());
                }
                listener.req.reset();
            }
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
    if (isDestroying_) return;
    std::lock_guard<std::mutex> lock(searchLock_);
    DHT_LOG.d("Refresh permanent puts");
    for (auto& search : searches_) {
        for (auto& put : search.second.puts) {
            if (!*put.second.ok) {
                auto ok = put.second.ok;
                doPut(search.first, put.second.value,
                [ok](bool result, const std::vector<std::shared_ptr<dht::Node> >&){
                    *ok = result;
                }, time_point::max(), true);
                scheduler.edit(put.second.refreshJob, scheduler.time() + proxy::OP_TIMEOUT - proxy::OP_MARGIN);
            }
        }
    }
    if (not deviceKey_.empty()) {
        DHT_LOG.d("resubscribe due to a connectivity change");
        // Connectivity changed, refresh all subscribe
        for (auto& search : searches_)
            for (auto& listener : search.second.listeners)
                if (!listener.second.state->ok)
                    resubscribe(search.first, listener.second);
        return;
    }
    DHT_LOG.d("Restarting listeners");
    for (auto& search: searches_) {
        for (auto& l: search.second.listeners) {
            auto& listener = l.second;
            if (auto state = listener.state)
                state->cancel = true;
            if (listener.req) {
                try {
                    restbed::Http::close(listener.req);
                } catch (const std::exception& e) {
                    DHT_LOG.w("Error closing socket: %s", e.what());
                }
                listener.req.reset();
            }
        }
    }
    for (auto& search: searches_) {
        for (auto& l: search.second.listeners) {
            auto& listener = l.second;
            auto state = listener.state;
            if (listener.thread.joinable()) {
                listener.thread.join();
            }
            // Redo listen
            state->cancel = false;
            state->ok = true;
            auto filter = listener.filter;
            auto cb = listener.cb;
            restbed::Uri uri(serverHost_ + "/" + search.first.toString());
            auto req = std::make_shared<restbed::Request>(uri);
            req->set_method("LISTEN");
            listener.req = req;
            listener.thread = std::thread([this, req, cb, filter, state]() {
                sendListen(req, cb, filter, state);
            });
        }
    }
}

void
DhtProxyClient::pushNotificationReceived(const std::map<std::string, std::string>& notification)
{
#ifdef OPENDHT_PUSH_NOTIFICATIONS
    scheduler.syncTime();
    {
        // If a push notification is received, the proxy is up and running
        std::lock_guard<std::mutex> l(lockCurrentProxyInfos_);
        statusIpv4_ = NodeStatus::Connected;
        statusIpv6_ = NodeStatus::Connected;
    }
    try {
        std::lock_guard<std::mutex> lock(searchLock_);
        auto timeout = notification.find("timeout");
        if (timeout != notification.cend()) {
            InfoHash key(timeout->second);
            auto& search = searches_.at(key);
            auto vidIt = notification.find("vid");
            if (vidIt != notification.end()) {
                // Refresh put
                auto vid = std::stoull(vidIt->second);
                auto& put = search.puts.at(vid);
                scheduler.edit(put.refreshJob, scheduler.time());
                loopSignal_();
            } else {
                // Refresh listen
                for (auto& list : search.listeners)
                    resubscribe(key, list.second);
            }
        } else {
            auto key = InfoHash(notification.at("key"));
            auto& search = searches_.at(key);
            for (auto& list : search.listeners) {
                if (list.second.state->cancel)
                    continue;
                DHT_LOG.d(key, "[search %s] handling push notification", key.to_c_str());
                auto expired = notification.find("exp");
                auto token = list.first;
                auto state = list.second.state;
                if (expired == notification.end()) {
                    auto cb = list.second.cb;
                    auto filter = list.second.filter;
                    auto oldValues = list.second.cache.getValues();
                    get(key, [cb](const std::vector<Sp<Value>>& vals) {
                        return cb(vals, false);
                    }, [cb, oldValues](bool /*ok*/) {
                        // Decrement old values refcount to expire values not present in the new list
                        cb(oldValues, true);
                    }, std::move(filter));
                } else {
                    std::stringstream ss(expired->second);
                    std::vector<Value::Id> ids;
                    while(ss.good()){
                        std::string substr;
                        getline(ss, substr, ',');
                        ids.emplace_back(std::stoull(substr));
                    }
                    {
                        std::lock_guard<std::mutex> lock(lockCallbacks);
                        callbacks_.emplace_back([this, key, token, state, ids]() {
                            if (state->cancel) return;
                            std::lock_guard<std::mutex> lock(searchLock_);
                            auto s = searches_.find(key);
                            if (s == searches_.end()) return;
                            auto l = s->second.listeners.find(token);
                            if (l == s->second.listeners.end()) return;
                            if (not state->cancel and not l->second.cache.onValuesExpired(ids))
                                state->cancel = true;
                        });
                    }
                    loopSignal_();
                }
            }
        }
    } catch (const std::exception& e) {
        DHT_LOG.e("Error handling push notification: %s", e.what());
    }
#else
    (void) notification;
#endif
}

void
DhtProxyClient::resubscribe(const InfoHash& key, Listener& listener)
{
#ifdef OPENDHT_PUSH_NOTIFICATIONS
    if (deviceKey_.empty()) return;
    scheduler.syncTime();
    DHT_LOG.d(key, "[search %s] resubscribe push listener", key.to_c_str());
    // Subscribe
    auto state = listener.state;
    if (listener.thread.joinable()) {
        state->cancel = true;
        if (listener.req) {
            try {
                restbed::Http::close(listener.req);
            } catch (const std::exception& e) {
                DHT_LOG.w("Error closing socket: %s", e.what());
            }
            listener.req.reset();
        }
        listener.thread.join();
    }
    state->cancel = false;
    state->ok = true;
    auto req = std::make_shared<restbed::Request>(restbed::Uri {serverHost_ + "/" + key.toString()});
    req->set_method("SUBSCRIBE");
    listener.req = req;
    scheduler.edit(listener.refreshJob, scheduler.time() + proxy::OP_TIMEOUT - proxy::OP_MARGIN);
    auto vcb = listener.cb;
    auto filter = listener.filter;
    listener.thread = std::thread([this, req, vcb, filter, state]() {
        sendListen(req, vcb, filter, state, ListenMethod::RESUBSCRIBE);
    });
#else
    (void) key;
    (void) listener;
#endif
}

#ifdef OPENDHT_PUSH_NOTIFICATIONS
void
DhtProxyClient::getPushRequest(Json::Value& body) const
{
    body["key"] = deviceKey_;
    body["client_id"] = pushClientId_;
#ifdef __ANDROID__
    body["platform"] = "android";
#endif
#ifdef __APPLE__
    body["platform"] = "apple";
#endif
}

void
DhtProxyClient::fillBody(std::shared_ptr<restbed::Request> req, bool resubscribe)
{
    // Fill body with
    // {
    //   "key":"device_key",
    // }
    Json::Value body;
    getPushRequest(body);
    if (resubscribe) {
        // This is the first listen, we want to retrieve previous values.
        body["refresh"] = true;
    }
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
