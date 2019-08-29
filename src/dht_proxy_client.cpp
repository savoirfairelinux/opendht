/*
 *  Copyright (C) 2016-2019 Savoir-faire Linux Inc.
 *  Author: Sébastien Blin <sebastien.blin@savoirfairelinux.com>
 *          Adrien Béraud <adrien.beraud@savoirfairelinux.com>
 *          Vsevolod Ivanov <vsevolod.ivanov@savoirfairelinux.com>
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

#include <http_parser.h>

namespace dht {

struct DhtProxyClient::InfoState {
    std::atomic_uint ipv4 {0}, ipv6 {0};
    std::atomic_bool cancel {false};
};

struct DhtProxyClient::OperationState {
    std::atomic_bool ok {true};
    std::atomic_bool stop {false};
};

struct DhtProxyClient::Listener
{
    Listener(OpValueCache&& c):
        cache(std::move(c))
    {}

    unsigned callbackId;
    OpValueCache cache;
    ValueCallback cb;
    Sp<OperationState> opstate;
    std::shared_ptr<http::Request> request;
    std::unique_ptr<asio::steady_timer> refreshSubscriberTimer;
};

struct PermanentPut {
    PermanentPut(const Sp<Value>& v, std::unique_ptr<asio::steady_timer>&& j,
                 const Sp<std::atomic_bool>& o):
        value(v), refreshPutTimer(std::move(j)), ok(o)
    {}

    Sp<Value> value;
    std::unique_ptr<asio::steady_timer> refreshPutTimer;
    Sp<std::atomic_bool> ok;
};

struct DhtProxyClient::ProxySearch {
    SearchCache ops {};
    std::unique_ptr<asio::steady_timer> opExpirationTimer;
    std::map<size_t, Listener> listeners {};
    std::map<Value::Id, PermanentPut> puts {};
};

DhtProxyClient::DhtProxyClient() {}

DhtProxyClient::DhtProxyClient(
        std::shared_ptr<dht::crypto::Certificate> certificate,
        std::function<void()> signal, const std::string& serverHost,
        const std::string& pushClientId, std::shared_ptr<dht::Logger> logger)
    :
        serverCertificate_(certificate),
        pushClientId_(pushClientId), loopSignal_(signal), logger_(logger)
{
    // build http client
    serverHostService_ = splitPort(serverHost);
    serverHostService_.second = serverHostService_.second.empty() ? "80" :
                                serverHostService_.second;
    if (serverCertificate_ and logger_)
        logger_->d("[proxy:client] using server certificate for ssl:\n%s",
                   serverCertificate_->toString(false/*chain*/).c_str());
    // resolve once
    resolver_ = std::make_shared<http::Resolver>(httpContext_, serverHost, logger_);
    // run http client
    httpClientThread_ = std::thread([this](){
        try {
            if (logger_)
                logger_->d("[proxy:client] starting io_context");
            // Ensures the httpContext_ won't run out of work
            auto work = asio::make_work_guard(httpContext_);
            httpContext_.run();
            if (logger_)
                logger_->d("[proxy:client] http client io_context stopped");
        }
        catch(const std::exception& ex){
            if (logger_)
                logger_->e("[proxy:client] run error: %s", ex.what());
        }
    });
    if (!serverHostService_.first.empty())
        startProxy();
}

void
DhtProxyClient::startProxy()
{
    if (serverHostService_.first.empty())
        return;

    if (logger_)
        logger_->d("[proxy:client] start proxy with %s", serverHostService_.first.c_str());

    nextProxyConfirmationTimer_ = std::make_shared<asio::steady_timer>(httpContext_, std::chrono::steady_clock::now());
    nextProxyConfirmationTimer_->async_wait(std::bind(&DhtProxyClient::handleProxyConfirm, this, std::placeholders::_1));

    listenerRestartTimer_ = std::make_shared<asio::steady_timer>(httpContext_);

    loopSignal_();
}

void
DhtProxyClient::handleProxyConfirm(const asio::error_code &ec)
{
    if (ec == asio::error::operation_aborted)
        return;
    else if (ec){
        if (logger_)
            logger_->e("[proxy:client] confirm error: %s", ec.message().c_str());
        return;
    }
    if (serverHostService_.first.empty())
        return;
    getConnectivityStatus();
}

DhtProxyClient::~DhtProxyClient()
{
    stop();
}

void
DhtProxyClient::stop()
{
    isDestroying_ = true;
    cancelAllOperations();
    cancelAllListeners();
    if (infoState_)
        infoState_->cancel = true;
    if (statusTimer_)
        statusTimer_->cancel();
    if (httpClientThread_.joinable())
        httpClientThread_.join();
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
    if (!httpContext_.stopped())
        httpContext_.stop();
}

void
DhtProxyClient::cancelAllListeners()
{
    std::lock_guard<std::mutex> lock(searchLock_);
    if (logger_)
        logger_->d("[proxy:client] [listeners] [%zu searches] cancel all", searches_.size());
    for (auto& s: searches_) {
        s.second.ops.cancelAll([&](size_t token){
            auto l = s.second.listeners.find(token);
            if (l == s.second.listeners.end())
                return;
            l->second.opstate->stop.store(true);
            l->second.request->cancel();
            // implicit request.reset()
            s.second.listeners.erase(token);
        });
    }
}

void
DhtProxyClient::shutdown(ShutdownCallback cb)
{
    stop();
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
    decltype(callbacks_) callbacks;
    {
        std::lock_guard<std::mutex> lock(lockCallbacks_);
        callbacks = std::move(callbacks_);
    }
    for (auto& callback : callbacks)
        callback();
    callbacks.clear();
    return time_point::max();
}

void
DhtProxyClient::setHeaderFields(std::shared_ptr<http::Request> request){
    request->set_header_field(restinio::http_field_t::host,
                             (serverHostService_.first + ":" + serverHostService_.second).c_str());
    request->set_header_field(restinio::http_field_t::user_agent, "RESTinio client");
    request->set_header_field(restinio::http_field_t::accept, "*/*");
    request->set_header_field(restinio::http_field_t::content_type, "application/json");
}

void
DhtProxyClient::get(const InfoHash& key, GetCallback cb, DoneCallback donecb, Value::Filter&& f, Where&& w)
{
    if (logger_)
        logger_->d("[proxy:client] [get] [search %s]", key.to_c_str());

    auto request = std::make_shared<http::Request>(httpContext_, resolver_, logger_);
    auto reqid = request->id();
    try {
        request->set_connection_type(restinio::http_connection_header_t::keep_alive);
        request->set_target("/" + key.toString());
        request->set_method(restinio::http_method_get());
        setHeaderFields(request);

        auto opstate = std::make_shared<OperationState>();
        Value::Filter filter = w.empty() ? f : f.chain(w.getFilter());

        request->add_on_status_callback([this, key, opstate](unsigned int status_code){
            if (status_code != 200){
                if (logger_)
                    logger_->e("[proxy:client] [get %s] status error: %i", key.to_c_str(), status_code);
                opstate->ok.store(false);
            }
        });
        request->add_on_body_callback([this, key, opstate, filter, cb](const char* at, size_t length){
            try {
                Json::CharReaderBuilder rbuilder;
                auto body = std::string(at, length);
                // one value per body line
                std::string data_line;
                std::stringstream body_stream(body);
                while (std::getline(body_stream, data_line, '\n') and !(opstate->stop.load())){
                    std::string err;
                    Json::Value json;
                    auto* char_data = static_cast<const char*>(&data_line[0]);
                    auto reader = std::unique_ptr<Json::CharReader>(rbuilder.newCharReader());
                    if (!reader->parse(char_data, char_data + data_line.size(), &json, &err)){
                        opstate->ok.store(false);
                        return;
                    }
                    auto value = std::make_shared<Value>(json);
                    if ((not filter or filter(*value)) and cb){
                        {
                            std::lock_guard<std::mutex> lock(lockCallbacks_);
                            callbacks_.emplace_back([opstate, cb, value](){
                                if (not opstate->stop.load() and not cb({value})){
                                    opstate->stop.store(true);
                                }
                            });
                        }
                        loopSignal_();
                    }
                }
            } catch(const std::exception& e) {
                if (logger_)
                    logger_->e("[proxy:client] [get %s] body parsing error: %s", key.to_c_str(), e.what());
                opstate->ok.store(false);
            }
        });
        request->add_on_state_change_callback([this, reqid, opstate, donecb, key]
                                              (const http::Request::State state, const http::Response response){
            if (state == http::Request::State::DONE){
                if (response.status_code != 200){
                    if (logger_)
                        logger_->e("[proxy:client] [get %s] failed with code=%i", key.to_c_str(), response.status_code);
                    opstate->ok.store(false);
                }
                if (donecb){
                    {
                        std::lock_guard<std::mutex> lock(lockCallbacks_);
                        callbacks_.emplace_back([donecb, opstate](){
                            donecb(opstate->ok, {});
                            opstate->stop.store(true);
                        });
                    }
                    loopSignal_();
                }
                requests_.erase(reqid);
            }
        });
        if (serverCertificate_)
            request->set_certificate(serverCertificate_);
        request->set_certificate(serverCertificate_);
        request->send();
        requests_[reqid] = request;
    }
    catch (const std::exception &e){
        if (logger_)
            logger_->e("[proxy:client] [get %s] error: %s", key.to_c_str(), e.what());
        requests_.erase(reqid);
    }
}

void
DhtProxyClient::put(const InfoHash& key, Sp<Value> val, DoneCallback cb, time_point created, bool permanent)
{
    if (not val){
        if (cb)
            cb(false, {});
        return;
    }
    if (logger_)
        logger_->d("[proxy:client] [put] [search %s]", key.to_c_str());

    if (val->id == Value::INVALID_ID) {
        crypto::random_device rdev;
        std::uniform_int_distribution<Value::Id> rand_id {};
        val->id = rand_id(rdev);
    }
    if (permanent) {
        std::lock_guard<std::mutex> lock(searchLock_);
        auto id = val->id;
        auto& search = searches_[key];
        auto refreshPutTimer = std::make_unique<asio::steady_timer>(httpContext_, std::chrono::steady_clock::now() +
                                                                    proxy::OP_TIMEOUT - proxy::OP_MARGIN);
        auto ok = std::make_shared<std::atomic_bool>();
        ok->store(true);
        refreshPutTimer->async_wait(std::bind(&DhtProxyClient::handleRefreshPut, this,
                                              std::placeholders::_1, key, id, ok));
        search.puts.erase(id);
        search.puts.emplace(std::piecewise_construct,
            std::forward_as_tuple(id),
            std::forward_as_tuple(val, std::move(refreshPutTimer), ok));
    }
    doPut(key, val, std::move(cb), created, permanent);
}
void
DhtProxyClient::handleRefreshPut(const asio::error_code &ec, const InfoHash& key, const Value::Id id,
                                 std::shared_ptr<std::atomic_bool> ok)
{
    if (ec == asio::error::operation_aborted)
        return;
    else if (ec){
        if (logger_)
            logger_->e("[proxy:client] [listener] [refresh %s] %s", key.toString().c_str(), ec.message().c_str());
        return;
    }
    if (logger_)
        logger_->d("[proxy:client] [put] [refresh %s]", key.to_c_str());
    std::lock_guard<std::mutex> lock(searchLock_);
    auto search = searches_.find(key);
    if (search != searches_.end()) {
        auto p = search->second.puts.find(id);
        if (p != search->second.puts.end()){
            doPut(key, p->second.value, [ok](bool result, const std::vector<std::shared_ptr<dht::Node>>&){
                *ok = result;
            }, time_point::max(), true);
            p->second.refreshPutTimer->expires_at(std::chrono::steady_clock::now() +
                                               proxy::OP_TIMEOUT - proxy::OP_MARGIN);
            p->second.refreshPutTimer->async_wait(std::bind(&DhtProxyClient::handleRefreshPut, this, std::placeholders::_1, key, id, ok));
        }
    }
}

void
DhtProxyClient::doPut(const InfoHash& key, Sp<Value> val, DoneCallback cb, time_point /*created*/, bool permanent)
{
    if (logger_)
        logger_->d("[proxy:client] [put] [search %s] executing for %s", key.to_c_str(), val->toString().c_str());

    auto request = std::make_shared<http::Request>(httpContext_, resolver_, logger_);
    auto reqid = request->id();
    try {
        request->set_target("/" + key.toString());
        request->set_method(restinio::http_method_post());
        setHeaderFields(request);

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
        auto body = Json::writeString(wbuilder, json);
        request->set_body(body);

        auto ok = std::make_shared<std::atomic_bool>();
        ok->store(true);

        request->add_on_status_callback([this, key, ok](unsigned int status_code){
            if (status_code != 200){
                if (logger_)
                    logger_->e("[proxy:client] [put %s] status error: %i", key.to_c_str(), status_code);
                ok->store(false);
            }
            return 0;
        });
        request->add_on_state_change_callback([this, reqid, ok, cb, key]
                                              (const http::Request::State state, const http::Response response){
            if (state == http::Request::State::DONE){
                if (response.status_code != 200)
                    if (logger_)
                        logger_->e("[proxy:client] [status] failed with code=%i", response.status_code);
                if (cb){
                    {
                        std::lock_guard<std::mutex> lock(lockCallbacks_);
                        callbacks_.emplace_back([cb, ok](){
                            cb(ok->load(), {});
                        });
                    }
                    loopSignal_();
                }
                requests_.erase(reqid);
            }
        });
        if (serverCertificate_)
            request->set_certificate(serverCertificate_);
        request->set_certificate(serverCertificate_);
        request->send();
        requests_[reqid] = request;
    }
    catch (const std::exception &e){
        if (logger_)
            logger_->e("[proxy:client] [put %s] error: %s", key.to_c_str(), e.what());
        requests_.erase(reqid);
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
    if (logger_)
        logger_->d("[proxy:client] [put] [search %s] cancel", key.to_c_str());
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
    if (logger_)
        logger_->d("[proxy:client] [info] requesting proxy server node information");
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
    // Try to contact the proxy and set the status to connected when done.
    // will change the connectivity status
    if (!statusTimer_)
        statusTimer_ = std::make_shared<asio::steady_timer>(httpContext_);
    statusTimer_->expires_at(std::chrono::steady_clock::now());
    statusTimer_->async_wait(std::bind(&DhtProxyClient::handleProxyStatus, this,
                             std::placeholders::_1, infoState));
}

void
DhtProxyClient::handleProxyStatus(const asio::error_code& ec, std::shared_ptr<InfoState> infoState)
{
    if (ec == asio::error::operation_aborted)
        return;
    else if (ec){
        if (logger_)
            logger_->e("[proxy:client] [status] handling error: %s", ec.message().c_str());
        return;
    }
    if (logger_)
        logger_->d("[proxy:client] [status] sending request");

    resolver_->add_callback([this, infoState](const asio::error_code& ec,
                                              std::vector<asio::ip::tcp::endpoint> endpoints)
    {
        if (ec){
            if (logger_)
                logger_->e("[proxy:client] [status] resolve error: %s", ec.message().c_str());
            return;
        }
        std::vector<asio::ip::tcp::endpoint> endpointsIpv4;
        std::vector<asio::ip::tcp::endpoint> endpointsIpv6;

        for (auto& endpoint: endpoints){
            try {
                if (endpoint.address().is_v6())
                    endpointsIpv6.push_back(endpoint);
                if (endpoint.address().is_v4())
                    endpointsIpv4.push_back(endpoint);
            } catch (const std::exception&){};
        }
        // avoiding nested add_callback call
        if (!endpointsIpv4.empty())
            queryProxyInfo(infoState, AF_INET, std::move(endpointsIpv4));
        if (!endpointsIpv6.empty())
            queryProxyInfo(infoState, AF_INET6, std::move(endpointsIpv6));
    });
}

void
DhtProxyClient::queryProxyInfo(std::shared_ptr<InfoState> infoState, const sa_family_t family,
                               std::vector<asio::ip::tcp::endpoint>&& endpoints)
{
    if (logger_)
        logger_->d("[proxy:client] [status] query ipv%i info", family == AF_INET ? 4 : 6);
    auto request = std::make_shared<http::Request>(httpContext_, std::move(endpoints),
        resolver_->get_url().protocol == "https" ? /*ssl*/ true : false, logger_);
    auto reqid = request->id();
    try {
        request->set_connection_type(restinio::http_connection_header_t::keep_alive);
        request->set_target("/");
        request->set_method(restinio::http_method_get());
        setHeaderFields(request);

        auto ok = std::make_shared<std::atomic_bool>();
        ok->store(true);

        request->add_on_status_callback([this, ok, family](unsigned int status_code){
            if (status_code != 200){
                if (logger_)
                    logger_->e("[proxy:client] [status] ipv%i status code error: %i", family, status_code);
                ok->store(false);
            }
        });
        request->add_on_body_callback([this, ok, infoState, family](const char* at, size_t length){
            try{
                std::string err;
                Json::Value proxyInfos;
                Json::CharReaderBuilder rbuilder;
                auto body = std::string(at, length);
                auto* char_data = static_cast<const char*>(&body[0]);
                auto reader = std::unique_ptr<Json::CharReader>(rbuilder.newCharReader());
                if (!reader->parse(char_data, char_data + body.size(), &proxyInfos, &err)){
                    ok->store(false);
                    return;
                }
                if (not infoState->cancel)
                    onProxyInfos(proxyInfos, family);
            }
            catch (const std::exception& e) {
                if (logger_)
                    logger_->e("[proxy:client] [status] body error: %s", e.what());
                ok->store(false);
            }
        });
        request->add_on_state_change_callback([this, reqid, family, infoState]
                                              (const http::Request::State state, const http::Response response){
            if (state == http::Request::State::DONE){
                if (response.status_code != 200)
                    if (logger_)
                        logger_->e("[proxy:client] [status] ipv%i failed with code=%i",
                                    family == AF_INET ? 4 : 6, response.status_code);
                if (infoState->cancel.load()){
                    // pass along the failures
                    if (family == AF_INET and infoState->ipv4 == 0)
                        onProxyInfos(Json::Value{}, AF_INET);
                    if (family == AF_INET6 and infoState->ipv6 == 0)
                    onProxyInfos(Json::Value{}, AF_INET6);
                }
                requests_.erase(reqid);
            }
        });

        if (infoState->cancel.load())
            return;

        if (serverCertificate_)
            request->set_certificate(serverCertificate_);
        request->send();
        requests_[reqid] = request;
    }
    catch (const std::exception &e){
        if (logger_)
            logger_->e("[proxy:client] [status] error sending request: %s", e.what());
        requests_.erase(reqid);
    }
}

void
DhtProxyClient::onProxyInfos(const Json::Value& proxyInfos, const sa_family_t family)
{
    if (isDestroying_)
        return;
    std::lock_guard<std::mutex> l(lockCurrentProxyInfos_);
    auto oldStatus = std::max(statusIpv4_, statusIpv6_);
    auto& status = family == AF_INET ? statusIpv4_ : statusIpv6_;
    if (not proxyInfos.isMember("node_id")) {
        if (logger_)
            logger_->e("[proxy:client] [info] request failed for %s", family == AF_INET ? "ipv4" : "ipv6");
        status = NodeStatus::Disconnected;
    } else {
        if (logger_)
            logger_->d("[proxy:client] [info] got proxy reply for %s",
                       family == AF_INET ? "ipv4" : "ipv6");
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
            if (logger_)
                logger_->e("[proxy:client] [info] error processing: %s", e.what());
        }
    }
    auto newStatus = std::max(statusIpv4_, statusIpv6_);
    if (newStatus == NodeStatus::Connected) {
        if (oldStatus == NodeStatus::Disconnected || oldStatus == NodeStatus::Connecting) {
            listenerRestartTimer_->expires_at(std::chrono::steady_clock::now());
            listenerRestartTimer_->async_wait(std::bind(&DhtProxyClient::restartListeners, this));
        }
        nextProxyConfirmationTimer_->expires_at(std::chrono::steady_clock::now() + std::chrono::minutes(15));
        nextProxyConfirmationTimer_->async_wait(std::bind(&DhtProxyClient::handleProxyConfirm, this, std::placeholders::_1));
    }
    else if (newStatus == NodeStatus::Disconnected) {
        nextProxyConfirmationTimer_->expires_at(std::chrono::steady_clock::now() + std::chrono::minutes(1));
        nextProxyConfirmationTimer_->async_wait(std::bind(&DhtProxyClient::handleProxyConfirm, this, std::placeholders::_1));
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
DhtProxyClient::listen(const InfoHash& key, ValueCallback cb, Value::Filter filter, Where where)
{
    if (logger_)
        logger_->d("[proxy:client] [listen] [search %s]", key.to_c_str());

    auto& search = searches_[key];
    auto query = std::make_shared<Query>(Select{}, std::move(where));
    return search.ops.listen(cb, query, filter, [this, key](Sp<Query>, ValueCallback cb, SyncCallback) -> size_t {
        std::lock_guard<std::mutex> lock(searchLock_);
        // Find search
        auto search = searches_.find(key);
        if (search == searches_.end()) {
            if (logger_)
                logger_->e("[proxy:client] [listen] [search %s] search not found", key.to_c_str());
            return 0;
        }
        if (logger_)
            logger_->d("[proxy:client] [listen] [search %s] sending %s", key.to_c_str(),
                  deviceKey_.empty() ? "listen" : "subscribe");
        // Add listener
        auto token = ++listenerToken_;
        auto l = search->second.listeners.find(token);
        if (l == search->second.listeners.end()) {
            l = search->second.listeners.emplace(std::piecewise_construct,
                    std::forward_as_tuple(token),
                    std::forward_as_tuple(std::move(cb))).first;
        } else {
            if (l->second.opstate)
                l->second.opstate->stop = true;
        }
        // Add cache callback
        auto opstate = std::make_shared<OperationState>();
        l->second.opstate = opstate;
        l->second.cb = [this,key,token,opstate](const std::vector<Sp<Value>>& values, bool expired){
            if (opstate->stop)
                return false;
            std::lock_guard<std::mutex> lock(searchLock_);
            auto s = searches_.find(key);
            if (s != searches_.end()) {
                auto l = s->second.listeners.find(token);
                if (l != s->second.listeners.end()) {
                    return l->second.cache.onValue(values, expired);
                }
            }
            return false;
        };
        if (not deviceKey_.empty()) {
            /*
             * Relaunch push listeners even if a timeout is not received
             * (if the proxy crash for any reason)
             */
            if (!l->second.refreshSubscriberTimer)
                l->second.refreshSubscriberTimer = std::make_unique<asio::steady_timer>(httpContext_);
            l->second.refreshSubscriberTimer->expires_at(std::chrono::steady_clock::now() +
                                                         proxy::OP_TIMEOUT - proxy::OP_MARGIN);
            l->second.refreshSubscriberTimer->async_wait(std::bind(&DhtProxyClient::handleResubscribe, this,
                                                         std::placeholders::_1, key, token, opstate));
        }
        ListenMethod method;
        restinio::http_request_header_t header;
        if (deviceKey_.empty()){ // listen
            method = ListenMethod::LISTEN;
#ifdef OPENDHT_PROXY_HTTP_PARSER_FORK
            header.method(restinio::method_listen);
            header.request_target("/" + key.toString());
#else
            header.method(restinio::http_method_get());
            header.request_target("/key/" + key.toString() + "/listen");
#endif
        }
        else {
            method = ListenMethod::SUBSCRIBE;
            header.method(restinio::http_method_subscribe());
            header.request_target("/" + key.toString());
        }
        sendListen(header, l->second.cb, opstate, l->second, method);
        return token;
    });
}

void
DhtProxyClient::handleResubscribe(const asio::error_code &ec, const InfoHash& key,
                                  const size_t token, std::shared_ptr<OperationState> opstate)
{
    if (ec == asio::error::operation_aborted)
        return;
    else if (ec){
        if (logger_)
            logger_->e("[proxy:client] [resubscribe %s] %s", key.toString().c_str(), ec.message().c_str());
        return;
    }
    if (opstate->stop)
        return;
    std::lock_guard<std::mutex> lock(searchLock_);
    auto s = searches_.find(key);
    if (s != searches_.end()){
        auto l = s->second.listeners.find(token);
        if (l != s->second.listeners.end()) {
            resubscribe(key, token, l->second);
        }
        else {
            if (logger_)
                logger_->e("[proxy:client] [resubscribe %s] token not found", key.toString().c_str());
        }
    }
}

bool
DhtProxyClient::cancelListen(const InfoHash& key, size_t gtoken)
{
    if (logger_)
        logger_->d(key, "[proxy:client] [search %s] cancel listen %zu", key.to_c_str(), gtoken);

    std::lock_guard<std::mutex> lock(searchLock_);
    // find the listener in cache
    auto it = searches_.find(key);
    if (it == searches_.end())
        return false;
    auto& ops = it->second.ops;
    bool canceled = ops.cancelListen(gtoken, std::chrono::steady_clock::now());

    // define real cancel listen only once
    if (not it->second.opExpirationTimer)
        it->second.opExpirationTimer = std::make_unique<asio::steady_timer>(httpContext_, ops.getExpiration());
    else
        it->second.opExpirationTimer->expires_at(ops.getExpiration());
    it->second.opExpirationTimer->async_wait(std::bind(&DhtProxyClient::handleExpireListener, this, std::placeholders::_1, key));
    return canceled;
}

void
DhtProxyClient::handleExpireListener(const asio::error_code &ec, const InfoHash& key)
{
    if (ec == asio::error::operation_aborted)
        return;
    else if (ec){
        if (logger_)
            logger_->e("[proxy:client] [listen %s] error in cancel: %s", key.toString().c_str(), ec.message().c_str());
        return;
    }
    if (logger_)
        logger_->d("[proxy:client] [listen %s] expire listener", key.toString().c_str());

    std::lock_guard<std::mutex> lock(searchLock_);
    auto search = searches_.find(key);
    if (search == searches_.end())
        return;

    // everytime a new expiry is set, a previous gets aborted
    time_point next = search->second.ops.expire(std::chrono::steady_clock::now(), [&](size_t ltoken) {
        auto it = search->second.listeners.find(ltoken);
        if (it == search->second.listeners.end())
            return;

        auto& listener = it->second;
        listener.opstate->stop = true;

        if (not deviceKey_.empty()) {
            // UNSUBSCRIBE
            auto request = std::make_shared<http::Request>(httpContext_, resolver_, logger_);
            auto reqid = request->id();
            try {
                request->set_target("/" + key.toString());
                request->set_method(restinio::http_method_unsubscribe());
                setHeaderFields(request);

                Json::Value body;
                body["key"] = deviceKey_;
                body["client_id"] = pushClientId_;
                Json::StreamWriterBuilder wbuilder;
                wbuilder["commentStyle"] = "None";
                wbuilder["indentation"] = "";
                auto content = Json::writeString(wbuilder, body) + "\n";
                std::replace(content.begin(), content.end(), '\n', ' ');
                request->set_body(content);

                request->add_on_status_callback([this, key](unsigned int status_code){
                    if (status_code != 200)
                        if (logger_)
                            logger_->e("[proxy:client] [unsubscribe %s] failed with code=%i",
                                       key.to_c_str(), status_code);
                });
                request->add_on_state_change_callback([this, reqid, key]
                                                      (const http::Request::State state, const http::Response response){
                    if (state == http::Request::State::DONE){
                        if (response.status_code != 200)
                            if (logger_)
                                logger_->e("[proxy:client] [unsubscribe %s] failed with code=%i",
                                           key.to_c_str(), response.status_code);
                        requests_.erase(reqid);
                    }
                });
                if (serverCertificate_)
                    request->set_certificate(serverCertificate_);
                request->send();
                requests_[reqid] = request;
            }
            catch (const std::exception &e){
                if (logger_)
                     logger_->e("[proxy:client] [unsubscribe %s] failed: %s", key.to_c_str(), e.what());
                requests_.erase(reqid);
            }
        } else {
            // stop the request
            listener.request.reset();
        }
        search->second.listeners.erase(it);
        if (logger_)
            logger_->d("[proxy:client] [listen:cancel] [search %s] %zu listener remaining",
                    key.to_c_str(), search->second.listeners.size());
    });
    if (next != time_point::max()){
        search->second.opExpirationTimer->expires_at(next);
        search->second.opExpirationTimer->async_wait(std::bind(
            &DhtProxyClient::handleExpireListener, this, std::placeholders::_1, key));
    }
    if (search->second.listeners.empty()){
        searches_.erase(search);
    }
}

void
DhtProxyClient::sendListen(const restinio::http_request_header_t header,
                           const ValueCallback& cb,
                           const Sp<OperationState>& opstate,
                           Listener& listener, ListenMethod method)
{
    auto request = std::make_shared<http::Request>(httpContext_, resolver_, logger_);
    listener.request = request;
    auto reqid = request->id();
    try {
        request->set_header(header);
        setHeaderFields(request);
        if (method == ListenMethod::LISTEN)
            request->set_connection_type(restinio::http_connection_header_t::keep_alive);
        std::string body;
#ifdef OPENDHT_PUSH_NOTIFICATIONS
        if (method != ListenMethod::LISTEN)
            body = fillBody(method == ListenMethod::RESUBSCRIBE);
#endif
        request->set_body(body);

        request->add_on_status_callback([this, reqid, opstate](unsigned int status_code){
            if (status_code != 200){
                if (logger_)
                    logger_->e("[proxy:client] [listen] send request #%i status error: %i", reqid, status_code);
                opstate->ok.store(false);
            }
        });
        request->add_on_body_callback([this, reqid, opstate, cb](const char* at, size_t length){
            try {
                Json::CharReaderBuilder rbuilder;
                auto body = std::string(at, length);
                std::vector<dht::Sp<dht::Value>> values;
                // one value per body line
                std::string data_line;
                std::stringstream body_stream(body);
                while (std::getline(body_stream, data_line, '\n') and !opstate->stop){
                    std::string err;
                    Json::Value json;
                    auto* char_data = static_cast<const char*>(&data_line[0]);
                    auto reader = std::unique_ptr<Json::CharReader>(rbuilder.newCharReader());
                    if (!reader->parse(char_data, char_data + data_line.size(), &json, &err)){
                        opstate->ok.store(false);
                        return;
                    }
                    if (json.size() == 0){ // it's the end
                        opstate->stop.store(true);
                    }
                    auto value = std::make_shared<Value>(json);
                    if (cb){
                        auto expired = json.get("expired", Json::Value(false)).asBool();
                        {
                            std::lock_guard<std::mutex> lock(lockCallbacks_);
                            callbacks_.emplace_back([cb, value, opstate, expired]() {
                                if (not opstate->stop.load() and not cb({value}, expired))
                                    opstate->stop.store(true);
                            });
                        }
                        loopSignal_();
                    }
                }
            } catch(const std::exception& e) {
                if (logger_)
                    logger_->e("[proxy:client] [listen] request #%i error in parsing: %s", reqid, e.what());
                opstate->ok.store(false);
            }
        });
        request->add_on_state_change_callback([this, reqid]
                                              (const http::Request::State state, const http::Response response){
            if (state == http::Request::State::DONE){
                if (response.status_code != 200)
                    if (logger_)
                        logger_->e("[proxy:client] [listen] send request #%i failed with code=%i",
                                   reqid, response.status_code);
                requests_.erase(reqid);
            }
        });
        if (serverCertificate_)
            request->set_certificate(serverCertificate_);
        request->send();
        requests_[reqid] = request;
    }
    catch (const std::exception &e){
        if (logger_)
            logger_->e("[proxy:client] [listen] request #%i failed: %s", reqid, e.what());
        requests_.erase(reqid);
    }
}

void
DhtProxyClient::opFailed()
{
    if (logger_)
        logger_->e("[proxy:client] proxy request failed");
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
    if (logger_)
        logger_->d("[proxy:client] [connectivity] get status");
    if (!isDestroying_)
        getProxyInfos();
}

void
DhtProxyClient::restartListeners()
{
    if (isDestroying_)
        return;
    if (logger_)
        logger_->d("[proxy:client] [listeners] refresh permanent puts");

    std::lock_guard<std::mutex> lock(searchLock_);
    for (auto& search : searches_) {
        auto key = search.first;
        for (auto& put : search.second.puts) {
            if (!*put.second.ok) {
                auto ok = put.second.ok;
                doPut(key, put.second.value, [ok](bool result, const std::vector<std::shared_ptr<dht::Node>>&){
                    *ok = result;
                }, time_point::max(), true);
                if (!put.second.refreshPutTimer){
                    put.second.refreshPutTimer = std::make_unique<asio::steady_timer>(httpContext_);
                }
                put.second.refreshPutTimer->expires_at(std::chrono::steady_clock::now() +
                                                       proxy::OP_TIMEOUT - proxy::OP_MARGIN);
                put.second.refreshPutTimer->async_wait(std::bind(&DhtProxyClient::handleRefreshPut, this,
                                                       std::placeholders::_1, key, put.first, put.second.ok));
            }
        }
    }
    if (not deviceKey_.empty()) {
        if (logger_)
            logger_->d("[proxy:client] [listeners] resubscribe due to a connectivity change");
        // Connectivity changed, refresh all subscribe
        for (auto& search : searches_)
            for (auto& listener : search.second.listeners)
                if (!listener.second.opstate->ok)
                    resubscribe(search.first, listener.first, listener.second);
        return;
    }
    if (logger_)
        logger_->d("[proxy:client] [listeners] restarting listeners");
    for (auto& search: searches_) {
        for (auto& l: search.second.listeners) {
            auto& listener = l.second;
            if (auto opstate = listener.opstate)
                opstate->stop = true;
            listener.request->cancel();
            listener.request.reset();
        }
    }
    for (auto& search: searches_) {
        for (auto& l: search.second.listeners) {
            auto& listener = l.second;
            auto opstate = listener.opstate;
            // Redo listen
            opstate->stop.store(false);
            opstate->ok.store(true);
            auto cb = listener.cb;
            // define header
            restinio::http_request_header_t header;
#ifdef OPENDHT_PROXY_HTTP_PARSER_FORK
            header.method(restinio::method_listen);
            header.request_target("/" + search.first.toString());
#else
            header.method(restinio::http_method_get());
            header.request_target("/key/" + search.first.toString() + "/listen");
#endif
            sendListen(header, cb, opstate, listener, ListenMethod::LISTEN);
        }
    }
}

void
DhtProxyClient::pushNotificationReceived(const std::map<std::string, std::string>& notification)
{
#ifdef OPENDHT_PUSH_NOTIFICATIONS
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
                if (!put.refreshPutTimer)
                    put.refreshPutTimer = std::make_unique<asio::steady_timer>(httpContext_, std::chrono::steady_clock::now());
                else
                    put.refreshPutTimer->expires_at(std::chrono::steady_clock::now());
                put.refreshPutTimer->async_wait(std::bind(&DhtProxyClient::handleRefreshPut, this, std::placeholders::_1, key, vid, put.ok));
            } else {
                // Refresh listen
                for (auto& list : search.listeners)
                    resubscribe(key, list.first, list.second);
            }
        } else {
            auto key = InfoHash(notification.at("key"));
            auto& search = searches_.at(key);
            for (auto& list : search.listeners) {
                if (list.second.opstate->stop)
                    continue;
                if (logger_)
                    logger_->d("[proxy:client] [push] [search %s] received", key.to_c_str());
                auto expired = notification.find("exp");
                auto token = list.first;
                auto opstate = list.second.opstate;
                if (expired == notification.end()) {
                    auto cb = list.second.cb;
                    auto oldValues = list.second.cache.getValues();
                    get(key, [cb](const std::vector<Sp<Value>>& vals) {
                        return cb(vals, false);
                    }, [cb, oldValues](bool /*ok*/) {
                        // Decrement old values refcount to expire values not
                        // present in the new list
                        cb(oldValues, true);
                    });
                } else {
                    std::stringstream ss(expired->second);
                    std::vector<Value::Id> ids;
                    while(ss.good()){
                        std::string substr;
                        getline(ss, substr, ',');
                        ids.emplace_back(std::stoull(substr));
                    }
                    {
                        std::lock_guard<std::mutex> lock(lockCallbacks_);
                        callbacks_.emplace_back([this, key, token, opstate, ids]() {
                            if (opstate->stop)
                                return;
                            std::lock_guard<std::mutex> lock(searchLock_);
                            auto s = searches_.find(key);
                            if (s == searches_.end())
                                return;
                            auto l = s->second.listeners.find(token);
                            if (l == s->second.listeners.end())
                                return;
                            if (not opstate->stop and not l->second.cache.onValuesExpired(ids))
                                opstate->stop = true;
                        });
                    }
                    loopSignal_();
                }
            }
        }
    } catch (const std::exception& e) {
        if (logger_)
            logger_->e("[proxy:client] [push] receive error: %s", e.what());
    }
#else
    (void) notification;
#endif
}

void
DhtProxyClient::resubscribe(const InfoHash& key, const size_t token, Listener& listener)
{
#ifdef OPENDHT_PUSH_NOTIFICATIONS
    if (deviceKey_.empty())
        return;
    if (logger_)
        logger_->d("[proxy:client] [resubscribe] [search %s]", key.to_c_str());

    auto opstate = listener.opstate;
    opstate->stop = true;
    if (listener.request){
        listener.request.reset();
    }
    opstate.reset(new OperationState());

    restinio::http_request_header_t header;
    header.method(restinio::http_method_subscribe());
    header.request_target("/" + key.toString());
    if (!listener.refreshSubscriberTimer){
        listener.refreshSubscriberTimer = std::make_unique<asio::steady_timer>(httpContext_);
    }
    listener.refreshSubscriberTimer->expires_at(std::chrono::steady_clock::now() +
                                                proxy::OP_TIMEOUT - proxy::OP_MARGIN);
    listener.refreshSubscriberTimer->async_wait(std::bind(&DhtProxyClient::handleResubscribe, this,
                                                std::placeholders::_1, key, token, opstate));
    auto vcb = listener.cb;
    sendListen(header, vcb, opstate, listener, ListenMethod::RESUBSCRIBE);
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

std::string
DhtProxyClient::fillBody(bool resubscribe)
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
    return content;
}
#endif // OPENDHT_PUSH_NOTIFICATIONS

} // namespace dht
