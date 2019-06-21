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
    Listener(OpValueCache&& c, Value::Filter&& f):
        cache(std::move(c)), filter(std::move(f))
    {}

    uint16_t connId {0};
    unsigned callbackId;
    OpValueCache cache;
    ValueCallback cb;
    Value::Filter filter;
    Sp<ListenState> state;
    Sp<asio::steady_timer> refreshTimer;

};

struct PermanentPut {
    PermanentPut(const Sp<Value>& v, Sp<asio::steady_timer>&& j,
                 const Sp<std::atomic_bool>& o):
        value(v), refreshTimer(std::move(j)), ok(o)
    {}

    Sp<Value> value;
    Sp<asio::steady_timer> refreshTimer;
    Sp<std::atomic_bool> ok;
};

struct DhtProxyClient::ProxySearch {
    SearchCache ops {};
    Sp<asio::steady_timer> opExpirationTimer;
    std::map<size_t, Listener> listeners {};
    std::map<Value::Id, PermanentPut> puts {};
};

DhtProxyClient::DhtProxyClient() {}

DhtProxyClient::DhtProxyClient(std::function<void()> signal, const std::string &serverHost,
    const std::string &pushClientId, std::shared_ptr<dht::Logger> logger):
        serverHost_(serverHost), pushClientId_(pushClientId), loopSignal_(signal),
        logger_(logger)
{
    // build http client
    auto hostAndPort = splitPort(serverHost_);
    serverHostIp_ = hostAndPort.first;
    serverHostPort_ = std::atoi(hostAndPort.second.c_str());
    httpClient_ = std::make_unique<http::Client>(
        httpContext_, serverHostIp_, serverHostPort_, logger);
    // run http client
    httpClientThread_ = std::thread([this](){
        try {
            if (logger_)
                logger_->d("Starting the HTTP Client io_context");
            // Ensures the httpContext_ won't run out of work
            auto work = asio::make_work_guard(httpContext_);
            httpContext_.run();
            if (logger_)
                logger_->d("HTTP Client io_context stopped");
        }
        catch(const std::exception &ex){
            if (logger_)
                logger_->e("Error starting the HTTP Client io_context");
        }
    });

    if (serverHost_.find("://") == std::string::npos)
        serverHost_ = proxy::HTTP_PROTO + serverHost_;

    if (!serverHost_.empty())
        startProxy();
}

void
DhtProxyClient::confirmProxy()
{
    if (serverHost_.empty())
        return;
    getConnectivityStatus();
}

void
DhtProxyClient::startProxy()
{
    if (serverHost_.empty())
        return;

    if (logger_)
        logger_->w("Staring proxy client to %s", serverHost_.c_str());

    nextProxyConfirmationTimer_ = std::make_shared<asio::steady_timer>(
        periodicContext_, std::chrono::steady_clock::now());
    nextProxyConfirmationTimer_->async_wait(std::bind(&DhtProxyClient::confirmProxy, this));

    listenerRestartTimer_ = std::make_shared<asio::steady_timer>(periodicContext_);
    listenerRestartTimer_->async_wait(std::bind(&DhtProxyClient::restartListeners, this));

    loopSignal_();
}

DhtProxyClient::~DhtProxyClient()
{
    isDestroying_ = true;
    cancelAllOperations();
    cancelAllListeners();
    if (infoState_)
        infoState_->cancel = true;
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
        logger_->w("Cancelling all listeners for %zu searches", searches_.size());
    for (auto& s: searches_) {
        s.second.ops.cancelAll([&](size_t token){
            auto l = s.second.listeners.find(token);
            if (l == s.second.listeners.end())
                return;
            if (httpClient_->active_connection(l->second.connId)){
                l->second.state->cancel = true;
                try {
                    httpClient_->close_connection(l->second.connId);
                } catch (const std::exception& e) {
                    if (logger_)
                        logger_->w("Error closing socket: %s", e.what());
                }
                l->second.connId = 0;
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
    // Execute all HTTP opeations
    if (logger_)
        logger_->d("[periodic] running the io_context operations");
    periodicContext_.run();
    // Exec all currently stored callbacks
    if (logger_)
        logger_->d("[periodic] executing the stored callbacks");
    scheduler.syncTime();
    decltype(callbacks_) callbacks;
    {
        std::lock_guard<std::mutex> lock(lockCallbacks);
        callbacks = std::move(callbacks_);
    }
    for (auto& callback : callbacks)
        callback();
    callbacks.clear();

    return scheduler.run();
}

restinio::http_header_fields_t
DhtProxyClient::initHeaderFields(){
    restinio::http_header_fields_t header_fields;
    header_fields.append_field(restinio::http_field_t::host,
        (serverHostIp_ + ":" + std::to_string(serverHostPort_)).c_str());
    header_fields.append_field(restinio::http_field_t::user_agent, "RESTinio client");
    header_fields.append_field(restinio::http_field_t::accept, "*/*");
    header_fields.append_field(restinio::http_field_t::content_type, "application/json");
    return header_fields;
}

void
DhtProxyClient::get(const InfoHash& key, GetCallback cb, DoneCallback donecb,
                    Value::Filter&& f, Where&& w)
{
    if (logger_)
        logger_->d(key, "[search %s]: get", key.to_c_str());
    restinio::http_request_header_t header;
    header.request_target("/" + key.toString());
    header.method(restinio::http_method_get());
    auto header_fields = this->initHeaderFields();
    auto request = httpClient_->create_request(header, header_fields,
        restinio::http_connection_header_t::keep_alive, ""/*body*/);
    if (logger_)
        logger_->d(request.c_str());

    struct GetContext {
        GetCallback cb;
        DoneCallbackSimple donecb; // wrapper
        Value::Filter filter;
        std::atomic_bool ok {true};
        std::atomic_bool stop {false};
    };
    auto context = std::make_shared<GetContext>();
    context->filter = w.empty() ? f : f.chain(w.getFilter());
    context->cb = [this, context, cb]
        (const std::vector<dht::Sp<dht::Value>>& values) -> bool {
        {
            std::lock_guard<std::mutex> lock(lockCallbacks);
            callbacks_.emplace_back([context, cb, values](){
                if (not context->stop and not cb(values)){
                    context->stop = true;
                }
            });
        }
        loopSignal_();
        return context->ok;
    };
    // keeping context data alive
    context->donecb = [this, context, donecb](bool ok){
        std::lock_guard<std::mutex> lock(lockCallbacks);
        callbacks_.emplace_back([=](){
            donecb(context->ok, {});
            context->stop = true;
        });
    };

    auto parser = std::make_shared<http_parser>();
    http_parser_init(parser.get(), HTTP_RESPONSE);
    parser->data = static_cast<void*>(context.get());

    auto parser_s = std::make_shared<http_parser_settings>();
    http_parser_settings_init(parser_s.get());
    parser_s->on_status = [](http_parser *parser, const char *at, size_t length) -> int {
        auto context = static_cast<GetContext*>(parser->data);
        if (parser->status_code != 200){
            std::cerr << "Error in get status_code=" << parser->status_code << std::endl;
            context->ok = true;
        }
        return 0;
    };
    parser_s->on_body = [](http_parser *parser, const char *at, size_t length) -> int {
        auto context = static_cast<GetContext*>(parser->data);
        try{
            Json::Value json;
            std::string err;
            Json::CharReaderBuilder rbuilder;
            auto body = std::string(at, length);
            auto* char_data = static_cast<const char*>(&body[0]);
            auto reader = std::unique_ptr<Json::CharReader>(rbuilder.newCharReader());
            if (!reader->parse(char_data, char_data + body.size(), &json, &err)){
                context->ok = false;
                return 1;
            }
            auto value = std::make_shared<Value>(json);
            if ((not context->filter or context->filter(*value)) and context->cb){
                context->cb({value});
            }
        } catch(const std::exception& e) {
            std::cerr << "Error in get parsing: " << e.what() << std::endl;
            context->ok = false;
            return 1;
        }
        return 0;
    };
    parser_s->on_message_complete = [](http_parser *parser) -> int {
        auto context = static_cast<GetContext*>(parser->data);
        try {
            if (context->donecb)
                context->donecb(context->ok);
        } catch(const std::exception& e) {
            std::cerr << "Error in get parsing: " << e.what() << std::endl;
            return 1;
        }
        return 0;
    };
    httpClient_->post_request(request, parser, parser_s);
}

void
DhtProxyClient::put(const InfoHash& key, Sp<Value> val, DoneCallback cb,
                    time_point created, bool permanent)
{
    if (logger_)
        logger_->d(key, "[search %s]: put", key.to_c_str());
    if (not val){
        if (cb)
            cb(false, {});
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
        auto &search = searches_[key];
        auto refreshTimer = std::make_shared<asio::steady_timer>(periodicContext_,
            std::chrono::steady_clock::now() + proxy::OP_TIMEOUT - proxy::OP_MARGIN);
        auto ok = std::make_shared<std::atomic_bool>(false);
        // define refresh timer handler
        refreshTimer->async_wait([this, key, id, ok](const asio::error_code &ec){
            if (ec){
                if (logger_)
                    logger_->d("[listener:refresh] error key=%s", key.toString().c_str());
                return;
            }
            std::lock_guard<std::mutex> lock(searchLock_);
            auto s = searches_.find(key);
            if (s != searches_.end()) {
                auto p = s->second.puts.find(id);
                if (p != s->second.puts.end()) {
                    doPut(key, p->second.value, [ok]
                    (bool result, const std::vector<std::shared_ptr<dht::Node> >&){
                        *ok = result;
                    }, time_point::max(), true);
                    p->second.refreshTimer->expires_at(std::chrono::steady_clock::now() +
                        proxy::OP_TIMEOUT - proxy::OP_MARGIN);
                }
            }
        });
        search.puts.erase(id);
        search.puts.emplace(std::piecewise_construct,
            std::forward_as_tuple(id),
            std::forward_as_tuple(val, std::move(refreshTimer), ok));
    }
    doPut(key, val, std::move(cb), created, permanent);
}

void
DhtProxyClient::doPut(const InfoHash& key, Sp<Value> val, DoneCallback cb, time_point /*created*/, bool permanent)
{
    if (logger_)
        logger_->d(key, "[search %s] performing put of %s", key.to_c_str(), val->toString().c_str());
    restinio::http_request_header_t header;
    header.request_target("/" + key.toString());
    header.method(restinio::http_method_post());
    auto header_fields = this->initHeaderFields();

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
    auto request = httpClient_->create_request(header, header_fields,
        restinio::http_connection_header_t::close, body);
    if (logger_)
        logger_->d("%s", request.c_str());

    struct GetContext {
        DoneCallbackSimple donecb; // wrapper
        std::atomic_bool ok {false};
    };
    auto context = std::make_shared<GetContext>();
    // keeping context data alive
    context->donecb = [this, context, cb](bool ok){
        {
            std::lock_guard<std::mutex> lock(lockCallbacks);
            callbacks_.emplace_back([=](){
                cb(context->ok, {});
            });
        }
        loopSignal_();
    };

    auto parser = std::make_shared<http_parser>();
    http_parser_init(parser.get(), HTTP_RESPONSE);
    parser->data = static_cast<void*>(context.get());

    auto parser_s = std::make_shared<http_parser_settings>();
    http_parser_settings_init(parser_s.get());
    parser_s->on_status = [](http_parser *parser, const char *at, size_t length) -> int {
        GetContext* context = static_cast<GetContext*>(parser->data);
        if (parser->status_code == 200){
            context->ok = true;
        } else {
            std::cerr << "Error in get status_code=" << parser->status_code << std::endl;
        }
        return 0;
    };
    parser_s->on_message_complete = [](http_parser * parser) -> int {
        auto context = static_cast<GetContext*>(parser->data);
        try {
            if (context->donecb)
                context->donecb(context->ok);
        } catch(const std::exception& e) {
            std::cerr << "Error in get parsing: " << e.what() << std::endl;
            return 1;
        }
        return 0;
    };
    httpClient_->post_request(request, parser, parser_s);
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
        logger_->d(key, "[search %s] cancel put", key.to_c_str());
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
        logger_->d("Requesting proxy server node information");
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
        statusTimer_ = std::make_shared<asio::steady_timer>(periodicContext_);

    statusTimer_->async_wait(std::bind(&DhtProxyClient::handleProxyStatus, this,
        std::placeholders::_1, infoState));
    statusTimer_->expires_at(std::chrono::steady_clock::now());
}

void
DhtProxyClient::handleProxyStatus(const asio::error_code &ec,
                                  std::shared_ptr<InfoState> infoState)
{
    if (ec){
        if (logger_)
            logger_->e("[proxy:status] handling error: %s", ec.message().c_str());
        return;
    }
    auto serverHost = serverHost_;
    try {
        // A node can have a Ipv4 and a Ipv6. So, we need to retrieve all public ips
        auto endpointStr = serverHost;
        auto protocol = std::string(proxy::HTTP_PROTO);
        auto protocolIdx = serverHost.find("://");
        if (protocolIdx != std::string::npos) {
            protocol = endpointStr.substr(0, protocolIdx + 3);
            endpointStr = endpointStr.substr(protocolIdx + 3);
        }
        auto hostAndService = splitPort(endpointStr);
        auto resolvedProxies = SockAddr::resolve(hostAndService.first, hostAndService.second);

        for (const auto& resolvedProxy: resolvedProxies){
            auto server = resolvedProxy.toString();
            //if (resolvedProxy.getFamily() == AF_INET6) {
                // TODO verify with asio http class; if not, add handling there
                // HACK restbed seems to not correctly handle directly http://[ipv6]
                // See https://github.com/Corvusoft/restbed/issues/290.
                //server = endpointStr;
            // make an http header
            restinio::http_request_header_t header;
            header.request_target("/");
            header.method(restinio::http_method_get());
            auto header_fields = this->initHeaderFields();
            auto request = httpClient_->create_request(header, header_fields,
                restinio::http_connection_header_t::keep_alive, ""/*body*/);
            if (logger_)
                logger_->w(request.c_str());

            // initalise the parser callback data
            struct GetContext {
                std::atomic_bool ok {true};
                std::shared_ptr<InfoState> infoState;
                SockAddr resolvedProxy;
                std::function<void(const Json::Value&, sa_family_t)> proxyInfo;
            };
            auto context = std::make_shared<GetContext>();
            context->infoState = infoState;
            context->resolvedProxy = resolvedProxy;
            context->proxyInfo = std::bind(&DhtProxyClient::onProxyInfos, this,
                std::placeholders::_1, std::placeholders::_2);

            // initialize the parser
            auto parser = std::make_shared<http_parser>();
            http_parser_init(parser.get(), HTTP_RESPONSE);
            parser->data = static_cast<void*>(context.get());

            // init the parser callbacks
            auto parser_s = std::make_shared<http_parser_settings>();
            http_parser_settings_init(parser_s.get());
            parser_s->on_status = [](http_parser *parser, const char *at, size_t length) -> int {
                auto context = static_cast<GetContext*>(parser->data);
                if (parser->status_code != 200){
                    std::cerr << "Error in get status_code=" << parser->status_code << std::endl;
                    context->ok = true;
                }
                return 0;
            };
            parser_s->on_body = [](http_parser *parser, const char *at, size_t length) -> int {
                auto context = static_cast<GetContext*>(parser->data);
                try{
                    std::string err;
                    Json::Value proxyInfos;
                    Json::CharReaderBuilder rbuilder;
                    auto body = std::string(at, length);
                    auto* char_data = static_cast<const char*>(&body[0]);
                    auto reader = std::unique_ptr<Json::CharReader>(rbuilder.newCharReader());
                    if (!reader->parse(char_data, char_data + body.size(), &proxyInfos, &err)){
                        context->ok = false;
                        return 1;
                    }
                    auto family = context->resolvedProxy.getFamily();
                    if (family == AF_INET) 
                        context->infoState->ipv4++;
                    else if (family == AF_INET6)
                        context->infoState->ipv6++;
                    if (not context->infoState->cancel)
                        context->proxyInfo(proxyInfos, family);
                }
                catch (const std::exception& e) {
                    std::cerr << "Error in get parsing: " << e.what() << std::endl;
                    context->ok = false;
                    return 1;
                }
                return 0;
            };
            if (context->infoState->cancel)
                return;
            httpClient_->post_request(request, parser, parser_s);
        }
    }
    catch (const std::exception& e) {
        if (logger_)
            logger_->e("Error sending proxy info request: %s", e.what());
    }
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
        if (logger_)
            logger_->e("Proxy info request failed for %s", family == AF_INET ? "IPv4" : "IPv6");
        status = NodeStatus::Disconnected;
    } else {
        if (logger_)
            logger_->d("Got proxy reply for %s", family == AF_INET ? "IPv4" : "IPv6");
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
                logger_->w("Error processing proxy infos: %s", e.what());
        }
    }

    auto newStatus = std::max(statusIpv4_, statusIpv6_);
    if (newStatus == NodeStatus::Connected) {
        if (oldStatus == NodeStatus::Disconnected || oldStatus == NodeStatus::Connecting) {
            listenerRestartTimer_->expires_at(std::chrono::steady_clock::now());
        }
        nextProxyConfirmationTimer_->expires_at(std::chrono::steady_clock::now() +
            std::chrono::minutes(15));
    }
    else if (newStatus == NodeStatus::Disconnected) {
        nextProxyConfirmationTimer_->expires_at(std::chrono::steady_clock::now() +
            std::chrono::minutes(1));
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
    if (logger_)
        logger_->d(key, "[search %s]: listen", key.to_c_str());

    auto& search = searches_[key];
    auto query = std::make_shared<Query>(Select{}, where);
    auto token = search.ops.listen(cb, query, filter, [this, key, filter](
                                   Sp<Query>, ValueCallback cb, SyncCallback) -> size_t {
        std::lock_guard<std::mutex> lock(searchLock_);
        auto search = searches_.find(key);
        if (search == searches_.end()) {
            if (logger_)
                logger_->e(key, "[search %s] listen: search not found", key.to_c_str());
            return 0;
        }
        if (logger_)
            logger_->d("[search %s] sending %s", key.to_c_str(),
                  deviceKey_.empty() ? "listen" : "subscribe");

        auto token = ++listenerToken_;
        auto l = search->second.listeners.find(token);
        if (l == search->second.listeners.end()) {
            auto f = filter;
            l = search->second.listeners.emplace(std::piecewise_construct,
                    std::forward_as_tuple(token),
                    std::forward_as_tuple(std::move(cb), std::move(f))).first;
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

        if (not deviceKey_.empty()) {
            /*
             * Relaunch push listeners even if a timeout is not received
             * (if the proxy crash for any reason)
             */
            if (!l->second.refreshTimer)
                l->second.refreshTimer = std::make_shared<asio::steady_timer>(periodicContext_);
            l->second.refreshTimer->expires_at(std::chrono::steady_clock::now() +
                    proxy::OP_TIMEOUT - proxy::OP_MARGIN);
            l->second.refreshTimer->async_wait(
                [this, key, token, state](const asio::error_code &ec)
            {
                if (ec){
                    if (logger_)
                        logger_->d("[listener:refresh] error key=%s", key.toString().c_str());
                    return;
                }
                if (state->cancel)
                    return;
                std::lock_guard<std::mutex> lock(searchLock_);
                auto s = searches_.find(key);
                if (s != searches_.end()){
                    auto l = s->second.listeners.find(token);
                    if (l != s->second.listeners.end()) {
                        resubscribe(key, l->second);
                    }
                }
            });
        }
        ListenMethod method;
        restinio::http_request_header_t header;
        if (deviceKey_.empty()){ // listen
            method = ListenMethod::LISTEN;
            header.method(restinio::http_method_get());
            header.request_target("/" + key.toString() + "/listen");
        }
        else {
            method = ListenMethod::SUBSCRIBE;
            header.method(restinio::http_method_subscribe());
            header.request_target("/" + key.toString());
        }
        l->second.connId = sendListen(header, vcb, filter, state, method);
        return token;
    });
    return token;
}

bool
DhtProxyClient::cancelListen(const InfoHash& key, size_t gtoken) {
    scheduler.syncTime();
    if (logger_)
        logger_->d(key, "[search %s]: cancelListen %zu", key.to_c_str(), gtoken);
    auto it = searches_.find(key);
    if (it == searches_.end())
        return false;
    auto& ops = it->second.ops;
    bool canceled = ops.cancelListen(gtoken, std::chrono::steady_clock::now());
    if (not it->second.opExpirationTimer) {
        it->second.opExpirationTimer->expires_at(time_point::max());
        it->second.opExpirationTimer->async_wait([this, key](const asio::error_code ec){
            if (ec){
                if (logger_)
                    logger_->d("[liste::expiration] error key=%s", key.toString().c_str());
                return;
            }
            auto it = searches_.find(key);
            if (it != searches_.end()) {
                auto next = it->second.ops.expire(std::chrono::steady_clock::now(),
                                                 [this,key](size_t ltoken){
                    doCancelListen(key, ltoken);
                });
                if (next != time_point::max()) {
                    it->second.opExpirationTimer->expires_at(next);
                }
            }
        });
    }
    it->second.opExpirationTimer->expires_at(ops.getExpiration());
    loopSignal_();
    return canceled;
}

uint16_t
DhtProxyClient::sendListen(const restinio::http_request_header_t header,
                           const ValueCallback &cb, const Value::Filter &filter,
                           const Sp<ListenState> &state, ListenMethod method)
{
    auto headers = this->initHeaderFields();
    auto conn = restinio::http_connection_header_t::close;
    if (method == ListenMethod::LISTEN)
        conn = restinio::http_connection_header_t::keep_alive;
    std::string body;
#ifdef OPENDHT_PUSH_NOTIFICATIONS
    if (method != ListenMethod::LISTEN)
        body = fillBody(method == ListenMethod::RESUBSCRIBE);
#endif
    auto request = httpClient_->create_request(header, headers, conn, body);
    if (logger_)
        logger_->d(request.c_str());

    struct ListenContext {
        Logger *logger;
        ValueCallback cb; // wrapper
        Value::Filter filter;
        std::shared_ptr<ListenState> state;
    };
    auto context = std::make_shared<ListenContext>();
    if (logger_)
        context->logger = logger_.get();
    // keeping context data alive
    context->cb = [context, cb](const std::vector<std::shared_ptr<Value>>& values, bool expired){
        return cb(values, expired);
    };
    context->state = state;
    context->filter = filter;

    auto parser = std::make_shared<http_parser>();
    http_parser_init(parser.get(), HTTP_RESPONSE);
    parser->data = static_cast<void*>(context.get());

    auto parser_s = std::make_shared<http_parser_settings>();
    http_parser_settings_init(parser_s.get());
    parser_s->on_status = [](http_parser *parser, const char *at, size_t length) -> int {
        auto context = static_cast<ListenContext*>(parser->data);
        if (parser->status_code != 200){
            std::cerr << "Error in listen status_code=" << parser->status_code << std::endl;
            context->state->ok = false;
        }
        return 0;
    };
    parser_s->on_body = [](http_parser *parser, const char *at, size_t length) -> int {
        auto context = static_cast<ListenContext*>(parser->data);
        try {
            Json::Value json;
            std::string err;
            Json::CharReaderBuilder rbuilder;
            auto body = std::string(at, length);
            auto* char_data = static_cast<const char*>(&body[0]);
            auto reader = std::unique_ptr<Json::CharReader>(rbuilder.newCharReader());
            if (!reader->parse(char_data, char_data + body.size(), &json, &err)){
                context->state->ok = false;
                return 1;
            }
            if (json.size() == 0){ // it's the end
                context->state->cancel = true;
            }
            auto value = std::make_shared<Value>(json);
            auto expired = json.get("expired", Json::Value(false)).asBool();
            if ((not context->filter or context->filter(*value)) and context->cb){
                context->cb({value}, expired);
            }
        } catch(const std::exception& e) {
            if (context->logger)
                context->logger->e("Error in listen parsing: %s", e.what());
            context->state->ok = false;
            return 1;
        }
        return 0;
    };
    auto connId = httpClient_->post_request(request, parser, parser_s);
    return connId;
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

    if (logger_)
        logger_->d(key, "[search %s] cancel listen", key.to_c_str());

    auto& listener = it->second;
    listener.state->cancel = true;
    if (not deviceKey_.empty()) {
        // UNSUBSCRIBE
        restinio::http_request_header_t header;
        header.request_target("/" + key.toString());
        header.method(restinio::http_method_unsubscribe());
        auto header_fields = this->initHeaderFields();
        // fill request body
        Json::Value body;
        body["key"] = deviceKey_;
        body["client_id"] = pushClientId_;
        Json::StreamWriterBuilder wbuilder;
        wbuilder["commentStyle"] = "None";
        wbuilder["indentation"] = "";
        auto content = Json::writeString(wbuilder, body) + "\n";
        std::replace(content.begin(), content.end(), '\n', ' ');
        // build the request
        auto request = httpClient_->create_request(header, header_fields,
            restinio::http_connection_header_t::keep_alive, content);
        if (logger_)
            logger_->w(request.c_str());
        // define context
        struct UnsubscribeContext {
            InfoHash key;
        };
        auto context = std::make_shared<UnsubscribeContext>();
        context->key = key;
        // define parser
        auto parser = std::make_shared<http_parser>();
        http_parser_init(parser.get(), HTTP_RESPONSE);
        parser->data = static_cast<void*>(context.get());
        // define callbacks
        auto parser_s = std::make_shared<http_parser_settings>();
        http_parser_settings_init(parser_s.get());
        parser_s->on_status = [](http_parser *parser, const char *at, size_t length) -> int {
            auto context = static_cast<UnsubscribeContext*>(parser->data);
            if (parser->status_code != 200){
                std::cerr << "[search " << context->key.to_c_str() << "] " <<
                    "cancel listen failed status_code=" << parser->status_code << std::endl;
            }
            return 0;
        };
        httpClient_->post_request(request, parser, parser_s);
    } else {
        // Just stop the request
        if (httpClient_->active_connection(listener.connId)){
            try {
                httpClient_->close_connection(listener.connId);
            }
            catch (const std::exception& e){
                if (logger_)
                    logger_->w("Error closing socket: %s", e.what());
            }
        }
    }
    search->second.listeners.erase(it);
    if (logger_)
        logger_->d(key, "[search %s] cancelListen: %zu listener remaining",
                   key.to_c_str(), search->second.listeners.size());
    if (search->second.listeners.empty()){
        searches_.erase(search);
    }
    return true;
}

void
DhtProxyClient::opFailed()
{
    if (logger_)
        logger_->e("Proxy request failed");
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
    if (!isDestroying_)
        getProxyInfos();
}

void
DhtProxyClient::restartListeners()
{
    if (isDestroying_) return;
    std::lock_guard<std::mutex> lock(searchLock_);
    if (logger_)
        logger_->d("Refresh permanent puts");
    for (auto& search : searches_) {
        for (auto& put : search.second.puts) {
            if (!*put.second.ok) {
                auto ok = put.second.ok;
                doPut(search.first, put.second.value,
                [ok](bool result, const std::vector<std::shared_ptr<dht::Node> >&){
                    *ok = result;
                }, time_point::max(), true);
                put.second.refreshTimer->expires_at(std::chrono::steady_clock::now() +
                    proxy::OP_TIMEOUT - proxy::OP_MARGIN);
            }
        }
    }
    if (not deviceKey_.empty()) {
        if (logger_)
            logger_->d("resubscribe due to a connectivity change");
        // Connectivity changed, refresh all subscribe
        for (auto& search : searches_)
            for (auto& listener : search.second.listeners)
                if (!listener.second.state->ok)
                    resubscribe(search.first, listener.second);
        return;
    }
    if (logger_)
        logger_->d("Restarting listeners");
    for (auto& search: searches_) {
        for (auto& l: search.second.listeners) {
            auto& listener = l.second;
            if (auto state = listener.state)
                state->cancel = true;
            if (httpClient_->active_connection(listener.connId)){
                try {
                    httpClient_->close_connection(listener.connId);
                } catch (const std::exception& e) {
                    if (logger_)
                        logger_->w("Error closing socket: %s", e.what());
                }
                l.second.connId = 0;
            }
        }
    }
    for (auto& search: searches_) {
        for (auto& l: search.second.listeners) {
            auto& listener = l.second;
            auto state = listener.state;
            // Redo listen
            state->cancel = false;
            state->ok = true;
            auto filter = listener.filter;
            auto cb = listener.cb;
            // define header
            restinio::http_request_header_t header;
            header.method(restinio::http_method_get());
            header.request_target("/" + search.first.toString() + "/listen");
            // send listen
            listener.connId = sendListen(header, cb, filter, state, ListenMethod::LISTEN);
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
                put.refreshTimer->expires_at(std::chrono::steady_clock::now());
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
                if (logger_)
                    logger_->d(key, "[search %s] handling push notification", key.to_c_str());
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
                            if (state->cancel)
                                return;
                            std::lock_guard<std::mutex> lock(searchLock_);
                            auto s = searches_.find(key);
                            if (s == searches_.end())
                                return;
                            auto l = s->second.listeners.find(token);
                            if (l == s->second.listeners.end())
                                return;
                            if (not state->cancel and not l->second.cache.onValuesExpired(ids))
                                state->cancel = true;
                        });
                    }
                    loopSignal_();
                }
            }
        }
    } catch (const std::exception& e) {
        if (logger_)
            logger_->e("Error handling push notification: %s", e.what());
    }
#else
    (void) notification;
#endif
}

void
DhtProxyClient::resubscribe(const InfoHash& key, Listener& listener)
{
#ifdef OPENDHT_PUSH_NOTIFICATIONS
    if (deviceKey_.empty())
        return;
    scheduler.syncTime();
    if (logger_)
        logger_->d(key, "[search %s] resubscribe push listener", key.to_c_str());
    // Subscribe
    auto state = listener.state;
    state->cancel = true;
    if (listener.connId) {
        try {
            httpClient_->close_connection(listener.connId);
        } catch (const std::exception& e) {
            if (logger_)
                logger_->w("Error closing socket: %s", e.what());
        }
    }
    state->cancel = false;
    state->ok = true;

    restinio::http_request_header_t header;
    header.method(restinio::http_method_subscribe());
    header.request_target("/" + key.toString());
    listener.refreshTimer->expires_at(std::chrono::steady_clock::now() +
                                      proxy::OP_TIMEOUT - proxy::OP_MARGIN);
    auto vcb = listener.cb;
    auto filter = listener.filter;
    listener.connId = sendListen(header, vcb, filter, state, ListenMethod::RESUBSCRIBE);
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
