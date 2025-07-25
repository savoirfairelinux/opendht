/*
 *  Copyright (C) 2014-2025 Savoir-faire Linux Inc.
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

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include "dht_proxy_server.h"

#include "default_types.h"
#include "dhtrunner.h"

#include <msgpack.hpp>
#include <json/json.h>

#include <chrono>
#include <functional>
#include <limits>
#include <iostream>
#include <fstream>

using namespace std::placeholders;
using namespace std::chrono_literals;
using namespace std::literals;

namespace dht {
constexpr char RESP_MSG_JSON_INCORRECT[] = "{\"err:\":\"Incorrect JSON\"}";
constexpr char RESP_MSG_SERVICE_UNAVAILABLE[] = "{\"err\":\"Incorrect DhtRunner\"}";
constexpr char RESP_MSG_INTERNAL_SERVER_ERRROR[] = "{\"err\":\"Internal server error\"}";
constexpr char RESP_MSG_MISSING_PARAMS[] = "{\"err\":\"Missing parameters\"}";
constexpr char RESP_MSG_PUT_FAILED[] = "{\"err\":\"Put failed\"}";
#ifdef OPENDHT_PROXY_SERVER_IDENTITY
constexpr char RESP_MSG_DESTINATION_NOT_FOUND[] = "{\"err\":\"No destination found\"}";
#endif
#ifdef OPENDHT_PUSH_NOTIFICATIONS
constexpr char RESP_MSG_NO_TOKEN[] = "{\"err\":\"No token\"}";
#endif

constexpr const std::chrono::minutes PRINT_STATS_PERIOD {2};

using ResponseByParts = restinio::chunked_output_t;
using ResponseByPartsBuilder = restinio::response_builder_t<ResponseByParts>;

namespace http {
/**
 * Session value associated with a connection_id_t key.
 */
struct ListenerSession
{
    ListenerSession() = default;
    dht::InfoHash hash;
    std::future<size_t> token;
    std::shared_ptr<restinio::response_builder_t<restinio::chunked_output_t>> response;
};
}

class opendht_logger_t
{
public:
    opendht_logger_t(std::shared_ptr<Logger> logger = {}) : m_logger(std::move(logger)) {}

    template <typename Builder>
    void trace(Builder&& /* msg_builder */) {
        /* if (m_logger) m_logger->d("[proxy:server] %s", msg_builder().c_str()); */
    }

    template <typename Builder>
    void info(Builder&& msg_builder) {
        if (m_logger) m_logger->d("[proxy:server] %s", msg_builder().c_str());
    }

    template <typename Builder>
    void warn(Builder&& msg_builder) {
        if (m_logger) m_logger->w("[proxy:server] %s", msg_builder().c_str());
    }

    template <typename Builder>
    void error(Builder&& msg_builder) {
        if (m_logger) m_logger->e("[proxy:server] %s", msg_builder().c_str());
    }

private:
    std::shared_ptr<Logger> m_logger;
};


std::string
DhtProxyServer::ServerStats::toString() const
{
    auto ret = fmt::format("Listens: {}, Puts: {}, PushListeners: {}\n"
                "Push requests in the last {}: [Android: {}], [iOS: {}], [Unified: {}]\n"
                "Requests: {} per second.",
                listenCount, putCount, pushListenersCount,
                print_duration(lastUpdated - serverStartTime),
                androidPush.toString(), iosPush.toString(), unifiedPush.toString(),
                requestRate);
    if (nodeInfo) {
        auto& ipv4 = nodeInfo->ipv4;
        if (ipv4.table_depth > 1)
            ret += fmt::format("IPv4 Network estimation: {}\n", ipv4.getNetworkSizeEstimation());
        auto& ipv6 = nodeInfo->ipv6;
        if (ipv6.table_depth > 1)
            ret += fmt::format("IPv6 Network estimation: {}\n", ipv6.getNetworkSizeEstimation());
    }
    return ret;
}

Json::Value
DhtProxyServer::ServerStats::toJson() const
{
    Json::Value result;
    result["listenCount"] = static_cast<Json::UInt64>(listenCount);
    result["putCount"] = static_cast<Json::UInt64>(putCount);
    result["totalPermanentPuts"] = static_cast<Json::UInt64>(totalPermanentPuts);
    result["pushListenersCount"] = static_cast<Json::UInt64>(pushListenersCount);
    result["serverStartTime"] = static_cast<Json::LargestInt>(to_time_t(serverStartTime));
    result["lastUpdated"] = static_cast<Json::LargestInt>(to_time_t(lastUpdated));
    result["androidPush"] = androidPush.toJson();
    result["iosPush"] = iosPush.toJson();
    result["unifiedPush"] = unifiedPush.toJson();
    result["requestRate"] = requestRate;
    if (nodeInfo)
        result["nodeInfo"] = nodeInfo->toJson();
    return result;
}

restinio::request_handling_status_t
DhtProxyServer::serverError(restinio::request_t& request) {
    auto response = initHttpResponse(request.create_response(restinio::status_internal_server_error()));
    response.set_body(RESP_MSG_INTERNAL_SERVER_ERRROR);
    return response.done();
}

// connection listener

class DhtProxyServer::ConnectionListener
{
public:
    ConnectionListener() {};
    explicit ConnectionListener(std::function<void(restinio::connection_id_t)> onClosed) : onClosed_(std::move(onClosed)) {};
    ~ConnectionListener() {};

    /**
     * Connection state change used to handle Listeners disconnects.
     * RESTinio >= 0.5.1 https://github.com/Stiffstream/restinio/issues/28
     */
    void state_changed(const restinio::connection_state::notice_t& notice) noexcept;

private:
    std::function<void(restinio::connection_id_t)> onClosed_;
};

void
DhtProxyServer::ConnectionListener::state_changed(const restinio::connection_state::notice_t& notice) noexcept
{
    if (std::holds_alternative<restinio::connection_state::closed_t>(notice.cause())) {
        onClosed_(notice.connection_id());
    }
}

void
DhtProxyServer::onConnectionClosed(restinio::connection_id_t id)
{
    std::lock_guard<std::mutex> lock(lockListener_);
    auto it = listeners_.find(id);
    if (it != listeners_.end()) {
        dht_->cancelListen(it->second.hash, std::move(it->second.token));
        listeners_.erase(it);
        if (logger_)
            logger_->d("[proxy:server] [connection:%li] listener cancelled, %li still connected", id, listeners_.size());
    }
}

struct DhtProxyServer::RestRouterTraitsTls : public restinio::default_tls_traits_t
{
    using timer_manager_t = restinio::asio_timer_manager_t;
    using logger_t = opendht_logger_t;
    using request_handler_t = RestRouter;
    using connection_state_listener_t = ConnectionListener;
};
struct DhtProxyServer::RestRouterTraits : public restinio::default_traits_t
{
    using timer_manager_t = restinio::asio_timer_manager_t;
    using logger_t = opendht_logger_t;
    using request_handler_t = RestRouter;
    using connection_state_listener_t = ConnectionListener;
};

void
DhtProxyServer::PermanentPut::msgpack_unpack(const msgpack::object& o)
{
    if (auto cid = findMapValue(o, "cid"sv)) {
        clientId = cid->as<std::string>();
    }
    if (auto exp = findMapValue(o, "exp"sv)) {
        expiration = from_time_t(exp->as<time_t>());
    }
    if (auto token = findMapValue(o, "token"sv)) {
        pushToken = token->as<std::string>();
    }
    if (auto sid = findMapValue(o, "sid"sv)) {
        if (not sessionCtx)
            sessionCtx = std::make_shared<PushSessionContext>(sid->as<std::string>());
        else
            sessionCtx->sessionId = sid->as<std::string>();
    }
    if (auto t = findMapValue(o, "t"sv)) {
        type = t->as<PushType>();
    }
    if (auto val = findMapValue(o, "value"sv)) {
        value = std::make_shared<dht::Value>(*val);
    }
    if (auto top = findMapValue(o, "top"sv)) {
        topic = top->as<std::string>();
    }
}

#ifdef OPENDHT_PUSH_NOTIFICATIONS
void
DhtProxyServer::Listener::msgpack_unpack(const msgpack::object& o)
{
    if (auto cid = findMapValue(o, "cid"sv)) {
        clientId = cid->as<std::string>();
    }
    if (auto exp = findMapValue(o, "exp"sv)) {
        expiration = from_time_t(exp->as<time_t>());
    }
    if (auto sid = findMapValue(o, "sid"sv)) {
        if (not sessionCtx)
            sessionCtx = std::make_shared<PushSessionContext>(sid->as<std::string>());
        else
            sessionCtx->sessionId = sid->as<std::string>();
    }
    if (auto t = findMapValue(o, "t"sv)) {
        type = t->as<PushType>();
    }
    if (auto top = findMapValue(o, "top"sv)) {
        topic = top->as<std::string>();
    }
}
#endif

DhtProxyServer::DhtProxyServer(const std::shared_ptr<DhtRunner>& dht,
        const ProxyServerConfig& config,
        const std::shared_ptr<dht::Logger>& logger
)
    :   ioContext_(std::make_shared<asio::io_context>()),
        dht_(dht), persistPath_(config.persistStatePath), logger_(logger),
        printStatsTimer_(std::make_unique<asio::steady_timer>(*ioContext_, 3s)),
        serverStartTime_(clock::now()),
        connListener_(std::make_shared<ConnectionListener>(std::bind(&DhtProxyServer::onConnectionClosed, this, std::placeholders::_1))),
        pushServer_(config.pushServer),
        bundleId_(config.bundleId)
{
    if (not dht_)
        throw std::invalid_argument("A DHT instance must be provided");

    if (logger_)
        logger_->d("[proxy:server] [init] running on %i", config.port);
    if (not pushServer_.empty()){
#ifdef OPENDHT_PUSH_NOTIFICATIONS
        if (logger_)
            logger_->d("[proxy:server] [init] using push server %s", pushServer_.c_str());
#else
        if (logger_)
            logger_->e("[proxy:server] [init] opendht built without push notification support");
#endif
    }

    jsonBuilder_["commentStyle"] = "None";
    jsonBuilder_["indentation"] = "";

    if (!pushServer_.empty()){
        // no host delim, assume port only
        if (pushServer_.find(":") == std::string::npos)
            pushServer_ =  "localhost:" + pushServer_;
        // define http request destination for push notifications
        pushHostPort_ = splitPort(pushServer_);
        if (logger_)
            logger_->d("Using push server for notifications: %s:%s", pushHostPort_.first.c_str(),
                                                                     pushHostPort_.second.c_str());
    }
    if (config.identity.first and config.identity.second) {
        asio::error_code ec;
        // define tls context
        asio::ssl::context tls_context { asio::ssl::context::sslv23 };
        tls_context.set_options(asio::ssl::context::default_workarounds
                                | asio::ssl::context::no_sslv2
                                | asio::ssl::context::single_dh_use, ec);
        if (ec)
            throw std::runtime_error("Error setting tls context options: " + ec.message());
        // add more security options
#ifdef SSL_OP_NO_RENEGOTIATION
        SSL_CTX_set_options(tls_context.native_handle(), SSL_OP_NO_RENEGOTIATION); // CVE-2009-3555
#endif
        // node private key
        auto key = config.identity.first->serialize();
        tls_context.use_private_key(asio::const_buffer{key.data(), key.size()},
                                    asio::ssl::context::file_format::pem, ec);
        if (ec)
            throw std::runtime_error("Error setting node's private key: " + ec.message());
        // certificate chain
        auto certchain = config.identity.second->toString(true/*chain*/);
        tls_context.use_certificate_chain(asio::const_buffer{certchain.data(), certchain.size()}, ec);
        if (ec)
            throw std::runtime_error("Error setting certificate chain: " + ec.message());
        if (logger_)
            logger_->d("[proxy:server] using certificate chain for ssl:\n%s", certchain.c_str());
        // build http server
        auto settings = restinio::run_on_this_thread_settings_t<RestRouterTraitsTls>();
        addServerSettings(settings);
        if (not config.address.empty())
            settings.address(config.address);
        settings.port(config.port);
        settings.tls_context(std::move(tls_context));
        httpsServer_ = std::make_unique<restinio::http_server_t<RestRouterTraitsTls>>(
            ioContext_,
            std::forward<restinio::run_on_this_thread_settings_t<RestRouterTraitsTls>>(std::move(settings))
        );
        // run http server
        serverThread_ = std::thread([this]{
            httpsServer_->open_async([]{/*ok*/}, [](std::exception_ptr ex){
                std::rethrow_exception(ex);
            });
            httpsServer_->io_context().run();
        });
    }
    else {
        auto settings = restinio::run_on_this_thread_settings_t<RestRouterTraits>();
        addServerSettings(settings);
        if (not config.address.empty())
            settings.address(config.address);
        settings.port(config.port);
        httpServer_ = std::make_unique<restinio::http_server_t<RestRouterTraits>>(
            ioContext_,
            std::forward<restinio::run_on_this_thread_settings_t<RestRouterTraits>>(std::move(settings))
        );
        // run http server
        serverThread_ = std::thread([this](){
            httpServer_->open_async([]{/*ok*/}, [](std::exception_ptr ex){
                std::rethrow_exception(ex);
            });
            httpServer_->io_context().run();
        });
    }
    dht->forwardAllMessages(true);
    updateStats();
    printStatsTimer_->async_wait(std::bind(&DhtProxyServer::handlePrintStats, this, std::placeholders::_1));

    if (not persistPath_.empty()) {
        try {
            std::ifstream stateFile(persistPath_, std::ios::binary | std::ios::ate);
            if (stateFile) {
                std::streamsize size = stateFile.tellg();
                stateFile.seekg(0, std::ios::beg);
                if (logger_)
                    logger_->d("Loading proxy state from %.*s (%td bytes)", (int)persistPath_.size(), persistPath_.c_str(), size);
                loadState(stateFile, size);
            }
        } catch (const std::exception& e) {
            if (logger_)
                logger_->e("Error loading state from file: %s", e.what());
        }
    }
}

template <typename Os>
void
DhtProxyServer::saveState(Os& stream) {
    msgpack::packer<Os> pk(&stream);
    pk.pack_map(2);
    {
        std::lock_guard<std::mutex> lock(lockSearchPuts_);
        pk.pack("puts");
        pk.pack(puts_);
    }
#ifdef OPENDHT_PUSH_NOTIFICATIONS
    {
        std::lock_guard<std::mutex> lock(lockListener_);
        pk.pack("pushListeners");
        pk.pack(pushListeners_);
    }
#endif
}

template <typename Is>
void
DhtProxyServer::loadState(Is& is, size_t size) {
    msgpack::unpacker pac;
    pac.reserve_buffer(size);
    if (is.read(pac.buffer(), size)) {
        pac.buffer_consumed(size);

        msgpack::object_handle oh;
        while (pac.next(oh)) {
            if (oh.get().type != msgpack::type::MAP)
                continue;
            if (auto puts = findMapValue(oh.get(), "puts"sv)) {
                std::lock_guard<std::mutex> lock(lockSearchPuts_);
                puts_ = puts->as<decltype(puts_)>();
                if (logger_)
                    logger_->d("Loading %zu persistent puts", puts_.size());
                for (auto& put : puts_) {
                    for (auto& pput : put.second.puts) {
                        pput.second.expireTimer = std::make_unique<asio::steady_timer>(io_context(), pput.second.expiration);
                        pput.second.expireTimer->async_wait(std::bind(&DhtProxyServer::handleCancelPermamentPut, this,
                                                std::placeholders::_1, put.first, pput.first));
#ifdef OPENDHT_PUSH_NOTIFICATIONS
                        if (not pput.second.pushToken.empty()) {
                            auto jsonProvider = [infoHash=put.first.toString(), clientId=pput.second.clientId, vid = pput.first, sessionCtx = pput.second.sessionCtx](){
                                Json::Value json;
                                json["timeout"] = infoHash;
                                json["to"] = clientId;
                                json["vid"] = std::to_string(vid);
                                if (sessionCtx) {
                                    std::lock_guard<std::mutex> l(sessionCtx->lock);
                                    json["s"] = sessionCtx->sessionId;
                                }
                                return json;
                            };
                            pput.second.expireNotifyTimer = std::make_unique<asio::steady_timer>(io_context(), pput.second.expiration - proxy::OP_MARGIN);
                            pput.second.expireNotifyTimer->async_wait(std::bind(
                                &DhtProxyServer::handleNotifyPushListenExpire, this,
                                std::placeholders::_1, pput.second.pushToken, std::move(jsonProvider), pput.second.type, pput.second.topic));
                        }
#endif
                        dht_->put(put.first, pput.second.value, DoneCallbackSimple{}, time_point::max(), true);
                    }
                }
            } else {
                if (logger_)
                    logger_->d("No persistent puts in state");
            }
#ifdef OPENDHT_PUSH_NOTIFICATIONS
            if (auto pushListeners = findMapValue(oh.get(), "pushListeners"sv)) {
                std::lock_guard<std::mutex> lock(lockListener_);
                pushListeners_ = pushListeners->as<decltype(pushListeners_)>();
                if (logger_)
                    logger_->d("Loading %zu push listeners", pushListeners_.size());
                for (auto& pushListener : pushListeners_) {
                    for (auto& listeners : pushListener.second.listeners) {
                        for (auto& listener : listeners.second) {
                            // start listening
                            listener.internalToken = dht_->listen(listeners.first,
                                [this, infoHash=listeners.first, pushToken=pushListener.first, type=listener.type,
                                 clientId=listener.clientId, sessionCtx = listener.sessionCtx, topic=listener.topic]
                                (const std::vector<Sp<Value>>& values, bool expired) {
                                    return this->handlePushListen(infoHash, pushToken, type, clientId, sessionCtx, topic, values, expired);
                                }
                            );
                            // expire notify
                            listener.expireNotifyTimer = std::make_unique<asio::steady_timer>(io_context(), listener.expiration - proxy::OP_MARGIN);
                            auto jsonProvider = [infoHash = listeners.first.toString(), clientId = listener.clientId, sessionCtx = listener.sessionCtx](){
                                Json::Value json;
                                json["timeout"] = infoHash;
                                json["to"] = clientId;
                                std::lock_guard<std::mutex> l(sessionCtx->lock);
                                json["s"] = sessionCtx->sessionId;
                                return json;
                            };
                            listener.expireNotifyTimer->async_wait(std::bind(&DhtProxyServer::handleNotifyPushListenExpire, this,
                                                                std::placeholders::_1, pushListener.first, std::move(jsonProvider), listener.type, listener.topic));
                            // cancel push listen
                            listener.expireTimer = std::make_unique<asio::steady_timer>(io_context(), listener.expiration);
                            listener.expireTimer->async_wait(std::bind(&DhtProxyServer::handleCancelPushListen, this,
                                                            std::placeholders::_1, pushListener.first, listeners.first, listener.clientId));
                        }
                    }
                }
            } else {
                if (logger_)
                    logger_->d("No push listeners in state");
            }
#endif
        }
        if (logger_)
            logger_->d("loading ended");
    }
}


asio::io_context&
DhtProxyServer::io_context() const
{
    return *ioContext_;
}

DhtProxyServer::~DhtProxyServer()
{
    if (not persistPath_.empty()) {
        if (logger_)
            logger_->d("Saving proxy state to %.*s", (int)persistPath_.size(), persistPath_.c_str());
        std::ofstream stateFile(persistPath_, std::ios::binary);
        saveState(stateFile);
    }
    if (dht_) {
        std::lock_guard<std::mutex> lock(lockListener_);
        for (auto& l : listeners_) {
            dht_->cancelListen(l.second.hash, std::move(l.second.token));
            if (l.second.response)
                l.second.response->done();
        }
#ifdef OPENDHT_PUSH_NOTIFICATIONS
        for (auto& lm: pushListeners_)  {
            for (auto& ls: lm.second.listeners)
                for (auto& l : ls.second) {
                    if (l.expireNotifyTimer)
                        l.expireNotifyTimer->cancel();
                    if (l.expireTimer)
                        l.expireTimer->cancel();
                    dht_->cancelListen(ls.first, std::move(l.internalToken));
                }
        }
        pushListeners_.clear();
#endif
    }
    if (logger_)
        logger_->d("[proxy:server] closing http server");
    ioContext_->stop();
    if (serverThread_.joinable())
        serverThread_.join();
    if (logger_)
        logger_->d("[proxy:server] http server closed");
}

template< typename ServerSettings >
void
DhtProxyServer::addServerSettings(ServerSettings& settings, const unsigned int max_pipelined_requests)
{
    using namespace std::chrono;
    /**
     * If max_pipelined_requests is greater than 1 then RESTinio will continue
     * to read from the socket after parsing the first request.
     * In that case, RESTinio can detect the disconnection
     * and calls state listener as expected.
     * https://github.com/Stiffstream/restinio/issues/28
     */
    settings.max_pipelined_requests(max_pipelined_requests);
    // one less to detect the listener disconnect
    settings.concurrent_accepts_count(max_pipelined_requests - 1);
    settings.separate_accept_and_create_connect(true);
    settings.logger(logger_);
    settings.protocol(restinio::asio_ns::ip::tcp::v6());
    settings.request_handler(createRestRouter());
    // time limits                                              // ~ 0.8 month
    std::chrono::milliseconds timeout_request(std::numeric_limits<int>::max());
    settings.read_next_http_message_timelimit(timeout_request);
    settings.write_http_response_timelimit(60s);
    settings.handle_request_timeout(timeout_request);
    // socket options
    settings.socket_options_setter([](auto & options){
        options.set_option(asio::ip::tcp::no_delay{true});
        options.set_option(asio::socket_base::keep_alive{true});
    });
    settings.connection_state_listener(connListener_);
}

std::shared_ptr<DhtProxyServer::ServerStats>
DhtProxyServer::updateStats(std::shared_ptr<NodeInfo> info) const
{
    auto now = clock::now();
    auto last = lastStatsReset_.exchange(now);
    auto count = requestNum_.exchange(0);
    auto dt = std::chrono::duration<double>(now - last);
    auto sstats = std::make_shared<ServerStats>();
    auto& stats = *sstats;
    stats.requestRate = count / dt.count();
#ifdef OPENDHT_PUSH_NOTIFICATIONS
    stats.pushListenersCount = pushListeners_.size();
    {
        std::lock_guard lk(pushStatsMutex_);
        stats.androidPush = androidPush_;
        stats.iosPush = iosPush_;
        stats.unifiedPush = unifiedPush_;
    }
#endif
    stats.serverStartTime = serverStartTime_;
    stats.lastUpdated = now;
    stats.totalPermanentPuts = 0;
    std::for_each(puts_.begin(), puts_.end(), [&stats](const auto& put) {
        stats.totalPermanentPuts += put.second.puts.size();
    });
    stats.putCount = puts_.size();
    stats.listenCount = listeners_.size();
    stats.nodeInfo = std::move(info);
    return sstats;
}

void
DhtProxyServer::updateStats() {
    dht_->getNodeInfo([this](std::shared_ptr<NodeInfo> newInfo){
        stats_ = updateStats(newInfo);
        nodeInfo_ = newInfo;
        if (logger_) {
            auto str = Json::writeString(jsonBuilder_, newInfo->toJson());
            logger_->d("[proxy:server] [stats] %s", str.c_str());
        }
    });
}

void
DhtProxyServer::handlePrintStats(const asio::error_code &ec)
{
    if (ec == asio::error::operation_aborted)
        return;
    updateStats();
    printStatsTimer_->expires_at(printStatsTimer_->expiry() + PRINT_STATS_PERIOD);
    printStatsTimer_->async_wait(std::bind(&DhtProxyServer::handlePrintStats, this, std::placeholders::_1));
}

template <typename HttpResponse>
HttpResponse DhtProxyServer::initHttpResponse(HttpResponse response)
{
    response.append_header("Server", "RESTinio");
    response.append_header(restinio::http_field::content_type, "application/json");
    response.append_header(restinio::http_field::access_control_allow_origin, "*");
    return response;
}

std::unique_ptr<RestRouter>
DhtProxyServer::createRestRouter()
{
    using namespace std::placeholders;
    auto router = std::make_unique<RestRouter>();

    // **************************** LEGACY ROUTES ****************************
    // node.info
    router->http_get("/", std::bind(&DhtProxyServer::getNodeInfo, this, _1, _2));
    // key.options
    router->add_handler(restinio::http_method_options(),
                        "/:hash", std::bind(&DhtProxyServer::options, this, _1, _2));
    // key.get
    router->http_get("/:hash", std::bind(&DhtProxyServer::get, this, _1, _2));
    // key.post
    router->http_post("/:hash", std::bind(&DhtProxyServer::put, this, _1, _2));
#ifdef OPENDHT_PUSH_NOTIFICATIONS
    // key.subscribe
    router->add_handler(restinio::http_method_subscribe(),
                        "/:hash", std::bind(&DhtProxyServer::subscribe, this, _1, _2));
    // key.unsubscribe
    router->add_handler(restinio::http_method_unsubscribe(),
                        "/:hash", std::bind(&DhtProxyServer::unsubscribe, this, _1, _2));
#endif //OPENDHT_PUSH_NOTIFICATIONS
#ifdef OPENDHT_PROXY_SERVER_IDENTITY
#endif // OPENDHT_PROXY_SERVER_IDENTITY

    // **************************** NEW ROUTES ****************************
    // node.info
    router->http_get("/node/info", std::bind(&DhtProxyServer::getNodeInfo, this, _1, _2));
    // node.stats
    router->http_get("/node/stats", std::bind(&DhtProxyServer::getStats, this, _1, _2));
    // key.options
    router->http_get("/key/:hash/options", std::bind(&DhtProxyServer::options, this, _1, _2));
    // key.get
    router->http_get("/key/:hash", std::bind(&DhtProxyServer::get, this, _1, _2));
    // key.post
    router->http_post("/key/:hash", std::bind(&DhtProxyServer::put, this, _1, _2));
    router->add_handler(restinio::http_method_options(),
                        "/key/:hash/listen", std::bind(&DhtProxyServer::options, this, _1, _2));
    // key.listen
    router->http_get("/key/:hash/listen", std::bind(&DhtProxyServer::listen, this, _1, _2));
#ifdef OPENDHT_PUSH_NOTIFICATIONS
    // node.pingPush
    router->http_post("/node/pingPush", std::bind(&DhtProxyServer::pingPush, this, _1, _2));
    // key.subscribe
    router->add_handler(restinio::http_method_subscribe(),
                        "/key/:hash", std::bind(&DhtProxyServer::subscribe, this, _1, _2));
    // key.unsubscribe
    router->add_handler(restinio::http_method_unsubscribe(),
                        "/key/:hash", std::bind(&DhtProxyServer::unsubscribe, this, _1, _2));
#endif //OPENDHT_PUSH_NOTIFICATIONS
#ifdef OPENDHT_PROXY_SERVER_IDENTITY
    // key.sign
    router->http_post("/key/:hash/sign", std::bind(&DhtProxyServer::putSigned, this, _1, _2));
    // key.encrypt
    router->http_post("/key/:hash/encrypt", std::bind(&DhtProxyServer::putEncrypted, this, _1, _2));
#endif // OPENDHT_PROXY_SERVER_IDENTITY

    return router;
}

RequestStatus
DhtProxyServer::getNodeInfo(restinio::request_handle_t request,
                            restinio::router::route_params_t /*params*/) const
{
    try {
        if (auto nodeInfo = nodeInfo_) {
            auto result = nodeInfo->toJson();
            // [ipv6:ipv4]:port or ipv4:port
            result["public_ip"] = request->remote_endpoint().address().to_string();
            auto response = initHttpResponse(request->create_response());
            response.append_body(Json::writeString(jsonBuilder_, result) + "\n");
            return response.done();
        }
        auto response = initHttpResponse(request->create_response(restinio::status_service_unavailable()));
        response.set_body(RESP_MSG_SERVICE_UNAVAILABLE);
        return response.done();
    } catch (...) {
        return serverError(*request);
    }
}

RequestStatus
DhtProxyServer::getStats(restinio::request_handle_t request,
                         restinio::router::route_params_t /*params*/)
{
    requestNum_++;
    try {
        if (auto stats = stats_) {
            auto response = initHttpResponse(request->create_response());
            response.append_body(Json::writeString(jsonBuilder_, stats->toJson()) + "\n");
            return response.done();
        } else {
            auto response = initHttpResponse(request->create_response(restinio::status_service_unavailable()));
            response.set_body(RESP_MSG_SERVICE_UNAVAILABLE);
            return response.done();
        }
    } catch (...){
        return serverError(*request);
    }
}

RequestStatus
DhtProxyServer::get(restinio::request_handle_t request,
                    restinio::router::route_params_t params)
{
    requestNum_++;
    try {
        InfoHash infoHash(params["hash"]);
        if (!infoHash)
            infoHash = InfoHash::get(params["hash"]);
        auto response = std::make_shared<ResponseByPartsBuilder>(
            initHttpResponse(request->create_response<ResponseByParts>()));
        response->flush();
        dht_->get(infoHash, [this, response](const std::vector<Sp<Value>>& values) {
            std::ostringstream output;
            for (const auto& value : values) {
                output << Json::writeString(jsonBuilder_, value->toJson()) << "\n";
            }
            response->append_chunk(output.str());
            response->flush();
            return true;
        },
        [response] (bool /*ok*/){
            response->done();
        });
        return restinio::request_handling_status_t::accepted;
    } catch (const std::exception& e){
        return serverError(*request);
    }
}

RequestStatus
DhtProxyServer::listen(restinio::request_handle_t request,
                       restinio::router::route_params_t params)
{
    requestNum_++;

    try {
        InfoHash infoHash(params["hash"]);
        if (!infoHash)
            infoHash = InfoHash::get(params["hash"]);
        auto response = std::make_shared<ResponseByPartsBuilder>(
            initHttpResponse(request->create_response<ResponseByParts>()));
        response->flush();
        std::lock_guard<std::mutex> lock(lockListener_);
        // save the listener to handle a disconnect
        auto &session = listeners_[request->connection_id()];
        session.hash = infoHash;
        session.response = response;
        session.token = dht_->listen(infoHash, [this, response]
                (const std::vector<Sp<Value>>& values, bool expired){
            for (const auto& value: values){
                auto jsonVal = value->toJson();
                if (expired)
                    jsonVal["expired"] = true;
                response->append_chunk(Json::writeString(jsonBuilder_, jsonVal) + "\n");
            }
            response->flush();
            return true;
        });
        return restinio::request_handling_status_t::accepted;
    } catch (const std::exception& e){
        return serverError(*request);
    }
}

#ifdef OPENDHT_PUSH_NOTIFICATIONS

PushType
DhtProxyServer::getTypeFromString(const std::string& type) {
    if (type == "android")
        return PushType::Android;
    else if (type == "ios")
        return PushType::iOS;
    else if (type == "unifiedpush")
        return PushType::UnifiedPush;
    return PushType::None;
}

std::string
DhtProxyServer::getDefaultTopic(PushType) {
    return bundleId_;
}

RequestStatus
DhtProxyServer::pingPush(restinio::request_handle_t request,
                         restinio::router::route_params_t /*params*/)
{
    requestNum_++;
    try {
        std::string err;
        Json::Value r;
        auto* char_data = reinterpret_cast<const char*>(request->body().data());
        auto reader = std::unique_ptr<Json::CharReader>(jsonReaderBuilder_.newCharReader());
        if (!reader->parse(char_data, char_data + request->body().size(), &r, &err)){
            auto response = initHttpResponse(request->create_response(restinio::status_bad_request()));
            response.set_body(RESP_MSG_JSON_INCORRECT);
            return response.done();
        }
        const Json::Value& root(r); // parse using const Json so [] never creates element
        auto pushToken = root["key"].asString();
        if (pushToken.empty()){
            auto response = initHttpResponse(request->create_response(restinio::status_bad_request()));
            response.set_body(RESP_MSG_NO_TOKEN);
            return response.done();
        }
        auto type = getTypeFromString(root["platform"].asString());
        auto topic = root["topic"].asString();
        if (topic.empty()) {
            topic = getDefaultTopic(type);
        }
        Json::Value json;
        json["to"] = root["client_id"];
        json["pong"] = true;
        sendPushNotification(pushToken, std::move(json), type, true, topic);
    } catch (...) {
        return serverError(*request);
    }
    return restinio::request_handling_status_t::accepted;
}

RequestStatus
DhtProxyServer::subscribe(restinio::request_handle_t request,
                          restinio::router::route_params_t params)
{
    requestNum_++;
    try {
        InfoHash infoHash(params["hash"]);
        if (!infoHash)
            infoHash = InfoHash::get(params["hash"]);

        std::string err;
        Json::Value r;
        auto* char_data = reinterpret_cast<const char*>(request->body().data());
        auto reader = std::unique_ptr<Json::CharReader>(jsonReaderBuilder_.newCharReader());
        if (!reader->parse(char_data, char_data + request->body().size(), &r, &err)){
            auto response = initHttpResponse(request->create_response(restinio::status_bad_request()));
            response.set_body(RESP_MSG_JSON_INCORRECT);
            return response.done();
        }
        const Json::Value& root(r); // parse using const Json so [] never creates element
        auto pushToken = root["key"].asString();
        if (pushToken.empty()){
            auto response = initHttpResponse(request->create_response(restinio::status_bad_request()));
            response.set_body(RESP_MSG_NO_TOKEN);
            return response.done();
        }
        auto type = getTypeFromString(root["platform"].asString());
        auto topic = root["topic"].asString();
        if (topic.empty()) {
            topic = getDefaultTopic(type);
        }
        auto clientId = root["client_id"].asString();
        auto sessionId = root["session_id"].asString();

        if (logger_)
            logger_->d("[proxy:server] [subscribe %s] [client %s] [session %s]", infoHash.toString().c_str(), clientId.c_str(), sessionId.c_str());

        // Insert new or return existing push listeners of a token
        std::lock_guard<std::mutex> lock(lockListener_);
        auto& pushListener = pushListeners_[pushToken];
        auto& pushListeners = pushListener.listeners[infoHash];

        auto listIt = std::find_if(pushListeners.begin(), pushListeners.end(), [&](const Listener& l) {
            return l.clientId == clientId;
        });
        bool newListener = listIt == pushListeners.end();
        if (newListener) {
            pushListeners.emplace_back(Listener{});
            listIt = std::prev(pushListeners.end());
            listIt->clientId = clientId;
            listIt->sessionCtx = std::make_shared<PushSessionContext>(sessionId);
        } else {
            std::lock_guard<std::mutex> l(listIt->sessionCtx->lock);
            listIt->sessionCtx->sessionId = sessionId;
        }
        auto& listener = *listIt;

        // Expiration
        auto timeout = std::chrono::steady_clock::now() + proxy::OP_TIMEOUT;
        listener.expiration = timeout;
        listener.type = type;
        listener.topic = topic;
        if (listener.expireNotifyTimer)
            listener.expireNotifyTimer->expires_at(timeout - proxy::OP_MARGIN);
        else
            listener.expireNotifyTimer = std::make_unique<asio::steady_timer>(io_context(), timeout - proxy::OP_MARGIN);
        auto jsonProvider = [h=infoHash.toString(), clientId, sessionCtx = listener.sessionCtx](){
            Json::Value json;
            json["timeout"] = h;
            json["to"] = clientId;
            std::lock_guard<std::mutex> l(sessionCtx->lock);
            json["s"] = sessionCtx->sessionId;
            return json;
        };
        listener.expireNotifyTimer->async_wait(std::bind(&DhtProxyServer::handleNotifyPushListenExpire, this,
                                               std::placeholders::_1, pushToken, std::move(jsonProvider), listener.type, listener.topic));
        if (!listener.expireTimer)
            listener.expireTimer = std::make_unique<asio::steady_timer>(io_context(), timeout);
        else
            listener.expireTimer->expires_at(timeout);
        listener.expireTimer->async_wait(std::bind(&DhtProxyServer::handleCancelPushListen, this,
                                        std::placeholders::_1, pushToken, infoHash, clientId));

        // Send response
        if (not newListener) {
            if (logger_)
                logger_->d("[proxy:server] [subscribe %s] found [client %s]", infoHash.toString().c_str(), listener.clientId.c_str());
            // Send response header
            auto response = std::make_shared<ResponseByPartsBuilder>(initHttpResponse(request->create_response<ResponseByParts>()));
            response->flush();
            if (!root["refresh"].asBool()) {
                // No Refresh
                dht_->get(infoHash, [this, response](const Sp<Value>& value) {
                    auto output = Json::writeString(jsonBuilder_, value->toJson()) + "\n";
                    response->append_chunk(output);
                    response->flush();
                    return true;
                },
                [response] (bool){
                    response->done();
                });
            } else {
                // Refresh
                response->append_chunk("{}\n");
                return response->done();
            }
        } else {
            // =========== No existing listener for an infoHash ============
            // Add listen on dht
            if (logger_)
                logger_->d("[proxy:server] [subscribe %s] new", infoHash.toString().c_str());
            listener.internalToken = dht_->listen(infoHash,
                [this, infoHash, pushToken, type, clientId, sessionCtx = listener.sessionCtx, topic]
                (const std::vector<Sp<Value>>& values, bool expired) {
                    return this->handlePushListen(infoHash, pushToken, type, clientId, sessionCtx, topic, values, expired);
                }
            );
            // Send response header
            auto response = initHttpResponse(request->create_response());
            response.set_body("{}\n");
            return response.done();
        }
    }
    catch (...) {
        return serverError(*request);
    }
    return restinio::request_handling_status_t::accepted;
}

RequestStatus
DhtProxyServer::unsubscribe(restinio::request_handle_t request,
                            restinio::router::route_params_t params)
{
    requestNum_++;

    InfoHash infoHash(params["hash"]);
    if (!infoHash)
        infoHash = InfoHash::get(params["hash"]);

    if (logger_)
        logger_->d("[proxy:server] [unsubscribe %s]", infoHash.toString().c_str());

    try {
        std::string err;
        Json::Value root;
        auto* char_data = reinterpret_cast<const char*>(request->body().data());
        auto reader = std::unique_ptr<Json::CharReader>(jsonReaderBuilder_.newCharReader());

        if (!reader->parse(char_data, char_data + request->body().size(), &root, &err)){
            auto response = initHttpResponse(
                request->create_response(restinio::status_bad_request()));
            response.set_body(RESP_MSG_JSON_INCORRECT);
            return response.done();
        }
        auto pushToken = root["key"].asString();
        if (pushToken.empty())
            return restinio::request_handling_status_t::rejected;
        auto clientId = root["client_id"].asString();

        handleCancelPushListen(asio::error_code() /*success*/, pushToken, infoHash, clientId);
        auto response = initHttpResponse(request->create_response());
        return response.done();
    }
    catch (...) {
        return serverError(*request);
    }
}

void
DhtProxyServer::handleNotifyPushListenExpire(const asio::error_code &ec, const std::string pushToken,
                                             std::function<Json::Value()> jsonProvider, PushType type, const std::string& topic)
{
    if (ec == asio::error::operation_aborted)
        return;
    else if (ec) {
        if (logger_)
            logger_->e("[proxy:server] [subscribe] error sending put refresh: %s", ec.message().c_str());
    }
    if (logger_)
        logger_->d("[proxy:server] [subscribe] sending refresh to %s token", pushToken.c_str());
    sendPushNotification(pushToken, jsonProvider(), type, false, topic);
}

void
DhtProxyServer::handleCancelPushListen(const asio::error_code &ec, const std::string pushToken,
                                       const InfoHash key, const std::string clientId)
{
    if (ec == asio::error::operation_aborted)
        return;
    else if (ec){
        if (logger_)
            logger_->e("[proxy:server] [listen:push %s] error cancel: %s",
                        key.toString().c_str(), ec.message().c_str());
    }
    if (logger_)
        logger_->d("[proxy:server] [listen:push %s] cancelled for %s",
                   key.toString().c_str(), clientId.c_str());
    std::lock_guard<std::mutex> lock(lockListener_);

    auto pushListener = pushListeners_.find(pushToken);
    if (pushListener == pushListeners_.end())
        return;
    auto listeners = pushListener->second.listeners.find(key);
    if (listeners == pushListener->second.listeners.end())
        return;

    for (auto listener = listeners->second.begin(); listener != listeners->second.end();){
        if (listener->clientId == clientId){
            if (dht_)
                dht_->cancelListen(key, std::move(listener->internalToken));
            listener = listeners->second.erase(listener);
        } else {
            ++listener;
        }
    }
    if (listeners->second.empty())
        pushListener->second.listeners.erase(listeners);
    if (pushListener->second.listeners.empty())
        pushListeners_.erase(pushListener);
}

bool
DhtProxyServer::handlePushListen(const InfoHash& infoHash, const std::string& pushToken, PushType type, const std::string& clientId,
                                 const std::shared_ptr<DhtProxyServer::PushSessionContext>& sessionCtx, const std::string& topic,
                                 const std::vector<std::shared_ptr<Value>>& values, bool expired)
{
    Json::Value json;
    json["key"] = infoHash.toString();
    json["to"] = clientId;
    using namespace std::chrono;
    json["t"] = Json::Value::Int64(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());

    {
        std::lock_guard<std::mutex> l(sessionCtx->lock);
        json["s"] = sessionCtx->sessionId;
    }

    // Build a comma-separated list of ids from the values. This is intended to be used when
    // streaming from the iOS notification extension in order to filter out unwanted values.
    std::string ids;
    for(const auto& value : values) {
        if (!ids.empty()) ids += ",";
        ids += std::to_string(value->id);
    }
    json["ids"] = ids;

    // If message is expired copy the value ID to the `exp` field.
    // This is presumably used by the Android notification system.
    if (expired && values.size() < 2) {
        json["exp"] = json["ids"];
    }

    auto minPriority = 1000u;
    for (const auto& v : values)
        minPriority = std::min(minPriority, v->priority);

    if (logger_)
        logger_->d("[proxy:server] [listen %s] [client %s] [session %s] [expired %i] [priority %i] [values %zu]",
                   infoHash.toString().c_str(), clientId.c_str(), sessionCtx->sessionId.c_str(), expired, minPriority, values.size());

    sendPushNotification(pushToken, std::move(json), type, !expired and minPriority == 0, topic);

    return true;
}

void
DhtProxyServer::sendPushNotification(const std::string& token, Json::Value&& json, PushType type, bool highPriority, const std::string& topic)
{
    if (pushServer_.empty() && type != PushType::UnifiedPush)
        return;

    unsigned reqid = 0;
    try {
        std::shared_ptr<http::Request> request;
        http::Url tokenUrl(token);
        if (type == PushType::UnifiedPush)
            request = std::make_shared<http::Request>(io_context(), tokenUrl.protocol + "://" + tokenUrl.host + (tokenUrl.service.empty() ? "" : (":" + tokenUrl.service)), logger_);
        else
            request = std::make_shared<http::Request>(io_context(), pushHostPort_.first, pushHostPort_.second, pushHostPort_.first.find("https://") == 0, logger_);;
        reqid = request->id();
        request->set_target(type == PushType::UnifiedPush ? (tokenUrl.target) : "/api/push");
        request->set_method(restinio::http_method_post());
        request->set_header_field(restinio::http_field_t::host, type == PushType::UnifiedPush ? tokenUrl.host.c_str() : pushServer_.c_str());
        request->set_header_field(restinio::http_field_t::user_agent, "RESTinio client");
        request->set_header_field(restinio::http_field_t::accept, "*/*");
        request->set_header_field(restinio::http_field_t::content_type, "application/json");

        if (type == PushType::UnifiedPush) {
            Json::Value notification(Json::objectValue);
            notification["message"] = Json::writeString(jsonBuilder_, std::move(json));
            notification["topic"] = token;
            notification["priority"] = highPriority ? 5 : 1;
            request->set_body(Json::writeString(jsonBuilder_, std::move(json)));
        } else {
            // NOTE: see https://github.com/appleboy/gorush
            auto isResubscribe = json.isMember("timeout");
            Json::Value notification(Json::objectValue);
            Json::Value tokens(Json::arrayValue);
            tokens[0] = token;
            notification["tokens"] = std::move(tokens);
            notification["platform"] = type == PushType::Android ? 2 : 1;
            notification["data"] = std::move(json);
            auto priority = highPriority ? "high" : "normal";
            if (type == PushType::Android) {
                Json::Value androidConfig(Json::objectValue);
                androidConfig["priority"] = priority;
                androidConfig["ttl"] = "86400s"; // time to live = 24 hours
                notification["android"] = std::move(androidConfig);
            } else {
                notification["priority"] = priority;
                const auto expiration = std::chrono::system_clock::now() + std::chrono::hours(24);
                uint32_t exp = std::chrono::duration_cast<std::chrono::seconds>(expiration.time_since_epoch()).count();
                notification["expiration"] = exp;
                if (!topic.empty())
                    notification["topic"] = topic;
                if (highPriority || isResubscribe) {
                    Json::Value alert(Json::objectValue);
                    alert["title"]="hello";
                    notification["push_type"] = "alert";
                    notification["alert"] = alert;
                    notification["mutable_content"] = true;
                    notification["priority"] = "high";
                } else {
                    notification["push_type"] = "background";
                    notification["content_available"] = true;
                }
            }

            Json::Value notifications(Json::arrayValue);
            notifications[0] = notification;

            Json::Value content;
            content["notifications"] = std::move(notifications);
            request->set_body(Json::writeString(jsonBuilder_, content));
        }

        request->add_on_state_change_callback([this, reqid]
                                              (http::Request::State state, const http::Response& response){
            if (state == http::Request::State::DONE){
                if (logger_ and response.status_code != 200)
                    logger_->e("[proxy:server] [notification] push failed: %i", response.status_code);
                std::lock_guard<std::mutex> l(requestLock_);
                requests_.erase(reqid);
            }
        });
        {
            std::lock_guard<std::mutex> l(requestLock_);
            requests_[reqid] = request;
        }
        request->send();
        // For monitoring purposes
        std::lock_guard lk(pushStatsMutex_);
        switch (type) {
        case PushType::Android:
            androidPush_.increment(highPriority);
            break;
        case PushType::iOS:
            iosPush_.increment(highPriority);
            break;
        case PushType::UnifiedPush:
            unifiedPush_.increment(highPriority);
            break;
        default:
            break;
        }
    }
    catch (const std::exception &e){
        if (logger_)
            logger_->e("[proxy:server] [notification] error send push: %s", e.what());
        if (reqid) {
            std::lock_guard<std::mutex> l(requestLock_);
            requests_.erase(reqid);
        }
    }
}

#endif //OPENDHT_PUSH_NOTIFICATIONS

void
DhtProxyServer::handleCancelPermamentPut(const asio::error_code &ec, const InfoHash& key, Value::Id vid)
{
    if (ec == asio::error::operation_aborted)
        return;
    else if (ec){
        if (logger_)
            logger_->e("[proxy:server] [put:permament] error sending put refresh: %s", ec.message().c_str());
    }
    if (logger_)
        logger_->d("[proxy:server] [put %s] cancel permament put %i", key.toString().c_str(), vid);
    std::lock_guard<std::mutex> lock(lockSearchPuts_);
    auto sPuts = puts_.find(key);
    if (sPuts == puts_.end())
        return;
    auto& sPutsMap = sPuts->second.puts;
    auto put = sPutsMap.find(vid);
    if (put == sPutsMap.end())
        return;
    if (dht_)
        dht_->cancelPut(key, vid);
    if (put->second.expireTimer)
        put->second.expireTimer->cancel();
    if (put->second.expireNotifyTimer)
        put->second.expireNotifyTimer->cancel();
    sPutsMap.erase(put);
    if (sPutsMap.empty())
        puts_.erase(sPuts);
}

RequestStatus
DhtProxyServer::put(restinio::request_handle_t request,
                    restinio::router::route_params_t params)
{
    requestNum_++;
    InfoHash infoHash(params["hash"]);
    if (!infoHash)
        infoHash = InfoHash::get(params["hash"]);

    if (request->body().empty()){
        auto response = initHttpResponse(request->create_response(restinio::status_bad_request()));
        response.set_body(RESP_MSG_MISSING_PARAMS);
        return response.done();
    }

    try {
        std::string err;
        Json::Value root;
        auto* char_data = reinterpret_cast<const char*>(request->body().data());
        auto reader = std::unique_ptr<Json::CharReader>(jsonReaderBuilder_.newCharReader());

        if (reader->parse(char_data, char_data + request->body().size(), &root, &err)){
            auto value = std::make_shared<Value>(root);
            bool permanent = root.isMember("permanent");
            if (logger_)
                logger_->d("[proxy:server] [put %s] %s %s", infoHash.toString().c_str(),
                          value->toString().c_str(), (permanent ? "permanent" : ""));
            if (permanent) {
                std::string pushToken, clientId, sessionId, platform, topic;
                auto& pVal = root["permanent"];
                if (pVal.isObject()){
                    pushToken = pVal["key"].asString();
                    clientId = pVal["client_id"].asString();
                    platform = pVal["platform"].asString();
                    sessionId = pVal["session_id"].asString();
                    topic = pVal["topic"].asString();
                }
                std::lock_guard<std::mutex> lock(lockSearchPuts_);
                auto timeout = std::chrono::steady_clock::now() + proxy::OP_TIMEOUT;
                auto& sPuts = puts_[infoHash];
                if (value->id == Value::INVALID_ID) {
                    for (auto& pp : sPuts.puts) {
                        if (pp.second.pushToken == pushToken
                            and pp.second.clientId == clientId
                            and pp.second.value->contentEquals(*value))
                        {
                            pp.second.expireTimer->expires_at(timeout);
                            pp.second.expireTimer->async_wait(std::bind(&DhtProxyServer::handleCancelPermamentPut, this,
                                                        std::placeholders::_1, infoHash, pp.second.value->id));
                            if (not sessionId.empty()) {
                                if (not pp.second.sessionCtx)
                                    pp.second.sessionCtx = std::make_shared<PushSessionContext>(sessionId);
                                else {
                                    std::lock_guard<std::mutex> l(pp.second.sessionCtx->lock);
                                    pp.second.sessionCtx->sessionId = sessionId;
                                }
                            }
                            auto response = initHttpResponse(request->create_response());
                            response.append_body(Json::writeString(jsonBuilder_, pp.second.value->toJson()) + "\n");
                            return response.done();
                        }
                    }
                    value->id = std::uniform_int_distribution<Value::Id>{1}(rd);
                }

                auto vid = value->id;
                auto& pput = sPuts.puts[vid];
                pput.value = value;
                pput.expiration = timeout;
                if (not pput.expireTimer) {
                    // cancel permanent put
                    pput.expireTimer = std::make_unique<asio::steady_timer>(io_context(), timeout);
#ifdef OPENDHT_PUSH_NOTIFICATIONS
                    if (not pushToken.empty()) {
                        pput.pushToken = pushToken;
                        pput.clientId = clientId;
                        pput.type = getTypeFromString(platform);
                        if (topic.empty())
                            topic = getDefaultTopic(pput.type);
                        pput.topic = topic;
                        pput.sessionCtx = std::make_shared<PushSessionContext>(sessionId);
                    }
#endif
                } else {
                    if (not sessionId.empty()) {
                        if (not pput.sessionCtx)
                            pput.sessionCtx = std::make_shared<PushSessionContext>(sessionId);
                        else {
                            std::lock_guard<std::mutex> l(pput.sessionCtx->lock);
                            pput.sessionCtx->sessionId = sessionId;
                        }
                    }
                    pput.expireTimer->expires_at(timeout);
                }
                pput.expireTimer->async_wait(std::bind(&DhtProxyServer::handleCancelPermamentPut, this,
                                                std::placeholders::_1, infoHash, vid));

#ifdef OPENDHT_PUSH_NOTIFICATIONS
                // notify put permanent expiration
                if (pput.sessionCtx) {
                    auto jsonProvider = [infoHash, clientId, vid, sessionCtx = pput.sessionCtx](){
                        Json::Value json;
                        json["timeout"] = infoHash.toString();
                        json["to"] = clientId;
                        json["vid"] = std::to_string(vid);
                        std::lock_guard<std::mutex> l(sessionCtx->lock);
                        json["s"] = sessionCtx->sessionId;
                        return json;
                    };
                    if (!pput.expireNotifyTimer)
                        pput.expireNotifyTimer = std::make_unique<asio::steady_timer>(io_context(),
                                                    timeout - proxy::OP_MARGIN);
                    else
                        pput.expireNotifyTimer->expires_at(timeout - proxy::OP_MARGIN);
                    pput.expireNotifyTimer->async_wait(std::bind(
                        &DhtProxyServer::handleNotifyPushListenExpire, this,
                        std::placeholders::_1, pushToken, std::move(jsonProvider), pput.type, pput.topic));
                }
#endif
            }

            dht_->put(infoHash, value, [this, request, value](bool ok){
                if (ok){
                    auto response = initHttpResponse(request->create_response());
                    response.append_body(Json::writeString(jsonBuilder_, value->toJson()) + "\n");
                    response.done();
                } else {
                    auto response = initHttpResponse(request->create_response(restinio::status_bad_gateway()));
                    response.set_body(RESP_MSG_PUT_FAILED);
                    response.done();
                }
            }, time_point::max(), permanent);
            return restinio::request_handling_status_t::accepted;
        } else {
            auto response = initHttpResponse(request->create_response(restinio::status_bad_request()));
            response.set_body(RESP_MSG_JSON_INCORRECT);
            return response.done();
        }
    } catch (const std::exception& e){
        if (logger_)
            logger_->d("[proxy:server] error in put: %s", e.what());
        return serverError(*request);
    }
}

#ifdef OPENDHT_PROXY_SERVER_IDENTITY

RequestStatus
DhtProxyServer::putSigned(restinio::request_handle_t request,
                          restinio::router::route_params_t params) const
{
    requestNum_++;
    InfoHash infoHash(params["hash"]);
    if (!infoHash)
        infoHash = InfoHash::get(params["hash"]);

    if (request->body().empty()){
        auto response = initHttpResponse(request->create_response(restinio::status_bad_request()));
        response.set_body(RESP_MSG_MISSING_PARAMS);
        return response.done();
    }

    try {
        std::string err;
        Json::Value root;
        auto* char_data = reinterpret_cast<const char*>(request->body().data());
        auto reader = std::unique_ptr<Json::CharReader>(jsonReaderBuilder_.newCharReader());

        if (reader->parse(char_data, char_data + request->body().size(), &root, &err)){

            auto value = std::make_shared<Value>(root);

            dht_->putSigned(infoHash, value, [this, request, value](bool ok){
                if (ok){
                    auto output = Json::writeString(jsonBuilder_, value->toJson()) + "\n";
                    auto response = initHttpResponse(request->create_response());
                    response.append_body(output);
                    response.done();
                } else {
                    auto response = initHttpResponse(request->create_response(restinio::status_bad_gateway()));
                    response.set_body(RESP_MSG_PUT_FAILED);
                    response.done();
                }
            });
            return restinio::request_handling_status_t::accepted;
        } else {
            auto response = initHttpResponse(request->create_response(restinio::status_bad_request()));
            response.set_body(RESP_MSG_JSON_INCORRECT);
            return response.done();
        }
    } catch (const std::exception& e){
        if (logger_)
            logger_->d("[proxy:server] error in putSigned: %s", e.what());
        return serverError(*request);
    }
}

RequestStatus
DhtProxyServer::putEncrypted(restinio::request_handle_t request,
                             restinio::router::route_params_t params)
{
    requestNum_++;
    InfoHash infoHash(params["hash"]);
    if (!infoHash)
        infoHash = InfoHash::get(params["hash"]);

    if (request->body().empty()){
        auto response = initHttpResponse(request->create_response(restinio::status_bad_request()));
        response.set_body(RESP_MSG_MISSING_PARAMS);
        return response.done();
    }

    try {
        std::string err;
        Json::Value root;
        auto* char_data = reinterpret_cast<const char*>(request->body().data());
        auto reader = std::unique_ptr<Json::CharReader>(jsonReaderBuilder_.newCharReader());

        if (reader->parse(char_data, char_data + request->body().size(), &root, &err)){
            InfoHash to(root["to"].asString());
            if (!to){
                auto response = initHttpResponse(request->create_response(restinio::status_bad_request()));
                response.set_body(RESP_MSG_DESTINATION_NOT_FOUND);
                return response.done();
            }
            auto value = std::make_shared<Value>(root);
            dht_->putEncrypted(infoHash, to, value, [this, request, value](bool ok){
                if (ok){
                    auto response = initHttpResponse(request->create_response());
                    response.append_body(Json::writeString(jsonBuilder_, value->toJson()) + "\n");
                    response.done();
                } else {
                    auto response = initHttpResponse(request->create_response(restinio::status_bad_gateway()));
                    response.set_body(RESP_MSG_PUT_FAILED);
                    response.done();
                }
            });
            return restinio::request_handling_status_t::accepted;
        } else {
            auto response = initHttpResponse(request->create_response(restinio::status_bad_request()));
            response.set_body(RESP_MSG_JSON_INCORRECT);
            return response.done();
        }
    } catch (const std::exception& e){
        if (logger_)
            logger_->d("[proxy:server] error in put: %s", e.what());
        return serverError(*request);
    }
}

#endif // OPENDHT_PROXY_SERVER_IDENTITY

RequestStatus
DhtProxyServer::options(restinio::request_handle_t request,
                        restinio::router::route_params_t /*params*/)
{
    requestNum_++;
#ifdef OPENDHT_PROXY_SERVER_IDENTITY
    const auto methods = "OPTIONS, GET, POST, LISTEN, SIGN, ENCRYPT";
#else
    const auto methods = "OPTIONS, GET, POST, LISTEN";
#endif
    auto response = initHttpResponse(request->create_response());
    response.append_header(restinio::http_field::access_control_allow_methods, methods);
    response.append_header(restinio::http_field::access_control_allow_headers, "content-type");
    response.append_header(restinio::http_field::access_control_max_age, "86400");
    return response.done();
}

RequestStatus
DhtProxyServer::getFiltered(restinio::request_handle_t request,
                            restinio::router::route_params_t params)
{
    requestNum_++;
    auto query = params["value"];
    InfoHash infoHash(params["hash"]);
    if (!infoHash)
        infoHash = InfoHash::get(params["hash"]);

    try {
        auto response = std::make_shared<ResponseByPartsBuilder>(
            initHttpResponse(request->create_response<ResponseByParts>()));
        response->flush();
        dht_->get(infoHash,
            [this, response](const Sp<Value>& value) {
                response->append_chunk(Json::writeString(jsonBuilder_, value->toJson()) + "\n");
                response->flush();
                return true;
            },
            [response] (bool /*ok*/){
                response->done();
            },
            {}, query);
        return restinio::request_handling_status_t::accepted;
    } catch (const std::exception& e){
        return serverError(*request);
    }
}

}
