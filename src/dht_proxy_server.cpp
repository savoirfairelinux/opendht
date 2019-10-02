/*
 *  Copyright (C) 2017-2019 Savoir-faire Linux Inc.
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

#include "dht_proxy_server.h"

#include "default_types.h"
#include "dhtrunner.h"

#include <msgpack.hpp>
#include <json/json.h>

#include <chrono>
#include <functional>
#include <limits>
#include <iostream>

using namespace std::placeholders;

#ifdef OPENDHT_PROXY_HTTP_PARSER_FORK
namespace restinio {
struct custom_http_methods_t
{
    static constexpr restinio::http_method_id_t from_nodejs(int m) noexcept {
        if(m == method_listen.raw_id())
            return method_listen;
        else if(m == method_stats.raw_id())
            return method_stats;
        else if(m == method_sign.raw_id())
            return method_sign;
        else if(m == method_encrypt.raw_id())
            return method_encrypt;
        else
            return restinio::default_http_methods_t::from_nodejs(m);
    }
};
}
#endif

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

class opendht_logger_t
{
public:
    opendht_logger_t(std::shared_ptr<dht::Logger> logger = {}){
        if (logger)
            m_logger = logger;
    }

    template <typename Builder>
    void trace(Builder && msg_builder){
        if (m_logger)
            m_logger->d("[proxy:server] %s", msg_builder().c_str());
    }

    template <typename Builder>
    void info(Builder && msg_builder){
        if (m_logger)
            m_logger->d("[proxy:server] %s", msg_builder().c_str());
    }

    template <typename Builder>
    void warn(Builder && msg_builder){
        if (m_logger)
            m_logger->w("[proxy:server] %s", msg_builder().c_str());
    }

    template <typename Builder>
    void error(Builder && msg_builder){
        if (m_logger)
            m_logger->e("[proxy:server] %s", msg_builder().c_str());
    }

private:
    std::shared_ptr<dht::Logger> m_logger;
};

// connection listener

class DhtProxyServer::ConnectionListener
{
public:
    ConnectionListener() {};
    ConnectionListener(std::shared_ptr<dht::DhtRunner> dht,
        std::shared_ptr<std::map<restinio::connection_id_t, http::ListenerSession>> listeners,
        std::shared_ptr<std::mutex> lock, std::shared_ptr<dht::Logger> logger):
        dht_(dht), lock_(lock), listeners_(listeners), logger_(logger) {};
    ~ConnectionListener() {};

    /**
     * Connection state change used to handle Listeners disconnects.
     * RESTinio >= 0.5.1 https://github.com/Stiffstream/restinio/issues/28
     */
    void state_changed(const restinio::connection_state::notice_t& notice) noexcept;

private:
    std::string to_str( restinio::connection_state::cause_t cause ) noexcept;

    std::shared_ptr<dht::DhtRunner> dht_;
    std::shared_ptr<std::mutex> lock_;
    std::shared_ptr<std::map<restinio::connection_id_t, http::ListenerSession>> listeners_;

    std::shared_ptr<dht::Logger> logger_;
};

void
DhtProxyServer::ConnectionListener::state_changed(const restinio::connection_state::notice_t& notice) noexcept
{
    std::lock_guard<std::mutex> lock(*lock_);
    auto id = notice.connection_id();
    auto cause = to_str(notice.cause());

    if (listeners_->find(id) != listeners_->end()){
        if (notice.cause() == restinio::connection_state::cause_t::closed){
            if (logger_)
                logger_->d("[proxy:server] [connection:%li] cancelling listener", id);
            dht_->cancelListen(listeners_->at(id).hash,
                               std::move(listeners_->at(id).token));
            listeners_->erase(id);
            if (logger_)
                logger_->d("[proxy:server] %li listeners are connected", listeners_->size());
        }
    }
}

std::string
DhtProxyServer::ConnectionListener::to_str(restinio::connection_state::cause_t cause) noexcept
{
    std::string result;
    switch(cause)
    {
    case restinio::connection_state::cause_t::accepted:
        result = "accepted";
        break;
    case restinio::connection_state::cause_t::closed:
        result = "closed";
        break;
    case restinio::connection_state::cause_t::upgraded_to_websocket:
        result = "upgraded";
        break;
    default:
        result = "unknown";
    }
    return result;
}

struct DhtProxyServer::RestRouterTraitsTls : public restinio::default_tls_traits_t
{
    using timer_manager_t = restinio::asio_timer_manager_t;
#ifdef OPENDHT_PROXY_HTTP_PARSER_FORK
    using http_methods_mapper_t = restinio::custom_http_methods_t;
#endif
    using logger_t = opendht_logger_t;
    using request_handler_t = RestRouter;
    using connection_state_listener_t = ConnectionListener;
};
struct DhtProxyServer::RestRouterTraits : public restinio::default_traits_t
{
    using timer_manager_t = restinio::asio_timer_manager_t;
#ifdef OPENDHT_PROXY_HTTP_PARSER_FORK
    using http_methods_mapper_t = restinio::custom_http_methods_t;
#endif
    using logger_t = opendht_logger_t;
    using request_handler_t = RestRouter;
    using connection_state_listener_t = ConnectionListener;
};

DhtProxyServer::DhtProxyServer(
    dht::crypto::Identity identity,
    std::shared_ptr<DhtRunner> dht, in_port_t port, const std::string& pushServer,
    std::shared_ptr<dht::Logger> logger
)
    :   dht_(dht), logger_(logger), lockListener_(std::make_shared<std::mutex>()),
        listeners_(std::make_shared<std::map<restinio::connection_id_t, http::ListenerSession>>()),
        connListener_(std::make_shared<ConnectionListener>(dht, listeners_, lockListener_, logger)),
        pushServer_(pushServer)
{
    if (not dht_)
        throw std::invalid_argument("A DHT instance must be provided");

    if (logger_)
        logger_->d("[proxy:server] [init] running on %i", port);
    if (not pushServer.empty()){
#ifdef OPENDHT_PUSH_NOTIFICATIONS
        if (logger_)
            logger_->d("[proxy:server] [init] using push server %s", pushServer.c_str());
#else
        if (logger_)
            logger_->e("[proxy:server] [init] opendht built without push notification support");
#endif
    }

    jsonBuilder_["commentStyle"] = "None";
    jsonBuilder_["indentation"] = "";

    if (!pushServer.empty()){
        // no host delim, assume port only
        if (pushServer.find(":") == std::string::npos)
            pushServer_ =  "localhost:" + pushServer_;
        // define http request destination for push notifications
        pushHostPort_ = splitPort(pushServer_);
        if (logger_)
            logger_->d("Using push server for notifications: %s:%s", pushHostPort_.first.c_str(),
                                                                     pushHostPort_.second.c_str());
    }
    if (identity.first and identity.second) {
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
        server_key_ = identity.first->serialize();
        tls_context.use_private_key(asio::const_buffer{server_key_.data(), server_key_.size()},
                                    asio::ssl::context::file_format::pem, ec);
        if (ec)
            throw std::runtime_error("Error setting node's private key: " + ec.message());
        // certificate chain
        server_certchain_ = identity.second->toString(true/*chain*/);
        tls_context.use_certificate_chain(asio::const_buffer{server_certchain_.data(), server_certchain_.size()}, ec);
        if (ec)
            throw std::runtime_error("Error setting certificate chain: " + ec.message());
        if (logger_)
            logger_->d("[proxy:server] using certificate chain for ssl:\n%s", server_certchain_.c_str());
        // build http server
        auto settings = restinio::run_on_this_thread_settings_t<RestRouterTraitsTls>();
        addServerSettings(settings);
        settings.port(port);
        settings.tls_context(std::move(tls_context));
        httpsServer_ = std::make_unique<restinio::http_server_t<RestRouterTraitsTls>>(
            restinio::own_io_context(),
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
        settings.port(port);
        httpServer_ = std::make_unique<restinio::http_server_t<RestRouterTraits>>(
            restinio::own_io_context(),
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

    printStatsTimer_ = std::make_unique<asio::steady_timer>(io_context(), PRINT_STATS_PERIOD);
    printStatsTimer_->async_wait(std::bind(&DhtProxyServer::handlePrintStats, this, std::placeholders::_1));
}


asio::io_context&
DhtProxyServer::io_context() const
{
    if (httpsServer_)
        return httpsServer_->io_context();
    else if (httpServer_)
        return httpServer_->io_context();
    throw std::runtime_error("No available server");
}

DhtProxyServer::~DhtProxyServer()
{
    if (logger_)
        logger_->d("[proxy:server] closing http server");
    if (httpServer_)
        httpServer_->io_context().stop();
    if (httpsServer_)
        httpsServer_->io_context().stop();
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
    });
    settings.connection_state_listener(connListener_);
}

void
DhtProxyServer::updateStats() const
{
    auto now = clock::now();
    auto last = lastStatsReset_.exchange(now);
    auto count = requestNum_.exchange(0);
    auto dt = std::chrono::duration<double>(now - last);
    stats_.requestRate = count / dt.count();
#ifdef OPENDHT_PUSH_NOTIFICATIONS
    stats_.pushListenersCount = pushListeners_.size();
#endif
    stats_.putCount = puts_.size();
    stats_.listenCount = listeners_->size();
    stats_.nodeInfo = nodeInfo_;
}

void
DhtProxyServer::handlePrintStats(const asio::error_code &ec)
{
    if (ec == asio::error::operation_aborted)
        return;
    else if (ec){
        if (logger_)
            logger_->e("[proxy:server] [stats] error printing: %s", ec.message().c_str());
    }
    if (io_context().stopped())
        return;

    if (dht_){
        updateStats();
        // Refresh stats cache
        auto newInfo = dht_->getNodeInfo();
        std::lock_guard<std::mutex> lck(statsMutex_);
        nodeInfo_ = std::move(newInfo);
        auto json = nodeInfo_.toJson();
        auto str = Json::writeString(jsonBuilder_, json);
        if (logger_)
            logger_->d("[proxy:server] [stats] %s", str.c_str());
    }
    printStatsTimer_->expires_at(printStatsTimer_->expiry() + PRINT_STATS_PERIOD);
    printStatsTimer_->async_wait(std::bind(&DhtProxyServer::handlePrintStats, this, std::placeholders::_1));
}

template <typename HttpResponse>
HttpResponse DhtProxyServer::initHttpResponse(HttpResponse response) const
{
    response.append_header("Server", "RESTinio");
    response.append_header(restinio::http_field::content_type, "application/json");
    response.append_header(restinio::http_field::access_control_allow_origin, "*");
    response.connection_keep_alive();
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
#ifdef OPENDHT_PROXY_HTTP_PARSER_FORK
    // node.stats
    router->add_handler(restinio::custom_http_methods_t::from_nodejs(restinio::method_stats.raw_id()),
                        "/", std::bind(&DhtProxyServer::getStats, this, _1, _2));
#endif
    // key.options
    router->add_handler(restinio::http_method_options(),
                        "/:hash", std::bind(&DhtProxyServer::options, this, _1, _2));
    // key.get
    router->http_get("/:hash", std::bind(&DhtProxyServer::get, this, _1, _2));
    // key.post
    router->http_post("/:hash", std::bind(&DhtProxyServer::put, this, _1, _2));
#ifdef OPENDHT_PROXY_HTTP_PARSER_FORK
    // key.listen
    router->add_handler(restinio::custom_http_methods_t::from_nodejs(restinio::method_listen.raw_id()),
                        "/:hash", std::bind(&DhtProxyServer::listen, this, _1, _2));
#endif
#ifdef OPENDHT_PUSH_NOTIFICATIONS
    // key.subscribe
    router->add_handler(restinio::http_method_subscribe(),
                        "/:hash", std::bind(&DhtProxyServer::subscribe, this, _1, _2));
    // key.unsubscribe
    router->add_handler(restinio::http_method_unsubscribe(),
                        "/:hash", std::bind(&DhtProxyServer::unsubscribe, this, _1, _2));
#endif //OPENDHT_PUSH_NOTIFICATIONS
#ifdef OPENDHT_PROXY_SERVER_IDENTITY
#ifdef OPENDHT_PROXY_HTTP_PARSER_FORK
    // key.sign
    router->add_handler(restinio::custom_http_methods_t::from_nodejs(restinio::method_sign.raw_id()),
                        "/:hash", std::bind(&DhtProxyServer::putSigned, this, _1, _2));
    // key.encrypt
    router->add_handler(restinio::custom_http_methods_t::from_nodejs(restinio::method_encrypt.raw_id()),
                        "/:hash", std::bind(&DhtProxyServer::putEncrypted, this, _1, _2));
#endif
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
    // key.listen
    router->http_get("/key/:hash/listen", std::bind(&DhtProxyServer::listen, this, _1, _2));
#ifdef OPENDHT_PUSH_NOTIFICATIONS
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
    Json::Value result;
    std::lock_guard<std::mutex> lck(statsMutex_);
    if (nodeInfo_.ipv4.good_nodes == 0 &&
        nodeInfo_.ipv6.good_nodes == 0){
        nodeInfo_ = this->dht_->getNodeInfo();
    }
    result = nodeInfo_.toJson();
    // [ipv6:ipv4]:port or ipv4:port
    result["public_ip"] = request->remote_endpoint().address().to_string();
    auto output = Json::writeString(jsonBuilder_, result) + "\n";

    auto response = this->initHttpResponse(request->create_response());
    response.append_body(output);
    return response.done();
}

RequestStatus
DhtProxyServer::getStats(restinio::request_handle_t request,
                         restinio::router::route_params_t /*params*/)
{
    requestNum_++;
    try {
        if (dht_){
            auto output = Json::writeString(jsonBuilder_, stats_.toJson()) + "\n";
            auto response = this->initHttpResponse(request->create_response());
            response.append_body(output);
            response.done();
        } else {
            auto response = this->initHttpResponse(
                request->create_response(restinio::status_service_unavailable()));
            response.set_body(RESP_MSG_SERVICE_UNAVAILABLE);
            return response.done();
        }
    } catch (...){
        auto response = this->initHttpResponse(
            request->create_response(restinio::status_internal_server_error()));
        response.set_body(RESP_MSG_INTERNAL_SERVER_ERRROR);
        return response.done();
    }
    return restinio::request_handling_status_t::accepted;
}

RequestStatus
DhtProxyServer::get(restinio::request_handle_t request,
                    restinio::router::route_params_t params)
{
    requestNum_++;
    dht::InfoHash infoHash(params["hash"].to_string());
    if (!infoHash)
        infoHash = dht::InfoHash::get(params["hash"].to_string());

    if (!dht_){
        auto response = this->initHttpResponse(
            request->create_response(restinio::status_service_unavailable()));
        response.set_body(RESP_MSG_SERVICE_UNAVAILABLE);
        return response.done();
    }

    auto response = std::make_shared<ResponseByPartsBuilder>(
        this->initHttpResponse(request->create_response<ResponseByParts>()));
    response->flush();
    try {
        dht_->get(infoHash, [this, response](const dht::Sp<dht::Value>& value){
            auto output = Json::writeString(jsonBuilder_, value->toJson()) + "\n";
            response->append_chunk(output);
            response->flush();
            return true;
        },
        [response] (bool /*ok*/){
            response->done();
        });
    } catch (const std::exception& e){
        auto response = this->initHttpResponse(
            request->create_response(restinio::status_internal_server_error()));
        response.set_body(RESP_MSG_INTERNAL_SERVER_ERRROR);
        return response.done();
    }
    return restinio::request_handling_status_t::accepted;
}

RequestStatus
DhtProxyServer::listen(restinio::request_handle_t request,
                       restinio::router::route_params_t params)
{
    requestNum_++;
    dht::InfoHash infoHash(params["hash"].to_string());
    if (!infoHash)
        infoHash = dht::InfoHash::get(params["hash"].to_string());

    if (!dht_){
        auto response = this->initHttpResponse(
            request->create_response(restinio::status_service_unavailable()));
        response.set_body(RESP_MSG_SERVICE_UNAVAILABLE);
        return response.done();
    }
    auto response = std::make_shared<ResponseByPartsBuilder>(
        this->initHttpResponse(request->create_response<ResponseByParts>()));
    response->flush();
    try {
        std::lock_guard<std::mutex> lock(*lockListener_);
        // save the listener to handle a disconnect
        auto &session = (*listeners_)[request->connection_id()];
        session.hash = infoHash;
        session.response = response;
        session.token = dht_->listen(infoHash, [this, response]
                (const std::vector<dht::Sp<dht::Value>>& values, bool expired){
            for (const auto& value: values){
                auto jsonVal = value->toJson();
                if (expired)
                    jsonVal["expired"] = true;
                auto output = Json::writeString(jsonBuilder_, jsonVal) + "\n";
                response->append_chunk(output);
                response->flush();
            }
            return true;
        });

    } catch (const std::exception& e){
        auto response = this->initHttpResponse(
            request->create_response(restinio::status_internal_server_error()));
        response.set_body(RESP_MSG_INTERNAL_SERVER_ERRROR);
        return response.done();
    }
    return restinio::request_handling_status_t::accepted;
}

#ifdef OPENDHT_PUSH_NOTIFICATIONS

RequestStatus
DhtProxyServer::subscribe(restinio::request_handle_t request,
                          restinio::router::route_params_t params)
{
    requestNum_++;

    dht::InfoHash infoHash(params["hash"].to_string());
    if (!infoHash)
        infoHash = dht::InfoHash::get(params["hash"].to_string());

    if (!dht_){
        auto response = this->initHttpResponse(
            request->create_response(restinio::status_service_unavailable()));
        response.set_body(RESP_MSG_SERVICE_UNAVAILABLE);
        return response.done();
    }
    try {
        std::string err;
        Json::Value root;
        Json::CharReaderBuilder rbuilder;
        auto* char_data = reinterpret_cast<const char*>(request->body().data());
        auto reader = std::unique_ptr<Json::CharReader>(rbuilder.newCharReader());
        if (!reader->parse(char_data, char_data + request->body().size(), &root, &err)){
            auto response = this->initHttpResponse(
                request->create_response(restinio::status_bad_request()));
            response.set_body(RESP_MSG_JSON_INCORRECT);
            return response.done();
        }
        auto pushToken = root["key"].asString();
        if (pushToken.empty()){
            auto response = this->initHttpResponse(
                request->create_response(restinio::status_bad_request()));
            response.set_body(RESP_MSG_NO_TOKEN);
            return response.done();
        }
        auto platform = root["platform"].asString();
        auto isAndroid = platform == "android";
        auto clientId = root.isMember("client_id") ? root["client_id"].asString() : std::string();

        if (logger_)
            logger_->d("[proxy:server] [subscribe %s] [client %s]", infoHash.toString().c_str(), clientId.c_str());
        // ================ Search for existing listener ===================
        // start the timer
        auto timeout = std::chrono::steady_clock::now() + proxy::OP_TIMEOUT;
        std::lock_guard<std::mutex> lock(lockPushListeners_);

        // Insert new or return existing push listeners of a token
        auto pushListener = pushListeners_.emplace(pushToken, PushListener{}).first;
        auto pushListeners = pushListener->second.listeners.emplace(infoHash, std::vector<Listener>{}).first;

        for (auto &listener: pushListeners->second){
            if (logger_)
                logger_->d("[proxy:server] [subscribe] found [client %s]", listener.clientId.c_str());
            // Found -> Resubscribe
            if (listener.clientId == clientId){
                // Reset timers
                listener.expireTimer->expires_at(timeout);
                listener.expireNotifyTimer->expires_at(timeout - proxy::OP_MARGIN);
                // Send response header
                auto response = std::make_shared<ResponseByPartsBuilder>(
                    this->initHttpResponse(request->create_response<ResponseByParts>()));
                response->flush();
                // No Refresh
                if (!root.isMember("refresh") or !root["refresh"].asBool()){
                    dht_->get(infoHash, [this, response](const dht::Sp<dht::Value>& value){
                        auto output = Json::writeString(jsonBuilder_, value->toJson()) + "\n";
                        response->append_chunk(output);
                        response->flush();
                        return true;
                    },
                    [response] (bool){
                        response->done();
                    });
                // Refresh
                } else {
                    response->append_chunk("{}\n");
                    response->done();
                }
                return restinio::request_handling_status_t::accepted;
            }
        }
        // =========== No existing listener for an infoHash ============
        // Add new listener to list of listeners
        pushListeners->second.emplace_back(Listener{});
        auto &listener = pushListeners->second.back();
        listener.clientId = clientId;

        // Add listen on dht
        listener.internalToken = dht_->listen(infoHash,
            [this, infoHash, pushToken, isAndroid, clientId]
            (const std::vector<std::shared_ptr<Value>>& values, bool expired){
                // Build message content
                Json::Value json;
                json["key"] = infoHash.toString();
                json["to"] = clientId;
                if (expired and values.size() < 2){
                    std::stringstream ss;
                    for(size_t i = 0; i < values.size(); ++i){
                        if(i != 0) ss << ",";
                        ss << values[i]->id;
                    }
                    json["exp"] = ss.str();
                }
                sendPushNotification(pushToken, std::move(json), isAndroid);
                return true;
            }
        );
        // Launch timers
        auto &ctx = io_context();
        // expire notify
        if (!listener.expireNotifyTimer)
            listener.expireNotifyTimer = std::make_unique<asio::steady_timer>(ctx, timeout - proxy::OP_MARGIN);
        else
            listener.expireNotifyTimer->expires_at(timeout - proxy::OP_MARGIN);
        Json::Value json;
        json["timeout"] = infoHash.toString();
        json["to"] = clientId;
        listener.expireNotifyTimer->async_wait(std::bind(&DhtProxyServer::handleNotifyPushListenExpire, this,
                                               std::placeholders::_1, pushToken, json, isAndroid));
        // cancel push listen
        if (!listener.expireTimer)
            listener.expireTimer = std::make_unique<asio::steady_timer>(ctx, timeout);
        else
            listener.expireTimer->expires_at(timeout);
        listener.expireTimer->async_wait(std::bind(&DhtProxyServer::handleCancelPushListen, this,
                                         std::placeholders::_1, pushToken, infoHash, clientId));
        auto response = this->initHttpResponse(request->create_response());
        response.set_body("{}\n");
        return response.done();
    }
    catch (...) {
        auto response = this->initHttpResponse(
            request->create_response(restinio::status_internal_server_error()));
        response.set_body(RESP_MSG_INTERNAL_SERVER_ERRROR);
        return response.done();
    }
    return restinio::request_handling_status_t::accepted;
}

RequestStatus
DhtProxyServer::unsubscribe(restinio::request_handle_t request,
                            restinio::router::route_params_t params)
{
    requestNum_++;

    dht::InfoHash infoHash(params["hash"].to_string());
    if (!infoHash)
        infoHash = dht::InfoHash::get(params["hash"].to_string());

    if (!dht_){
        auto response = this->initHttpResponse(
            request->create_response(restinio::status_service_unavailable()));
        response.set_body(RESP_MSG_SERVICE_UNAVAILABLE);
        return response.done();
    }
    if (logger_)
        logger_->d("[proxy:server] [unsubscribe %s]", infoHash.toString().c_str());

    try {
        std::string err;
        Json::Value root;
        Json::CharReaderBuilder rbuilder;
        auto* char_data = reinterpret_cast<const char*>(request->body().data());
        auto reader = std::unique_ptr<Json::CharReader>(rbuilder.newCharReader());

        if (!reader->parse(char_data, char_data + request->body().size(), &root, &err)){
            auto response = this->initHttpResponse(
                request->create_response(restinio::status_bad_request()));
            response.set_body(RESP_MSG_JSON_INCORRECT);
            return response.done();
        }
        auto pushToken = root["key"].asString();
        if (pushToken.empty())
            return restinio::request_handling_status_t::rejected;
        auto clientId = root["client_id"].asString();

        handleCancelPushListen(asio::error_code() /*success*/, pushToken, infoHash, clientId);
        auto response = this->initHttpResponse(request->create_response());
        return response.done();
    }
    catch (...) {
        auto response = this->initHttpResponse(
            request->create_response(restinio::status_internal_server_error()));
        response.set_body(RESP_MSG_INTERNAL_SERVER_ERRROR);
        return response.done();
    }
}

void
DhtProxyServer::handleNotifyPushListenExpire(const asio::error_code &ec, const std::string pushToken,
                                             Json::Value json, const bool isAndroid)
{
    if (ec == asio::error::operation_aborted)
        return;
    else if (ec){
        if (logger_)
            logger_->e("[proxy:server] [subscribe] error sending put refresh: %s", ec.message().c_str());
    }
    if (logger_)
        logger_->d("[proxy:server] [subscribe] sending put refresh to %s token", pushToken.c_str());
    sendPushNotification(pushToken, std::move(json), isAndroid);
}

void
DhtProxyServer::handleCancelPushListen(const asio::error_code &ec, const std::string pushToken,
                                       const dht::InfoHash key, const std::string clientId)
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
    std::lock_guard<std::mutex> lock(*lockListener_);

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

void
DhtProxyServer::sendPushNotification(const std::string& token, Json::Value&& json, bool isAndroid)
{
    if (pushServer_.empty())
        return;

    auto request = std::make_shared<http::Request>(io_context(), pushHostPort_.first, pushHostPort_.second,
                                                                 httpsServer_ ? true : false, logger_);
    auto reqid = request->id();
    try {
        request->set_target("/api/push");
        request->set_method(restinio::http_method_post());

        request->set_header_field(restinio::http_field_t::host, pushServer_.c_str());
        request->set_header_field(restinio::http_field_t::user_agent, "RESTinio client");
        request->set_header_field(restinio::http_field_t::accept, "*/*");
        request->set_header_field(restinio::http_field_t::content_type, "application/json");

        // NOTE: see https://github.com/appleboy/gorush
        Json::Value notification(Json::objectValue);
        Json::Value tokens(Json::arrayValue);
        tokens[0] = token;
        notification["tokens"] = std::move(tokens);
        notification["platform"] = isAndroid ? 2 : 1;
        notification["data"] = std::move(json);
        notification["priority"] = "high";
        notification["time_to_live"] = 600;

        Json::Value notifications(Json::arrayValue);
        notifications[0] = notification;

        Json::Value content;
        content["notifications"] = std::move(notifications);

        Json::StreamWriterBuilder wbuilder;
        wbuilder["commentStyle"] = "None";
        wbuilder["indentation"] = "";

        auto body = Json::writeString(wbuilder, content);
        request->set_body(body);

        request->add_on_state_change_callback([this, reqid]
                                              (const http::Request::State state, const http::Response response){
            if (state == http::Request::State::DONE){
                if (logger_ and response.status_code != 200)
                    logger_->e("[proxy:server] [notification] push failed: %i", response.status_code);
                requests_.erase(reqid);
            }
        });
        request->send();
        requests_[reqid] = request;
    }
    catch (const std::exception &e){
        if (logger_)
            logger_->e("[proxy:server] [notification] error send push: %i", e.what());
        requests_.erase(reqid);
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
    auto sPuts = puts_.find(key);
    if (sPuts == puts_.end())
        return;
    auto& sPutsMap = sPuts->second.puts;
    auto put = sPutsMap.find(vid);
    if (put == sPutsMap.end())
        return;
    if (dht_)
        dht_->cancelPut(key, vid);
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
    dht::InfoHash infoHash(params["hash"].to_string());
    if (!infoHash)
        infoHash = dht::InfoHash::get(params["hash"].to_string());

    if (!dht_){
        auto response = this->initHttpResponse(
            request->create_response(restinio::status_service_unavailable()));
        response.set_body(RESP_MSG_SERVICE_UNAVAILABLE);
        return response.done();
    }
    else if (request->body().empty()){
        auto response = this->initHttpResponse(
            request->create_response(restinio::status_bad_request()));
        response.set_body(RESP_MSG_MISSING_PARAMS);
        return response.done();
    }

    try {
        std::string err;
        Json::Value root;
        Json::CharReaderBuilder rbuilder;
        auto* char_data = reinterpret_cast<const char*>(request->body().data());
        auto reader = std::unique_ptr<Json::CharReader>(rbuilder.newCharReader());

        if (reader->parse(char_data, char_data + request->body().size(), &root, &err)){
            auto value = std::make_shared<dht::Value>(root);
            bool permanent = root.isMember("permanent");
            if (logger_)
                logger_->d("[proxy:server] [put %s] %s %s", infoHash.toString().c_str(),
                          value->toString().c_str(), (permanent ? "permanent" : ""));
            if (permanent){
                std::string pushToken, clientId, platform;
                auto& pVal = root["permanent"];
                if (pVal.isObject()){
                    pushToken = pVal["key"].asString();
                    clientId = pVal["client_id"].asString();
                    platform = pVal["platform"].asString();
                }
                std::unique_lock<std::mutex> lock(lockSearchPuts_);
                auto timeout = std::chrono::steady_clock::now() + proxy::OP_TIMEOUT;
                auto vid = value->id;
                auto sPuts = puts_.emplace(infoHash, SearchPuts{}).first;
                auto r = sPuts->second.puts.emplace(vid, PermanentPut{});
                auto& pput = r.first->second;
                if (r.second){
                    auto &ctx = io_context();
                    // cancel permanent put
                    if (!pput.expireTimer)
                        pput.expireTimer = std::make_unique<asio::steady_timer>(ctx, timeout);
                    else
                        pput.expireTimer->expires_at(timeout);
                    pput.expireTimer->async_wait(std::bind(&DhtProxyServer::handleCancelPermamentPut, this,
                                                 std::placeholders::_1, infoHash, vid));
#ifdef OPENDHT_PUSH_NOTIFICATIONS
                    if (not pushToken.empty()){
                        // notify push listen expire
                        bool isAndroid = platform == "android";
                        Json::Value json;
                        json["timeout"] = infoHash.toString();
                        json["to"] = clientId;
                        json["vid"] = std::to_string(vid);
                        if (!pput.expireNotifyTimer)
                            pput.expireNotifyTimer = std::make_unique<asio::steady_timer>(ctx,
                                                     timeout - proxy::OP_MARGIN);
                        else
                            pput.expireNotifyTimer->expires_at(timeout - proxy::OP_MARGIN);
                        pput.expireNotifyTimer->async_wait(std::bind(
                            &DhtProxyServer::handleNotifyPushListenExpire, this,
                            std::placeholders::_1, pushToken, json, isAndroid));
                    }
#endif
                } else {
                    pput.expireTimer->expires_at(timeout);
                    if (pput.expireNotifyTimer)
                        pput.expireNotifyTimer->expires_at(timeout - proxy::OP_MARGIN);
                }
                lock.unlock();
            }
            dht_->put(infoHash, value, [this, request, value](bool ok){
                if (ok){
                    auto output = Json::writeString(jsonBuilder_, value->toJson()) + "\n";
                    auto response = this->initHttpResponse(request->create_response());
                    response.append_body(output);
                    response.done();
                } else {
                    auto response = this->initHttpResponse(request->create_response(
                        restinio::status_bad_gateway()));
                    response.set_body(RESP_MSG_PUT_FAILED);
                    response.done();
                }
            }, dht::time_point::max(), permanent);
        } else {
            auto response = this->initHttpResponse(
                request->create_response(restinio::status_bad_request()));
            response.set_body(RESP_MSG_JSON_INCORRECT);
            return response.done();
        }
    } catch (const std::exception& e){
        if (logger_)
            logger_->d("[proxy:server] error in put: %s", e.what());
        auto response = this->initHttpResponse(
            request->create_response(restinio::status_internal_server_error()));
        response.set_body(RESP_MSG_INTERNAL_SERVER_ERRROR);
        return response.done();
    }
    return restinio::request_handling_status_t::accepted;
}

#ifdef OPENDHT_PROXY_SERVER_IDENTITY

RequestStatus DhtProxyServer::putSigned(restinio::request_handle_t request,
                                        restinio::router::route_params_t params) const
{
    requestNum_++;
    dht::InfoHash infoHash(params["hash"].to_string());
    if (!infoHash)
        infoHash = dht::InfoHash::get(params["hash"].to_string());

    if (!dht_){
        auto response = this->initHttpResponse(
            request->create_response(restinio::status_service_unavailable()));
        response.set_body(RESP_MSG_SERVICE_UNAVAILABLE);
        return response.done();
    }
    else if (request->body().empty()){
        auto response = this->initHttpResponse(
            request->create_response(restinio::status_bad_request()));
        response.set_body(RESP_MSG_MISSING_PARAMS);
        return response.done();
    }

    try {
        std::string err;
        Json::Value root;
        Json::CharReaderBuilder rbuilder;
        auto* char_data = reinterpret_cast<const char*>(request->body().data());
        auto reader = std::unique_ptr<Json::CharReader>(rbuilder.newCharReader());

        if (reader->parse(char_data, char_data + request->body().size(), &root, &err)){

            auto value = std::make_shared<Value>(root);

            dht_->putSigned(infoHash, value, [this, request, value](bool ok){
                if (ok){
                    auto output = Json::writeString(jsonBuilder_, value->toJson()) + "\n";
                    auto response = this->initHttpResponse(request->create_response());
                    response.append_body(output);
                    response.done();
                } else {
                    auto response = this->initHttpResponse(request->create_response(
                        restinio::status_bad_gateway()));
                    response.set_body(RESP_MSG_PUT_FAILED);
                    response.done();
                }
            });
        } else {
            auto response = this->initHttpResponse(
                request->create_response(restinio::status_bad_request()));
            response.set_body(RESP_MSG_JSON_INCORRECT);
            return response.done();
        }
    } catch (const std::exception& e){
        if (logger_)
            logger_->d("[proxy:server] error in put: %s", e.what());
        auto response = this->initHttpResponse(
            request->create_response(restinio::status_internal_server_error()));
        response.set_body(RESP_MSG_INTERNAL_SERVER_ERRROR);
        return response.done();
    }
    return restinio::request_handling_status_t::accepted;
}

RequestStatus
DhtProxyServer::putEncrypted(restinio::request_handle_t request,
                             restinio::router::route_params_t params)
{
    requestNum_++;
    dht::InfoHash infoHash(params["hash"].to_string());
    if (!infoHash)
        infoHash = dht::InfoHash::get(params["hash"].to_string());

    if (!dht_){
        auto response = this->initHttpResponse(
            request->create_response(restinio::status_service_unavailable()));
        response.set_body(RESP_MSG_SERVICE_UNAVAILABLE);
        return response.done();
    }
    else if (request->body().empty()){
        auto response = this->initHttpResponse(
            request->create_response(restinio::status_bad_request()));
        response.set_body(RESP_MSG_MISSING_PARAMS);
        return response.done();
    }

    try {
        std::string err;
        Json::Value root;
        Json::CharReaderBuilder rbuilder;
        auto* char_data = reinterpret_cast<const char*>(request->body().data());
        auto reader = std::unique_ptr<Json::CharReader>(rbuilder.newCharReader());

        if (reader->parse(char_data, char_data + request->body().size(), &root, &err)){
            InfoHash to(root["to"].asString());
            if (!to){
                auto response = this->initHttpResponse(
                    request->create_response(restinio::status_bad_request()));
                response.set_body(RESP_MSG_DESTINATION_NOT_FOUND);
                return response.done();
            }
            auto value = std::make_shared<Value>(root);
            dht_->putEncrypted(infoHash, to, value, [this, request, value](bool ok){
                if (ok){
                    auto output = Json::writeString(jsonBuilder_, value->toJson()) + "\n";
                    auto response = this->initHttpResponse(request->create_response());
                    response.append_body(output);
                    response.done();
                } else {
                    auto response = this->initHttpResponse(request->create_response(
                        restinio::status_bad_gateway()));
                    response.set_body(RESP_MSG_PUT_FAILED);
                    response.done();
                }
            });
        } else {
            auto response = this->initHttpResponse(
                request->create_response(restinio::status_bad_request()));
            response.set_body(RESP_MSG_JSON_INCORRECT);
            return response.done();
        }
    } catch (const std::exception& e){
        if (logger_)
            logger_->d("[proxy:server] error in put: %s", e.what());
        auto response = this->initHttpResponse(
            request->create_response(restinio::status_internal_server_error()));
        response.set_body(RESP_MSG_INTERNAL_SERVER_ERRROR);
        return response.done();
    }
    return restinio::request_handling_status_t::accepted;
}

#endif // OPENDHT_PROXY_SERVER_IDENTITY

RequestStatus
DhtProxyServer::options(restinio::request_handle_t request,
                        restinio::router::route_params_t /*params*/)
{
    this->requestNum_++;
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
    auto value = params["value"].to_string();
    dht::InfoHash infoHash(params["hash"].to_string());
    if (!infoHash)
        infoHash = dht::InfoHash::get(params["hash"].to_string());

    if (!dht_){
        auto response = this->initHttpResponse(
            request->create_response(restinio::status_service_unavailable()));
        response.set_body(RESP_MSG_SERVICE_UNAVAILABLE);
        return response.done();
    }

    auto response = std::make_shared<ResponseByPartsBuilder>(
        this->initHttpResponse(request->create_response<ResponseByParts>()));
    response->flush();
    try {
        dht_->get(infoHash, [this, response](const dht::Sp<dht::Value>& value){
            auto output = Json::writeString(jsonBuilder_, value->toJson()) + "\n";
            response->append_chunk(output);
            response->flush();
            return true;
        },
        [response] (bool /*ok*/){
            response->done();
        },
            {}, value
        );
    } catch (const std::exception& e){
        auto response = this->initHttpResponse(
            request->create_response(restinio::status_internal_server_error()));
        response.set_body(RESP_MSG_INTERNAL_SERVER_ERRROR);
        return response.done();
    }
    return restinio::request_handling_status_t::accepted;
}

}
