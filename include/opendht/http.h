/*
 *  Copyright (C) 2016-2019 Savoir-faire Linux Inc.
 *  Author: Vsevolod Ivanov <vsevolod.ivanov@savoirfairelinux.com>
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

#pragma once

#include <asio.hpp>
#include <json/json.h>
#include <http_parser.h>
#include <restinio/all.hpp>
#include <opendht.h>
#include <opendht/def.h>
#include <opendht/log.h>

namespace http {

using HandlerCb = std::function<void(const asio::error_code& ec)>;

class OPENDHT_PUBLIC Connection
{
public:
    Connection(asio::io_context& ctx, std::shared_ptr<dht::Logger> logger = {});
    ~Connection();

    unsigned int id();
    bool is_open();
    bool is_v6();

    void set_endpoint(const asio::ip::tcp::endpoint& endpoint);

    asio::streambuf& input();
    asio::streambuf& data();
    asio::ip::tcp::socket& socket();

    void timeout(const std::chrono::seconds timeout, HandlerCb cb = {});

    void close();

private:
    unsigned int id_;
    static unsigned int ids_;

    asio::ip::tcp::socket socket_;
    asio::ip::tcp::endpoint endpoint_;

    asio::streambuf write_buf_;
    asio::streambuf read_buf_;

    std::unique_ptr<asio::steady_timer> timeout_timer_;
    std::shared_ptr<dht::Logger> logger_;
};

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

class ConnectionListener
{
public:
    ConnectionListener();
    ConnectionListener(std::shared_ptr<dht::DhtRunner> dht,
        std::shared_ptr<std::map<restinio::connection_id_t, http::ListenerSession>> listeners,
        std::shared_ptr<std::mutex> lock, std::shared_ptr<dht::Logger> logger);
    ~ConnectionListener();

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

/* @class Resolver
 * @brief The purpose is to only resolve once to avoid mutliple dns requests per operation.
 */
class OPENDHT_PUBLIC Resolver
{
public:
    using ResolverCb = std::function<void(const asio::error_code& ec,
                                          std::vector<asio::ip::tcp::endpoint> endpoints)>;

    Resolver(asio::io_context& ctx, const std::string& host, const std::string& service = "80",
             std::shared_ptr<dht::Logger> logger = {});

    // use already resolved endpoints with classes using this resolver
    Resolver(asio::io_context& ctx, std::vector<asio::ip::tcp::endpoint> endpoints,
             std::shared_ptr<dht::Logger> logger = {});

    ~Resolver();

    void add_callback(ResolverCb cb);

private:
    void resolve(const std::string host, const std::string service);

    std::mutex mutex_;

    asio::error_code ec_;
    asio::ip::tcp::resolver resolver_;
    std::vector<asio::ip::tcp::endpoint> endpoints_;

    bool completed_ {false};
    std::queue<ResolverCb> cbs_;

    std::shared_ptr<dht::Logger> logger_;
};

struct Response
{
    unsigned int status_code;
    std::map<std::string, std::string> headers;
    std::string body;
};

class OPENDHT_PUBLIC Request
{
public:
    enum class State {
        CREATED,
        SENDING,
        HEADER_RECEIVED,
        RECEIVING,
        FINISHING,
        DONE
    };
    using OnStatusCb = std::function<void(unsigned int status_code)>;
    using OnDataCb = std::function<void(const char* at, size_t length)>;
    using OnStateChangeCb = std::function<void(const State state, const Response response)>;

    // resolves implicitly
    Request(asio::io_context& ctx, const std::string& host, const std::string& service = "80",
            std::shared_ptr<dht::Logger> logger = {});

    // user defined resolver
    Request(asio::io_context& ctx, std::shared_ptr<Resolver> resolver, std::shared_ptr<dht::Logger> logger = {});

    // user defined resolved endpoints
    Request(asio::io_context& ctx, std::vector<asio::ip::tcp::endpoint>&& endpoints,
            std::shared_ptr<dht::Logger> logger = {});

    ~Request();

    unsigned int id() const;
    std::shared_ptr<Connection> get_connection() const;

    void set_logger(std::shared_ptr<dht::Logger> logger);

    void set_header(const restinio::http_request_header_t header);
    void set_header_field(const restinio::http_field_t field, const std::string& value);
    void set_connection_type(const restinio::http_connection_header_t connection);
    void set_body(const std::string& body);

    void add_on_status_callback(OnStatusCb cb);
    void add_on_body_callback(OnDataCb cb);
    void add_on_state_change_callback(OnStateChangeCb cb);

    void send();
    void end();

private:
    using OnCompleteCb = std::function<void()>;

    struct Callbacks {
        Callbacks(){}

        OnStatusCb on_status;
        OnDataCb on_header_field;
        OnDataCb on_header_value;
        OnDataCb on_body;
        OnCompleteCb on_message_complete;

        OnStateChangeCb on_state_change;
    };

    void notify_state_change(const State state);

    void build();
    void init_parser();

    void connect(std::vector<asio::ip::tcp::endpoint>&& endpoints, HandlerCb cb = {});

    void terminate(const asio::error_code& ec);

    void post();

    void handle_request(const asio::error_code& ec);

    void handle_response_header(const asio::error_code& ec, const size_t bytes);

    void handle_response_body(const asio::error_code& ec, const size_t bytes, const std::string chunk);

    void parse_request(const std::string request);

    restinio::http_request_header_t header_;
    std::map<restinio::http_field_t, std::string> headers_;
    restinio::http_connection_header_t connection_type_;
    std::string body_;

    std::mutex cbs_mutex_;
    std::unique_ptr<Callbacks> cbs_;
    State state_;

    std::string service_;
    std::string host_;

    unsigned int id_;
    static unsigned int ids_;
    asio::io_context& ctx_;
    std::shared_ptr<Connection> conn_;
    std::shared_ptr<Resolver> resolver_;

    Response response_ {};
    std::string request_;
    std::unique_ptr<http_parser> parser_;
    std::unique_ptr<http_parser_settings> parser_s_;

    std::shared_ptr<dht::Logger> logger_;
};

} // namespace http

namespace restinio
{

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

/* Custom HTTP-methods for RESTinio > 0.5.0.
 * https://github.com/Stiffstream/restinio/issues/26
 */
constexpr const restinio::http_method_id_t method_listen{HTTP_LISTEN, "LISTEN"};
constexpr const restinio::http_method_id_t method_stats{HTTP_STATS, "STATS"};
constexpr const restinio::http_method_id_t method_sign{HTTP_SIGN, "SIGN"};
constexpr const restinio::http_method_id_t method_encrypt{HTTP_ENCRYPT, "ENCRYPT"};

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

} // namespace restinio
