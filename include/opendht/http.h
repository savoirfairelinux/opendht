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

using ConnectionId = unsigned int;

class Connection
{
public:
    Connection(const ConnectionId id, asio::ip::tcp::socket socket);
    ~Connection();

    ConnectionId id();
    bool is_open();
    bool is_v6();
    void close();

private:
    friend class Client;

    ConnectionId id_;
    asio::ip::tcp::socket socket_;
    asio::streambuf request_;
    asio::streambuf response_;
    asio::ip::tcp::endpoint endpoint_;
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

/**
 * Request is the context of an active connection allowing it to parse responses
 */
struct Request
{
    std::string content;
    std::shared_ptr<http_parser> parser;
    std::shared_ptr<http_parser_settings> parser_settings;
    std::shared_ptr<Connection> connection;
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
    std::shared_ptr<std::map<restinio::connection_id_t,
                             http::ListenerSession>> listeners_;
    std::shared_ptr<dht::Logger> logger_;
};

class OPENDHT_PUBLIC Client
{
public:
    using HandlerCb = std::function<void(const asio::error_code& ec)>;
    using ConnectionCb = std::function<void(std::shared_ptr<Connection>)>;

    Client(asio::io_context& ctx, const std::string host, const std::string service = "80",
           std::shared_ptr<dht::Logger> logger = {}, const bool resolve = true);

    asio::io_context& io_context();

    void set_logger(std::shared_ptr<dht::Logger> logger);

    bool active_connection(ConnectionId conn_id);
    void close_connection(ConnectionId conn_id);

    bool resolved();
    void async_resolve(const std::string host, const std::string service, HandlerCb cb = {});

    void async_connect(ConnectionCb cb);

    std::string create_request(const restinio::http_request_header_t header,
                               const restinio::http_header_fields_t header_fields,
                               const restinio::http_connection_header_t connection,
                               const std::string body);

    void async_request(std::shared_ptr<http::Connection> conn,
                       std::string request, std::shared_ptr<http_parser> parser,
                       std::shared_ptr<http_parser_settings> parser_s);

private:
    std::shared_ptr<Connection> create_connection();

    void handle_connect(const asio::error_code& ec,
                        asio::ip::tcp::resolver::iterator endpoint_it,
                        std::shared_ptr<Connection> conn = {}, HandlerCb cb = {});

    void handle_resolve(const asio::error_code& ec,
                        asio::ip::tcp::resolver::iterator endpoint_it,
                        std::shared_ptr<Connection> conn = {});

    void handle_request(const asio::error_code& ec,
                        std::shared_ptr<Connection> conn = {});

    void handle_response(const asio::error_code& ec,
                         std::shared_ptr<Connection> conn = {});

    std::string service_;
    std::string host_;

    // contains the io_context
    asio::ip::tcp::resolver resolver_;
    // resolved endpoint
    asio::ip::basic_resolver_results<asio::ip::tcp> endpoints_;

    ConnectionId connId_ {1};
    /*
     * An association between an active connection and its context, a Request.
     */
    std::map<ConnectionId, Request> requests_;

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
