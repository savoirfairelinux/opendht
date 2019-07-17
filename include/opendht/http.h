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

class Connection;

// basic types
using Id = unsigned int;

// asio handlers callbacks
using HandlerCb = std::function<void(const asio::error_code& ec)>;
using ConnectionCb = std::function<void(const asio::error_code& ec, std::shared_ptr<Connection>)>;

class OPENDHT_PUBLIC Connection
{
public:
    Connection(asio::ip::tcp::socket socket, std::shared_ptr<dht::Logger> logger = {});
    ~Connection();

    Id id();
    bool is_open();
    bool is_v6();
    void timeout(const std::chrono::seconds timeout, HandlerCb cb = {});
    // TODO abort to silence error in request?
    void close();

private:
    friend class Client;

    Id id_;
    static Id ids_;
    std::shared_ptr<dht::Logger> logger_;

    asio::ip::tcp::socket socket_;
    asio::ip::tcp::endpoint endpoint_;

    asio::streambuf request_;
    std::string response_body_;
    asio::streambuf response_chunk_;

    std::unique_ptr<asio::steady_timer> timeout_timer_;
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
    std::shared_ptr<std::map<restinio::connection_id_t,
                             http::ListenerSession>> listeners_;

    std::shared_ptr<dht::Logger> logger_;
};

class OPENDHT_PUBLIC Request
{
public:
    Request(asio::io_context& ctx, const std::string host, const std::string service = "80",
            const bool resolve = true, std::shared_ptr<dht::Logger> logger = {});
    ~Request();

    void set_logger(std::shared_ptr<dht::Logger> logger);

    void terminate();

    void resolve(const std::string host, const std::string service, HandlerCb cb = {});
    bool resolved();

    void connect(ConnectionCb cb = {});

    std::string build(const restinio::http_request_header_t header,
                      const restinio::http_header_fields_t header_fields,
                      const restinio::http_connection_header_t connection, const std::string body);

    void send(std::string request, std::unique_ptr<http_parser> parser,
              std::unique_ptr<http_parser_settings> parser_s, HandlerCb cb = {});

private:
    void handle_request(const asio::error_code& ec, HandlerCb cb = {});

    void handle_response_header(const asio::error_code& ec, const size_t bytes, HandlerCb cb = {});

    void handle_response_body(const asio::error_code& ec, const size_t bytes, HandlerCb cb = {});

    void parse_request(const std::string request);

    size_t get_content_length(const std::string str);

    std::string service_;
    std::string host_;

    asio::ip::tcp::resolver resolver_;
    asio::ip::basic_resolver_results<asio::ip::tcp> endpoints_;

    Id id_;
    static Id ids_;
    std::shared_ptr<Connection> conn_;

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
