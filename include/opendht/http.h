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
#include <opendht/log.h>

namespace http {

class Connection
{
public:
    Connection(const uint16_t id, asio::ip::tcp::socket socket);
    ~Connection();

    uint16_t id();
    void start(asio::ip::tcp::resolver::iterator &r_iter);
    bool is_open();
    asio::ip::tcp::socket& get_socket();
    std::string read(std::error_code& ec);
    void write(std::string request, std::error_code& ec);
    void close();

private:
    uint16_t id_;
    asio::ip::tcp::socket socket_;
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
    void state_changed(const restinio::connection_state::notice_t &notice) noexcept;

private:
    std::string to_str( restinio::connection_state::cause_t cause ) noexcept;

    std::shared_ptr<dht::DhtRunner> dht_;
    std::shared_ptr<std::mutex> lock_;
    std::shared_ptr<std::map<restinio::connection_id_t,
                             http::ListenerSession>> listeners_;
    std::shared_ptr<dht::Logger> logger_;
};

class Client
{
public:
    Client() = default;
    Client(std::string ip, uint16_t port);

    asio::io_context& io_context();
    void set_logger(std::shared_ptr<dht::Logger> logger);

    void set_query_address(const std::string ip, const uint16_t port);
    asio::ip::tcp::resolver::query build_query();

    std::shared_ptr<Connection> open_conn();

    std::string create_request(const restinio::http_request_header_t header,
                               const restinio::http_header_fields_t header_fields,
                               const restinio::http_connection_header_t connection,
                               const std::string body);

    void post_request(std::string request,
                      std::shared_ptr<http_parser> parser = nullptr,
                      std::shared_ptr<http_parser_settings> parser_s = nullptr,
                      std::shared_ptr<Connection> conn = nullptr);

private:
    void async_request(std::string request,
                       std::shared_ptr<http_parser> parser = nullptr,
                       std::shared_ptr<http_parser_settings> parser_s = nullptr,
                       std::shared_ptr<Connection> conn = nullptr);

    uint16_t port_;
    asio::ip::address addr_;
    asio::io_context ctx_;
    asio::ip::tcp::resolver resolver_ {ctx_};
    uint16_t connId_ {1};
    std::shared_ptr<dht::Logger> logger_;
};

} // namespace http

namespace restinio
{

class opendht_logger_t
{
public:
    opendht_logger_t(std::shared_ptr<dht::Logger> logger = nullptr){
        if (logger)
            m_logger = logger;
    }

    template <typename Builder>
    void trace(Builder && msg_builder){
        if (m_logger)
            m_logger->d("[restinio] %s", msg_builder().c_str());
    }

    template <typename Builder>
    void info(Builder && msg_builder){
        if (m_logger)
            m_logger->d("[restinio] %s", msg_builder().c_str());
    }

    template <typename Builder>
    void warn(Builder && msg_builder){
        if (m_logger)
            m_logger->w("[restinio] %s", msg_builder().c_str());
    }

    template <typename Builder>
    void error(Builder && msg_builder){
        if (m_logger)
            m_logger->e("[restinio] %s", msg_builder().c_str());
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
