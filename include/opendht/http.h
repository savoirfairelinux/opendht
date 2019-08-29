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

#include "def.h"
#include "infohash.h"

#include <asio.hpp>
#include <asio/ssl.hpp>

#include <restinio/all.hpp>

#include <memory>
#include <queue>

extern "C" {
struct http_parser;
struct http_parser_settings;
}

namespace restinio {
namespace impl {
class tls_socket_t;
}
}

namespace dht {
struct Logger;

namespace crypto {
class Certificate;
}

namespace http {

using HandlerCb = std::function<void(const asio::error_code& ec)>;
using BytesHandlerCb = std::function<void(const asio::error_code& ec, const size_t bytes)>;
using ConnectHandlerCb = std::function<void(const asio::error_code& ec,
                                            const asio::ip::tcp::endpoint& endpoint)>;

using ssl_socket_t = restinio::impl::tls_socket_t;
using socket_t = asio::ip::tcp::socket;

class OPENDHT_PUBLIC Url
{
public:
    Url(){};
    Url(const std::string& url);
    std::string url;
    std::string protocol {"http"};
    std::string host;
    std::string service {"80"};
    std::string target {"/"};
    std::string query;
};

class OPENDHT_PUBLIC Connection
{
public:
    Connection(asio::io_context& ctx, const bool ssl = true, std::shared_ptr<dht::Logger> l = {});
    Connection(asio::io_context& ctx, std::shared_ptr<dht::crypto::Certificate> certificate,
               std::shared_ptr<dht::Logger> l = {});
    ~Connection();

    unsigned int id();
    bool is_open();
    bool is_v6();
    bool is_ssl();

    void set_endpoint(const asio::ip::tcp::endpoint& endpoint,
                      const asio::ssl::verify_mode verify_mode = asio::ssl::verify_none);

    asio::streambuf& input();
    asio::streambuf& data();

    std::string read_bytes(const size_t bytes);
    std::string read_until(const char delim);

    void async_connect(std::vector<asio::ip::tcp::endpoint>&& endpoints, ConnectHandlerCb);
    void async_handshake(HandlerCb cb);
    void async_write(BytesHandlerCb cb);
    void async_read_until(const char* delim, BytesHandlerCb cb);
    void async_read(const size_t bytes, BytesHandlerCb cb);

    void timeout(const std::chrono::seconds timeout, HandlerCb cb = {});

private:
    unsigned int id_;
    static unsigned int ids_;

    asio::io_context& ctx_;
    std::unique_ptr<socket_t> socket_;
    std::shared_ptr<asio::ssl::context> ssl_ctx_;
    std::unique_ptr<ssl_socket_t> ssl_socket_;
    std::unique_ptr<asio::const_buffer> certificate_;

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

/* @class Resolver
 * @brief The purpose is to only resolve once to avoid mutliple dns requests per operation.
 */
class OPENDHT_PUBLIC Resolver
{
public:
    using ResolverCb = std::function<void(const asio::error_code& ec,
                                          std::vector<asio::ip::tcp::endpoint> endpoints)>;

    Resolver(asio::io_context& ctx, const std::string& url, std::shared_ptr<dht::Logger> logger = {});
    Resolver(asio::io_context& ctx, const std::string& host, const std::string& service = "80",
             std::shared_ptr<dht::Logger> logger = {});

    // use already resolved endpoints with classes using this resolver
    Resolver(asio::io_context& ctx, std::vector<asio::ip::tcp::endpoint> endpoints,
             const bool ssl = false, std::shared_ptr<dht::Logger> logger = {});

    ~Resolver();

    Url get_url() const;
    std::string get_service() const;

    void add_callback(ResolverCb cb);

private:
    void resolve(const std::string host, const std::string service);

    std::mutex mutex_;

    asio::error_code ec_;
    std::string service_;
    asio::ip::tcp::resolver resolver_;
    std::vector<asio::ip::tcp::endpoint> endpoints_;
    Url url_;

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
        DONE
    };
    using OnStatusCb = std::function<void(unsigned int status_code)>;
    using OnDataCb = std::function<void(const char* at, size_t length)>;
    using OnStateChangeCb = std::function<void(const State state, const Response response)>;

    // resolves implicitly
    Request(asio::io_context& ctx, const std::string& url, std::shared_ptr<dht::Logger> logger = {});
    Request(asio::io_context& ctx, const std::string& host, const std::string& service = "80",
            std::shared_ptr<dht::Logger> logger = {});

    // user defined resolver
    Request(asio::io_context& ctx, std::shared_ptr<Resolver> resolver, std::shared_ptr<dht::Logger> logger = {});

    // user defined resolved endpoints
    Request(asio::io_context& ctx, std::vector<asio::ip::tcp::endpoint>&& endpoints,
            const bool ssl = false, std::shared_ptr<dht::Logger> logger = {});

    ~Request();

    unsigned int id() const;
    void set_connection(std::shared_ptr<Connection> connection);
    std::shared_ptr<Connection> get_connection() const;
    Url get_url() const;

    void set_certificate(std::shared_ptr<dht::crypto::Certificate> certificate);
    void set_logger(std::shared_ptr<dht::Logger> logger);

    /**
     * Define the HTTP header/body as per https://tools.ietf.org/html/rfc7230.
     */
    void set_header(const restinio::http_request_header_t header);
    void set_method(const restinio::http_method_id_t method);
    void set_target(const std::string target);
    void set_header_field(const restinio::http_field_t field, const std::string& value);
    void set_connection_type(const restinio::http_connection_header_t connection);
    void set_body(const std::string& body);

    void add_on_status_callback(OnStatusCb cb);
    void add_on_body_callback(OnDataCb cb);
    void add_on_state_change_callback(OnStateChangeCb cb);

    void send();

    /**
     * User action to cancel the Request and call the completion callbacks.
     */
    void cancel();

private:
    using OnCompleteCb = std::function<void()>;

    struct Callbacks {
        Callbacks(){}

        OnStatusCb on_status;
        OnDataCb on_header_field;
        OnDataCb on_header_value;
        OnDataCb on_body;
        OnCompleteCb on_headers_complete;
        OnCompleteCb on_message_complete;

        OnStateChangeCb on_state_change;
    };

    void notify_state_change(const State state);

    void build();

    /**
     * Initialized and wraps the http_parser callbacks with our user defined callbacks.
     */
    void init_parser();

    void connect(std::vector<asio::ip::tcp::endpoint>&& endpoints, HandlerCb cb = {});

    void terminate(const asio::error_code& ec);

    void post();

    void handle_request(const asio::error_code& ec);

    void handle_response_header(const asio::error_code& ec);

    void handle_response_body(const asio::error_code& ec, const size_t bytes);

    /**
     * Parse the request with http_parser.
     * Return how many bytes were parsed.
     * Note: we pass requerst.size()==0 to signal that EOF has been received.
     */
    size_t parse_request(const std::string request);

    restinio::http_request_header_t header_;
    std::map<restinio::http_field_t, std::string> headers_;
    restinio::http_connection_header_t connection_type_;
    std::string body_;

    std::mutex cbs_mutex_;
    std::unique_ptr<Callbacks> cbs_;
    State state_;

    std::shared_ptr<dht::crypto::Certificate> certificate_;
    std::string service_;
    std::string host_;

    unsigned int id_;
    static unsigned int ids_;
    asio::io_context& ctx_;
    std::shared_ptr<Connection> conn_;
    std::shared_ptr<Resolver> resolver_;

    Response response_ {};
    std::string request_;
    std::atomic<bool> message_complete_ {false};
    std::atomic<bool> finishing_ {false};
    std::unique_ptr<http_parser> parser_;
    std::unique_ptr<http_parser_settings> parser_s_;

    std::shared_ptr<dht::Logger> logger_;
};

} // namespace http
} // namespace dht

#ifdef OPENDHT_PROXY_HTTP_PARSER_FORK
namespace restinio
{
/* Custom HTTP-methods for RESTinio > 0.5.0.
 * https://github.com/Stiffstream/restinio/issues/26
 */
constexpr const restinio::http_method_id_t method_listen {HTTP_LISTEN, "LISTEN"};
constexpr const restinio::http_method_id_t method_stats {HTTP_STATS, "STATS"};
constexpr const restinio::http_method_id_t method_sign {HTTP_SIGN, "SIGN"};
constexpr const restinio::http_method_id_t method_encrypt {HTTP_ENCRYPT, "ENCRYPT"};
} // namespace restinio
#endif
