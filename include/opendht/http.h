/*
 *  Copyright (C) 2014-2020 Savoir-faire Linux Inc.
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
#include "crypto.h"

// some libraries may try to redefine snprintf
// but restinio will use it in std namespace
#ifdef _MSC_VER
#   undef snprintf
#   define snprintf snprintf
#endif

#include <asio/ssl/context.hpp>
#include <restinio/http_headers.hpp>
#include <restinio/message_builders.hpp>

#include <memory>
#include <queue>
#include <mutex>

namespace Json {
class Value;
}

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
struct Certificate;
}

namespace http {

using HandlerCb = std::function<void(const asio::error_code& ec)>;
using BytesHandlerCb = std::function<void(const asio::error_code& ec, size_t bytes)>;
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
    std::string fragment;
};

class OPENDHT_PUBLIC Connection : public std::enable_shared_from_this<Connection>
{
public:
    Connection(asio::io_context& ctx, const bool ssl = true, std::shared_ptr<dht::Logger> l = {});
    Connection(asio::io_context& ctx, std::shared_ptr<dht::crypto::Certificate> server_ca,
               const dht::crypto::Identity& identity, std::shared_ptr<dht::Logger> l = {});
    ~Connection();

    inline unsigned int id() const { return  id_; };
    bool is_open() const;
    bool is_ssl() const;

    void set_ssl_verification(const asio::ip::tcp::endpoint& endpoint, const asio::ssl::verify_mode verify_mode);

    asio::streambuf& input();
    std::istream& data() { return istream_; }

    std::string read_bytes(size_t bytes = 0);
    std::string read_until(const char delim);

    void async_connect(std::vector<asio::ip::tcp::endpoint>&& endpoints, ConnectHandlerCb);
    void async_handshake(HandlerCb cb);
    void async_write(BytesHandlerCb cb);
    void async_read_until(const char* delim, BytesHandlerCb cb);
    void async_read_until(char delim, BytesHandlerCb cb);
    void async_read(size_t bytes, BytesHandlerCb cb);
    void async_read_some(size_t bytes, BytesHandlerCb cb);

    void timeout(const std::chrono::seconds timeout, HandlerCb cb = {});
    void close();

private:

    template<typename T>
    T wrapCallabck(T cb) const {
        return [t=shared_from_this(),cb=std::move(cb)](auto ...params) {
            cb(params...);
        };
    }

    mutable std::mutex mutex_;

    unsigned int id_;
    static std::atomic_uint ids_;

    asio::io_context& ctx_;
    std::unique_ptr<socket_t> socket_;
    std::shared_ptr<asio::ssl::context> ssl_ctx_;
    std::unique_ptr<ssl_socket_t> ssl_socket_;

    asio::ip::tcp::endpoint endpoint_;

    asio::streambuf write_buf_;
    asio::streambuf read_buf_;
    std::istream istream_;

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
                                          const std::vector<asio::ip::tcp::endpoint>& endpoints)>;

    Resolver(asio::io_context& ctx, const std::string& url, std::shared_ptr<dht::Logger> logger = {});
    Resolver(asio::io_context& ctx, const std::string& host, const std::string& service,
             const bool ssl = false, std::shared_ptr<dht::Logger> logger = {});

    // use already resolved endpoints with classes using this resolver
    Resolver(asio::io_context& ctx, std::vector<asio::ip::tcp::endpoint> endpoints,
             const bool ssl = false, std::shared_ptr<dht::Logger> logger = {});
    Resolver(asio::io_context& ctx, const std::string& url, std::vector<asio::ip::tcp::endpoint> endpoints,
            std::shared_ptr<dht::Logger> logger = {});

    ~Resolver();

    inline const Url& get_url() const {
        return url_;
    }

    void add_callback(ResolverCb cb, sa_family_t family = AF_UNSPEC);

    std::shared_ptr<Logger> getLogger() const {
        return logger_;
    }

private:
    void resolve(const std::string& host, const std::string& service);

    mutable std::mutex mutex_;

    Url url_;
    asio::error_code ec_;
    asio::ip::tcp::resolver resolver_;
    std::shared_ptr<bool> destroyed_;
    std::vector<asio::ip::tcp::endpoint> endpoints_;

    bool completed_ {false};
    std::queue<ResolverCb> cbs_;

    std::shared_ptr<dht::Logger> logger_;
};

class Request;

struct Response
{
    unsigned status_code {0};
    std::map<std::string, std::string> headers;
    std::string body;
    bool aborted {false};
    std::weak_ptr<Request> request;
};

class OPENDHT_PUBLIC Request : public std::enable_shared_from_this<Request>
{
public:
    enum class State {
        CREATED,
        SENDING,
        HEADER_RECEIVED,
        RECEIVING,
        DONE
    };
    using OnStatusCb = std::function<void(unsigned status_code)>;
    using OnDataCb = std::function<void(const char* at, size_t length)>;
    using OnStateChangeCb = std::function<void(State state, const Response& response)>;
    using OnJsonCb = std::function<void(Json::Value value, unsigned status_code)>;
    using OnDoneCb = std::function<void(const Response& response)>;

    // resolves implicitly
    Request(asio::io_context& ctx, const std::string& url, const Json::Value& json, OnJsonCb jsoncb,
            std::shared_ptr<dht::Logger> logger = {});
    Request(asio::io_context& ctx, const std::string& url, std::shared_ptr<dht::Logger> logger = {});
    Request(asio::io_context& ctx, const std::string& host, const std::string& service,
            const bool ssl = false, std::shared_ptr<dht::Logger> logger = {});
    Request(asio::io_context& ctx, const std::string& url, OnDoneCb onDone, std::shared_ptr<dht::Logger> logger = {});

    // user defined resolver
    Request(asio::io_context& ctx, std::shared_ptr<Resolver> resolver, sa_family_t family = AF_UNSPEC);
    Request(asio::io_context& ctx, std::shared_ptr<Resolver> resolver, const std::string& target, sa_family_t family = AF_UNSPEC);

    // user defined resolved endpoints
    Request(asio::io_context& ctx, std::vector<asio::ip::tcp::endpoint>&& endpoints,
            const bool ssl = false, std::shared_ptr<dht::Logger> logger = {});

    ~Request();

    inline unsigned int id() const { return  id_; };
    void set_connection(std::shared_ptr<Connection> connection);
    std::shared_ptr<Connection> get_connection() const;
    inline const Url& get_url() const {
        return resolver_->get_url();
    };

    /** The previous request in case of redirect following */
    std::shared_ptr<Request> getPrevious() const {
        return prev_.lock();
    }

    inline std::string& to_string() {
        return request_;
    }

    void set_certificate_authority(std::shared_ptr<dht::crypto::Certificate> certificate);
    void set_identity(const dht::crypto::Identity& identity);
    void set_logger(std::shared_ptr<dht::Logger> logger);

    /**
     * Define the HTTP header/body as per https://tools.ietf.org/html/rfc7230.
     */
    void set_header(restinio::http_request_header_t header);
    void set_method(restinio::http_method_id_t method);
    void set_target(std::string target);
    void set_header_field(restinio::http_field_t field, std::string value);
    void set_connection_type(restinio::http_connection_header_t connection);
    void set_body(std::string body);
    void set_auth(const std::string& username, const std::string& password);

    void add_on_status_callback(OnStatusCb cb);
    void add_on_body_callback(OnDataCb cb);
    void add_on_state_change_callback(OnStateChangeCb cb);
    void add_on_done_callback(OnDoneCb cb);

    void send();

    /**
     * User action to cancel the Request and call the completion callbacks.
     */
    void cancel();

private:
    using OnCompleteCb = std::function<void()>;

    struct Callbacks {
        OnStatusCb on_status;
        OnDataCb on_header_field;
        OnDataCb on_header_value;
        OnDataCb on_body;
        OnStateChangeCb on_state_change;
    };

    void notify_state_change(State state);

    void build();

    void init_default_headers();
    /**
     * Initialized and wraps the http_parser callbacks with our user defined callbacks.
     */
    void init_parser();

    void connect(std::vector<asio::ip::tcp::endpoint>&& endpoints, HandlerCb cb = {});

    void terminate(const asio::error_code& ec);

    void post();

    void handle_request(const asio::error_code& ec);
    void handle_response(const asio::error_code& ec, size_t bytes);

    void onHeadersComplete();
    void onBody(const char* at, size_t length);
    void onComplete();

    mutable std::mutex mutex_;

    std::shared_ptr<dht::Logger> logger_;

    restinio::http_request_header_t header_;
    std::map<restinio::http_field_t, std::string> headers_;
    restinio::http_connection_header_t connection_type_ {restinio::http_connection_header_t::close};
    std::string body_;

    Callbacks cbs_;
    State state_;

    dht::crypto::Identity client_identity_;
    std::shared_ptr<dht::crypto::Certificate> server_ca_;
    std::string service_;
    std::string host_;

    unsigned int id_;
    static std::atomic_uint ids_;
    asio::io_context& ctx_;
    sa_family_t family_ = AF_UNSPEC;
    std::shared_ptr<Connection> conn_;
    std::shared_ptr<Resolver> resolver_;

    Response response_ {};
    std::string request_;
    std::atomic<bool> finishing_ {false};
    std::unique_ptr<http_parser> parser_;
    std::unique_ptr<http_parser_settings> parser_s_;

    // Next request in case of redirect following
    std::shared_ptr<Request> next_;
    std::weak_ptr<Request> prev_;
    unsigned num_redirect {0};
    bool follow_redirect {true};
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
