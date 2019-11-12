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

#include "http.h"
#include "log_enable.h"
#include "crypto.h"
#include "base64.h"

#include <asio.hpp>
#include <restinio/impl/tls_socket.hpp>
#include <http_parser.h>
#include <json/json.h>

namespace dht {
namespace http {

constexpr char HTTP_HEADER_CONNECTION[] = "Connection";
constexpr char HTTP_HEADER_CONNECTION_KEEP_ALIVE[] = "keep-alive";
constexpr char HTTP_HEADER_CONNECTION_CLOSE[] = "close";
constexpr char HTTP_HEADER_CONTENT_LENGTH[] = "Content-Length";
constexpr char HTTP_HEADER_CONTENT_TYPE[] = "Content-Type";
constexpr char HTTP_HEADER_CONTENT_TYPE_JSON[] = "application/json";
constexpr char HTTP_HEADER_TRANSFER_ENCODING[] = "Transfer-Encoding";
constexpr char HTTP_HEADER_TRANSFER_ENCODING_CHUNKED[] = "chunked";
constexpr char HTTP_HEADER_DELIM[] = "\r\n\r\n";
constexpr char BODY_VALUE_DELIM[] = "\n";

Url::Url(const std::string& url): url(url)
{
    size_t addr_begin = 0;
    // protocol
    const size_t proto_end = url.find("://");
    if (proto_end != std::string::npos){
        addr_begin = proto_end + 3;
        if (url.substr(0, proto_end) == "https"){
            protocol = "https";
            service = protocol;
        }
    }
    // host and service
    size_t addr_size = url.substr(addr_begin).find("/");
    if (addr_size == std::string::npos)
        addr_size = url.size() - addr_begin;
    auto host_service = splitPort(url.substr(addr_begin, addr_size));
    host = host_service.first;
    if (!host_service.second.empty())
        service = host_service.second;
    // target, query and fragment
    size_t query_begin = url.find("?");
    auto addr_end = addr_begin + addr_size;
    if (addr_end < url.size())
        target = url.substr(addr_end);
    size_t fragment_begin = url.find("#");
    if (fragment_begin == std::string::npos){
        query = url.substr(query_begin + 1);
    } else {
        target = url.substr(addr_end, fragment_begin - addr_end);
        query = url.substr(query_begin + 1, fragment_begin - query_begin - 1);
        fragment = url.substr(fragment_begin);
    }
}

// connection

unsigned int Connection::ids_ = 1;

Connection::Connection(asio::io_context& ctx, const bool ssl, std::shared_ptr<dht::Logger> l)
    : id_(Connection::ids_++), ctx_(ctx), logger_(l)
{
    if (ssl){
        ssl_ctx_ = std::make_shared<asio::ssl::context>(asio::ssl::context::sslv23);
        ssl_ctx_->set_default_verify_paths();
        ssl_ctx_->set_verify_mode(asio::ssl::verify_none);
        ssl_socket_ = std::make_unique<ssl_socket_t>(ctx_, ssl_ctx_);
        if (logger_)
            logger_->d("[http:client]  [connection:%i] start https session", id_);
    }
    else {
        socket_ = std::make_unique<socket_t>(ctx);
        if (logger_)
            logger_->d("[http:client]  [connection:%i] start http session", id_);
    }
}

Connection::Connection(asio::io_context& ctx, std::shared_ptr<dht::crypto::Certificate> server_ca,
                       const dht::crypto::Identity& identity, std::shared_ptr<dht::Logger> l)
    : id_(Connection::ids_++), ctx_(ctx), logger_(l)
{
    ssl_ctx_ = std::make_shared<asio::ssl::context>(asio::ssl::context::sslv23);
    ssl_ctx_->set_default_verify_paths();
    asio::error_code ec;
    if (server_ca){
        auto ca = server_ca->toString(false/*chain*/);
        ssl_ctx_->add_certificate_authority(asio::const_buffer{ca.data(), ca.size()}, ec);
        if (ec)
            throw std::runtime_error("Error adding certificate authority: " + ec.message());
        else if (logger_)
            logger_->d("[http:client]  [connection:%i] certficate authority %s", id_, server_ca->getUID().c_str());
    }
    if (identity.first){
        auto key = identity.first->serialize();
        ssl_ctx_->use_private_key(asio::const_buffer{key.data(), key.size()},
                                  asio::ssl::context::file_format::pem, ec);
        if (ec)
            throw std::runtime_error("Error setting client private key: " + ec.message());
    }
    if (identity.second){
        auto cert = identity.second->toString(true/*chain*/);
        ssl_ctx_->use_certificate_chain(asio::const_buffer{cert.data(), cert.size()}, ec);
        if (ec)
            throw std::runtime_error("Error adding client certificate: " + ec.message());
        else if (logger_)
            logger_->d("[http:client]  [connection:%i] client certificate %s", id_, identity.second->getUID().c_str());
    }
    ssl_ctx_->set_verify_mode(asio::ssl::verify_peer | asio::ssl::verify_fail_if_no_peer_cert);
    ssl_socket_ = std::make_unique<ssl_socket_t>(ctx_, ssl_ctx_);
}

Connection::~Connection()
{
    close();
}

void
Connection::close()
{
    if (!is_open())
        return;
    asio::error_code ec;
    if (ssl_socket_)
        ssl_socket_->close(ec);
    else if (socket_)
        socket_->close(ec);
    if (ec and logger_)
        logger_->e("[http:client]  [connection:%i] error closing: %s", id_, ec.message().c_str());
}

unsigned int
Connection::id()
{
    return id_;
}

bool
Connection::is_open()
{
    if (ssl_socket_)
        return ssl_socket_->is_open();
    else if (socket_)
        return socket_->is_open();
    else
        return false;
}

bool
Connection::is_ssl()
{
    return ssl_ctx_ ? true : false;
}

void
Connection::set_ssl_verification(const asio::ip::tcp::endpoint& endpoint, const asio::ssl::verify_mode verify_mode)
{
    if (ssl_socket_ and verify_mode != asio::ssl::verify_none){
        auto hostname = endpoint.address().to_string();
        ssl_socket_->asio_ssl_stream().set_verify_mode(verify_mode);
        ssl_socket_->asio_ssl_stream().set_verify_callback(
            [this, hostname](bool preverified, asio::ssl::verify_context& ctx) -> bool {
                if (preverified)
                    return preverified;
                // starts from CA and goes down the presented chain
                auto verifier = asio::ssl::rfc2818_verification(hostname);
                bool verified = verifier(preverified, ctx);
                auto verify_ec = X509_STORE_CTX_get_error(ctx.native_handle());
                if (verified != 0 /*X509_V_OK*/ and logger_)
                    logger_->e("[http::connection:%i] ssl verification error=%i", id_, verify_ec);
                return verified;
            }
        );
        if (logger_)
            logger_->d("[http:client]  [connection:%i] verify %s compliance to RFC 2818", id_, hostname.c_str());
    }
}

asio::streambuf&
Connection::input()
{
    return write_buf_;
}

asio::streambuf&
Connection::data()
{
    return read_buf_;
}

std::string
Connection::read_bytes(const size_t bytes)
{
    std::string content;
    std::istream is(&read_buf_);
    content.resize(bytes);
    auto rb = is.readsome(&content[0], bytes);
    content.resize(rb);
    return content;
}

std::string
Connection::read_until(const char delim)
{
    std::string content;
    std::istream is(&read_buf_);
    std::getline(is, content, delim);
    return content;
}

void
Connection::async_connect(std::vector<asio::ip::tcp::endpoint>&& endpoints, ConnectHandlerCb cb)
{
    if (ssl_socket_)
        asio::async_connect(ssl_socket_->lowest_layer(), std::move(endpoints), cb);
    else if (socket_)
        asio::async_connect(*socket_, std::move(endpoints), cb);
    else if (cb)
        cb(asio::error::operation_aborted, {});
}

void
Connection::async_handshake(HandlerCb cb)
{
    if (ssl_socket_)
        ssl_socket_->async_handshake(asio::ssl::stream<asio::ip::tcp::socket>::client,
                                    [this, cb](const asio::error_code& ec)
        {
            if (ec == asio::error::operation_aborted)
                return;
            auto verify_ec = SSL_get_verify_result(ssl_socket_->asio_ssl_stream().native_handle());
            if (logger_){
                if (verify_ec == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT /*18*/
                    || verify_ec == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN /*19*/)
                    logger_->d("[http:client]  [connection:%i] allow self-signed certificate in handshake", id_);
                else if (verify_ec != X509_V_OK)
                    logger_->e("[http:client]  [connection:%i] verify handshake error: %i", id_, verify_ec);
            }
            if (cb)
                cb(ec);
        });
    else if (socket_)
        cb(asio::error::no_protocol_option);
    else if (cb)
        cb(asio::error::operation_aborted);
}

void
Connection::async_write(BytesHandlerCb cb)
{
    if (!is_open())
        return;
    if (ssl_socket_)
        asio::async_write(*ssl_socket_, write_buf_, cb);
    else if (socket_)
        asio::async_write(*socket_, write_buf_, cb);
    else if (cb)
        cb(asio::error::operation_aborted, 0);
}

void
Connection::async_read_until(const char* delim, BytesHandlerCb cb)
{
    if (!is_open())
        return;
    if (ssl_socket_)
        asio::async_read_until(*ssl_socket_, read_buf_, delim, cb);
    else if (socket_)
        asio::async_read_until(*socket_, read_buf_, delim, cb);
    else if (cb)
        cb(asio::error::operation_aborted, 0);
}

void
Connection::async_read(const size_t bytes, BytesHandlerCb cb)
{
    if (!is_open())
        return;
    if (ssl_socket_)
        asio::async_read(*ssl_socket_, read_buf_, asio::transfer_exactly(bytes), cb);
    else if (socket_)
        asio::async_read(*socket_, read_buf_, asio::transfer_exactly(bytes), cb);
    else if (cb)
        cb(asio::error::operation_aborted, 0);
}

void
Connection::timeout(const std::chrono::seconds timeout, HandlerCb cb)
{
    if (!is_open()){
        if (logger_)
            logger_->e("[http:client]  [connection:%i] closed, can't timeout", id_);
        if (cb)
            cb(asio::error::operation_aborted);
        return;
    }
    if (!timeout_timer_)
        timeout_timer_ = std::make_unique<asio::steady_timer>(ctx_);
    timeout_timer_->expires_at(std::chrono::steady_clock::now() + timeout);
    timeout_timer_->async_wait([this, cb](const asio::error_code &ec){
        if (ec == asio::error::operation_aborted)
            return;
        else if (ec){
            if (logger_)
                logger_->e("[http:client]  [connection:%i] timeout error: %s", id_, ec.message().c_str());
        }
        if (cb)
            cb(ec);
    });
}

// Resolver

Resolver::Resolver(asio::io_context& ctx, const std::string& url, std::shared_ptr<dht::Logger> logger)
    : url_(url), resolver_(ctx), destroyed_(std::make_shared<bool>(false)), logger_(logger)
{
    resolve(url_.host, url_.service);
}

Resolver::Resolver(asio::io_context& ctx, const std::string& host, const std::string& service,
                   const bool ssl, std::shared_ptr<dht::Logger> logger)
    : resolver_(ctx), destroyed_(std::make_shared<bool>(false)), logger_(logger)
{
    url_.host = host;
    url_.service = service;
    url_.protocol = (ssl ? "https" : "http");
    resolve(url_.host, url_.service);
}

Resolver::Resolver(asio::io_context& ctx, std::vector<asio::ip::tcp::endpoint> endpoints, const bool ssl,
                   std::shared_ptr<dht::Logger> logger)
    : resolver_(ctx), destroyed_(std::make_shared<bool>(false)), logger_(logger)
{
    url_.protocol = (ssl ? "https" : "http");
    endpoints_ = std::move(endpoints);
    completed_ = true;
}

Resolver::~Resolver()
{
    decltype(cbs_) cbs;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        cbs = std::move(cbs_);
    }
    while (not cbs.empty()){
        auto cb = cbs.front();
        if (cb)
            cb(asio::error::operation_aborted, {});
        cbs.pop();
    }
    *destroyed_ = true;
}

inline
std::vector<asio::ip::tcp::endpoint>
filter(const std::vector<asio::ip::tcp::endpoint>& epts, sa_family_t family)
{
    if (family == AF_UNSPEC)
        return epts;
    std::vector<asio::ip::tcp::endpoint> ret;
    for (const auto& ep : epts) {
        if (family == AF_INET && ep.address().is_v4())
            ret.emplace_back(ep);
        else if (family == AF_INET6 && ep.address().is_v6())
            ret.emplace_back(ep);
    }
    return ret;
}

void
Resolver::add_callback(ResolverCb cb, sa_family_t family)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!completed_)
        cbs_.emplace(family == AF_UNSPEC ? std::move(cb) : [cb, family](const asio::error_code& ec, const std::vector<asio::ip::tcp::endpoint>& endpoints){
            if (ec)
                cb(ec, endpoints);
            else
                cb(ec, filter(endpoints, family));
        });
    else
        cb(ec_, family == AF_UNSPEC ? endpoints_ : filter(endpoints_, family));
}

void
Resolver::resolve(const std::string& host, const std::string& service)
{
    asio::ip::tcp::resolver::query query_(host, service);

    resolver_.async_resolve(query_, [this, host, service, destroyed = destroyed_]
        (const asio::error_code& ec, asio::ip::tcp::resolver::results_type endpoints)
    {
        if (ec == asio::error::operation_aborted or *destroyed)
            return;
        if (logger_){
            if (ec)
                logger_->e("[http:client] [resolver] error for %s:%s: %s",
                           host.c_str(), service.c_str(), ec.message().c_str());
        }
        decltype(cbs_) cbs;
        {
            std::lock_guard<std::mutex> lock(mutex_);
            ec_ = ec;
            endpoints_ = std::vector<asio::ip::tcp::endpoint>{endpoints.begin(), endpoints.end()};
            completed_ = true;
            cbs = std::move(cbs_);
        }
        while (not cbs.empty()){
            auto cb = cbs.front();
            if (cb)
                cb(ec, endpoints_);
            cbs.pop();
        }
    });
}

// Request

unsigned int Request::ids_ = 1;


Request::Request(asio::io_context& ctx, const std::string& url, const Json::Value& json, OnJsonCb jsoncb,
                 std::shared_ptr<dht::Logger> logger)
    : id_(Request::ids_++), ctx_(ctx),
      resolver_(std::make_shared<Resolver>(ctx, url, logger)), logger_(logger)
{
    init_default_headers();
    set_header_field(restinio::http_field_t::content_type, "application/json");
    set_header_field(restinio::http_field_t::accept, "application/json");
    Json::StreamWriterBuilder wbuilder;
    set_body(Json::writeString(wbuilder, json));
    add_on_state_change_callback([this, jsoncb](State state, const Response& response){
        if (state != Request::State::DONE)
            return;
        Json::Value json;
        std::string err;
        Json::CharReaderBuilder rbuilder;
        auto reader = std::unique_ptr<Json::CharReader>(rbuilder.newCharReader());
        if (!reader->parse(response.body.data(), response.body.data() + response.body.size(), &json, &err) and logger_)
            logger_->e("[http:client]  [request:%i] can't parse response to json", id_, err.c_str());
        if (jsoncb)
            jsoncb(json, response.status_code);
    });
}

Request::Request(asio::io_context& ctx, const std::string& url, std::shared_ptr<dht::Logger> logger)
    : id_(Request::ids_++), ctx_(ctx),
      resolver_(std::make_shared<Resolver>(ctx, url, logger)), logger_(logger)
{
    init_default_headers();
}

Request::Request(asio::io_context& ctx, const std::string& host, const std::string& service,
                 const bool ssl, std::shared_ptr<dht::Logger> logger)
    : id_(Request::ids_++), ctx_(ctx),
      resolver_(std::make_shared<Resolver>(ctx, host, service, ssl, logger)), logger_(logger)
{
    init_default_headers();
}

Request::Request(asio::io_context& ctx, std::shared_ptr<Resolver> resolver, sa_family_t family)
    : id_(Request::ids_++), ctx_(ctx), family_(family), resolver_(resolver), logger_(resolver->getLogger())
{
    init_default_headers();
}

Request::Request(asio::io_context& ctx, std::vector<asio::ip::tcp::endpoint>&& endpoints, const bool ssl,
                 std::shared_ptr<dht::Logger> logger)
    : id_(Request::ids_++), ctx_(ctx),
      resolver_(std::make_shared<Resolver>(ctx, std::move(endpoints), ssl, logger)), logger_(logger)
{
    init_default_headers();
}

Request::Request(asio::io_context& ctx, std::shared_ptr<Resolver> resolver, const std::string& target, sa_family_t family)
    : id_(Request::ids_++), ctx_(ctx), family_(family), resolver_(resolver), logger_(resolver->getLogger())
{
    set_header_field(restinio::http_field_t::host, get_url().host + ":" + get_url().service);
    set_target(target);
}

Request::~Request()
{
}

void
Request::init_default_headers()
{
    const auto& url = resolver_->get_url();
    set_header_field(restinio::http_field_t::host, url.host + ":" + url.service);
    set_target(url.target);
}

void
Request::cancel()
{
    if (auto c = conn_)
        c->close();
}

unsigned int
Request::id() const
{
    return id_;
}

void
Request::set_connection(std::shared_ptr<Connection> connection)
{
    conn_ = connection;
}

std::shared_ptr<Connection>
Request::get_connection() const
{
    return conn_;
}

void
Request::set_certificate_authority(std::shared_ptr<dht::crypto::Certificate> certificate)
{
    server_ca_ = certificate;
}

void
Request::set_identity(const dht::crypto::Identity& identity)
{
    client_identity_ = identity;
}

void
Request::set_logger(std::shared_ptr<dht::Logger> logger)
{
    logger_ = logger;
}

void
Request::set_header(restinio::http_request_header_t header)
{
    header_ = header;
}

void
Request::set_method(restinio::http_method_id_t method)
{
    header_.method(method);
}

void
Request::set_target(std::string target)
{
    header_.request_target(std::move(target));
}

void
Request::set_header_field(restinio::http_field_t field, std::string value)
{
    headers_[field] = std::move(value);
}

void
Request::set_connection_type(restinio::http_connection_header_t connection)
{
    connection_type_ = connection;
}

void
Request::set_body(std::string body)
{
    body_ = std::move(body);
}

void
Request::set_auth(const std::string& username, const std::string& password)
{
    std::vector<uint8_t> creds;
    creds.reserve(username.size() + password.size() + 1);
    creds.insert(creds.end(), username.begin(), username.end());
    creds.emplace_back(':');
    creds.insert(creds.end(), password.begin(), password.end());
    set_header_field(restinio::http_field_t::authorization, "Basic " + base64_encode(creds));
}

void
Request::build()
{
    std::stringstream request;
    bool append_body = true;

    // first header
    request << header_.method().c_str() << " " << header_.request_target() << " " <<
               "HTTP/" << header_.http_major() << "." << header_.http_minor() << "\r\n";

    // other headers
    for (auto header: headers_){
        request << restinio::field_to_string(header.first) << ": " << header.second << "\r\n";
        if (header.first == restinio::http_field_t::expect and header.second == "100-continue")
            append_body = false;
    }

    // last connection header
    std::string conn_str = "";
    switch (connection_type_){
    case restinio::http_connection_header_t::upgrade:
        if (logger_)
            logger_->e("Unsupported connection type 'upgrade', fallback to 'close'");
    // fallthrough
    case restinio::http_connection_header_t::close:
        conn_str = "close";
        break;
    case restinio::http_connection_header_t::keep_alive:
        conn_str = "keep-alive";
        break;
    }
    if (!conn_str.empty())
        request << "Connection: " << conn_str << "\r\n";

    // body & content-length
    if (!body_.empty())
        request << "Content-Length: " << body_.size() << "\r\n\r\n";
    // last delim
    if (append_body)
        request << body_ << "\r\n";
    request_ = request.str();
}

void
Request::add_on_status_callback(OnStatusCb cb)
{
    std::lock_guard<std::mutex> lock(cbs_mutex_);
    cbs_.on_status = std::move(cb);
}

void
Request::add_on_body_callback(OnDataCb cb)
{
    std::lock_guard<std::mutex> lock(cbs_mutex_);
    cbs_.on_body = std::move(cb);
}

void
Request::add_on_state_change_callback(OnStateChangeCb cb)
{
    std::lock_guard<std::mutex> lock(cbs_mutex_);
    cbs_.on_state_change = std::move(cb);
}

void
Request::notify_state_change(const State state)
{
    state_ = state;
    if (cbs_.on_state_change)
        cbs_.on_state_change(state, response_);
}

void
Request::init_parser()
{
    if (!parser_)
        parser_ = std::make_unique<http_parser>();
    http_parser_init(parser_.get(), HTTP_RESPONSE);
    parser_->data = static_cast<void*>(&cbs_);

    if (!parser_s_)
        parser_s_ = std::make_unique<http_parser_settings>();
    http_parser_settings_init(parser_s_.get());
    {
        // user registered callbacks wrappers to store its data in the response
        std::lock_guard<std::mutex> lock(cbs_mutex_);
        cbs_.on_status = [this, statusCb = std::move(cbs_.on_status)](unsigned int status_code){
            response_.status_code = status_code;
            if (statusCb)
                statusCb(status_code);
        };
        auto header_field = std::make_shared<std::string>();
        cbs_.on_header_field = [header_field, headerFieldCb = std::move(cbs_.on_header_field)](const char* at, size_t length) {
            *header_field = std::string(at, length);
            if (headerFieldCb)
                headerFieldCb(at, length);
        };
        cbs_.on_header_value = [this, header_field, headerValueCb = std::move(cbs_.on_header_value)](const char* at, size_t length) {
            response_.headers[*header_field] = std::string(at, length);
            if (headerValueCb)
                headerValueCb(at, length);
        };
        cbs_.on_headers_complete = [this](){
            notify_state_change(State::HEADER_RECEIVED);
        };
        cbs_.on_body = [bodyCb = std::move(cbs_.on_body)](const char* at, size_t length) {
            if (bodyCb)
                bodyCb(at, length);
        };
        cbs_.on_message_complete = [this](){
            if (logger_)
                logger_->d("[http:client]  [request:%i] response: message complete", id_);
            message_complete_.store(true);
        };
    }
    // http_parser raw c callback (note: no context can be passed into them)
    parser_s_->on_status = [](http_parser* parser, const char* /*at*/, size_t /*length*/) -> int {
        static_cast<Callbacks*>(parser->data)->on_status(parser->status_code);
        return 0;
    };
    parser_s_->on_header_field = [](http_parser* parser, const char* at, size_t length) -> int {
        static_cast<Callbacks*>(parser->data)->on_header_field(at, length);
        return 0;
    };
    parser_s_->on_header_value = [](http_parser* parser, const char* at, size_t length) -> int {
        static_cast<Callbacks*>(parser->data)->on_header_value(at, length);
        return 0;
    };
    parser_s_->on_body = [](http_parser* parser, const char* at, size_t length) -> int {
        static_cast<Callbacks*>(parser->data)->on_body(at, length);
        return 0;
    };
    parser_s_->on_headers_complete = [](http_parser* parser) -> int {
        static_cast<Callbacks*>(parser->data)->on_headers_complete();
        return 0;
    };
    parser_s_->on_message_complete = [](http_parser* parser) -> int {
        static_cast<Callbacks*>(parser->data)->on_message_complete();
        return 0;
    };
}

void
Request::connect(std::vector<asio::ip::tcp::endpoint>&& endpoints, HandlerCb cb)
{
    if (endpoints.empty()){
        if (logger_)
            logger_->e("[http:client]  [request:%i] connect: no endpoints provided", id_);
        if (cb)
            cb(asio::error::connection_aborted);
        return;
    }
    if (logger_){
        std::string eps = "";
        for (const auto& endpoint : endpoints)
            eps.append(endpoint.address().to_string() + " ");
        logger_->d("[http:client]  [request:%i] connect begin: %s", id_, eps.c_str());
    }
    if (get_url().protocol == "https"){
        if (server_ca_)
            conn_ = std::make_shared<Connection>(ctx_, server_ca_, client_identity_, logger_);
        else
            conn_ = std::make_shared<Connection>(ctx_, true/*ssl*/, logger_);
    }
    else
        conn_ = std::make_shared<Connection>(ctx_, false/*ssl*/, logger_);

    // try to connect to any until one works
    conn_->async_connect(std::move(endpoints), [this, cb]
                        (const asio::error_code& ec, const asio::ip::tcp::endpoint& endpoint){
        if (ec == asio::error::operation_aborted){
            terminate(ec);
            return;
        }
        else if (ec and logger_)
            logger_->e("[http:client]  [request:%i] connect: failed with all endpoints", id_);
        else {
            if (logger_)
                logger_->d("[http:client]  [request:%i] connect success", id_);

            if (get_url().protocol == "https"){
                if (server_ca_)
                    conn_->set_ssl_verification(endpoint, asio::ssl::verify_peer
                                                          | asio::ssl::verify_fail_if_no_peer_cert);

                if (conn_ and conn_->is_open() and conn_->is_ssl()){
                    conn_->async_handshake([this, cb](const asio::error_code& ec){
                        if (ec == asio::error::operation_aborted)
                            return;
                        if (ec and logger_)
                            logger_->e("[http:client]  [request:%i] handshake error: %s", id_, ec.message().c_str());
                        else if (logger_)
                            logger_->d("[http:client]  [request:%i] handshake success", id_);
                        if (cb)
                            cb(ec);
                    });
                }
                else if (cb)
                    cb(asio::error::operation_aborted);
                return;
            }
        }
        if (cb)
            cb(ec);
    });
}

void
Request::send()
{
    notify_state_change(State::CREATED);

    resolver_->add_callback([this](const asio::error_code& ec,
                                   std::vector<asio::ip::tcp::endpoint> endpoints){
        if (ec){
            if (logger_)
                logger_->e("[http:client]  [request:%i] resolve error: %s", id_, ec.message().c_str());
            terminate(asio::error::connection_aborted);
        }
        else if (!conn_ or !conn_->is_open()){
            connect(std::move(endpoints), [this](const asio::error_code &ec){
                if (ec)
                    terminate(asio::error::not_connected);
                else
                    post();
            });
        }
        else
            post();
    }, family_);
}

void
Request::post()
{
    if (!conn_ or !conn_->is_open()){
        terminate(asio::error::not_connected);
        return;
    }
    build();
    init_parser();

    if (logger_){
        std::string header; std::getline(std::istringstream(request_), header);
        logger_->d("[http:client]  [request:%i] send: %s", id_, header.c_str());
    }
    // write the request to buffer
    std::ostream request_stream(&conn_->input());
    request_stream << request_;

    // send the request
    notify_state_change(State::SENDING);
    conn_->async_write(std::bind(&Request::handle_request, this, std::placeholders::_1));
}

void
Request::terminate(const asio::error_code& ec)
{
    if (finishing_.exchange(true))
        return;

    if (ec != asio::error::eof and ec != asio::error::operation_aborted and logger_)
        logger_->e("[http:client]  [request:%i] end with error: %s", id_, ec.message().c_str());

    // set response outcome, ignore end of file and abort
    if (!ec or ec == asio::error::eof or ec == asio::error::operation_aborted)
        response_.status_code = 200;
    else
        response_.status_code = 0;

    if (logger_)
        logger_->d("[http:client]  [request:%i] done", id_);
    notify_state_change(State::DONE);
}

void
Request::handle_request(const asio::error_code& ec)
{
    if (ec and ec != asio::error::eof){
        terminate(ec);
        return;
    }
    if (!conn_->is_open()){
        terminate(asio::error::not_connected);
        return;
    }
    if (logger_)
        logger_->d("[http:client]  [request:%i] send success", id_);
    // read response
    notify_state_change(State::RECEIVING);
    conn_->async_read_until(HTTP_HEADER_DELIM, std::bind(&Request::handle_response_header,
                                                         this, std::placeholders::_1));
}

void
Request::handle_response_header(const asio::error_code& ec)
{
    if (ec && ec != asio::error::eof){
        terminate(ec);
        return;
    }
    if (!conn_->is_open()){
        terminate(asio::error::not_connected);
        return;
    }
    if (logger_)
        logger_->d("[http:client]  [request:%i] response headers received", id_);
    // read the header
    std::string header;
    std::string headers;
    std::istream is(&conn_->data());
    while (std::getline(is, header) && header != "\r"){
        headers.append(header + "\n");
    }
    headers.append("\n");
    parse_request(headers);

    if (headers_[restinio::http_field_t::expect] == "100-continue" and response_.status_code != 200){
        notify_state_change(State::SENDING);
        request_.append(body_);
        std::ostream request_stream(&conn_->input());
        request_stream << body_ << "\r\n";
        conn_->async_write(std::bind(&Request::handle_request, this, std::placeholders::_1));
        return;
    }

    // avoid creating non-existant headers by accessing the headers map without the presence of key
    auto connection_it = response_.headers.find(HTTP_HEADER_CONNECTION);
    auto content_length_it = response_.headers.find(HTTP_HEADER_CONTENT_LENGTH);
    auto transfer_encoding_it = response_.headers.find(HTTP_HEADER_TRANSFER_ENCODING);

    // has content-length
    if (content_length_it != response_.headers.end())
    {
        unsigned int content_length = atoi(content_length_it->second.c_str());
        response_.body.append(conn_->read_bytes(content_length));
        // full body already in the header
        if (response_.body.size() + 1 == content_length) {
            response_.body.append("\n");
            parse_request(response_.body);
            if (message_complete_.load())
                terminate(asio::error::eof);
        }
        else { // more chunks to come (don't add the missing \n from std::getline)
            conn_->async_read(content_length - response_.body.size(),
                std::bind(&Request::handle_response_body, this, std::placeholders::_1, std::placeholders::_2));
        }
    }
    // server wants to keep sending or we have content-length defined
    else if (connection_it != response_.headers.end() and connection_it->second == HTTP_HEADER_CONNECTION_KEEP_ALIVE)
    {
        conn_->async_read_until(BODY_VALUE_DELIM,
            std::bind(&Request::handle_response_body, this, std::placeholders::_1, std::placeholders::_2));
    }
    // server wants to close the connection
    else if (connection_it != response_.headers.end() and connection_it->second == HTTP_HEADER_CONNECTION_CLOSE)
    {
        terminate(asio::error::eof);
    }
    // client wants to close the connection
    else if (connection_type_ == restinio::http_connection_header_t::close)
    {
        terminate(asio::error::eof);
    }
    else if (transfer_encoding_it != response_.headers.end() and
             transfer_encoding_it->second == HTTP_HEADER_TRANSFER_ENCODING_CHUNKED)
    {
        std::string chunk_size;
        std::getline(is, chunk_size);
        unsigned int content_length = std::stoul(chunk_size, nullptr, 16);
        conn_->async_read(content_length,
            std::bind(&Request::handle_response_body, this, std::placeholders::_1, std::placeholders::_2));
    }
}

void
Request::handle_response_body(const asio::error_code& ec, const size_t bytes)
{
    if (ec && ec != asio::error::eof){
        terminate(ec);
        return;
    }
    if (!conn_->is_open()){
        terminate(asio::error::not_connected);
        return;
    }
    if (logger_)
        logger_->d("[http:client]  [request:%i] response body: %i bytes received", id_, bytes);

    if (bytes == 0){
        terminate(asio::error::eof);
        return;
    }

    // avoid creating non-existant headers by accessing the headers map without the presence of key
    auto connection_it = response_.headers.find(HTTP_HEADER_CONNECTION);
    auto content_length_it = response_.headers.find(HTTP_HEADER_CONTENT_LENGTH);
    auto transfer_encoding_it = response_.headers.find(HTTP_HEADER_TRANSFER_ENCODING);

    // read the content-length body
    unsigned int content_length;
    if (content_length_it != response_.headers.end() and !response_.body.empty()){
        // extract the content-length
        content_length = atoi(content_length_it->second.c_str());
        response_.body.append(conn_->read_bytes(bytes));
        // check if fully parsed
        if (response_.body.size() == content_length)
            parse_request(response_.body);
    }
    // read and parse the chunked encoding fragment
    else {
        auto body = conn_->read_until(BODY_VALUE_DELIM[0]);
        response_.body += body;
        if (body == "0\r\n"){
            parse_request(response_.body);
            terminate(asio::error::eof);
            return;
        }
        parse_request(body + '\n');
    }

    // should be executed after each parse_request who can trigger http_parser on_message_complete
    if (message_complete_.load()){
        terminate(asio::error::eof);
    }
    // has content-length
    else if (content_length_it != response_.headers.end() and response_.body.size() != content_length)
    {
        conn_->async_read(content_length - response_.body.size(),
            std::bind(&Request::handle_response_body, this, std::placeholders::_1, std::placeholders::_2));
    }
    // server wants to keep sending
    else if (connection_it != response_.headers.end() and connection_it->second == HTTP_HEADER_CONNECTION_KEEP_ALIVE)
    {
        conn_->async_read_until(BODY_VALUE_DELIM,
            std::bind(&Request::handle_response_body, this, std::placeholders::_1, std::placeholders::_2));
    }
    // server wants to close the connection
    else if (connection_it != response_.headers.end() and connection_it->second == HTTP_HEADER_CONNECTION_CLOSE)
    {
        terminate(asio::error::eof);
    }
    // client wants to close the connection
    else if (connection_type_ == restinio::http_connection_header_t::close)
    {
        terminate(asio::error::eof);
    }
    else if (transfer_encoding_it != response_.headers.end() and
             transfer_encoding_it->second == HTTP_HEADER_TRANSFER_ENCODING_CHUNKED)
    {
        std::istream is(&conn_->data());
        std::string chunk_size;
        std::getline(is, chunk_size);
        if (chunk_size.size() == 0){
            parse_request(response_.body);
            terminate(asio::error::eof);
        }
        else
            conn_->async_read_until(BODY_VALUE_DELIM,
                std::bind(&Request::handle_response_body, this, std::placeholders::_1, std::placeholders::_2));
    }
}

size_t
Request::parse_request(const std::string& request)
{
    std::lock_guard<std::mutex> lock(cbs_mutex_);
    return http_parser_execute(parser_.get(), parser_s_.get(), request.c_str(), request.size());
}

} // namespace http
} // namespace dht
