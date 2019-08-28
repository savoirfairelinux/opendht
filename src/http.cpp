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

#include <restinio/impl/tls_socket.hpp>
#include <http_parser.h>

namespace dht {
namespace http {

constexpr char HTTP_HEADER_CONNECTION[] = "Connection";
constexpr char HTTP_HEADER_CONNECTION_KEEP_ALIVE[] = "keep-alive";
constexpr char HTTP_HEADER_CONTENT_LENGTH[] = "Content-Length";
constexpr char HTTP_HEADER_CONTENT_TYPE[] = "Content-Type";
constexpr char HTTP_HEADER_CONTENT_TYPE_JSON[] = "application/json";
constexpr char HTTP_HEADER_DELIM[] = "\r\n\r\n";
constexpr char JSON_VALUE_DELIM[] = "\n";

Url::Url(const std::string& url): url(url)
{
    size_t addr_begin = 0;
    // protocol
    const size_t proto_end = url.find("://");
    if (proto_end != std::string::npos){
        addr_begin = proto_end + 3;
        if (url.substr(0, proto_end) == "https")
            protocol = "https";
    }
    // host and service
    size_t addr_size = url.substr(addr_begin).find("/");
    if (addr_size == std::string::npos)
        addr_size = url.size() - addr_begin;
    auto host_service = splitPort(url.substr(addr_begin, addr_size));
    host = host_service.first;
    if (!host_service.second.empty())
        service = host_service.second;
    // target, query
    size_t query_begin = url.find("?");
    auto addr_end = addr_begin + addr_size;
    if (addr_end < url.size()){
        if (query_begin == std::string::npos)
            target = url.substr(addr_end);
        else
            target = url.substr(addr_end, query_begin - addr_end);
    }
    query = url.substr(query_begin + 1);
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

Connection::Connection(asio::io_context& ctx, std::shared_ptr<dht::crypto::Certificate> certificate,
                       std::shared_ptr<dht::Logger> l)
    : id_(Connection::ids_++), ctx_(ctx), logger_(l)
{
    ssl_ctx_ = std::make_shared<asio::ssl::context>(asio::ssl::context::sslv23);
    ssl_ctx_->set_default_verify_paths();

    asio::error_code ec;
    auto cert = certificate->toString(false/*chain*/);
    certificate_ = std::make_unique<asio::const_buffer>(static_cast<const void*>(cert.data()),
                                                       (std::size_t) cert.size());
    ssl_ctx_->use_certificate(*certificate_, asio::ssl::context::file_format::pem, ec);
    if (ec)
        throw std::runtime_error("Error setting certificate: " + ec.message());
    else if (logger_)
        logger_->d("[http:client]  [connection:%i] start https session with %s", id_, certificate->getUID().c_str());

    ssl_ctx_->set_verify_mode(asio::ssl::verify_peer | asio::ssl::verify_fail_if_no_peer_cert);
    ssl_socket_ = std::make_unique<ssl_socket_t>(ctx_, ssl_ctx_);
}

Connection::~Connection()
{
    asio::error_code ec;
    if (is_open()){
        if (ssl_ctx_){
            ssl_socket_->cancel(ec);
            ssl_socket_->close(ec);
        }
        else {
            socket_->cancel(ec);
            socket_->close(ec);
        }
        if (ec and logger_)
            logger_->e("[http:client]  [connection:%i] error closing: %s", id_, ec.message().c_str());
    }
}

unsigned int
Connection::id()
{
    return id_;
}

bool
Connection::is_open()
{
    if (ssl_ctx_)
        return ssl_socket_->is_open();
    else
        return socket_->is_open();
}

bool
Connection::is_v6()
{
    return endpoint_.address().is_v6();
}

bool
Connection::is_ssl()
{
    return ssl_ctx_ ? true : false;
}

void
Connection::set_endpoint(const asio::ip::tcp::endpoint& endpoint, const asio::ssl::verify_mode verify_mode)
{
    endpoint_ = endpoint;
    if (ssl_ctx_ and verify_mode != asio::ssl::verify_none){
        auto hostname = endpoint_.address().to_string();
        ssl_socket_->asio_ssl_stream().set_verify_mode(verify_mode);
        ssl_socket_->asio_ssl_stream().set_verify_callback(
            [this, hostname](bool preverified, asio::ssl::verify_context& ctx) -> bool
            {
                // extract cert info prior to verification
                char subject_name[256];
                X509* cert = X509_STORE_CTX_get_current_cert(ctx.native_handle());
                X509_NAME_oneline(X509_get_subject_name(cert), subject_name, 256);
                if (logger_)
                    logger_->d("[http:client]  [connection:%i] verify certificate: %s", id_, subject_name);
                // run the verification
                auto verifier = asio::ssl::rfc2818_verification(hostname);
                bool verified = verifier(preverified, ctx);
                // post verification, codes: https://www.openssl.org/docs/man1.0.2/man1/verify.html
                auto verify_ec = X509_STORE_CTX_get_error(ctx.native_handle());
                if (verify_ec == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN /*19*/)
                    verified = true;
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
    std::ostringstream str_s;
    str_s << &read_buf_;
    return str_s.str().substr(0, bytes);
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
    if (ssl_ctx_)
        asio::async_connect(ssl_socket_->lowest_layer(), std::move(endpoints), cb);
    else
        asio::async_connect(*socket_, std::move(endpoints), cb);
}

void
Connection::async_handshake(HandlerCb cb)
{
    if (ssl_ctx_)
        ssl_socket_->async_handshake(asio::ssl::stream<asio::ip::tcp::socket>::client,
                                    [this, cb](const asio::error_code& ec)
        {
            if (ec == asio::error::operation_aborted)
                return;
            auto verify_ec = SSL_get_verify_result(ssl_socket_->asio_ssl_stream().native_handle());
            if (verify_ec == X509_V_ERR_SELF_SIGNED_CERT_IN_CHAIN /*19*/ and logger_)
                logger_->d("[http:client]  [connection:%i] allow self-signed certificate in handshake", id_);
            else if (verify_ec != X509_V_OK and logger_)
                logger_->e("[http:client]  [connection:%i] verify handshake error: %i", id_, verify_ec);
            if (cb)
                cb(ec);
        });
    else if (socket_)
        cb(asio::error::no_protocol_option);
}

void
Connection::async_write(BytesHandlerCb cb)
{
    if (!is_open())
        return;
    if (ssl_ctx_)
        asio::async_write(*ssl_socket_, write_buf_, cb);
    else
        asio::async_write(*socket_, write_buf_, cb);
}

void
Connection::async_read_until(const char* delim, BytesHandlerCb cb)
{
    if (!is_open())
        return;
    if (ssl_ctx_)
        asio::async_read_until(*ssl_socket_, read_buf_, delim, cb);
    else
        asio::async_read_until(*socket_, read_buf_, delim, cb);
}

void
Connection::async_read(const size_t bytes, BytesHandlerCb cb)
{
    if (!is_open())
        return;
    if (ssl_socket_)
        asio::async_read(*ssl_socket_, read_buf_, asio::transfer_exactly(bytes), cb);
    else
        asio::async_read(*socket_, read_buf_, asio::transfer_exactly(bytes), cb);
}

void
Connection::timeout(const std::chrono::seconds timeout, HandlerCb cb)
{
    if (!is_open()){
        if (logger_)
            logger_->e("[http:client]  [connection:%i] closed, can't timeout", id_);
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
    : resolver_(ctx), logger_(logger)
{
    dht::http::Url http_url(url);
    service_ = http_url.service;
    resolve(http_url.host, http_url.service);
}

Resolver::Resolver(asio::io_context& ctx, const std::string& host, const std::string& service,
                   std::shared_ptr<dht::Logger> logger)
    : resolver_(ctx), logger_(logger)
{
    service_ = service;
    resolve(host, service);
}

Resolver::Resolver(asio::io_context& ctx, std::vector<asio::ip::tcp::endpoint> endpoints,
                   std::shared_ptr<dht::Logger> logger)
    : resolver_(ctx), logger_(logger)
{
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
}

std::string
Resolver::get_service() const
{
    return service_;
}

void
Resolver::add_callback(ResolverCb cb)
{
    std::lock_guard<std::mutex> lock(mutex_);
    if (!completed_)
        cbs_.push(std::move(cb));
    else
        cb(ec_, endpoints_);
}

void
Resolver::resolve(const std::string host, const std::string service)
{
    asio::ip::tcp::resolver::query query_(host, service);

    resolver_.async_resolve(query_, [this, host, service]
        (const asio::error_code& ec, asio::ip::tcp::resolver::results_type endpoints)
    {
        if (ec == asio::error::operation_aborted)
            return;
        if (logger_){
            if (ec)
                logger_->e("[http:client]  [resolver] error for %s:%s: %s",
                           host.c_str(), service.c_str(), ec.message().c_str());
            else {
                for (auto it = endpoints.begin(); it != endpoints.end(); ++it){
                    asio::ip::tcp::endpoint endpoint = *it;
                    logger_->d("[http:client]  [resolver] %s:%s endpoint (ipv%i): %s",
                        host.c_str(), service.c_str(), endpoint.address().is_v6() ? 6 : 4,
                        endpoint.address().to_string().c_str());
                }
            }
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

Request::Request(asio::io_context& ctx, const std::string& host, const std::string& service,
                 std::shared_ptr<dht::Logger> logger)
    : id_(Request::ids_++), ctx_(ctx), logger_(logger)
{
    cbs_ = std::make_unique<Callbacks>();
    resolver_ = std::make_shared<Resolver>(ctx, host, service, logger_);
}

Request::Request(asio::io_context& ctx, std::shared_ptr<Resolver> resolver, std::shared_ptr<dht::Logger> logger)
    : id_(Request::ids_++), ctx_(ctx), logger_(logger)
{
    cbs_ = std::make_unique<Callbacks>();
    resolver_ = resolver;
}

Request::Request(asio::io_context& ctx, std::vector<asio::ip::tcp::endpoint>&& endpoints,
                 std::shared_ptr<dht::Logger> logger)
    : id_(Request::ids_++), ctx_(ctx), logger_(logger)
{
    cbs_ = std::make_unique<Callbacks>();
    resolver_ = std::make_shared<Resolver>(ctx, std::move(endpoints), logger_);
}

Request::~Request()
{
}

void
Request::cancel()
{
    terminate(asio::error::eof);
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
Request::set_certificate(std::shared_ptr<dht::crypto::Certificate> certificate)
{
    certificate_ = certificate;
}

void
Request::set_logger(std::shared_ptr<dht::Logger> logger)
{
    logger_ = logger;
}

void
Request::set_header(const restinio::http_request_header_t header)
{
    header_ = header;
}

void
Request::set_method(const restinio::http_method_id_t method)
{
    header_.method(method);
}

void
Request::set_target(const std::string target)
{
    header_.request_target(target);
}

void
Request::set_header_field(const restinio::http_field_t field, const std::string& value)
{
    headers_[field] = value;
}

void
Request::set_connection_type(const restinio::http_connection_header_t connection)
{
    connection_type_ = connection;
}

void
Request::set_body(const std::string& body)
{
    body_ = body;
}

void
Request::build()
{
    std::stringstream request;

    // first header
    request << header_.method().c_str() << " " << header_.request_target() << " " <<
               "HTTP/" << header_.http_major() << "." << header_.http_minor() << "\r\n";

    // other headers
    for (auto header: headers_)
        request << restinio::field_to_string(header.first) << ": " << header.second << "\r\n";

    // last connection header
    std::string conn_str = "";
    switch (connection_type_){
    case restinio::http_connection_header_t::upgrade:
        throw std::invalid_argument("upgrade");
        break;
    case restinio::http_connection_header_t::keep_alive:
        conn_str = "keep-alive";
        break;
    case restinio::http_connection_header_t::close:
        conn_str = "close";
        connection_type_ = restinio::http_connection_header_t::close;
    }
    if (!conn_str.empty())
        request << "Connection: " << conn_str << "\r\n";

    // body & content-length
    if (!body_.empty()){
        request << "Content-Length: " << body_.size() << "\r\n\r\n";
        request << body_;
    }

    // last delim
    request << "\r\n";
    request_ = request.str();
}

void
Request::add_on_status_callback(OnStatusCb cb)
{
    std::lock_guard<std::mutex> lock(cbs_mutex_);
    cbs_->on_status = std::move(cb);
}

void
Request::add_on_body_callback(OnDataCb cb)
{
    std::lock_guard<std::mutex> lock(cbs_mutex_);
    cbs_->on_body = std::move(cb);
}

void
Request::add_on_state_change_callback(OnStateChangeCb cb)
{
    std::lock_guard<std::mutex> lock(cbs_mutex_);
    cbs_->on_state_change = std::move(cb);
}

void
Request::notify_state_change(const State state)
{
    state_ = state;
    if (cbs_->on_state_change)
        cbs_->on_state_change(state, response_);
}

void
Request::init_parser()
{
    if (!parser_)
        parser_ = std::make_unique<http_parser>();
    http_parser_init(parser_.get(), HTTP_RESPONSE);
    parser_->data = static_cast<void*>(cbs_.get());

    if (!parser_s_)
        parser_s_ = std::make_unique<http_parser_settings>();
    http_parser_settings_init(parser_s_.get());
    {
        // user registered callbacks wrappers to store its data in the response
        std::lock_guard<std::mutex> lock(cbs_mutex_);
        auto on_status_cb = cbs_->on_status;
        cbs_->on_status = [this, on_status_cb](unsigned int status_code){
            response_.status_code = status_code;
            if (on_status_cb)
                on_status_cb(status_code);
        };
        auto header_field = std::make_shared<std::string>("");
        auto on_header_field_cb = cbs_->on_header_field;
        cbs_->on_header_field = [this, header_field, on_header_field_cb](const char* at, size_t length){
            header_field->erase();
            auto field = std::string(at, length);
            header_field->append(field);
            if (on_header_field_cb)
                on_header_field_cb(at, length);
        };
        auto on_header_value_cb = cbs_->on_header_value;
        cbs_->on_header_value = [this, header_field, on_header_value_cb](const char* at, size_t length){
            response_.headers[*header_field] = std::string(at, length);
            if (on_header_value_cb)
                on_header_value_cb(at, length);
        };
        cbs_->on_headers_complete = [this](){
            notify_state_change(State::HEADER_RECEIVED);
        };
        auto on_body_cb = cbs_->on_body;
        cbs_->on_body = [this, on_body_cb](const char* at, size_t length){
            auto content = std::string(at, length);
            if (on_body_cb)
                on_body_cb(at, length);
        };
        cbs_->on_message_complete = [this](){
            message_complete_.store(true);
        };
    }
    // http_parser raw c callback (note: no context can be passed into them)
    parser_s_->on_status = [](http_parser* parser, const char* /*at*/, size_t /*length*/) -> int {
        auto cbs = static_cast<Callbacks*>(parser->data);
        if (cbs->on_status)
            cbs->on_status(parser->status_code);
        return 0;
    };
    parser_s_->on_header_field = [](http_parser* parser, const char* at, size_t length) -> int {
        auto cbs = static_cast<Callbacks*>(parser->data);
        if (cbs->on_header_field)
            cbs->on_header_field(at, length);
        return 0;
    };
    parser_s_->on_header_value = [](http_parser* parser, const char* at, size_t length) -> int {
        auto cbs = static_cast<Callbacks*>(parser->data);
        if (cbs->on_header_value)
            cbs->on_header_value(at, length);
        return 0;
    };
    parser_s_->on_body = [](http_parser* parser, const char* at, size_t length) -> int {
        auto cbs = static_cast<Callbacks*>(parser->data);
        if (cbs->on_body)
            cbs->on_body(at, length);
        return 0;
    };
    parser_s_->on_headers_complete = [](http_parser* parser) -> int {
        auto cbs = static_cast<Callbacks*>(parser->data);
        if (cbs->on_headers_complete)
            cbs->on_headers_complete();
        return 0;
    };
    parser_s_->on_message_complete = [](http_parser* parser) -> int {
        auto cbs = static_cast<Callbacks*>(parser->data);
        if (cbs->on_message_complete)
            cbs->on_message_complete();
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
        for (auto& endpoint : endpoints)
            eps.append(endpoint.address().to_string() + " ");
        logger_->d("[http:client]  [request:%i] connect begin: %s", id_, eps.c_str());
    }
    if (certificate_)
        conn_ = std::make_shared<Connection>(ctx_, certificate_, logger_);
    else if (resolver_->get_service() == "https" or resolver_->get_service() == "443")
        conn_ = std::make_shared<Connection>(ctx_, true/*ssl*/, logger_);
    else
        conn_ = std::make_shared<Connection>(ctx_, false/*ssl*/, logger_);

    // try to connect to any until one works
    conn_->async_connect(std::move(endpoints), [this, cb]
                        (const asio::error_code& ec, const asio::ip::tcp::endpoint& endpoint){
        if (ec == asio::error::operation_aborted)
            return;
        else if (ec and logger_)
            logger_->e("[http:client]  [request:%i] connect: failed with all endpoints", id_);
        else {
            if (logger_)
                logger_->d("[http:client]  [request:%i] connect success", id_);

            if (!certificate_)
                conn_->set_endpoint(endpoint, asio::ssl::verify_none);
            else
                conn_->set_endpoint(endpoint, asio::ssl::verify_peer
                                              | asio::ssl::verify_fail_if_no_peer_cert);
            if (conn_->is_ssl()){
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
                if (ec == asio::error::operation_aborted)
                    return;
                else if (ec)
                    terminate(asio::error::not_connected);
                else
                    post();
            });
        }
        else
            post();
    });
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
    if (finishing_.load())
        return;

    if (ec != asio::error::eof and ec != asio::error::operation_aborted and logger_)
        logger_->e("[http:client]  [request:%i] end with error: %s", id_, ec.message().c_str());

    finishing_.store(true);

    // reset the http_parser holding the data pointer to the user callbacks
    parser_.reset();
    parser_s_.reset();

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
    if (ec == asio::error::operation_aborted)
        return;
    else if (ec and ec != asio::error::eof){
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
    if (ec == asio::error::operation_aborted)
        return;
    else if ((ec == asio::error::eof) or (ec == asio::error::connection_reset)){
        terminate(ec);
        return;
    }
    else if ((ec == asio::error::eof) || (ec == asio::error::connection_reset)){
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
    // parse the headers
    parse_request(headers);

    // has content-length
    auto content_length_it = response_.headers.find(HTTP_HEADER_CONTENT_LENGTH);
    if (content_length_it != response_.headers.end())
    {
        std::getline(is, response_.body);
        unsigned int content_length = atoi(content_length_it->second.c_str());
        // full body already in the header
        if ((response_.body.size() + 1) == (content_length)){
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
    else if (response_.headers[HTTP_HEADER_CONNECTION] == HTTP_HEADER_CONNECTION_KEEP_ALIVE)
    {
        conn_->async_read_until(JSON_VALUE_DELIM,
            std::bind(&Request::handle_response_body, this, std::placeholders::_1, std::placeholders::_2));
    }
    else if (connection_type_ == restinio::http_connection_header_t::close)
        terminate(asio::error::eof);
}

void
Request::handle_response_body(const asio::error_code& ec, const size_t bytes)
{
    if (ec == asio::error::operation_aborted)
        return;
    else if ((ec == asio::error::eof) or (ec == asio::error::connection_reset)){
        terminate(ec);
        return;
    }
    else if (ec && ec != asio::error::eof){
        terminate(ec);
        return;
    }
    if (!conn_->is_open()){
        terminate(asio::error::not_connected);
        return;
    }
    if (logger_)
        logger_->d("[http:client]  [request:%i] response body: %i bytes received", id_, bytes);

    unsigned int content_length;
    auto content_length_it = response_.headers.find(HTTP_HEADER_CONTENT_LENGTH);

    // read the content-length body
    if (content_length_it != response_.headers.end() and !response_.body.empty()){
        response_.body.append(conn_->read_bytes(bytes));
        // extract the content-length
        content_length = atoi(content_length_it->second.c_str());
        // check if fully parsed
        if (response_.body.size() == content_length)
            parse_request(response_.body);
    }
    // read and parse the chunked encoding fragment
    else {
        auto body = conn_->read_until(JSON_VALUE_DELIM[0]) + '\n';
        response_.body = body;
        parse_request(body);
    }

    // should be executed after each parse_request who can trigger http_parser on_message_complete
    if (message_complete_.load()){
        terminate(asio::error::eof);
    }
    // has content-length
    else if (content_length_it != response_.headers.end() and response_.body.size() != content_length)
        conn_->async_read(content_length - response_.body.size(),
            std::bind(&Request::handle_response_body, this, std::placeholders::_1, std::placeholders::_2));
    // server wants to keep sending
    else if (response_.headers[HTTP_HEADER_CONNECTION] == HTTP_HEADER_CONNECTION_KEEP_ALIVE){
        conn_->async_read_until(JSON_VALUE_DELIM,
            std::bind(&Request::handle_response_body, this, std::placeholders::_1, std::placeholders::_2));
    }
    else if (connection_type_ == restinio::http_connection_header_t::close)
        terminate(asio::error::eof);
}

size_t
Request::parse_request(const std::string request)
{
    std::lock_guard<std::mutex> lock(cbs_mutex_);
    return http_parser_execute(parser_.get(), parser_s_.get(), request.c_str(), request.size());
}

} // namespace http
} // namespace dht
