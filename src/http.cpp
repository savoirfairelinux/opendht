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

namespace http {

constexpr char HTTP_HEADER_CONTENT_LENGTH[] = "Content-Length:";

// connection

Connection::Connection(asio::ip::tcp::socket socket, std::shared_ptr<dht::Logger> logger):
    id_(++ids_), socket_(std::move(socket)), logger_(logger)
{}

Connection::~Connection(){
    close();
}

ConnectionId
Connection::id(){
    return id_;
}

bool
Connection::is_open(){
    return socket_.is_open();
}

bool
Connection::is_v6(){
    return endpoint_.address().is_v6();
}

void
Connection::timeout(const std::chrono::seconds timeout, HandlerCb cb)
{
    if (!is_open()){
        if (logger_)
            logger_->e("[connection:%i] closed, can't timeout", id_);
        return;
    }
    if (!timeout_timer_)
        timeout_timer_ = std::make_unique<asio::steady_timer>(io_context());
    timeout_timer_->expires_at(std::chrono::steady_clock::now() + timeout);
    timeout_timer_->async_wait([this, cb](const asio::error_code &ec){
        if (ec == asio::error_code::operation_aborted)
            return;
        else if (ec){
            if (logger_)
                logger_->e("[connection:%i] timeout error: %s", id_, ec.message().c_str());
        }
        if (cb)
            cb(ec);
    });
}

void
Connection::close(){
    socket_.close();
}

// connection listener

ConnectionListener::ConnectionListener()
{}

ConnectionListener::ConnectionListener(std::shared_ptr<dht::DhtRunner> dht,
    std::shared_ptr<std::map<restinio::connection_id_t, http::ListenerSession>> listeners,
    std::shared_ptr<std::mutex> lock, std::shared_ptr<dht::Logger> logger):
        dht_(dht), lock_(lock), listeners_(listeners), logger_(logger)
{}

ConnectionListener::~ConnectionListener()
{
}

void
ConnectionListener::state_changed(const restinio::connection_state::notice_t& notice) noexcept
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
ConnectionListener::to_str(restinio::connection_state::cause_t cause) noexcept
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

// request

Request::Request(asio::io_context& ctx, const std::string host, const std::string service,
                 const bool resolve, std::shared_ptr<dht::Logger> logger):
        id_(++ids_), resolver_(ctx), logger_(logger)
{
    if (resolve)
        resolve(host, service);
}

Request::~Request()
{
    terminate();
}

void
Request::set_logger(std::shared_ptr<dht::Logger> logger)
{
    logger_ = logger;
}

void
Request::terminate()
{
    if (parser_)
        // ensure on_message_complete callback is called
        http_parser_execute(parser_.get(), parser_s_.get(), "", 0);
    if (logger_)
        logger_->d("[http:request:%i] done", id_);
}

bool
Request::resolved()
{
    return !endpoints_.empty();
}

void
Request::resolve(const std::string host, const std::string service, HandlerCb cb)
{
    // build the query
    asio::ip::tcp::resolver::query query(host, service);

    // resolve the query to the server
    resolver_.async_resolve(query, [this, host, service, cb]
        (const asio::error_code& ec, asio::ip::tcp::resolver::results_type endpoints)
    {
        if (ec){
            if (logger_)
                logger_->e("[http:request:%i] error resolving %s:%s: %s",
                           id_, host.c_str(), service.c_str(), ec.message().c_str());
        }
        else {
            for (auto it = endpoints.begin(); it != endpoints.end(); ++it){
                if (logger_){
                    asio::ip::tcp::endpoint endpoint = *it;
                    logger_->d("[http:request:%i] resolved %s:%s: address=%s ipv%i",
                        id_, host.c_str(), service.c_str(), endpoint.address().to_string().c_str(),
                        endpoint.address().is_v6() ? 6 : 4);
                }
            }
            endpoints_ = endpoints;
        }
        if (cb)
            cb(ec);
    });
}

std::string
Request::build(const restinio::http_request_header_t header,
               const restinio::http_header_fields_t header_fields,
               const restinio::http_connection_header_t connection, const std::string body)
{
    std::stringstream request;

    // first header
    request << header.method().c_str() << " " << header.request_target() << " " <<
               "HTTP/" << header.http_major() << "." << header.http_minor() << "\r\n";

    // other headers
    for (auto header_field: header_fields)
        request << header_field.name() << ": " << header_field.value() << "\r\n";

    // last connection header
    std::string conn_str;
    switch (connection){
    case restinio::http_connection_header_t::keep_alive:
        conn_str = "keep-alive";
        break;
    case restinio::http_connection_header_t::close:
        conn_str = "close";
        break;
    case restinio::http_connection_header_t::upgrade:
        throw std::invalid_argument("upgrade");
        break;
    }
    request << "Connection: " << conn_str << "\r\n";

    // body & content-length
    if (!body.empty()){
        request << "Content-Length: " << body.size() << "\r\n\r\n";
        request << body;
    }

    // last delim
    request << "\r\n";
    return request.str();
}

void
Request::connect(ConnectionCb cb)
{
    if (endpoints_.empty()){
        if (logger_)
            logger_->e("[http:request] [connect] host not resolved");
        if (cb)
            cb(asio::error::connection_aborted, nullptr);
        return;
    }
    auto socket = asio::ip::tcp::socket{resolver_.get_io_context()};
    conn_ = std::make_shared<Connection>(std::move(socket));

    // try to connect to any until one works
    asio::async_connect(conn_->socket_, endpoints_, [this, conn, cb]
                       (const asio::error_code& ec, const asio::ip::tcp::endpoint& endpoint){
        if (ec){ // all endpoints failed
            if (logger_)
                logger_->e("[http:request:%i] [connect] failed to connect to any endpoints", id_);
        }
        else {
            if (logger_)
                logger_->d("[http:request:%i] [connect] success", id_);
            // save the associated endpoint
            conn_->endpoint_ = endpoint;
        }
        if (cb)
            cb(ec, conn_);
    });
}

void
Request::send(std::string request, std::unique_ptr<http_parser> parser,
              std::unique_ptr<http_parser_settings> parser_s, HandlerCb cb)
{
    if (endpoints_.empty()){
        if (logger_)
            logger_->e("[http:request:%i] [send] unresolved destination", id_);
        if (cb)
            cb(asio::error::addrinfo_errors::service_not_found);
    }
    if (!conn_){
        if (logger_)
            logger_->e("[http:request:%i] [send] uninitialized connection", id_);
        if (cb)
            cb(asio::error::not_connected);
    }
    else if (!conn_->is_open()){
        if (logger_)
            logger_->e("[http:request] [send] closed connection");
        if (cb)
            cb(asio::error::not_connected);
    }
    else {
        // save the request context
        request_ = request;
        parser_ = std::move(parser);
        parser_s_ = std::move(parser_s);

        // write the request to buffer
        std::ostream request_stream(&conn_->request_);
        request_stream << request;

        // send the request
        asio::async_write(conn_->socket_, conn_->request_,
            std::bind(&Request::handle_request, this, std::placeholders::_1, cb));
    }
}

void
Request::handle_request(const asio::error_code& ec, HandlerCb cb)
{
    if (!conn_->is_open()){
        if (logger_)
            logger_->e("[http:request:%i] [write] closed connection", id_);
        terminate();
        if (cb)
            cb(asio::error::not_connected);
        return;
    }
    if (ec and ec != asio::error::eof){
        if (logger_)
            logger_->e("[http:request:%i] [write] error: %s", id_, ec.message().c_str());
        terminate();
        if (cb)
            cb(ec);
        return;
    }
    if (logger_)
        logger_->d("[http:request:%i] [write] success", id_);

    // read response
    asio::async_read_until(conn_->socket_, conn_->response_chunk_, "\r\n\r\n",
        std::bind(&Request::handle_response_header, this,
                  std::placeholders::_1, std::placeholders::_2, cb));
}

void
Request::handle_response_header(const asio::error_code& ec, const size_t bytes, HandlerCb cb)
{
    if (!conn_->is_open()){
        if (logger_)
            logger_->e("[http:request:%i] [read:header] closed connection", id_);
        terminate();
        if (cb)
            cb(asio::error::not_connected);
        return;
    }
    if (ec && ec != asio::error::eof){
        if (logger_)
            logger_->e("[http:request:%i] [read:header] error: %s", id_, ec.message().c_str());
        terminate();
        if (cb)
            cb(ec);
        return;
    }
    else if ((ec == asio::error::eof) || (ec == asio::error::connection_reset)){
        terminate();
        if (cb)
            cb(ec);
        return;
    }
    // read the response buffer
    std::ostringstream str_s;
    str_s << &conn_->response_chunk_;
    auto chunk = str_s.str();
    auto header = chunk.substr(0, bytes);
    if (logger_)
        logger_->d("[http:request:%i] [read:header]:\n%s", id_, header.c_str());
    // parse the header right away
    parse_request(header, conn_->id());

    unsigned int content_length = get_content_length(header);
    // has body size
    if (content_length){
        // append current body chunk
        auto body_chunk = chunk.substr(bytes, std::string::npos);
        conn_->response_body_.append(body_chunk);
        // read the rest of body
        asio::async_read(conn_->socket_, conn_->response_chunk_,
            asio::transfer_exactly(content_length - (body_chunk.size())),
            std::bind(&Request::handle_response_body, this,
                std::placeholders::_1, content_length, conn, cb));
        return;
    }
    // has potential body but no content-length (current proxy behavior on key get/listen)
    else if (header.find("Content-Type: application/json") != std::string::npos){
        auto body_chunk = chunk.substr(bytes, std::string::npos);
        if (!body_chunk.empty()){
            parse_request(body_chunk, conn_->id());
        }
        // keep reading
        asio::async_read(conn_->socket_, conn_->response_chunk_, asio::transfer_at_least(1),
            std::bind(&Request::handle_response_body, this,
                std::placeholders::_1, std::placeholders::_2, conn, cb));
    }
}

void
Request::handle_response_body(const asio::error_code& ec, const size_t bytes,
                             std::shared_ptr<Connection> conn, HandlerCb cb)
{
    if (!conn_->is_open()){
        if (logger_)
            logger_->e("[http:request] [read:body] closed connection");
        terminate();
        if (cb)
            cb(asio::error::not_connected);
        return;
    }
    if (ec && ec != asio::error::eof){
        if (logger_)
            logger_->e("[http:request:%i] [read:body] error: %s", id_, ec.message().c_str());
        terminate();
        if (cb)
            cb(ec);
        return;
    }
    else if ((ec == asio::error::eof) || (ec == asio::error::connection_reset)){
        terminate();
        if (cb)
            cb(ec);
        return;
    }
    std::string body;
    if (!conn_->response_body_.empty()){
        // append previous incomplete chunk from header
        body.append(conn_->response_body_);
    }
    // read the response buffer
    std::ostringstream str_s;
    str_s << &conn_->response_chunk_;
    body.append(str_s.str().substr(0, bytes));
    if (logger_)
        logger_->d("[http:request:%i] [read:body] success:\n%s", id_, body.c_str());

    parse_request(body);
    conn_->response_body_.clear();

    asio::async_read(conn_->socket_, conn_->response_chunk_, asio::transfer_at_least(1),
        std::bind(&Request::handle_response_body, this,
            std::placeholders::_1, std::placeholders::_2, conn, cb));
}

void
Request::parse_request(const std::string request)
{
    http_parser_execute(parser_.get(), parser_s_.get(), request.c_str(), request.size());
    // detect parsing errors
    if (HPE_OK != parser_->http_errno && HPE_PAUSED != parser_->http_errno){
        if (logger_){
            auto err = HTTP_PARSER_ERRNO(parser_.get());
            logger_->e("[http:request:%i] [parse] error: %s", id_, http_errno_name(err));
        }
    }
}

size_t
Request::get_content_length(const std::string str)
{
    size_t content_length = 0;
    auto content_length_i = str.find(HTTP_HEADER_CONTENT_LENGTH);
    if (content_length_i != std::string::npos){
        auto content_length_str = str.substr(content_length_i + std::strlen(HTTP_HEADER_CONTENT_LENGTH) + 1,
                                             str.find("\r\n", content_length_i));
        try {
            content_length = atoi(content_length_str.c_str());
        }
        catch (const std::exception& e){
            if (logger_)
                logger_->d("[http:request:%i] [content-length] invalid '%s': %s",
                           id_, content_length_str.c_str(), e.what());
        }
    }
    return content_length;
}


Resolver::Resolver(asio::io_context& ctx, const std::string& host, const std::string& service)
{
    resolver_.async_resolve({host, service}, [this]
        (const asio::error_code& ec, asio::ip::tcp::resolver::results_type endpoints)
    {
        std::lock_guard<std::mutex> lock(cbsMutex_);
        while (not cbs_.empty()) {
            cbs_.front()(ec, endpoints);
            cbs_.pop();
        }
        error_ = ec;
        endpoints_ = endpoints;
        completed_ = true;
    }
}

void
Resolver::addOnResolved(ResolvedCb cb)
{
    std::lock_guard<std::mutex> lock(cbsMutex_);
    if (completed_) {
        cb(error_, endpoints_);
    } else {
        cbs_.push(std::move(cb));
    }
}

/*
private:
    std::mutex cbsMutex_;
    std::queue<ResolvedCb> cbs_;

    asio::ip::tcp::resolver resolver_;
    asio::error_code error_;
    asio::ip::basic_resolver_results<asio::ip::tcp> endpoints_;
} */


} // namespace http
