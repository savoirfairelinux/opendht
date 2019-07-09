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

Connection::Connection(const ConnectionId id, asio::ip::tcp::socket socket):
    id_(id), socket_(std::move(socket))
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
Connection::close(){
    socket_.close();
}

// connection listener

ConnectionListener::ConnectionListener()
{}

ConnectionListener::ConnectionListener(std::shared_ptr<dht::DhtRunner> dht,
    std::shared_ptr<std::map<restinio::connection_id_t, http::ListenerSession>> listeners,
    std::shared_ptr<std::mutex> lock, std::shared_ptr<dht::Logger> logger):
        dht_(dht), listeners_(listeners), lock_(lock), logger_(logger)
{}

ConnectionListener::~ConnectionListener()
{}

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

// client

Client::Client(asio::io_context& ctx, const std::string host, const std::string service,
               std::shared_ptr<dht::Logger> logger, const bool resolve):
        resolver_(ctx), logger_(logger)
{
    if (resolve)
        async_resolve(host, service);
}

asio::io_context&
Client::io_context()
{
    return resolver_.get_io_context();
}

void
Client::set_logger(std::shared_ptr<dht::Logger> logger)
{
    logger_ = logger;
}

bool
Client::active_connection(const ConnectionId conn_id)
{
    auto conn_context = connections_.find(conn_id);
    if (conn_context == connections_.end())
        return false;
    return conn_context->second.connection->is_open();
}

void
Client::close_connection(const ConnectionId conn_id)
{
    auto& conn_context = connections_[conn_id];
    if (conn_context.parser)
        // ensure on_message_complete is fired
        http_parser_execute(conn_context.parser.get(),
                            conn_context.parser_settings.get(), "", 0);
    if (conn_context.connection){
        // close the socket
        if (conn_context.connection->is_open())
            conn_context.connection->close();
    }
    // remove from active requests
    connections_.erase(conn_id);
    if (logger_)
        logger_->d("[http::client] [connection:%i] closed", conn_id);
}

void
Client::set_connection_timeout(const ConnectionId conn_id,
                               const std::chrono::seconds timeout, HandlerCb cb)
{
    auto& conn_context = connections_[conn_id];
    if (!conn_context.connection){
        logger_->e("[http::client] [connection:%i] closed, can't timeout", conn_id);
        return;
    }
    if (!conn_context.timeout_timer)
        conn_context.timeout_timer = std::make_shared<asio::steady_timer>(io_context());
    // define or overwrites existing
    conn_context.timeout_timer->expires_at(std::chrono::steady_clock::now() + timeout);
    // define timeout
    conn_context.timeout_timer->async_wait([this, conn_id, cb](const asio::error_code &ec){
        if (ec){
            if (logger_)
                logger_->e("[http::client] [connection:%i] timeout error: %s",
                           conn_id, ec.message().c_str());
        }
        if (cb)
            cb(ec);
    });
}

bool
Client::resolved()
{
    return !endpoints_.empty();
}

void
Client::async_resolve(const std::string host, const std::string service, HandlerCb cb)
{
    // build the query
    asio::ip::tcp::resolver::query query(host, service);

    // resolve the query to the server
    resolver_.async_resolve(query, [this, host, service, cb](
            const asio::error_code& ec,
            asio::ip::tcp::resolver::results_type endpoints)
    {
        if (ec){
            if (logger_)
                logger_->e("[http::client] [resolve %s:%s] error resolving: %s",
                           host.c_str(), service.c_str(), ec.message().c_str());
        }
        else {
            for (auto it = endpoints.begin(); it != endpoints.end(); ++it){
                if (logger_){
                    asio::ip::tcp::endpoint endpoint = *it;
                    logger_->d("[http::client] [resolve %s:%s] address=%s ipv%i",
                        host.c_str(), service.c_str(),
                        endpoint.address().to_string().c_str(),
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
Client::create_request(const restinio::http_request_header_t header,
                       const restinio::http_header_fields_t header_fields,
                       const restinio::http_connection_header_t connection,
                       const std::string body)
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
Client::async_connect(ConnectionCb cb)
{
    if (endpoints_.empty()){
        if (logger_)
            logger_->e("[http::client] host not resolved, can't send request");
        if (cb)
            cb(nullptr);
        return;
    }
    auto conn = std::make_shared<Connection>(connId_++,
        std::move(asio::ip::tcp::socket{resolver_.get_io_context()}));
    if (logger_)
        logger_->d("[http::client] [connection:%i] created", conn->id());

    // try to connect to any until one works
    asio::async_connect(conn->socket_, endpoints_, [this, conn, cb](const asio::error_code& ec,
                                                                    const asio::ip::tcp::endpoint& endpoint){
        // only reacts if all endpoints fail
        if (ec){
            logger_->e("[http::client] [connection] failed to connect to any endpoints");
            close_connection(conn->id());
            if (cb)
                cb(nullptr);
            return;
        }
        // save the associated endpoint
        conn->endpoint_ = endpoint;
        // make the connection context and save it
        ConnectionContext conn_context = {};
        conn_context.connection = conn;
        connections_[conn->id()] = conn_context;
        // get back to user
        if (cb)
            cb(conn);
    });
}

void
Client::async_request(std::shared_ptr<Connection> conn, std::string request,
                      std::shared_ptr<http_parser> parser,
                      std::shared_ptr<http_parser_settings> parser_s, HandlerCb cb)
{
    if (endpoints_.empty()){
        if (logger_)
            logger_->e("[http::client] host not resolved, can't send request");
        if (cb)
            cb(asio::error::addrinfo_errors::service_not_found);
        return;
    }
    if (!conn){
        if (logger_)
            logger_->e("[http::client] invalid connection, can't post request:\n%s", request.c_str());
        if (cb)
            cb(asio::error::not_connected);
        return;
    }
    else if (!conn->is_open()){
        if (logger_)
            logger_->e("[http::client] closed connection, can't post request");
        close_connection(conn->id());
        if (cb)
            cb(asio::error::not_connected);
        return;
    }
    // save the request context
    auto& conn_context = connections_[conn->id()];
    conn_context.request = request;
    conn_context.parser = parser;
    conn_context.parser_settings = parser_s;

    // write the request to buffer
    std::ostream request_stream(&conn->request_);
    request_stream << request;

    // send the request
    asio::async_write(conn->socket_, conn->request_,
        std::bind(&Client::handle_request, this, std::placeholders::_1, conn, cb));
}

void
Client::handle_request(const asio::error_code& ec, std::shared_ptr<Connection> conn, HandlerCb cb)
{
    if (!conn->is_open()){
        if (logger_)
            logger_->e("[http::client] closed connection, can't handle request");
        close_connection(conn->id());
        if (cb)
            cb(asio::error::not_connected);
        return;
    }
    if (ec and ec != asio::error::eof){
        if (logger_)
            logger_->e("[http::client] [connection:%i] error handling request: %s",
                       conn->id(), ec.message().c_str());
        close_connection(conn->id());
        if (cb)
            cb(ec);
        return;
    }
    if (logger_)
        logger_->d("[http::client] [connection:%i] request write", conn->id());

    // read response
    asio::async_read_until(conn->socket_, conn->response_chunk_, "\r\n\r\n",
        std::bind(&Client::handle_response_header, this,
            std::placeholders::_1, std::placeholders::_2, conn, cb));
}

void
Client::handle_response_header(const asio::error_code& ec, const size_t bytes,
                               std::shared_ptr<Connection> conn, HandlerCb cb)
{
    if (!conn->is_open()){
        if (logger_)
            logger_->e("[http::client] closed connection, can't handle response header");
        close_connection(conn->id());
        if (cb)
            cb(asio::error::not_connected);
        return;
    }
    if (ec && ec != asio::error::eof){
        if (logger_)
            logger_->e("[http::client] [connection:%i] error handling response header: %s",
                       conn->id(), ec.message().c_str());
        close_connection(conn->id());
        if (cb)
            cb(ec);
        return;
    }
    else if ((ec == asio::error::eof) || (ec == asio::error::connection_reset)){
        close_connection(conn->id());
        if (cb)
            cb(ec);
        return;
    }
    // read the response buffer
    std::ostringstream str_s;
    str_s << &conn->response_chunk_;
    auto chunk = str_s.str();
    auto header = chunk.substr(0, bytes);
    if (logger_)
        logger_->d("[http::client] [connection:%i] response header read:\n%s", conn->id(), header.c_str());
    // parse the header right away
    parse_request(header, conn->id());

    unsigned int content_length = get_content_length(header);
    // has body size
    if (content_length){
        // append current body chunk
        auto body_chunk = chunk.substr(bytes, std::string::npos);
        conn->response_body_.append(body_chunk);
        // read the rest of body
        asio::async_read(conn->socket_, conn->response_chunk_,
            asio::transfer_exactly(content_length - (body_chunk.size())),
            std::bind(&Client::handle_response_body, this,
                std::placeholders::_1, content_length, conn, cb));
        return;
    }
    // has potential body but no content-length (current proxy behavior on key get/listen)
    else if (header.find("Content-Type: application/json") != std::string::npos){
        auto body_chunk = chunk.substr(bytes, std::string::npos);
        if (!body_chunk.empty()){
            parse_request(body_chunk, conn->id());
        }
        // keep reading
        asio::async_read(conn->socket_, conn->response_chunk_, asio::transfer_at_least(1),
            std::bind(&Client::handle_response_body, this,
                std::placeholders::_1, std::placeholders::_2, conn, cb));
    }
}

void
Client::handle_response_body(const asio::error_code& ec, const size_t bytes,
                             std::shared_ptr<Connection> conn, HandlerCb cb)
{
    if (!conn->is_open()){
        if (logger_)
            logger_->e("[http::client] closed connection, can't handle response body");
        close_connection(conn->id());
        if (cb)
            cb(asio::error::not_connected);
        return;
    }
    if (ec && ec != asio::error::eof){
        if (logger_)
            logger_->e("[http::client] [connection:%i] error handling response body: %s",
                       conn->id(), ec.message().c_str());
        close_connection(conn->id());
        if (cb)
            cb(ec);
        return;
    }
    else if ((ec == asio::error::eof) || (ec == asio::error::connection_reset)){
        close_connection(conn->id());
        if (cb)
            cb(ec);
        return;
    }
    std::string body;
    if (!conn->response_body_.empty()){
        // append previous incomplete chunk from header
        body.append(conn->response_body_);
    }
    // read the response buffer
    std::ostringstream str_s;
    str_s << &conn->response_chunk_;
    body.append(str_s.str().substr(0, bytes));
    if (logger_)
        logger_->d("[http::client] [connection:%i] response body read:\n%s", conn->id(), body.c_str());
    // parse the body
    parse_request(body, conn->id());
    // clear the read body
    conn->response_body_.clear();
    // keep reading line by line
    asio::async_read(conn->socket_, conn->response_chunk_, asio::transfer_at_least(1),
        std::bind(&Client::handle_response_body, this,
            std::placeholders::_1, std::placeholders::_2, conn, cb));
}

void
Client::parse_request(const std::string request, const ConnectionId conn_id)
{
    auto& conn_context = connections_[conn_id];
    http_parser_execute(conn_context.parser.get(), conn_context.parser_settings.get(),
                        request.c_str(), request.size());
    // detect parsing errors
    if (HPE_OK != conn_context.parser->http_errno && HPE_PAUSED != conn_context.parser->http_errno){
        if (logger_){
            auto err = HTTP_PARSER_ERRNO(conn_context.parser.get());
            logger_->e("[http::client] [connection:%i] error parsing: %s", conn_id, http_errno_name(err));
        }
    }
}

size_t
Client::get_content_length(const std::string str, const ConnectionId conn_id)
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
                logger_->d("[http::client] [connection:%i] invalid content-length '%s': %s",
                           conn_id, content_length_str.c_str(), e.what());
        }
    }
    return content_length;
}

} // namespace http
