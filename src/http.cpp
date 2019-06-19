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

// connection

Connection::Connection(const uint16_t id, asio::ip::tcp::socket socket):
    id_(id), socket_(std::move(socket))
{}

Connection::~Connection(){
    close();
}

uint16_t
Connection::id(){
    return id_;
}

bool
Connection::is_open(){
    return socket_.is_open();
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
ConnectionListener::state_changed(const restinio::connection_state::notice_t &notice) noexcept
{
    std::lock_guard<std::mutex> lock(*lock_);
    auto id = notice.connection_id();
    auto cause = to_str(notice.cause());

    if (listeners_->find(id) != listeners_->end()){
        if (notice.cause() == restinio::connection_state::cause_t::closed){
            if (logger_)
                logger_->d("[restinio] [connection:%li] cancelling listener", id);
            dht_->cancelListen(listeners_->at(id).hash,
                               std::move(listeners_->at(id).token));
            listeners_->erase(id);
            if (logger_)
                logger_->d("[restinio] %li listeners are connected", listeners_->size());
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

Client::Client(asio::io_context &ctx, const std::string host, const uint16_t port,
               std::shared_ptr<dht::Logger> logger):
        resolver_(ctx), logger_(logger)
{
    set_query_address(host, port);
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
void
Client::set_query_address(const std::string host, const uint16_t port)
{
    host_ = host;
    port_ = port;
}

std::shared_ptr<Connection>
Client::create_connection()
{
    auto conn = std::make_shared<Connection>(connId_,
        std::move(asio::ip::tcp::socket{resolver_.get_io_context()}));
    if (logger_)
        logger_->d("[connection:%i] created", conn->id());
    connId_++;
    return conn;
}

void
Client::close_connection(std::shared_ptr<Connection> conn)
{
    requests_.erase(conn->id());
    conn->close();
    if (logger_)
        logger_->d("[connection:%i] closed", conn->id());
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
Client::post_request(std::string request,
                     std::shared_ptr<http_parser> parser,
                     std::shared_ptr<http_parser_settings> parser_s)
{
    auto conn = create_connection();

    // write the request to buffer
    std::ostream request_stream(&conn->request_);
    request_stream << request;

    // save things needed later
    Request req = {};
    req.content = request;
    req.parser = parser;
    req.parser_settings = parser_s;
    requests_[conn->id()] = req;

    // resolve the query to the server
    asio::ip::tcp::resolver::query query(host_, std::to_string(port_));
    resolver_.async_resolve(query,
        std::bind(&Client::handle_resolve, this,
            std::placeholders::_1, std::placeholders::_2, conn));
}

void
Client::handle_resolve(const asio::error_code &ec,
                       asio::ip::tcp::resolver::iterator endpoint_it,
                       std::shared_ptr<Connection> conn)
{
    if (ec){
        if (logger_)
            logger_->e("[connection:%i] error resolving", conn->id());
        conn->close();
        return;
    }
    if (logger_){
        logger_->d("[connection:%i] resolved host=%s service=%s", conn->id(),
            endpoint_it->host_name().c_str(), endpoint_it->service_name().c_str());
    }
    conn->socket_.async_connect(*endpoint_it,
        std::bind(&Client::handle_connect, this,
                  std::placeholders::_1, ++endpoint_it, conn));
}

void
Client::handle_connect(const asio::error_code &ec,
                       asio::ip::tcp::resolver::iterator endpoint_it,
                       std::shared_ptr<Connection> conn)
{
    if (ec){
        if (logger_)
            logger_->e("[connection:%i] error opening: %s",
                       conn->id(), ec.message().c_str());
        close(conn->id());
        return;
    }
    else if (endpoint_it != asio::ip::tcp::resolver::iterator()){
        if (logger_)
            logger_->e("[connection:%i] error connecting, trying next endpoint", conn->id());
        conn->socket_.close();
        conn->socket_.async_connect(*endpoint_it,
            std::bind(&Client::handle_connect, this,
                      std::placeholders::_1, ++endpoint_it, conn));
        return;
    }
    // send the request
    asio::async_write(conn->socket_, conn->request_,
        std::bind(&Client::handle_request, this, std::placeholders::_1, conn));
}

void
Client::handle_request(const asio::error_code &ec, std::shared_ptr<Connection> conn)
{
    if (ec and ec != asio::error::eof){
        if (logger_)
            logger_->e("[connection:%i] error handling request: %s",
                       conn->id(), ec.message().c_str());
        close_connection(conn);
        return;
    }
    if (logger_)
        logger_->d("[connection:%i] request write", conn->id());

    // read response
    asio::async_read_until(conn->socket_, conn->response_, "\r\n\r\n",
        std::bind(&Client::handle_response, this, std::placeholders::_1, conn));
}

void
Client::handle_response(const asio::error_code &ec, std::shared_ptr<Connection> conn)
{
    if (ec && ec != asio::error::eof){
        if (logger_)
            logger_->e("[connection:%i] error handling response: %s",
                       conn->id(), ec.message().c_str());
        return;
    }
    else if ((ec == asio::error::eof) || (ec == asio::error::connection_reset)){
        close_connection(conn);
        return;
    }
    if (logger_)
        logger_->d("[connection:%i] response read", conn->id());

    // read the response buffer
    std::ostringstream str_s;
    str_s << &conn->response_;

    // parse the request
    auto &req = requests_[conn->id()];
    http_parser_execute(req.parser.get(), req.parser_settings.get(),
                        str_s.str().c_str(), str_s.str().size());

    // detect parsing errors
    if (HPE_OK != req.parser->http_errno && HPE_PAUSED != req.parser->http_errno){
        if (logger_){
            auto err = HTTP_PARSER_ERRNO(req.parser.get());
            logger_->e("[connection:%i] error parsing: %s", conn->id(), http_errno_name(err));
        }
    }
    asio::async_read(conn->socket_, conn->response_, asio::transfer_at_least(1),
        std::bind(&Client::handle_response, this, std::placeholders::_1, conn));
}

} // namespace http
