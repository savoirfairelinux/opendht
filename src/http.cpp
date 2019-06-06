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

void
Connection::start(asio::ip::tcp::resolver::iterator &r_iter){
    asio::connect(socket_, r_iter);
}

bool
Connection::is_open(){
    return socket_.is_open();
}

asio::ip::tcp::socket&
Connection::get_socket(){
    return socket_;
}

std::string
Connection::read(std::error_code& ec){
    std::string response;
    asio::read(socket_, asio::dynamic_buffer(response), ec);
    return response;
}

void
Connection::write(std::string request, std::error_code& ec){
    asio::write(socket_, asio::dynamic_buffer(request), ec);
}

void
Connection::close(){
    socket_.close();
}

// client

Client::Client(const std::string ip, const uint16_t port){
    set_query_address(ip, port);
}

asio::io_context&
Client::io_context(){
    return ctx_;
}

void
Client::set_query_address(const std::string ip, const uint16_t port){
    addr_ = asio::ip::address::from_string(ip);
    port_ = port;
}

asio::ip::tcp::resolver::query
Client::build_query(){
    // support of ipv4 & ipv6
    return asio::ip::tcp::resolver::query {
        addr_.is_v4() ? asio::ip::tcp::v4() : asio::ip::tcp::v6(),
        addr_.to_string(), std::to_string(port_)};
}

std::string
Client::create_request(const restinio::http_request_header_t header,
                       const restinio::http_header_fields_t header_fields,
                       const restinio::http_connection_header_t connection,
                       const std::string body){
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
Client::post_request(std::string request, std::shared_ptr<http_parser> parser,
                     std::shared_ptr<http_parser_settings> parser_s){
    // invoke the given handler and return immediately
    asio::post(ctx_, [this, request, parser, parser_s](){
        this->async_request(request, parser, parser_s);
        // execute at most one handler, it ensures that same func call
        // with different callback gets the priority on the io_context
        ctx_.run_one();
    });
}

void
Client::async_request(std::string request, std::shared_ptr<http_parser> parser,
                      std::shared_ptr<http_parser_settings> parser_s){
    using namespace asio::ip;

    auto conn = std::make_shared<Connection>(connId_, std::move(tcp::socket{ctx_}));
    printf("[connection:%i] created\n", conn->id());
    connId_++;

    // resolve sometime in future
    resolver_.async_resolve(build_query(), [=](std::error_code ec,
                                               tcp::resolver::results_type res){
        if (ec or res.empty()){
            printf("[connection:%i] error resolving\n", conn->id());
            conn->close();
            return;
        }
        for (auto da = res.begin(); da != res.end(); ++da){
            printf("[connection:%i] resolved host=%s service=%s\n",
                    conn->id(), da->host_name().c_str(), da->service_name().c_str());
            conn->start(da);
            break;
        }
        if (!conn->is_open()){
            printf("[connection:%i] error closed connection\n", conn->id());
            return;
        }
        // send request
        printf("[connection:%i] request write\n", conn->id());
        conn->write(request, ec);
        if (ec and ec != asio::error::eof){
            printf("[connection:%i] error: %s\n", conn->id(), ec.message().c_str());
            return;
        }
        // read response
        printf("[connection:%i] response read\n", conn->id());
        asio::streambuf resp_s;
        auto& socket = conn->get_socket();
        asio::read_until(socket, resp_s, "\r\n\r\n");

        while(asio::read(socket, resp_s, asio::transfer_at_least(1), ec)){
            std::ostringstream str_s;
            str_s << &resp_s;
            // parse the request
            http_parser_execute(parser.get(), parser_s.get(),
                                str_s.str().c_str(), str_s.str().size());
            // detect parsing errors
            if (HPE_OK != parser->http_errno && HPE_PAUSED != parser->http_errno){
                auto err = HTTP_PARSER_ERRNO(parser.get());
                printf("[connection:%i] error parsing: %s\n", conn->id(), http_errno_name(err));
            }
        }
        if (ec != asio::error::eof){
            throw std::runtime_error{fmt::format(
                "[connection:{}] error parsing: {}\n", conn->id(), ec)};
        }
        printf("[connection:%i] request finished\n", conn->id());
    });
}

}
