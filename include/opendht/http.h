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

using ResponseCallback = std::function<void(const std::string data)>;

class Client
{
public:
    Client() = default;
    Client(std::string ip, uint16_t port);

    asio::io_context& io_context();

    void set_query_address(const std::string ip, const uint16_t port);
    asio::ip::tcp::resolver::query build_query();

    std::string create_request(const restinio::http_request_header_t header,
                               const restinio::http_header_fields_t header_fields,
                               const restinio::http_connection_header_t connection,
                               const std::string body);

    void post_request(std::string request,
                      std::shared_ptr<http_parser> parser = nullptr,
                      std::shared_ptr<http_parser_settings> parser_s = nullptr);

private:
    void async_request(std::string request,
                       std::shared_ptr<http_parser> parser = nullptr,
                       std::shared_ptr<http_parser_settings> parser_s = nullptr);

    uint16_t port_;
    asio::ip::address addr_;
    asio::io_context ctx_;
    asio::ip::tcp::resolver resolver_ {ctx_};
    uint16_t connId_ {1};
};

}
