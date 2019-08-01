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

constexpr char HTTP_HEADER_CONNECTION[] = "Connection";
constexpr char HTTP_HEADER_CONNECTION_KEEP_ALIVE[] = "keep-alive";
constexpr char HTTP_HEADER_CONTENT_LENGTH[] = "Content-Length";
constexpr char HTTP_HEADER_CONTENT_TYPE[] = "Content-Type";
constexpr char HTTP_HEADER_CONTENT_TYPE_JSON[] = "application/json";
constexpr char HTTP_HEADER_DELIM[] = "\r\n\r\n";
constexpr char JSON_VALUE_DELIM = '\n';

// connection

unsigned int Connection::ids_ = 1;

Connection::Connection(asio::io_context& ctx, std::shared_ptr<dht::Logger> logger):
    id_(Connection::ids_++), socket_(ctx), logger_(logger)
{}

Connection::~Connection()
{
    close();
}

unsigned int
Connection::id()
{
    return id_;
}

bool
Connection::is_open()
{
    return socket_.is_open();
}

bool
Connection::is_v6()
{
    return endpoint_.address().is_v6();
}

void
Connection::set_endpoint(const asio::ip::tcp::endpoint& endpoint)
{
    endpoint_ = endpoint;
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

asio::ip::tcp::socket&
Connection::socket()
{
    return socket_;
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
        timeout_timer_ = std::make_unique<asio::steady_timer>(socket_.get_io_context());
    timeout_timer_->expires_at(std::chrono::steady_clock::now() + timeout);
    timeout_timer_->async_wait([this, cb](const asio::error_code &ec){
        if (ec == asio::error::operation_aborted)
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
Connection::close()
{
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

// Resolver

Resolver::Resolver(asio::io_context& ctx, const std::string& host, const std::string& service,
                   std::shared_ptr<dht::Logger> logger)
    : resolver_(ctx), logger_(logger)
{
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
                logger_->e("[http:resolver] error for %s:%s: %s",
                           host.c_str(), service.c_str(), ec.message().c_str());
            else {
                for (auto it = endpoints.begin(); it != endpoints.end(); ++it){
                    asio::ip::tcp::endpoint endpoint = *it;
                    logger_->d("[http:resolver] resolved %s:%s: address=%s ipv%i",
                        host.c_str(), service.c_str(), endpoint.address().to_string().c_str(),
                        endpoint.address().is_v6() ? 6 : 4);
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

std::shared_ptr<Connection>
Request::get_connection() const
{
    return conn_;
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
            logger_->e("[http:request:%i] [connect] no endpoints provided", id_);
        if (cb)
            cb(asio::error::connection_aborted);
        return;
    }
    if (logger_){
        std::string eps = "";
        for (auto& endpoint : endpoints)
            eps.append(endpoint.address().to_string() + " ");
        logger_->d("[http:request:%i] [connect] begin endpoints { %s}", id_, eps.c_str());
    }
    conn_ = std::make_shared<Connection>(ctx_);

    // try to connect to any until one works
    asio::async_connect(conn_->socket(), std::move(endpoints), [this, cb]
                       (const asio::error_code& ec, const asio::ip::tcp::endpoint& endpoint){
        if (ec == asio::error::operation_aborted)
            return;
        else if (ec){
            if (logger_)
                logger_->e("[http:request:%i] [connect] failed with all endpoints", id_);
        }
        else {
            if (logger_)
                logger_->d("[http:request:%i] [connect] success", id_);
            // save the associated endpoint
            conn_->set_endpoint(endpoint);
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
                logger_->e("[http:request:%i] [send] resolve error: %s", id_, ec.message().c_str());
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
        if (logger_)
            logger_->e("[http:request:%i] [post] closed connection", id_);
        terminate(asio::error::not_connected);
        return;
    }
    build();
    init_parser();

    if (logger_)
        logger_->d("[http:request:%i] [post]\n%s", id_, request_.c_str());

    // write the request to buffer
    std::ostream request_stream(&conn_->input());
    request_stream << request_;

    // send the request
    notify_state_change(State::SENDING);
    asio::async_write(conn_->socket(), conn_->input(),
        std::bind(&Request::handle_request, this, std::placeholders::_1));
}

void
Request::terminate(const asio::error_code& ec)
{
    if (ec != asio::error::eof and ec != asio::error::operation_aborted)
        if (logger_)
            logger_->e("[http:request:%i] end with error: %s", id_, ec.message().c_str());

    // close the connection cancelling the scheduled socket operations on the io_context
    conn_->close();
    // reset the http_parser holding the data pointer to the user callbacks
    parser_.reset();
    parser_s_.reset();

    // set response outcome, ignore end of file and abort
    if (!ec or ec == asio::error::eof or ec == asio::error::operation_aborted)
        response_.status_code = 200;
    else
        response_.status_code = 0;

    if (logger_)
        logger_->d("[http:request:%i] done", id_);

    notify_state_change(State::DONE);
}

void
Request::handle_request(const asio::error_code& ec)
{
    if (ec == asio::error::operation_aborted)
        return;
    else if (ec and ec != asio::error::eof){
        if (logger_)
            logger_->e("[http:request:%i] [write] error: %s", id_, ec.message().c_str());
        terminate(ec);
        return;
    }
    if (!conn_->is_open()){
        if (logger_)
            logger_->e("[http:request:%i] [write] closed connection", id_);
        terminate(asio::error::not_connected);
        return;
    }
    if (logger_)
        logger_->d("[http:request:%i] [write] success", id_);

    // read response
    notify_state_change(State::RECEIVING);
    asio::async_read_until(conn_->socket(), conn_->data(), HTTP_HEADER_DELIM,
        std::bind(&Request::handle_response_header, this, std::placeholders::_1));
}

void
Request::handle_response_header(const asio::error_code& ec)
{
    if (ec == asio::error::operation_aborted)
        return;
    else if ((ec == asio::error::eof) or (ec == asio::error::connection_reset)){
        if (logger_)
            logger_->e("[http:request:%i] [read:header] error: %s", id_, ec.message().c_str());
        terminate(ec);
        return;
    }
    else if ((ec == asio::error::eof) || (ec == asio::error::connection_reset)){
        terminate(ec);
        return;
    }
    if (!conn_->is_open()){
        if (logger_)
            logger_->e("[http:request:%i] [read:header] closed connection", id_);
        terminate(asio::error::not_connected);
        return;
    }
    // read the header
    std::string header;
    std::string headers;
    std::istream is(&conn_->data());
    while (std::getline(is, header) && header != "\r"){
        headers.append(header + "\n");
    }
    headers.append("\n");
    if (logger_)
        logger_->d("[http:request:%i] [read:header]\n%s", id_, headers.c_str());

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
            asio::async_read(conn_->socket(), conn_->data(),
                asio::transfer_exactly(content_length - response_.body.size()),
                std::bind(&Request::handle_response_body, this, std::placeholders::_1, std::placeholders::_2));
        }
    }
    // server wants to keep sending or we have content-length defined
    else if (response_.headers[HTTP_HEADER_CONNECTION] == HTTP_HEADER_CONNECTION_KEEP_ALIVE)
    {
        asio::async_read_until(conn_->socket(), conn_->data(), JSON_VALUE_DELIM,
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
        if (logger_)
            logger_->e("[http:request:%i] [read:body] error: %s", id_, ec.message().c_str());
        terminate(ec);
        return;
    }
    if (!conn_->is_open()){
        if (logger_)
            logger_->e("[http:request] [read:body] closed connection");
        terminate(asio::error::not_connected);
        return;
    }
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
        auto body = conn_->read_until(JSON_VALUE_DELIM) + '\n';
        response_.body = body;
        parse_request(body);
    }
    if (logger_)
        logger_->d("[http:request:%i] [read:body] success:\n%s", id_, response_.body.c_str());

    // should be executed after each parse_request who can trigger http_parser on_message_complete
    if (message_complete_.load()){
        terminate(asio::error::eof);
    }
    // has content-length
    else if (content_length_it != response_.headers.end() and response_.body.size() != content_length)
        asio::async_read(conn_->socket(), conn_->data(),
            asio::transfer_exactly(content_length - response_.body.size()),
            std::bind(&Request::handle_response_body, this, std::placeholders::_1, std::placeholders::_2));
    // server wants to keep sending
    else if (response_.headers[HTTP_HEADER_CONNECTION] == HTTP_HEADER_CONNECTION_KEEP_ALIVE){
        asio::async_read_until(conn_->socket(), conn_->data(), JSON_VALUE_DELIM,
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
