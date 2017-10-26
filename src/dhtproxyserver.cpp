// TODO GPL

#include "dhtproxyserver.h"

#include <chrono>
#include <functional>

#include "default_types.h"
#include "dhtrunner.h"
#include "msgpack.hpp"

#include <iostream>

namespace dht {

DhtProxyServer::DhtProxyServer(DhtRunner* dht) : dht_(dht)
{
    // NOTE in c++14, use make_unique
    service_ = std::unique_ptr<restbed::Service>(new restbed::Service());

    auto resource = std::make_shared<restbed::Resource>();
    resource->set_path("/get/{hash: .*}");
    resource->set_method_handler("GET",
        [this](const std::shared_ptr<restbed::Session> session)
        {
            this->get(session);
        }
    );
    service_->publish(resource);
    resource = std::make_shared<restbed::Resource>();
    resource->set_path("/getId");
    resource->set_method_handler("GET",
        [this](const std::shared_ptr<restbed::Session> session)
        {
            this->getId(session);
        }
    );
    service_->publish(resource);
    resource = std::make_shared<restbed::Resource>();
    resource->set_path("/getNodeId");
    resource->set_method_handler("GET",
        [this](const std::shared_ptr<restbed::Session> session)
        {
            this->getNodeId(session);
        }
    );
    service_->publish(resource);
    resource = std::make_shared<restbed::Resource>();
    resource->set_path("/listen/{hash: .*}");
    resource->set_method_handler("GET",
        [this](const std::shared_ptr<restbed::Session> session)
        {
            this->listen(session);
        }
    );
    service_->publish(resource);
    resource = std::make_shared<restbed::Resource>();
    resource->set_path("/putSigned");
    resource->set_method_handler("PUT",
        [this](const std::shared_ptr<restbed::Session> session)
        {
            this->putSigned(session);
        }
    );
    service_->publish(resource);
    resource = std::make_shared<restbed::Resource>();
    resource->set_path("/putEncrypted");
    resource->set_method_handler("PUT",
        [this](const std::shared_ptr<restbed::Session> session)
        {
            this->putEncrypted(session);
        }
    );
    service_->publish(resource);
    resource = std::make_shared<restbed::Resource>();
    resource->set_path("/put");
    resource->set_method_handler("PUT",
        [this](const std::shared_ptr<restbed::Session> session)
        {
            this->put(session);
        }
    );
    service_->publish(resource);

    server_thread = std::thread([this]() {
        auto settings = std::make_shared<restbed::Settings>();
        settings->set_default_header("Connection", "close");
        int port = 1984;
        int started = false;
        std::chrono::seconds sec(3600);
        settings->set_connection_timeout(sec); // TODO
        while (!started)
        {
            try {
                settings->set_port(port); // TODO add argument and move this
                service_->start(settings);
                started = true;
            } catch (std::system_error& e) {
                port += 1;
            }
        }
    });
}

DhtProxyServer::~DhtProxyServer()
{
    service_->stop();
    if (server_thread.joinable())
        server_thread.join();
}

void
DhtProxyServer::get(const std::shared_ptr<restbed::Session>& session) const
{
    const auto request = session->get_request();

    int content_length = std::stoi(request->get_header("Content-Length", "0"));
    auto hash = request->get_path_parameter("hash");

    session->fetch(content_length,
        [&](const std::shared_ptr<restbed::Session> s, const restbed::Bytes& b)
        {
            if (dht_) {
                dht_->get(InfoHash(hash), [s](std::shared_ptr<Value> value) {
                    s->yield(restbed::OK,  value->toString());
                    return true;
                }, [s](bool ok) {
                    auto response = std::to_string(ok);
                    s->close(restbed::OK, response);//);
                });
            } else {
                s->close(restbed::NOT_FOUND, "");
            }
        }
    );
}

void
DhtProxyServer::getId(const std::shared_ptr<restbed::Session>& session) const
{
    const auto request = session->get_request();

    int content_length = std::stoi(request->get_header("Content-Length", "0"));

    session->fetch(content_length,
        [&](const std::shared_ptr<restbed::Session> s, const restbed::Bytes& b)
        {
            if (dht_) {
                auto id = dht_->getId().toString();
                s->close(restbed::OK, id);
            } else {
                s->close(restbed::NOT_FOUND, "");
            }
        }
    );
}

void
DhtProxyServer::getNodeId(const std::shared_ptr<restbed::Session>& session) const
{
    const auto request = session->get_request();

    int content_length = std::stoi(request->get_header("Content-Length", "0"));

    session->fetch(content_length,
        [&](const std::shared_ptr<restbed::Session> s, const restbed::Bytes& b)
        {
            if (dht_) {
                auto id = dht_->getNodeId().toString();
                s->close(restbed::OK, id);
            } else {
                s->close(restbed::NOT_FOUND, "");
            }
        }
    );
}

void
DhtProxyServer::listen(const std::shared_ptr<restbed::Session>& session) const
{
    const auto request = session->get_request();

    int content_length = std::stoi(request->get_header("Content-Length", "0"));
    auto hash = request->get_path_parameter("hash");

    session->fetch(content_length,
        [&](const std::shared_ptr<restbed::Session> s, const restbed::Bytes& b)
        {
            if (dht_) {
                dht_->listen(InfoHash(hash), [s](std::shared_ptr<Value> value) {
                    s->yield(restbed::OK,  value->toString());
                    return true;
                });
            } else {
                s->close(restbed::NOT_FOUND, "");
            }
        }
    );
}

void
DhtProxyServer::putSigned(const std::shared_ptr<restbed::Session>& session) const
{
    const auto request = session->get_request();

    int content_length = std::stoi(request->get_header("Content-Length", "0"));

    session->fetch(content_length,
        [&](const std::shared_ptr<restbed::Session> s, const restbed::Bytes& b)
        {
            if (dht_) {
                if(b.empty()) {
                    std::string response("Missing parameters");
                    s->close(restbed::BAD_REQUEST, response);
                } else {
                    restbed::Bytes buf(b);

                    unsigned char delimiter = static_cast<unsigned char>('\n');
                    // Retrieve hash
                    unsigned int idx = 0;
                    std::vector<unsigned char> hashBuf;
                    while(idx < buf.size() && buf[idx] != delimiter) {
                        hashBuf.emplace_back(buf[idx]);
                        ++idx;
                    }
                    ++idx;
                    // Retrieve value
                    std::vector<unsigned char> valueBuf;
                    while(idx < buf.size()) {
                        valueBuf.emplace_back(buf[idx]);
                        ++idx;
                    }
                    // Build parameters
                    InfoHash hash(hashBuf.data(), hashBuf.size());
                    msgpack::unpacked msg;
                    msgpack::unpack(msg, reinterpret_cast<const char*>(valueBuf.data()), valueBuf.size());
                    auto value = std::make_shared<Value>(msg.get());

                    dht_->putSigned(hash, value);
                    s->close(restbed::OK, "");
                }
            } else {
                s->close(restbed::NOT_FOUND, "");
            }
        }
    );
}

void
DhtProxyServer::putEncrypted(const std::shared_ptr<restbed::Session>& session) const
{
    const auto request = session->get_request();

    int content_length = std::stoi(request->get_header("Content-Length", "0"));

    session->fetch(content_length,
        [&](const std::shared_ptr<restbed::Session> s, const restbed::Bytes& b)
        {
            if (dht_) {
                if(b.empty()) {
                    std::string response("Missing parameters");
                    s->close(restbed::BAD_REQUEST, response);
                } else {
                    restbed::Bytes buf(b);

                    unsigned char delimiter = static_cast<unsigned char>('\n');
                    // Retrieve hash
                    unsigned int idx = 0;
                    std::vector<unsigned char> hashBuf;
                    while(idx < buf.size() && buf[idx] != delimiter) {
                        hashBuf.emplace_back(buf[idx]);
                        ++idx;
                    }
                    ++idx;
                    // Retrieve to
                    std::vector<unsigned char> toBuf;
                    while(idx < buf.size() && buf[idx] != delimiter) {
                        toBuf.emplace_back(buf[idx]);
                        ++idx;
                    }
                    ++idx;
                    // Retrieve value
                    std::vector<unsigned char> valueBuf;
                    while(idx < buf.size()) {
                        valueBuf.emplace_back(buf[idx]);
                        ++idx;
                    }
                    InfoHash hash(hashBuf.data(), hashBuf.size());
                    InfoHash to(toBuf.data(), toBuf.size());
                    msgpack::unpacked msg;
                    msgpack::unpack(msg, reinterpret_cast<const char*>(valueBuf.data()), valueBuf.size());
                    auto value = std::make_shared<Value>(msg.get());

                    dht_->putEncrypted(hash, to, value);
                    s->close(restbed::OK, "");
                }
            } else {
                s->close(restbed::NOT_FOUND, "");
            }
        }
    );
}

void
DhtProxyServer::put(const std::shared_ptr<restbed::Session>& session) const
{
    // TODO test with encrypted and signed value to send
    const auto request = session->get_request();

    int content_length = std::stoi(request->get_header("Content-Length", "0"));

    session->fetch(content_length,
        [&](const std::shared_ptr<restbed::Session> s, const restbed::Bytes& b)
        {
            if (dht_) {
                if(b.empty()) {
                    std::string response("Missing parameters");
                    s->close(restbed::BAD_REQUEST, response);
                } else {
                    restbed::Bytes buf(b);

                    unsigned char delimiter = static_cast<unsigned char>('\n');
                    // Retrieve hash
                    unsigned int idx = 0;
                    std::vector<unsigned char> hashBuf;
                    while(idx < buf.size() && buf[idx] != delimiter) {
                        hashBuf.emplace_back(buf[idx]);
                        ++idx;
                    }
                    ++idx;
                    // Retrieve value
                    std::vector<unsigned char> valueBuf;
                    while(idx < buf.size()) {
                        valueBuf.emplace_back(buf[idx]);
                        ++idx;
                    }
                    // Build parameters
                    InfoHash hash(hashBuf.data(), hashBuf.size());
                    msgpack::unpacked msg;
                    msgpack::unpack(msg, reinterpret_cast<const char*>(valueBuf.data()), valueBuf.size());
                    auto value = std::make_shared<Value>(msg.get());

                    auto response = value->toString();
                    dht_->put(hash, value);
                    s->close(restbed::OK, response);
                }
            } else {
                s->close(restbed::NOT_FOUND, "");
            }
        }
    );
}

}
