// TODO GPL

#include "dhtproxyserver.h"

#include <chrono>
#include <functional>

#include "default_types.h"
#include "dhtrunner.h"
#include "msgpack.hpp"

#include <json/json.h>
#include <limits>

namespace dht {

DhtProxyServer::DhtProxyServer(DhtRunner* dht) : dht_(dht)
{
    // NOTE in c++14, use make_unique
    service_ = std::unique_ptr<restbed::Service>(new restbed::Service());

    server_thread = std::thread([this]() {
        // Create endpoints
        auto resource = std::make_shared<restbed::Resource>();
        resource->set_path("/");
        resource->set_method_handler("GET",
            [this](const std::shared_ptr<restbed::Session> session)
            {
                this->getNodeInfo(session);
            }
        );
        service_->publish(resource);
        resource = std::make_shared<restbed::Resource>();
        resource->set_path("/{hash: .*}");
        resource->set_method_handler("GET",
            [this](const std::shared_ptr<restbed::Session> session)
            {
                this->get(session);
            }
        );
        resource->set_method_handler("LISTEN",
            [this](const std::shared_ptr<restbed::Session> session)
            {
                this->listen(session);
            }
        );
        service_->publish(resource);

        // Start server
        auto settings = std::make_shared<restbed::Settings>();
        settings->set_default_header("Content-Type", "application/json");
        int port = 1984;
        int started = false;
        std::chrono::milliseconds sec(std::numeric_limits<int>::max());
        settings->set_connection_timeout(sec); // there is a timeout, but really huge
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
DhtProxyServer::getNodeInfo(const std::shared_ptr<restbed::Session>& session) const
{
    const auto request = session->get_request();
    int content_length = std::stoi(request->get_header("Content-Length", "0"));
    session->fetch(content_length,
        [&](const std::shared_ptr<restbed::Session> s, const restbed::Bytes& b)
        {
            if (dht_) {
                Json::Value result;
                result["id"] = dht_->getId().toString();
                result["node_id"] = dht_->getNodeId().toString();
                result["ipv4"] = dht_->getNodesStats(AF_INET).toString();
                result["ipv6"] = dht_->getNodesStats(AF_INET6).toString();
                Json::FastWriter writer;
                s->close(restbed::OK, writer.write(result));
            }
            else
                s->close(restbed::NOT_FOUND, "{\"err\":\"Incorrect DhtRunner\"}");
        }
    );
}

void
DhtProxyServer::get(const std::shared_ptr<restbed::Session>& session) const
{
    static constexpr dht::InfoHash INVALID_ID {};
    const auto request = session->get_request();
    int content_length = std::stoi(request->get_header("Content-Length", "0"));
    auto hash = request->get_path_parameter("hash");
    session->fetch(content_length,
        [&](const std::shared_ptr<restbed::Session> s, const restbed::Bytes& b)
        {
            if (dht_) {
                InfoHash infoHash(hash);
                if (infoHash == INVALID_ID) {
                    infoHash = InfoHash::get(hash);
                }
                Json::FastWriter writer;
                dht_->get(infoHash, [s, &writer](std::shared_ptr<Value> value) {
                    Json::Value result;
                    s->yield(restbed::OK,  writer.write(value->toJson()));
                    return true;
                }, [s, &writer](bool ok) {
                    auto response = std::to_string(ok);
                    s->close(restbed::OK, "{\"ok\": " + response + "}");
                });
            } else {
                s->close(restbed::NOT_FOUND, "{\"err\":\"Incorrect DhtRunner\"}");
            }
        }
    );
}

void
DhtProxyServer::listen(const std::shared_ptr<restbed::Session>& session) const
{
    static constexpr dht::InfoHash INVALID_ID {};
    const auto request = session->get_request();
    int content_length = std::stoi(request->get_header("Content-Length", "0"));
    auto hash = request->get_path_parameter("hash");
    InfoHash infoHash(hash);
    if (infoHash == INVALID_ID)
        infoHash = InfoHash::get(hash);
    size_t token;
    session->fetch(content_length,
        [&](const std::shared_ptr<restbed::Session> s, const restbed::Bytes& b)
        {
            if (dht_) {
                Json::FastWriter writer;
                token = dht_->listen(infoHash, [s, &writer](std::shared_ptr<Value> value) {
                    Json::Value result;
                    s->yield(restbed::OK,  writer.write(value->toJson()));
                    return true;
                }).get();
            } else {
                s->close(restbed::NOT_FOUND, "{\"err\":\"Incorrect DhtRunner\"}");
            }
        }
    );

    // TODO cancel listen at the end
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
