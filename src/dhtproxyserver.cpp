// TODO GPL

#if OPENDHT_PROXY_SERVER
#include "dhtproxyserver.h"

#include <chrono>
#include <functional>

#include "default_types.h"
#include "dhtrunner.h"
#include "msgpack.hpp"

#include <json/json.h>
#include <limits>

#include <iostream>

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
        resource->set_method_handler("POST",
            [this](const std::shared_ptr<restbed::Session> session)
            {
                this->put(session);
            }
        );
        // NOTE/TODO ENCRYPT AND SIGN must be optionnal
        resource->set_method_handler("SIGN",
            [this](const std::shared_ptr<restbed::Session> session)
            {
                this->putSigned(session);
            }
        );
        resource->set_method_handler("ENCRYPT",
            [this](const std::shared_ptr<restbed::Session> session)
            {
                this->putEncrypted(session);
            }
        );
        service_->publish(resource);
        resource = std::make_shared<restbed::Resource>();
        resource->set_path("/{hash: .*}/{value: .*}");
        resource->set_method_handler("GET",
            [this](const std::shared_ptr<restbed::Session> session)
            {
                this->getFiltered(session);
            }
        );
        service_->publish(resource);

        // Start server
        auto settings = std::make_shared<restbed::Settings>();
        settings->set_default_header("Content-Type", "application/json");
        int port = 1984;
        int started = false;
        std::chrono::seconds sec(3600);
        //std::chrono::milliseconds sec(std::numeric_limits<int>::max());
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
    // listenThreads_ will stop because there is no more sessions
    for (auto& listenThread: listenThreads_)
        if (listenThread->joinable())
            listenThread->join();
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
                    if (!s->is_closed())
                        s->yield(restbed::OK,  writer.write(value->toJson()));
                    return !s->is_closed();
                }).get();
                // Handle client deconnection
                listenThreads_.emplace_back(std::shared_ptr<std::thread>(
                    new std::thread([&]() {
                        while(!s->is_closed())
                            std::this_thread::sleep_for(std::chrono::seconds(2));
                        if (dht_)
                            dht_->cancelListen(infoHash, token);
                    }))
                );
            } else {
                s->close(restbed::NOT_FOUND, "{\"err\":\"Incorrect DhtRunner\"}");
            }
        }
    );
}


void
DhtProxyServer::put(const std::shared_ptr<restbed::Session>& session) const
{
    // TODO test with encrypted and signed value to send
    static constexpr dht::InfoHash INVALID_ID {};
    const auto request = session->get_request();
    int content_length = std::stoi(request->get_header("Content-Length", "0"));
    auto hash = request->get_path_parameter("hash");
    InfoHash infoHash(hash);
    if (infoHash == INVALID_ID)
        infoHash = InfoHash::get(hash);

    session->fetch(content_length,
        [&](const std::shared_ptr<restbed::Session> s, const restbed::Bytes& b)
        {
            if (dht_) {
                if(b.empty()) {
                    std::string response("Missing parameters");
                    s->close(restbed::BAD_REQUEST, response);
                } else {
                    restbed::Bytes buf(b);
                    Json::Value root;
                    Json::Reader reader;
                    std::string strJson(buf.begin(), buf.end());
                    bool parsingSuccessful = reader.parse(strJson.c_str(), root);
                    if (parsingSuccessful) {
                        auto value = std::make_shared<Value>(root);

                        auto response = value->toString();
                        dht_->put(infoHash, value);
                        s->close(restbed::OK, response);
                    } else {
                        s->close(restbed::BAD_REQUEST, "Incorrect JSON");
                    }
                }
            } else {
                s->close(restbed::NOT_FOUND, "");
            }
        }
    );
}

void
DhtProxyServer::putSigned(const std::shared_ptr<restbed::Session>& session) const
{
    static constexpr dht::InfoHash INVALID_ID {};
    const auto request = session->get_request();
    int content_length = std::stoi(request->get_header("Content-Length", "0"));
    auto hash = request->get_path_parameter("hash");
    InfoHash infoHash(hash);
    if (infoHash == INVALID_ID)
        infoHash = InfoHash::get(hash);

    session->fetch(content_length,
        [&](const std::shared_ptr<restbed::Session> s, const restbed::Bytes& b)
        {
            if (dht_) {
                if(b.empty()) {
                    std::string response("Missing parameters");
                    s->close(restbed::BAD_REQUEST, response);
                } else {
                    restbed::Bytes buf(b);
                    Json::Value root;
                    Json::Reader reader;
                    std::string strJson(buf.begin(), buf.end());
                    bool parsingSuccessful = reader.parse(strJson.c_str(), root);
                    if (parsingSuccessful) {
                        auto value = std::make_shared<Value>(root);

                        auto response = value->toString();
                        dht_->putSigned(infoHash, value);
                        s->close(restbed::OK, response);
                    } else {
                        s->close(restbed::BAD_REQUEST, "Incorrect JSON" + strJson);
                    }
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
    static constexpr dht::InfoHash INVALID_ID {};
    const auto request = session->get_request();
    int content_length = std::stoi(request->get_header("Content-Length", "0"));
    auto hash = request->get_path_parameter("hash");
    InfoHash infoHash(hash);
    if (infoHash == INVALID_ID)
        infoHash = InfoHash::get(hash);

    session->fetch(content_length,
        [&](const std::shared_ptr<restbed::Session> s, const restbed::Bytes& b)
        {
            if (dht_) {
                if(b.empty()) {
                    std::string response("Missing parameters");
                    s->close(restbed::BAD_REQUEST, response);
                } else {
                    restbed::Bytes buf(b);
                    Json::Value root;
                    Json::Reader reader;
                    std::string strJson(buf.begin(), buf.end());
                    bool parsingSuccessful = reader.parse(strJson.c_str(), root);
                    auto toHash = root["to"].asString();
                    if (parsingSuccessful && !toHash.empty()) {
                        auto value = std::make_shared<Value>(root);
                        auto toHash = request->get_path_parameter("to");
                        InfoHash toInfoHash(toHash);
                        if (toInfoHash == INVALID_ID)
                            toInfoHash = InfoHash::get(toHash);

                        auto response = value->toString();
                        dht_->putEncrypted(infoHash, toInfoHash, value);
                        s->close(restbed::OK, response);
                    } else {
                        if(!parsingSuccessful)
                            s->close(restbed::BAD_REQUEST, "Incorrect JSON");
                        else
                            s->close(restbed::BAD_REQUEST, "No destination found");
                    }
                }
            } else {
                s->close(restbed::NOT_FOUND, "");
            }
        }
    );
}

void
DhtProxyServer::getFiltered(const std::shared_ptr<restbed::Session>& session) const
{
    static constexpr dht::InfoHash INVALID_ID {};
    const auto request = session->get_request();
    int content_length = std::stoi(request->get_header("Content-Length", "0"));
    auto hash = request->get_path_parameter("hash");
    auto value = request->get_path_parameter("value");
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
                }, {}, value);
            } else {
                s->close(restbed::NOT_FOUND, "{\"err\":\"Incorrect DhtRunner\"}");
            }
        }
    );
}

}
#endif //OPENDHT_PROXY_SERVER
