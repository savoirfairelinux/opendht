/*
 *  Copyright (C) 2017 Savoir-faire Linux Inc.
 *  Author : Sébastien Blin <sebastien.blin@savoirfairelinux.com>
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

#if OPENDHT_PROXY_SERVER
#include "dht_proxy_server.h"

#include "default_types.h"
#include "dhtrunner.h"
#include "msgpack.hpp"

#include <chrono>
#include <functional>
#include <json/json.h>
#include <limits>

namespace dht {

DhtProxyServer::DhtProxyServer(std::shared_ptr<DhtRunner> dht, in_port_t port)
: dht_(dht)
{
    // NOTE in c++14, use make_unique
    service_ = std::unique_ptr<restbed::Service>(new restbed::Service());

    server_thread = std::thread([this, port]() {
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
#if OPENDHT_PROXY_SERVER_IDENTITY
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
#endif // OPENDHT_PROXY_SERVER_IDENTITY
        resource->set_method_handler("OPTIONS",
            [this](const std::shared_ptr<restbed::Session> session)
            {
                this->handleOptionsMethod(session);
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
        settings->set_default_header("Connection", "keep-alive");
        std::chrono::milliseconds timeout(std::numeric_limits<int>::max());
        settings->set_connection_timeout(timeout); // there is a timeout, but really huge
        settings->set_port(port);
        try {
            service_->start(settings);
        } catch(std::system_error& e) {
            std::cerr << "Error running server on port " << port << ": " << e.what() << std::endl;
        }
    });

    listenThread_ = std::thread([this]() {
        auto stop = false;
        while (!stop) {
            auto listener = currentListeners_.begin();
            while (listener != currentListeners_.end()) {
                if (listener->session->is_closed() && dht_) {
                    dht_->cancelListen(listener->hash, listener->token);
                    // Remove listener if unused
                    listener = currentListeners_.erase(listener);
                } else {
                     ++listener;
                }
            }
            //NOTE: When supports restbed 5.0: service_->is_up() and remove stopListeners
            stop = stopListeners;
            if (!stop)
                std::this_thread::sleep_for(std::chrono::seconds(1));
        }
    });
}

DhtProxyServer::~DhtProxyServer()
{
    stop();
}

void
DhtProxyServer::stop()
{
    service_->stop();
    stopListeners = true;
    // listenThreads_ will stop because there is no more sessions
    if (listenThread_.joinable())
        listenThread_.join();
    if (server_thread.joinable())
        server_thread.join();
}

void
DhtProxyServer::getNodeInfo(const std::shared_ptr<restbed::Session>& session) const
{
    const auto request = session->get_request();
    int content_length = std::stoi(request->get_header("Content-Length", "0"));
    session->fetch(content_length,
        [=](const std::shared_ptr<restbed::Session> s, const restbed::Bytes& /*b*/)
        {
            if (dht_) {
                Json::Value result;
                auto id = dht_->getId();
                if (id)
                    result["id"] = id.toString();
                result["node_id"] = dht_->getNodeId().toString();
                result["ipv4"] = dht_->getNodesStats(AF_INET).toJson();
                result["ipv6"] = dht_->getNodesStats(AF_INET6).toJson();
                Json::FastWriter writer;
                s->close(restbed::OK, writer.write(result));
            }
            else
                s->close(restbed::SERVICE_UNAVAILABLE, "{\"err\":\"Incorrect DhtRunner\"}");
        }
    );
}

void
DhtProxyServer::get(const std::shared_ptr<restbed::Session>& session) const
{
    const auto request = session->get_request();
    int content_length = std::stoi(request->get_header("Content-Length", "0"));
    auto hash = request->get_path_parameter("hash");
    session->fetch(content_length,
        [=](const std::shared_ptr<restbed::Session> s, const restbed::Bytes& /*b* */)
        {
            if (dht_) {
                InfoHash infoHash(hash);
                if (!infoHash) {
                    infoHash = InfoHash::get(hash);
                }
                s->yield(restbed::OK, "", [=]( const std::shared_ptr< restbed::Session > s) {
                    dht_->get(infoHash, [s](std::shared_ptr<Value> value) {
                        // Send values as soon as we get them
                        Json::FastWriter writer;
                        s->yield(writer.write(value->toJson()), [](const std::shared_ptr<restbed::Session> /*session*/){ });
                        return true;
                    }, [s](bool /*ok* */) {
                        // Communication is finished
                        s->close();
                    });
                });
            } else {
                s->close(restbed::SERVICE_UNAVAILABLE, "{\"err\":\"Incorrect DhtRunner\"}");
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
    InfoHash infoHash(hash);
    if (!infoHash)
        infoHash = InfoHash::get(hash);
    session->fetch(content_length,
        [=](const std::shared_ptr<restbed::Session> s, const restbed::Bytes& /*b* */)
        {
            if (dht_) {
                InfoHash infoHash(hash);
                if (!infoHash) {
                    infoHash = InfoHash::get(hash);
                }
                s->yield(restbed::OK, "", [=]( const std::shared_ptr< restbed::Session > s) {
                    size_t token = dht_->listen(infoHash, [s](std::shared_ptr<Value> value) {
                        // Send values as soon as we get them
                        if (!s->is_closed()) {
                            Json::FastWriter writer;
                            s->yield(writer.write(value->toJson()), [](const std::shared_ptr<restbed::Session> /*session*/){ });
                        }
                        return !s->is_closed();
                    }).get();
                    // Handle client deconnection
                    // NOTE: for now, there is no handler, so we test the session in a thread
                    // will be the case in restbed 5.0
                    SessionToHashToken listener;
                    listener.session = s;
                    listener.hash = infoHash;
                    listener.token = token;
                    currentListeners_.emplace_back(listener);
                });
            } else {
                s->close(restbed::SERVICE_UNAVAILABLE, "{\"err\":\"Incorrect DhtRunner\"}");
            }
        }
    );
}


void
DhtProxyServer::put(const std::shared_ptr<restbed::Session>& session) const
{
    // TODO test with the proxy client
    const auto request = session->get_request();
    int content_length = std::stoi(request->get_header("Content-Length", "0"));
    auto hash = request->get_path_parameter("hash");
    InfoHash infoHash(hash);
    if (!infoHash)
        infoHash = InfoHash::get(hash);

    session->fetch(content_length,
        [=](const std::shared_ptr<restbed::Session> s, const restbed::Bytes& b)
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
                        // Build the Value from json
                        auto value = std::make_shared<Value>(root);

                        Json::FastWriter writer;
                        dht_->put(infoHash, value);
                        s->close(restbed::OK, writer.write(value->toJson()));
                    } else {
                        s->close(restbed::BAD_REQUEST, "Incorrect JSON");
                    }
                }
            } else {
                s->close(restbed::SERVICE_UNAVAILABLE, "{\"err\":\"Incorrect DhtRunner\"}");
            }
        }
    );
}

#if OPENDHT_PROXY_SERVER_IDENTITY
void
DhtProxyServer::putSigned(const std::shared_ptr<restbed::Session>& session) const
{
    const auto request = session->get_request();
    int content_length = std::stoi(request->get_header("Content-Length", "0"));
    auto hash = request->get_path_parameter("hash");
    InfoHash infoHash(hash);
    if (!infoHash)
        infoHash = InfoHash::get(hash);

    session->fetch(content_length,
        [=](const std::shared_ptr<restbed::Session> s, const restbed::Bytes& b)
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

                        Json::FastWriter writer;
                        dht_->putSigned(infoHash, value);
                        s->close(restbed::OK, writer.write(value->toJson()));
                    } else {
                        s->close(restbed::BAD_REQUEST, "Incorrect JSON" + strJson);
                    }
                }
            } else {
                s->close(restbed::SERVICE_UNAVAILABLE, "{\"err\":\"Incorrect DhtRunner\"}");
            }
        }
    );
}

void
DhtProxyServer::putEncrypted(const std::shared_ptr<restbed::Session>& session) const
{
    const auto request = session->get_request();
    int content_length = std::stoi(request->get_header("Content-Length", "0"));
    auto hash = request->get_path_parameter("hash");
    InfoHash infoHash(hash);
    if (!infoHash)
        infoHash = InfoHash::get(hash);

    session->fetch(content_length,
        [=](const std::shared_ptr<restbed::Session> s, const restbed::Bytes& b)
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
                        if (toInfoHash)
                            toInfoHash = InfoHash::get(toHash);

                        Json::FastWriter writer;
                        dht_->putEncrypted(infoHash, toInfoHash, value);
                        s->close(restbed::OK, writer.write(value->toJson()));
                    } else {
                        if(!parsingSuccessful)
                            s->close(restbed::BAD_REQUEST, "Incorrect JSON");
                        else
                            s->close(restbed::BAD_REQUEST, "No destination found");
                    }
                }
            } else {
                s->close(restbed::SERVICE_UNAVAILABLE, "{\"err\":\"Incorrect DhtRunner\"}");
            }
        }
    );
}
#endif // OPENDHT_PROXY_SERVER_IDENTITY

void
DhtProxyServer::handleOptionsMethod(const std::shared_ptr<restbed::Session>& session) const
{
#if OPENDHT_PROXY_SERVER_IDENTITY
    const auto allowed = "OPTIONS, GET, POST, LISTEN, SIGN, ENCRYPT";
#else
    const auto allowed = "OPTIONS, GET, POST, LISTEN";
#endif //OPENDHT_PROXY_SERVER_IDENTITY
    session->close(restbed::OK, {{"Access-Control-Allow-Methods", allowed},
                                 {"Access-Control-Allow-Headers", "content-type"},
                                 {"Access-Control-Max-Age", "86400"}});
}

void
DhtProxyServer::getFiltered(const std::shared_ptr<restbed::Session>& session) const
{
    const auto request = session->get_request();
    int content_length = std::stoi(request->get_header("Content-Length", "0"));
    auto hash = request->get_path_parameter("hash");
    auto value = request->get_path_parameter("value");
    session->fetch(content_length,
        [=](const std::shared_ptr<restbed::Session> s, const restbed::Bytes& /*b* */)
        {
            if (dht_) {
                InfoHash infoHash(hash);
                if (!infoHash) {
                    infoHash = InfoHash::get(hash);
                }
                s->yield(restbed::OK, "", [=]( const std::shared_ptr< restbed::Session > s) {
                    dht_->get(infoHash, [s](std::shared_ptr<Value> v) {
                        // Send values as soon as we get them
                        Json::FastWriter writer;
                        s->yield(writer.write(v->toJson()), [](const std::shared_ptr<restbed::Session> /*session*/){ });
                        return true;
                    }, [s](bool /*ok* */) {
                        // Communication is finished
                        s->close();
                    }, {}, value);
                });
            } else {
                s->close(restbed::SERVICE_UNAVAILABLE, "{\"err\":\"Incorrect DhtRunner\"}");
            }
        }
    );
}

}
#endif //OPENDHT_PROXY_SERVER
