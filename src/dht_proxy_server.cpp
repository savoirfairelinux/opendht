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

#include <iostream>

using namespace std::placeholders;

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
        resource->set_method_handler("GET", std::bind(&DhtProxyServer::getNodeInfo, this, _1));
        service_->publish(resource);
        resource = std::make_shared<restbed::Resource>();
        resource->set_path("/{hash: .*}");
        resource->set_method_handler("GET", std::bind(&DhtProxyServer::get, this, _1));
        resource->set_method_handler("LISTEN", std::bind(&DhtProxyServer::listen, this, _1));
        resource->set_method_handler("POST", std::bind(&DhtProxyServer::put, this, _1));
#if OPENDHT_PROXY_SERVER_IDENTITY
        resource->set_method_handler("SIGN", std::bind(&DhtProxyServer::putSigned, this, _1));
        resource->set_method_handler("ENCRYPT", std::bind(&DhtProxyServer::putEncrypted, this, _1));
#endif // OPENDHT_PROXY_SERVER_IDENTITY
        resource->set_method_handler("OPTIONS", std::bind(&DhtProxyServer::handleOptionsMethod, this, _1));
        service_->publish(resource);
        resource = std::make_shared<restbed::Resource>();
        resource->set_path("/{hash: .*}/{value: .*}");
        resource->set_method_handler("GET", std::bind(&DhtProxyServer::getFiltered, this, _1));
        service_->publish(resource);

        // Start server
        auto settings = std::make_shared<restbed::Settings>();
        settings->set_default_header("Content-Type", "application/json");
        settings->set_default_header("Connection", "keep-alive");
        settings->set_default_header("Access-Control-Allow-Origin", "*");
        std::chrono::milliseconds timeout(std::numeric_limits<int>::max());
        settings->set_connection_timeout(timeout); // there is a timeout, but really huge
        settings->set_port(port);
        auto maxThreads = std::thread::hardware_concurrency() - 1;
        settings->set_worker_limit(maxThreads > 1 ? maxThreads : 1);
        try {
            service_->start(settings);
        } catch(std::system_error& e) {
            std::cerr << "Error running server on port " << port << ": " << e.what() << std::endl;
        }
    });

    listenThread_ = std::thread([this]() {
        while (!service_->is_up() && !stopListeners) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        while (service_->is_up()  && !stopListeners) {
            auto listener = currentListeners_.begin();
            while (listener != currentListeners_.end()) {
                if (dht_ && listener->session->is_closed()) {
                    dht_->cancelListen(listener->hash, std::move(listener->token));
                    // Remove listener if unused
                    listener = currentListeners_.erase(listener);
                } else {
                     ++listener;
                }
            }
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        // Remove last listeners
        auto listener = currentListeners_.begin();
        while (listener != currentListeners_.end()) {
            if (dht_) {
                dht_->cancelListen(listener->hash, std::move(listener->token));
                // Remove listener if unused
                listener = currentListeners_.erase(listener);
            } else {
                 ++listener;
            }
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
    auto listener = currentListeners_.begin();
    while (listener != currentListeners_.end()) {
        listener->session->close();
        ++ listener;
    }
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
                result["public_ip"] = s->get_origin(); // [ipv6:ipv4]:port or ipv4:port
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
                s->yield(restbed::OK);
                // Handle client deconnection
                // NOTE: for now, there is no handler, so we test the session in a thread
                // will be the case in restbed 5.0
                SessionToHashToken listener;
                listener.session = session;
                listener.hash = infoHash;
                // cache the session to avoid an incrementation of the shared_ptr's counter
                // else, the session->close() will not close the socket.
                auto cacheSession = std::weak_ptr<restbed::Session>(s);
                listener.token = std::move(dht_->listen(infoHash, [cacheSession](std::shared_ptr<Value> value) {
                    auto s = cacheSession.lock();
                    if (!s) return false;
                    // Send values as soon as we get them
                    if (!s->is_closed()) {
                        Json::FastWriter writer;
                        s->yield(writer.write(value->toJson()), [](const std::shared_ptr<restbed::Session>){ });
                    }
                    return !s->is_closed();
                }));
                currentListeners_.emplace_back(std::move(listener));
            } else {
                session->close(restbed::SERVICE_UNAVAILABLE, "{\"err\":\"Incorrect DhtRunner\"}");
            }
        }
    );
}

void
DhtProxyServer::put(const std::shared_ptr<restbed::Session>& session) const
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
                    std::string response("{\"err\":\"Missing parameters\"}");
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
                        auto permanent = root.isMember("permanent") ? root["permanent"].asBool() : false;

                        dht_->put(infoHash, value, [s, value](bool ok) {
                            if (ok) {
                                Json::FastWriter writer;
                                s->close(restbed::OK, writer.write(value->toJson()));
                            } else {
                                s->close(restbed::BAD_GATEWAY, "{\"err\":\"put failed\"}");
                            }
                        }, time_point::max(), permanent);
                    } else {
                        s->close(restbed::BAD_REQUEST, "{\"err\":\"Incorrect JSON\"}");
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
                    std::string response("{\"err\":\"Missing parameters\"}");
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
                        s->close(restbed::BAD_REQUEST, "{\"err\":\"Incorrect JSON\"}");
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
    InfoHash key(hash);
    if (!key)
        key = InfoHash::get(hash);

    session->fetch(content_length,
        [=](const std::shared_ptr<restbed::Session> s, const restbed::Bytes& b)
        {
            if (dht_) {
                if(b.empty()) {
                    std::string response("{\"err\":\"Missing parameters\"}");
                    s->close(restbed::BAD_REQUEST, response);
                } else {
                    restbed::Bytes buf(b);
                    Json::Value root;
                    Json::Reader reader;
                    std::string strJson(buf.begin(), buf.end());
                    bool parsingSuccessful = reader.parse(strJson.c_str(), root);
                    InfoHash to(root["to"].asString());
                    if (parsingSuccessful && to) {
                        auto value = std::make_shared<Value>(root);
                        Json::FastWriter writer;
                        dht_->putEncrypted(key, to, value);
                        s->close(restbed::OK, writer.write(value->toJson()));
                    } else {
                        if(!parsingSuccessful)
                            s->close(restbed::BAD_REQUEST, "{\"err\":\"Incorrect JSON\"}");
                        else
                            s->close(restbed::BAD_REQUEST, "{\"err\":\"No destination found\"}");
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
