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

#include <chrono>
#include <functional>

#include "default_types.h"
#include "dhtrunner.h"
#include "msgpack.hpp"

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
        std::chrono::milliseconds timeout(std::numeric_limits<int>::max());
        settings->set_connection_timeout(timeout); // there is a timeout, but really huge
        settings->set_port(port);
        try {
            service_->start(settings);
        } catch(std::system_error& e) {
            // Fail silently for now.
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
        [=](const std::shared_ptr<restbed::Session> s, const restbed::Bytes& b)
        {
            (void)b;
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
    const auto request = session->get_request();
    int content_length = std::stoi(request->get_header("Content-Length", "0"));
    auto hash = request->get_path_parameter("hash");
    session->fetch(content_length,
        [=](const std::shared_ptr<restbed::Session> s, const restbed::Bytes& b)
        {
            (void)b;
            if (dht_) {
                InfoHash infoHash(hash);
                if (!infoHash) {
                    infoHash = InfoHash::get(hash);
                }
                Json::FastWriter writer;
                dht_->get(infoHash, [s, &writer](std::shared_ptr<Value> value) {
                    // Send values as soon as we get them
                    Json::Value result;
                    s->yield(restbed::OK,  writer.write(value->toJson()));
                    return true;
                }, [s, &writer](bool ok) {
                    // Communication is finished
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
    const auto request = session->get_request();
    int content_length = std::stoi(request->get_header("Content-Length", "0"));
    auto hash = request->get_path_parameter("hash");
    InfoHash infoHash(hash);
    if (!infoHash)
        infoHash = InfoHash::get(hash);
    session->fetch(content_length,
        [=](const std::shared_ptr<restbed::Session> s, const restbed::Bytes& b)
        {
            (void)b;
            if (dht_) {
                s->yield(restbed::OK,  ""); // Open the connection
                Json::FastWriter writer;
                size_t token = dht_->listen(infoHash, [s, &writer](std::shared_ptr<Value> value) {
                    // Send values as soon as we get them
                    if (!s->is_closed())
                        s->yield(restbed::OK,  writer.write(value->toJson()));
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
            } else {
                s->close(restbed::NOT_FOUND, "{\"err\":\"Incorrect DhtRunner\"}");
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
                        if (toinfoHash)
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
#endif // OPENDHT_PROXY_SERVER_IDENTITY

void
DhtProxyServer::getFiltered(const std::shared_ptr<restbed::Session>& session) const
{
    const auto request = session->get_request();
    int content_length = std::stoi(request->get_header("Content-Length", "0"));
    auto hash = request->get_path_parameter("hash");
    auto value = request->get_path_parameter("value");
    session->fetch(content_length,
        [=](const std::shared_ptr<restbed::Session> s, const restbed::Bytes& b)
        {
            (void)b;
            if (dht_) {
                InfoHash infoHash(hash);
                if (!infoHash) {
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
