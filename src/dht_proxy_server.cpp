/*
 *  Copyright (C) 2017 Savoir-faire Linux Inc.
 *  Author: Sébastien Blin <sebastien.blin@savoirfairelinux.com>
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

#if OPENDHT_PUSH_NOTIFICATIONS
constexpr int const TIMEOUT {6 * 60 * 60}; // in seconds (so six hours)
constexpr const char* const HTTP_PROTO {"http://"}; // TODO, https for prod
#endif //OPENDHT_PUSH_NOTIFICATIONS

using namespace std::placeholders;

namespace dht {

DhtProxyServer::DhtProxyServer(std::shared_ptr<DhtRunner> dht, in_port_t port
#if OPENDHT_PUSH_NOTIFICATIONS
                   , const std::string& pushServer
#endif // OPENDHT_PUSH_NOTIFICATIONS
)
: dht_(dht)
#if OPENDHT_PUSH_NOTIFICATIONS
, pushServer_(pushServer)
#endif // OPENDHT_PUSH_NOTIFICATIONS
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
#if OPENDHT_PUSH_NOTIFICATIONS
        resource->set_method_handler("SUBSCRIBE", std::bind(&DhtProxyServer::subscribe, this, _1));
        resource->set_method_handler("UNSUBSCRIBE", std::bind(&DhtProxyServer::unsubscribe, this, _1));
#endif //OPENDHT_PUSH_NOTIFICATIONS
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
            removeClosedListeners();
            // add listener from push notifs
#if OPENDHT_PUSH_NOTIFICATIONS
            handlePushListeners();
#endif //OPENDHT_PUSH_NOTIFICATIONS
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        // Remove last listeners
        removeClosedListeners(false);
    });

    dht->forwardAllMessages(true);
}

DhtProxyServer::~DhtProxyServer()
{
    stop();
}

void
DhtProxyServer::stop()
{
    service_->stop();
    {
        std::lock_guard<std::mutex> lock(lockListener_);
        auto listener = currentListeners_.begin();
        while (listener != currentListeners_.end()) {
            listener->session->close();
            ++ listener;
        }
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
                Json::StreamWriterBuilder wbuilder;
                wbuilder["commentStyle"] = "None";
                wbuilder["indentation"] = "";
                auto output = Json::writeString(wbuilder, result) + "\n";
                s->close(restbed::OK, output);
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
                    auto cacheSession = std::weak_ptr<restbed::Session>(s);

                    dht_->get(infoHash, [cacheSession](std::shared_ptr<Value> value) {
                        auto s = cacheSession.lock();
                        if (!s) return false;
                        // Send values as soon as we get them
                        Json::StreamWriterBuilder wbuilder;
                        wbuilder["commentStyle"] = "None";
                        wbuilder["indentation"] = "";
                        auto output = Json::writeString(wbuilder, value->toJson()) + "\n";
                        s->yield(output, [](const std::shared_ptr<restbed::Session> /*session*/){ });
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
                listener.token = dht_->listen(infoHash, [cacheSession](std::shared_ptr<Value> value) {
                    auto s = cacheSession.lock();
                    if (!s) return false;
                    // Send values as soon as we get them
                    if (!s->is_closed()) {
                        Json::StreamWriterBuilder wbuilder;
                        wbuilder["commentStyle"] = "None";
                        wbuilder["indentation"] = "";
                        auto output = Json::writeString(wbuilder, value->toJson()) + "\n";
                        s->yield(output, [](const std::shared_ptr<restbed::Session>){ });
                    }
                    return !s->is_closed();
                });
                {
                    std::lock_guard<std::mutex> lock(lockListener_);
                    currentListeners_.emplace_back(std::move(listener));
                }
            } else {
                session->close(restbed::SERVICE_UNAVAILABLE, "{\"err\":\"Incorrect DhtRunner\"}");
            }
        }
    );
}

#if OPENDHT_PUSH_NOTIFICATIONS
void
DhtProxyServer::subscribe(const std::shared_ptr<restbed::Session>& session) const
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
            try {
                restbed::Bytes buf(b);
                std::string strJson(buf.begin(), buf.end());

                std::string err;
                Json::Value root;
                Json::CharReaderBuilder rbuilder;
                auto* char_data = reinterpret_cast<const char*>(&strJson[0]);
                auto reader = std::unique_ptr<Json::CharReader>(rbuilder.newCharReader());
                if (!reader->parse(char_data, char_data + strJson.size(), &root, &err)) {
                    s->close(restbed::BAD_REQUEST, "{\"err\":\"Incorrect JSON\"}");
                    return;
                }
                auto userKey = root["key"].asString();
                if (userKey.empty()) return;
                auto callbackId = root.isMember("callback_id") ? root["callback_id"].asLargestUInt() : 0;
                auto isAndroid = root.isMember("isAndroid") ? root["isAndroid"].asBool() : true;

                auto token = 0;
                {
                    std::lock_guard<std::mutex> lock(lockListener_);
                    // Check if listener is already present and refresh timeout if launched
                    for(auto& listener: pushListeners_) {
                        if (listener.key == userKey && listener.hash == infoHash
                        && listener.callbackId == callbackId) {
                            if (listener.started)
                                listener.deadline = std::chrono::steady_clock::now()
                                                  + std::chrono::seconds(TIMEOUT);
                            s->close(restbed::OK, "{\"token\": " + std::to_string(listener.token) + "}\n");
                            return;
                        }
                    }
                    // The listener is not found, so add it.
                    ++tokenPushNotif_;
                    token = tokenPushNotif_;
                    PushListener listener;
                    listener.key = userKey;
                    listener.hash = std::move(infoHash);
                    listener.token = token;
                    listener.started = false;
                    listener.callbackId = callbackId;
                    listener.isAndroid = isAndroid;
                    pushListeners_.emplace_back(std::move(listener));
                }
                s->close(restbed::OK, "{\"token\": " + std::to_string(token) + "}\n");
            } catch (...) {
                // do nothing
            }
        }
    );
}

void
DhtProxyServer::unsubscribe(const std::shared_ptr<restbed::Session>& session) const
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
            try {
                restbed::Bytes buf(b);
                std::string strJson(buf.begin(), buf.end());

                std::string err;
                Json::Value root;
                Json::CharReaderBuilder rbuilder;
                auto* char_data = reinterpret_cast<const char*>(&strJson[0]);
                auto reader = std::unique_ptr<Json::CharReader>(rbuilder.newCharReader());
                if (!reader->parse(char_data, char_data + strJson.size(), &root, &err)) {
                    s->close(restbed::BAD_REQUEST, "{\"err\":\"Incorrect JSON\"}");
                    return;
                }
                auto userKey = root["key"].asString();
                if (userKey.empty()) return;
                auto token = root["token"].asLargestUInt();
                if (token == 0) return;
                auto callbackId = root.isMember("callback_id") ? root["callback_id"].asLargestUInt() : 0;

                std::lock_guard<std::mutex> lock(lockListener_);
                // Check if listener is already present and refresh timeout if launched
                auto listener = pushListeners_.begin();
                while (listener != pushListeners_.end()) {
                    if (listener->key == userKey && listener->token == token
                    && listener->hash == infoHash && listener->callbackId == callbackId) {
                        if (dht_ && listener->started)
                            dht_->cancelListen(listener->hash, std::move(listener->internalToken.get()));
                        listener = pushListeners_.erase(listener);
                    } else {
                        ++listener;
                    }
                }
            } catch (...) {
                // do nothing
            }
        }
    );
}

void
DhtProxyServer::sendPushNotification(const std::string& key, const Json::Value& json, bool isAndroid) const
{
    restbed::Uri uri(HTTP_PROTO + pushServer_ + "/api/push");
    auto req = std::make_shared<restbed::Request>(uri);
    req->set_method("POST");

    Json::StreamWriterBuilder wbuilder;
    wbuilder["commentStyle"] = "None";
    wbuilder["indentation"] = "";
    auto valueStr = Json::writeString(wbuilder, json);
    // Escape JSON
    std::string::size_type n = 0;
    while ((n = valueStr.find( "\"", n)) != std::string::npos) {
        valueStr.replace( n, 1, "\\\"" );
        n += 2;
    }
    std::replace(valueStr.begin(), valueStr.end(), '\n', ' ');

    // NOTE: see https://github.com/appleboy/gorush
    auto platform = isAndroid ? 2 : 1;
    auto content = std::string("{\"notifications\": [{\"tokens\": [\""
    + key + "\"], \"platform\":  " + std::to_string(platform)
    + ",\"message\": \"" + valueStr + "\"}]}");
    req->set_header("Content-Type", "application/json");
    req->set_header("Accept", "*/*");
    req->set_header("Host", pushServer_);
    req->set_header("Content-Length", std::to_string(content.length()));
    req->set_body(content);
    // Send request.
    restbed::Http::async(req, {});
}

void
DhtProxyServer::handlePushListeners()
{
    std::lock_guard<std::mutex> lock(lockListener_);
    auto pushListener = pushListeners_.begin();
    while (pushListener != pushListeners_.end()) {
        if (dht_ && !pushListener->started) {
            // Try to start unstarted listeners
            auto key = pushListener->key;
            auto token = pushListener->token;
            auto callbackId = pushListener->callbackId;
            auto isAndroid = pushListener->isAndroid;
            auto internalToken = std::move(dht_->listen(pushListener->hash,
                [this, key, callbackId, token, isAndroid](std::shared_ptr<Value> /*value*/) {
                    // Build message content.
                    Json::Value json;
                    if (callbackId > 0) {
                        json["callback_id"] = callbackId;
                    }
                    json["token"] = token;
                    sendPushNotification(key, json, isAndroid);
                    return true;
                }
            ));
            pushListener->internalToken = std::move(internalToken);
            pushListener->deadline = std::chrono::steady_clock::now() + std::chrono::seconds(TIMEOUT);
            pushListener->started = true;
            pushListener++;
        } else if (dht_ && pushListener->started && pushListener->deadline < std::chrono::steady_clock::now()) {
            // Cancel listen if deadline has been reached
            dht_->cancelListen(pushListener->hash, std::move(pushListener->internalToken.get()));
            // Send a push notification to inform the client that this listen has timeout
            Json::Value json;
            json["timeout"] = pushListener->hash.toString();
            if (pushListener->callbackId > 0) {
                json["callback_id"] = pushListener->callbackId;
            }
            json["token"] = pushListener->token;
            sendPushNotification(pushListener->key, json, pushListener->isAndroid);
            pushListener = pushListeners_.erase(pushListener);
        } else {
            pushListener++;
        }
    }
}
#endif //OPENDHT_PUSH_NOTIFICATIONS

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
                    std::string strJson(buf.begin(), buf.end());

                    std::string err;
                    Json::Value root;
                    Json::CharReaderBuilder rbuilder;
                    auto* char_data = reinterpret_cast<const char*>(&strJson[0]);
                    auto reader = std::unique_ptr<Json::CharReader>(rbuilder.newCharReader());
                    if (reader->parse(char_data, char_data + strJson.size(), &root, &err)) {
                        // Build the Value from json
                        auto value = std::make_shared<Value>(root);
                        auto permanent = root.isMember("permanent") ? root["permanent"].asBool() : false;

                        dht_->put(infoHash, value, [s, value](bool ok) {
                            if (ok) {
                                Json::StreamWriterBuilder wbuilder;
                                wbuilder["commentStyle"] = "None";
                                wbuilder["indentation"] = "";
                                if (s->is_open())
                                    s->close(restbed::OK, Json::writeString(wbuilder, value->toJson()) + "\n");
                            } else {
                                if (s->is_open())
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
                    std::string strJson(buf.begin(), buf.end());

                    std::string err;
                    Json::Value root;
                    Json::CharReaderBuilder rbuilder;
                    auto* char_data = reinterpret_cast<const char*>(&strJson[0]);
                    auto reader = std::unique_ptr<Json::CharReader>(rbuilder.newCharReader());
                    if (reader->parse(char_data, char_data + strJson.size(), &root, &err)) {
                        auto value = std::make_shared<Value>(root);

                        Json::StreamWriterBuilder wbuilder;
                        wbuilder["commentStyle"] = "None";
                        wbuilder["indentation"] = "";
                        auto output = Json::writeString(wbuilder, value->toJson()) + "\n";
                        dht_->putSigned(infoHash, value);
                        s->close(restbed::OK, output);
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
                    std::string strJson(buf.begin(), buf.end());

                    std::string err;
                    Json::Value root;
                    Json::CharReaderBuilder rbuilder;
                    auto* char_data = reinterpret_cast<const char*>(&strJson[0]);
                    auto reader = std::unique_ptr<Json::CharReader>(rbuilder.newCharReader());
                    bool parsingSuccessful = reader->parse(char_data, char_data + strJson.size(), &root, &err);
                    InfoHash to(root["to"].asString());
                    if (parsingSuccessful && to) {
                        auto value = std::make_shared<Value>(root);
                        Json::StreamWriterBuilder wbuilder;
                        wbuilder["commentStyle"] = "None";
                        wbuilder["indentation"] = "";
                        auto output = Json::writeString(wbuilder, value->toJson()) + "\n";
                        dht_->putEncrypted(key, to, value);
                        s->close(restbed::OK, output);
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
                        Json::StreamWriterBuilder wbuilder;
                        wbuilder["commentStyle"] = "None";
                        wbuilder["indentation"] = "";
                        auto output = Json::writeString(wbuilder, v->toJson()) + "\n";
                        s->yield(output, [](const std::shared_ptr<restbed::Session> /*session*/){ });
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

void
DhtProxyServer::removeClosedListeners(bool testSession)
{
    // clean useless listeners
    std::lock_guard<std::mutex> lock(lockListener_);
    auto listener = currentListeners_.begin();
    while (listener != currentListeners_.end()) {
        auto cancel = testSession ? dht_ && listener->session->is_closed() : static_cast<bool>(dht_);
        if (cancel) {
            dht_->cancelListen(listener->hash, std::move(listener->token.get()));
            // Remove listener if unused
            listener = currentListeners_.erase(listener);
        } else {
             ++listener;
        }
    }
}

}
#endif //OPENDHT_PROXY_SERVER
