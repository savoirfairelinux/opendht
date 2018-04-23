/*
 *  Copyright (C) 2017-2018 Savoir-faire Linux Inc.
 *  Author: Sébastien Blin <sebastien.blin@savoirfairelinux.com>
 *          Adrien Béraud <adrien.beraud@savoirfairelinux.com>
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

#include <msgpack.hpp>
#include <json/json.h>

#include <chrono>
#include <functional>
#include <limits>
#include <iostream>

using namespace std::placeholders;

namespace dht {

struct DhtProxyServer::PermanentPut {
    time_point expiration;
    std::string pushToken;
    std::string clientId;
    Sp<Scheduler::Job> expireJob;
    Sp<Scheduler::Job> expireNotifyJob;
};
struct DhtProxyServer::SearchPuts {
    std::map<dht::Value::Id, PermanentPut> puts;
};

constexpr const std::chrono::minutes PRINT_STATS_PERIOD {2};

DhtProxyServer::DhtProxyServer(std::shared_ptr<DhtRunner> dht, in_port_t port , const std::string& pushServer)
: dht_(dht) , pushServer_(pushServer)
{
    if (not dht_)
        throw std::invalid_argument("A DHT instance must be provided");
    // NOTE in c++14, use make_unique
    service_ = std::unique_ptr<restbed::Service>(new restbed::Service());

    std::cout << "Running DHT proxy server on port " << port << std::endl;
    if (not pushServer.empty()) {
#if !OPENDHT_PUSH_NOTIFICATIONS
        std::cerr << "Push server defined but built OpenDHT built without push notification support" << std::endl;
#else
        std::cout << "Using push notification server: " << pushServer << std::endl;
#endif
    }

    server_thread = std::thread([this, port]() {
        // Create endpoints
        auto resource = std::make_shared<restbed::Resource>();
        resource->set_path("/");
        resource->set_method_handler("GET", std::bind(&DhtProxyServer::getNodeInfo, this, _1));
        resource->set_method_handler("STATS", std::bind(&DhtProxyServer::getStats, this, _1));
        service_->publish(resource);
        resource = std::make_shared<restbed::Resource>();
        resource->set_path("/{hash: .*}");
        resource->set_method_handler("GET", std::bind(&DhtProxyServer::get, this, _1));
        resource->set_method_handler("LISTEN", [this](const Sp<restbed::Session>& session) mutable { listen(session); } );
#if OPENDHT_PUSH_NOTIFICATIONS
        resource->set_method_handler("SUBSCRIBE", [this](const Sp<restbed::Session>& session) mutable { subscribe(session); } );
        resource->set_method_handler("UNSUBSCRIBE", [this](const Sp<restbed::Session>& session) mutable { unsubscribe(session); } );
#endif //OPENDHT_PUSH_NOTIFICATIONS
        resource->set_method_handler("POST", [this](const Sp<restbed::Session>& session) mutable { put(session); });
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
        lastStatsReset_ = clock::now();
        try {
            service_->start(settings);
        } catch(std::system_error& e) {
            std::cerr << "Error running server on port " << port << ": " << e.what() << std::endl;
        }
    });

    listenThread_ = std::thread([this]() {
        while (not service_->is_up() and not stopListeners) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        while (service_->is_up() and not stopListeners) {
            removeClosedListeners();
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        // Remove last listeners
        removeClosedListeners(false);
    });
    schedulerThread_ = std::thread([this]() {
        while (not service_->is_up() and not stopListeners) {
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        while (service_->is_up()  and not stopListeners) {
            std::unique_lock<std::mutex> lock(schedulerLock_);
            auto next = scheduler_.run();
            if (next == time_point::max())
                schedulerCv_.wait(lock);
            else
                schedulerCv_.wait_until(lock, next);
        }
    });
    dht->forwardAllMessages(true);
    printStatsJob_ = scheduler_.add(scheduler_.time() + PRINT_STATS_PERIOD, [this] {
        if (stopListeners) return;
        if (service_->is_up())
            updateStats();
        // Refresh stats cache
        auto newInfo = dht_->getNodeInfo();
        {
            std::lock_guard<std::mutex> lck(statsMutex_);
            nodeInfo_ = std::move(newInfo);
        }
        scheduler_.edit(printStatsJob_, scheduler_.time() + PRINT_STATS_PERIOD);
    });
}

DhtProxyServer::~DhtProxyServer()
{
    stop();
}

void
DhtProxyServer::stop()
{
    if (printStatsJob_)
        printStatsJob_->cancel();
    service_->stop();
    {
        std::lock_guard<std::mutex> lock(lockListener_);
        auto listener = currentListeners_.begin();
        while (listener != currentListeners_.end()) {
            listener->session->close();
            ++listener;
        }
    }
    stopListeners = true;
    schedulerCv_.notify_all();
    // listenThreads_ will stop because there is no more sessions
    if (listenThread_.joinable())
        listenThread_.join();
    if (schedulerThread_.joinable())
        schedulerThread_.join();
    if (server_thread.joinable())
        server_thread.join();
}

void
DhtProxyServer::updateStats() const
{
    auto now = clock::now();
    auto last = lastStatsReset_.exchange(now);
    auto count = requestNum_.exchange(0);
    auto dt = std::chrono::duration<double>(now - last);
    stats_.requestRate = count / dt.count();
#if OPENDHT_PUSH_NOTIFICATIONS
    stats_.pushListenersCount = pushListeners_.size();
#endif
    stats_.putCount = puts_.size();
    stats_.listenCount = currentListeners_.size();
    stats_.nodeInfo = nodeInfo_;
}

void
DhtProxyServer::getNodeInfo(const Sp<restbed::Session>& session) const
{
    requestNum_++;
    const auto request = session->get_request();
    int content_length = std::stoi(request->get_header("Content-Length", "0"));
    session->fetch(content_length,
        [this](const Sp<restbed::Session>& s, const restbed::Bytes& /*b*/) mutable
        {
            try {
                if (dht_) {
                    Json::Value result;
                    {
                        std::lock_guard<std::mutex> lck(statsMutex_);
                        if (nodeInfo_.ipv4.good_nodes == 0 && nodeInfo_.ipv6.good_nodes == 0) {
                            // NOTE: we want to avoid the disconnected state as much as possible
                            // So, if the node is disconnected, we should force the update of the cache
                            // and reconnect as soon as possible
                            // This should not happen much
                            nodeInfo_ = dht_->getNodeInfo();
                        }
                        result = nodeInfo_.toJson();
                    }
                    result["public_ip"] = s->get_origin(); // [ipv6:ipv4]:port or ipv4:port
                    Json::StreamWriterBuilder wbuilder;
                    wbuilder["commentStyle"] = "None";
                    wbuilder["indentation"] = "";
                    auto output = Json::writeString(wbuilder, result) + "\n";
                    s->close(restbed::OK, output);
                }
                else
                    s->close(restbed::SERVICE_UNAVAILABLE, "{\"err\":\"Incorrect DhtRunner\"}");
            } catch (...) {
                s->close(restbed::INTERNAL_SERVER_ERROR, "{\"err\":\"Internal server error\"}");
            }
        }
    );
}

void
DhtProxyServer::getStats(const Sp<restbed::Session>& session) const
{
    requestNum_++;
    const auto request = session->get_request();
    int content_length = std::stoi(request->get_header("Content-Length", "0"));
    session->fetch(content_length,
        [this](const Sp<restbed::Session>& s, const restbed::Bytes& /*b*/) mutable
        {
            try {
                if (dht_) {
#ifdef OPENDHT_JSONCPP
                    Json::StreamWriterBuilder wbuilder;
                    wbuilder["commentStyle"] = "None";
                    wbuilder["indentation"] = "";
                    auto output = Json::writeString(wbuilder, stats_.toJson()) + "\n";
                    s->close(restbed::OK, output);
#else
                    s->close(restbed::NotFound, "{\"err\":\"JSON not enabled on this instance\"}");
#endif
                }
                else
                    s->close(restbed::SERVICE_UNAVAILABLE, "{\"err\":\"Incorrect DhtRunner\"}");
            } catch (...) {
                s->close(restbed::INTERNAL_SERVER_ERROR, "{\"err\":\"Internal server error\"}");
            }
        }
    );
}

void
DhtProxyServer::get(const Sp<restbed::Session>& session) const
{
    requestNum_++;
    const auto request = session->get_request();
    int content_length = std::stoi(request->get_header("Content-Length", "0"));
    auto hash = request->get_path_parameter("hash");
    session->fetch(content_length,
        [=](const Sp<restbed::Session>& s, const restbed::Bytes& /*b* */)
        {
            try {
                if (dht_) {
                    InfoHash infoHash(hash);
                    if (!infoHash) {
                        infoHash = InfoHash::get(hash);
                    }
                    s->yield(restbed::OK, "", [=](const Sp<restbed::Session>&) {});
                    dht_->get(infoHash, [s](const Sp<Value>& value) {
                        if (s->is_closed()) return false;
                        // Send values as soon as we get them
                        Json::StreamWriterBuilder wbuilder;
                        wbuilder["commentStyle"] = "None";
                        wbuilder["indentation"] = "";
                        auto output = Json::writeString(wbuilder, value->toJson()) + "\n";
                        s->yield(output, [](const Sp<restbed::Session>& /*session*/){ });
                        return true;
                    }, [s](bool /*ok* */) {
                        // Communication is finished
                        if (not s->is_closed()) {
                            s->close();
                        }
                    });
                } else {
                    s->close(restbed::SERVICE_UNAVAILABLE, "{\"err\":\"Incorrect DhtRunner\"}");
                }
            } catch (...) {
                s->close(restbed::INTERNAL_SERVER_ERROR, "{\"err\":\"Internal server error\"}");
            }
        }
    );
}

void
DhtProxyServer::listen(const Sp<restbed::Session>& session)
{
    requestNum_++;
    const auto request = session->get_request();
    int content_length = std::stoi(request->get_header("Content-Length", "0"));
    auto hash = request->get_path_parameter("hash");
    InfoHash infoHash(hash);
    if (!infoHash)
        infoHash = InfoHash::get(hash);
    session->fetch(content_length,
        [=](const Sp<restbed::Session>& s, const restbed::Bytes& /*b* */)
        {
            try {
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
                    listener.token = dht_->listen(infoHash, [cacheSession](const std::vector<Sp<Value>>& values, bool expired) {
                        auto s = cacheSession.lock();
                        if (!s) return false;
                        // Send values as soon as we get them
                        if (!s->is_closed()) {
                            Json::StreamWriterBuilder wbuilder;
                            wbuilder["commentStyle"] = "None";
                            wbuilder["indentation"] = "";
                            for (const auto& value : values) {
                                auto val = value->toJson();
                                if (expired)
                                    val["expired"] = true;
                                auto output = Json::writeString(wbuilder, val) + "\n";
                                s->yield(output, [](const Sp<restbed::Session>&){ });
                            }
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
            } catch (...) {
                s->close(restbed::INTERNAL_SERVER_ERROR, "{\"err\":\"Internal server error\"}");
            }
        }
    );
}

#if OPENDHT_PUSH_NOTIFICATIONS

struct DhtProxyServer::Listener {
    std::string clientId;
    std::future<size_t> internalToken;
    Sp<Scheduler::Job> expireJob;
    Sp<Scheduler::Job> expireNotifyJob;
};
struct DhtProxyServer::PushListener {
    std::map<InfoHash, std::vector<Listener>> listeners;
    bool isAndroid;
};

void
DhtProxyServer::subscribe(const std::shared_ptr<restbed::Session>& session)
{
    requestNum_++;
    const auto request = session->get_request();
    int content_length = std::stoi(request->get_header("Content-Length", "0"));
    auto hash = request->get_path_parameter("hash");
    InfoHash infoHash(hash);
    if (!infoHash)
        infoHash = InfoHash::get(hash);
    session->fetch(content_length,
        [=](const std::shared_ptr<restbed::Session> s, const restbed::Bytes& b) mutable
        {
            try {
                std::string err;
                Json::Value root;
                Json::CharReaderBuilder rbuilder;
                auto* char_data = reinterpret_cast<const char*>(b.data());
                auto reader = std::unique_ptr<Json::CharReader>(rbuilder.newCharReader());
                if (!reader->parse(char_data, char_data + b.size(), &root, &err)) {
                    s->close(restbed::BAD_REQUEST, "{\"err\":\"Incorrect JSON\"}");
                    return;
                }
                auto pushToken = root["key"].asString();
                if (pushToken.empty()) {
                    s->close(restbed::BAD_REQUEST, "{\"err\":\"No token\"}");
                    return;
                }
                auto platform = root["platform"].asString();
                auto isAndroid = platform == "android";
                auto clientId = root.isMember("client_id") ? root["client_id"].asString() : std::string();

                std::cout << "Subscribe " << infoHash << " client:" << clientId << std::endl;

                {
                    std::lock(schedulerLock_, lockListener_);
                    std::lock_guard<std::mutex> lk1(lockListener_, std::adopt_lock);
                    std::lock_guard<std::mutex> lk2(schedulerLock_, std::adopt_lock);
                    scheduler_.syncTime();
                    auto timeout = scheduler_.time() + proxy::OP_TIMEOUT;
                    // Check if listener is already present and refresh timeout if launched
                    // One push listener per pushToken.infoHash.clientId
                    auto pushListener = pushListeners_.emplace(pushToken, PushListener{}).first;
                    auto listeners = pushListener->second.listeners.emplace(infoHash, std::vector<Listener>{}).first;
                    for (auto& listener: listeners->second) {
                        if (listener.clientId == clientId) {
                            scheduler_.edit(listener.expireJob, timeout);
                            scheduler_.edit(listener.expireNotifyJob, timeout - proxy::OP_MARGIN);
                            s->close(restbed::OK, "{}\n");
                            schedulerCv_.notify_one();
                            return;
                        }
                    }
                    listeners->second.emplace_back(Listener{});
                    auto& listener = listeners->second.back();
                    listener.clientId = clientId;

                    // New listener
                    pushListener->second.isAndroid = isAndroid;

                    // The listener is not found, so add it.
                    listener.internalToken = dht_->listen(infoHash,
                        [this, infoHash, pushToken, isAndroid, clientId](std::vector<std::shared_ptr<Value>> /*value*/) {
                            // Build message content.
                            Json::Value json;
                            json["key"] = infoHash.toString();
                            json["to"] = clientId;
                            sendPushNotification(pushToken, json, isAndroid);
                            return true;
                        }
                    );
                    listener.expireJob = scheduler_.add(timeout,
                        [this, clientId, infoHash, pushToken] {
                            cancelPushListen(pushToken, infoHash, clientId);
                        }
                    );
                    listener.expireNotifyJob = scheduler_.add(timeout - proxy::OP_MARGIN,
                        [this, infoHash, pushToken, isAndroid, clientId] {
                            std::cout << "Listener: sending refresh " << infoHash << std::endl;
                            Json::Value json;
                            json["timeout"] = infoHash.toString();
                            json["to"] = clientId;
                            sendPushNotification(pushToken, json, isAndroid);
                        }
                    );
                }
                schedulerCv_.notify_one();
                s->close(restbed::OK, "{}\n");
            } catch (...) {
                s->close(restbed::INTERNAL_SERVER_ERROR, "{\"err\":\"Internal server error\"}");
            }
        }
    );
}

void
DhtProxyServer::unsubscribe(const std::shared_ptr<restbed::Session>& session)
{
    requestNum_++;
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
                std::string err;
                Json::Value root;
                Json::CharReaderBuilder rbuilder;
                auto* char_data = reinterpret_cast<const char*>(b.data());
                auto reader = std::unique_ptr<Json::CharReader>(rbuilder.newCharReader());
                if (!reader->parse(char_data, char_data + b.size(), &root, &err)) {
                    s->close(restbed::BAD_REQUEST, "{\"err\":\"Incorrect JSON\"}");
                    return;
                }
                auto pushToken = root["key"].asString();
                if (pushToken.empty()) return;
                auto clientId = root["client_id"].asString();

                cancelPushListen(pushToken, infoHash, clientId);
                s->close(restbed::OK);
            } catch (...) {
                s->close(restbed::INTERNAL_SERVER_ERROR, "{\"err\":\"Internal server error\"}");
            }
        }
    );
}

void
DhtProxyServer::cancelPushListen(const std::string& pushToken, const dht::InfoHash& key, const std::string& clientId)
{
    std::cout << "cancelPushListen: " << key << " clientId:" << clientId << std::endl;
    std::lock_guard<std::mutex> lock(lockListener_);
    auto pushListener = pushListeners_.find(pushToken);
    if (pushListener == pushListeners_.end())
        return;
    auto listeners = pushListener->second.listeners.find(key);
    if (listeners == pushListener->second.listeners.end())
        return;
    for (auto listener = listeners->second.begin(); listener != listeners->second.end();) {
        if (listener->clientId == clientId) {
            if (dht_)
                dht_->cancelListen(key, std::move(listener->internalToken));
            listener = listeners->second.erase(listener);
        } else {
            ++listener;
        }
    }
    if (listeners->second.empty()) {
        pushListener->second.listeners.erase(listeners);
    }
    if (pushListener->second.listeners.empty()) {
        pushListeners_.erase(pushListener);
    }
}

void
DhtProxyServer::sendPushNotification(const std::string& token, const Json::Value& json, bool isAndroid) const
{
    restbed::Uri uri(proxy::HTTP_PROTO + pushServer_ + "/api/push");
    auto req = std::make_shared<restbed::Request>(uri);
    req->set_method("POST");

    // NOTE: see https://github.com/appleboy/gorush
    Json::Value notification(Json::objectValue);
    Json::Value tokens(Json::arrayValue);
    tokens[0] = token;
    notification["tokens"] = tokens;
    notification["platform"] = isAndroid ? 2 : 1;
    notification["data"] = json;
    notification["priority"] = "high";
    notification["time_to_live"] = 600;

    Json::Value notifications(Json::arrayValue);
    notifications[0] = notification;

    Json::Value content;
    content["notifications"] = notifications;

    Json::StreamWriterBuilder wbuilder;
    wbuilder["commentStyle"] = "None";
    wbuilder["indentation"] = "";
    auto valueStr = Json::writeString(wbuilder, content);

    req->set_header("Content-Type", "application/json");
    req->set_header("Accept", "*/*");
    req->set_header("Host", pushServer_);
    req->set_header("Content-Length", std::to_string(valueStr.length()));
    req->set_body(valueStr);

    // Send request.
    restbed::Http::async(req, {});
}

#endif //OPENDHT_PUSH_NOTIFICATIONS

void
DhtProxyServer::cancelPut(const InfoHash& key, Value::Id vid)
{
    std::cout << "cancelPut " << key << " " << vid << std::endl;
    auto sPuts = puts_.find(key);
    if (sPuts == puts_.end())
        return;
    auto& sPutsMap = sPuts->second.puts;
    auto put = sPutsMap.find(vid);
    if (put == sPutsMap.end())
        return;
    if (dht_)
        dht_->cancelPut(key, vid);
    if (put->second.expireNotifyJob)
        put->second.expireNotifyJob->cancel();
    sPutsMap.erase(put);
    if (sPutsMap.empty())
        puts_.erase(sPuts);
}

void
DhtProxyServer::put(const std::shared_ptr<restbed::Session>& session)
{
    requestNum_++;
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
                if (dht_) {
                    if(b.empty()) {
                        std::string response("{\"err\":\"Missing parameters\"}");
                        s->close(restbed::BAD_REQUEST, response);
                    } else {
                        std::string err;
                        Json::Value root;
                        Json::CharReaderBuilder rbuilder;
                        auto* char_data = reinterpret_cast<const char*>(b.data());
                        auto reader = std::unique_ptr<Json::CharReader>(rbuilder.newCharReader());
                        if (reader->parse(char_data, char_data + b.size(), &root, &err)) {
                            // Build the Value from json
                            auto value = std::make_shared<Value>(root);
                            bool permanent = root.isMember("permanent");
                            std::cout << "Got put " << infoHash << " " << *value << " " << (permanent ? "permanent" : "") << std::endl;

                            if (permanent) {
                                std::string pushToken, clientId, platform;
                                auto& pVal = root["permanent"];
                                if (pVal.isObject()) {
                                    pushToken = pVal["key"].asString();
                                    clientId = pVal["client_id"].asString();
                                    platform = pVal["platform"].asString();
                                }
                                bool isAndroid = platform == "android";
                                std::unique_lock<std::mutex> lock(schedulerLock_);
                                scheduler_.syncTime();
                                auto timeout = scheduler_.time() + proxy::OP_TIMEOUT;
                                auto vid = value->id;
                                auto sPuts = puts_.emplace(infoHash, SearchPuts{}).first;
                                auto r = sPuts->second.puts.emplace(vid, PermanentPut{});
                                auto& pput = r.first->second;
                                if (r.second) {
                                    pput.expireJob = scheduler_.add(timeout, [this, infoHash, vid]{
                                        std::cout << "Permanent put expired: " << infoHash << " " << vid << std::endl;
                                        cancelPut(infoHash, vid);
                                    });
#if OPENDHT_PUSH_NOTIFICATIONS
                                    if (not pushToken.empty()) {
                                        pput.expireNotifyJob = scheduler_.add(timeout - proxy::OP_MARGIN,
                                            [this, infoHash, vid, pushToken, clientId, isAndroid]
                                        {
                                            std::cout << "Permanent put refresh: " << infoHash << " " << vid << std::endl;
                                            Json::Value json;
                                            json["timeout"] = infoHash.toString();
                                            json["to"] = clientId;
                                            json["vid"] = std::to_string(vid);
                                            sendPushNotification(pushToken, json, isAndroid);
                                        });
                                    }
#endif
                                } else {
                                    scheduler_.edit(pput.expireJob, timeout);
                                    if (pput.expireNotifyJob)
                                        scheduler_.edit(pput.expireNotifyJob, timeout - proxy::OP_MARGIN);
                                }
                                lock.unlock();
                                schedulerCv_.notify_one();
                            }

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
            } catch (const std::exception& e) {
                std::cout << "Error performing put: " << e.what() << std::endl;
                s->close(restbed::INTERNAL_SERVER_ERROR, "{\"err\":\"Internal server error\"}");
            }
        }
    );
}

#if OPENDHT_PROXY_SERVER_IDENTITY
void
DhtProxyServer::putSigned(const std::shared_ptr<restbed::Session>& session) const
{
    requestNum_++;
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
                if (dht_) {
                    if(b.empty()) {
                        std::string response("{\"err\":\"Missing parameters\"}");
                        s->close(restbed::BAD_REQUEST, response);
                    } else {
                        std::string err;
                        Json::Value root;
                        Json::CharReaderBuilder rbuilder;
                        auto* char_data = reinterpret_cast<const char*>(b.data());
                        auto reader = std::unique_ptr<Json::CharReader>(rbuilder.newCharReader());
                        if (reader->parse(char_data, char_data + b.size(), &root, &err)) {
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
            } catch (...) {
                s->close(restbed::INTERNAL_SERVER_ERROR, "{\"err\":\"Internal server error\"}");
            }
        }
    );
}

void
DhtProxyServer::putEncrypted(const std::shared_ptr<restbed::Session>& session) const
{
    requestNum_++;
    const auto request = session->get_request();
    int content_length = std::stoi(request->get_header("Content-Length", "0"));
    auto hash = request->get_path_parameter("hash");
    InfoHash key(hash);
    if (!key)
        key = InfoHash::get(hash);

    session->fetch(content_length,
        [=](const std::shared_ptr<restbed::Session> s, const restbed::Bytes& b)
        {
            try {
                if (dht_) {
                    if(b.empty()) {
                        std::string response("{\"err\":\"Missing parameters\"}");
                        s->close(restbed::BAD_REQUEST, response);
                    } else {
                        std::string err;
                        Json::Value root;
                        Json::CharReaderBuilder rbuilder;
                        auto* char_data = reinterpret_cast<const char*>(b.data());
                        auto reader = std::unique_ptr<Json::CharReader>(rbuilder.newCharReader());
                        bool parsingSuccessful = reader->parse(char_data, char_data + b.size(), &root, &err);
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
            } catch (...) {
                s->close(restbed::INTERNAL_SERVER_ERROR, "{\"err\":\"Internal server error\"}");
            }
        }
    );
}
#endif // OPENDHT_PROXY_SERVER_IDENTITY

void
DhtProxyServer::handleOptionsMethod(const std::shared_ptr<restbed::Session>& session) const
{
    requestNum_++;
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
    requestNum_++;
    const auto request = session->get_request();
    int content_length = std::stoi(request->get_header("Content-Length", "0"));
    auto hash = request->get_path_parameter("hash");
    auto value = request->get_path_parameter("value");
    session->fetch(content_length,
        [=](const std::shared_ptr<restbed::Session> s, const restbed::Bytes& /*b* */)
        {
            try {
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
            } catch (...) {
                s->close(restbed::INTERNAL_SERVER_ERROR, "{\"err\":\"Internal server error\"}");
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
        auto cancel = dht_ and (not testSession or listener->session->is_closed());
        if (cancel) {
            dht_->cancelListen(listener->hash, std::move(listener->token));
            // Remove listener if unused
            listener = currentListeners_.erase(listener);
        } else {
             ++listener;
        }
    }
}

}
#endif //OPENDHT_PROXY_SERVER
