/*
 *  Copyright (C) 2017-2019 Savoir-faire Linux Inc.
 *  Author: Sébastien Blin <sebastien.blin@savoirfairelinux.com>
 *          Adrien Béraud <adrien.beraud@savoirfairelinux.com>
 *          Vsevolod Ivanov <vsevolod.ivanov@savoirfairelinux.com>
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

#include "dht_proxy_server.h"

#include "thread_pool.h"
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
constexpr const size_t IO_THREADS_MAX {64};


DhtProxyServer::DhtProxyServer(std::shared_ptr<DhtRunner> dht, in_port_t port , const std::string& pushServer)
: dht_(dht), threadPool_(new ThreadPool(IO_THREADS_MAX)), pushServer_(pushServer)
{
    if (not dht_)
        throw std::invalid_argument("A DHT instance must be provided");

    //service_ = std::unique_ptr<restbed::Service>(new restbed::Service());

    std::cout << "Running DHT proxy server on port " << port << std::endl;
    if (not pushServer.empty()){
#ifdef OPENDHT_PUSH_NOTIFICATIONS
        std::cout << "Using push notification server: " << pushServer << std::endl;
#else
        std::cerr << "Push server defined but built OpenDHT built without push notification support" << std::endl;
#endif
    }

    jsonBuilder_["commentStyle"] = "None";
    jsonBuilder_["indentation"] = "";

    server_thread = std::thread([this, port](){
        using namespace std::chrono;
        auto maxThreads = std::thread::hardware_concurrency() - 1;
        auto restThreads = maxThreads > 1 ? maxThreads : 1;
        auto settings = restinio::on_thread_pool<RestRouterTraits>(restThreads);
        settings.address("0.0.0.0");
        settings.port(port);
        settings.request_handler(this->createRestRouter());
        // time limits
        settings.read_next_http_message_timelimit(10s);
        settings.write_http_response_timelimit(10s);
        std::chrono::milliseconds timeout_request(std::numeric_limits<int>::max());
        settings.handle_request_timeout(timeout_request);
        // socket options
        settings.socket_options_setter([](auto & options){
            options.set_option(asio::ip::tcp::no_delay{true});
        });
        try {
            restinio::run(std::move(settings));
        }
        catch(const std::exception &ex){
            std::cerr << "Error starting RESTinio: " << ex.what() << std::endl;
        }
    });
    listenThread_ = std::thread([this](){
        while (not server_thread.joinable() and not stopListeners){
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        while (server_thread.joinable() and not stopListeners){
            removeClosedListeners();
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        // Remove last listeners
        removeClosedListeners(false);
    });
    schedulerThread_ = std::thread([this](){
        while (not server_thread.joinable() and not stopListeners){
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        while (server_thread.joinable()  and not stopListeners){
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
        if (stopListeners)
            return;
        if (server_thread.joinable())
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

    std::lock_guard<std::mutex> lock(lockListener_);
    auto listener = currentListeners_.begin();
    while (listener != currentListeners_.end()){
        ++listener;
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
    threadPool_->stop();
}

void
DhtProxyServer::updateStats() const
{
    auto now = clock::now();
    auto last = lastStatsReset_.exchange(now);
    auto count = requestNum_.exchange(0);
    auto dt = std::chrono::duration<double>(now - last);
    stats_.requestRate = count / dt.count();
#ifdef OPENDHT_PUSH_NOTIFICATIONS
    stats_.pushListenersCount = pushListeners_.size();
#endif
    stats_.putCount = puts_.size();
    stats_.listenCount = currentListeners_.size();
    stats_.nodeInfo = nodeInfo_;
}

template <typename HttpResponse>
HttpResponse DhtProxyServer::initHttpResponse(HttpResponse response) const
{
    response.append_header("Server", "RESTinio");
    response.append_header(restinio::http_field::content_type, "application/json");
    response.append_header(restinio::http_field::access_control_allow_origin, "*");
    response.connection_keep_alive();
    return response;
}

std::unique_ptr<RestRouter>
DhtProxyServer::createRestRouter()
{
    using namespace std::placeholders;
    auto router = std::make_unique<RestRouter>();
    router->http_get("/", std::bind(&DhtProxyServer::getNodeInfo, this, _1, _2));
    router->http_get("/stats", std::bind(&DhtProxyServer::getStats, this, _1, _2));
    router->http_get("/:hash", std::bind(&DhtProxyServer::get, this, _1, _2));
    router->http_post("/:hash", std::bind(&DhtProxyServer::put, this, _1, _2));
    router->http_get("/:hash/listen", std::bind(&DhtProxyServer::listen, this, _1, _2));
#ifdef OPENDHT_PUSH_NOTIFICATIONS
    router->add_handler(restinio::http_method_t::http_subscribe,
                        "/:hash", std::bind(&DhtProxyServer::subscribe, this, _1, _2));
    router->add_handler(restinio::http_method_t::http_unsubscribe,
                        "/:hash", std::bind(&DhtProxyServer::unsubscribe, this, _1, _2));
#endif //OPENDHT_PUSH_NOTIFICATIONS
#ifdef OPENDHT_PROXY_SERVER_IDENTITY
    router->http_post("/:hash/sign", std::bind(&DhtProxyServer::putSigned, this, _1, _2));
    router->http_post("/:hash/encrypt", std::bind(&DhtProxyServer::putEncrypted, this, _1, _2));
#endif // OPENDHT_PROXY_SERVER_IDENTITY
    router->add_handler(restinio::http_method_t::http_options,
                        "/:hash", std::bind(&DhtProxyServer::options, this, _1, _2));
    router->http_get("/:hash/:value", std::bind(&DhtProxyServer::getFiltered, this, _1, _2));
    return router;
}

RequestStatus
DhtProxyServer::getNodeInfo(restinio::request_handle_t request,
                            restinio::router::route_params_t params) const
{
    Json::Value result;
    std::lock_guard<std::mutex> lck(statsMutex_);
    if (nodeInfo_.ipv4.good_nodes == 0 &&
        nodeInfo_.ipv6.good_nodes == 0){
        nodeInfo_ = this->dht_->getNodeInfo();
    }
    result = nodeInfo_.toJson();
    // [ipv6:ipv4]:port or ipv4:port
    result["public_ip"] = request->remote_endpoint().address().to_string();
    auto output = Json::writeString(jsonBuilder_, result) + "\n";

    auto response = this->initHttpResponse(request->create_response());
    response.append_body(output);
    return response.done();
}

RequestStatus
DhtProxyServer::getStats(restinio::request_handle_t request,
                         restinio::router::route_params_t params)
{
    requestNum_++;
    try {
        if (dht_){
#ifdef OPENDHT_JSONCPP
            auto output = Json::writeString(jsonBuilder_, stats_.toJson()) + "\n";
            auto response = this->initHttpResponse(request->create_response());
            response.append_body(output);
            response.done();
#else
            auto response = this->initHttpResponse(
                request->create_response(restinio::status_not_found()));
            response.set_body(this->RESP_MSG_JSON_NOT_ENABLED);
            return response.done();
#endif
        } else {
            auto response = this->initHttpResponse(
                request->create_response(restinio::status_service_unavailable()));
            response.set_body(this->RESP_MSG_SERVICE_UNAVAILABLE);
            return response.done();
        }
    } catch (...){
        auto response = this->initHttpResponse(
            request->create_response(restinio::status_internal_server_error()));
        response.set_body(this->RESP_MSG_INTERNAL_SERVER_ERRROR);
        return response.done();
    }
    return restinio::request_handling_status_t::accepted;
}

RequestStatus
DhtProxyServer::get(restinio::request_handle_t request,
                    restinio::router::route_params_t params)
{
    requestNum_++;
    dht::InfoHash infoHash(params["hash"].to_string());
    if (!infoHash)
        infoHash = dht::InfoHash::get(params["hash"].to_string());

    if (!dht_){
        auto response = this->initHttpResponse(
            request->create_response(restinio::status_service_unavailable()));
        response.set_body(this->RESP_MSG_SERVICE_UNAVAILABLE);
        return response.done();
    }

    auto response = std::make_shared<ResponseByPartsBuilder>(
        this->initHttpResponse(request->create_response<ResponseByParts>()));
    response->flush();
    try {
        dht_->get(infoHash, [this, response](const dht::Sp<dht::Value>& value){
            auto output = Json::writeString(jsonBuilder_, value->toJson()) + "\n";
            response->append_chunk(output);
            response->flush();
            return true;
        },
        [response] (bool /*ok*/){
            response->done();
        });
    } catch (const std::exception& e){
        auto response = this->initHttpResponse(
            request->create_response(restinio::status_internal_server_error()));
        response.set_body(this->RESP_MSG_INTERNAL_SERVER_ERRROR);
        return response.done();
    }
    return restinio::request_handling_status_t::accepted;
}

RequestStatus
DhtProxyServer::listen(restinio::request_handle_t request,
                       restinio::router::route_params_t params)
{
    requestNum_++;
    dht::InfoHash infoHash(params["hash"].to_string());
    if (!infoHash)
        infoHash = dht::InfoHash::get(params["hash"].to_string());

    if (!dht_){
        auto response = this->initHttpResponse(
            request->create_response(restinio::status_service_unavailable()));
        response.set_body(this->RESP_MSG_SERVICE_UNAVAILABLE);
        return response.done();
    }
    auto response = std::make_shared<ResponseByPartsBuilder>(
        this->initHttpResponse(request->create_response<ResponseByParts>()));
    response->flush();
    try {
        SessionToHashToken listener;
        listener.hash = infoHash;
        listener.connId = request->connection_id();
        listener.token = dht_->listen(infoHash, [this, response]
                (const std::vector<dht::Sp<dht::Value>>& values, bool expired){
            for (const auto& value: values){
                auto jsonVal = value->toJson();
                if (expired)
                    jsonVal["expired"] = true;
                auto output = Json::writeString(jsonBuilder_, jsonVal) + "\n";
                response->append_chunk(output);
                response->flush();
            }
            return true;
        });
        std::lock_guard<std::mutex> lock(lockListener_);
        currentListeners_.emplace_back(std::move(listener));
    } catch (const std::exception& e){
        auto response = this->initHttpResponse(
            request->create_response(restinio::status_internal_server_error()));
        response.set_body(this->RESP_MSG_INTERNAL_SERVER_ERRROR);
        return response.done();
    }
    return restinio::request_handling_status_t::accepted;
}

#ifdef OPENDHT_PUSH_NOTIFICATIONS

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

RequestStatus
DhtProxyServer::subscribe(restinio::request_handle_t request,
                          restinio::router::route_params_t params)
{
    requestNum_++;

    dht::InfoHash infoHash(params["hash"].to_string());
    if (!infoHash)
        infoHash = dht::InfoHash::get(params["hash"].to_string());

    if (!dht_){
        auto response = this->initHttpResponse(
            request->create_response(restinio::status_service_unavailable()));
        response.set_body(this->RESP_MSG_SERVICE_UNAVAILABLE);
        return response.done();
    }

    try {
        std::string err;
        Json::Value root;
        Json::CharReaderBuilder rbuilder;
        auto* char_data = reinterpret_cast<const char*>(b.data());
        auto reader = std::unique_ptr<Json::CharReader>(rbuilder.newCharReader());
        if (!reader->parse(char_data, char_data + b.size(), &root, &err)){
            auto response = this->initHttpResponse(
                request->create_response(restinio::status_bad_request()));
            response.set_body(this->RESP_MSG_JSON_INCORRECT);
            return response.done();
        }
        auto pushToken = root["key"].asString();
        if (pushToken.empty()){
            auto response = this->initHttpResponse(
                request->create_response(restinio::status_bad_request()));
            response.set_body(this->RESP_MSG_NO_TOKEN);
            return response.done();
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
            for (auto& listener: listeners->second){
                if (listener.clientId == clientId){
                    scheduler_.edit(listener.expireJob, timeout);
                    scheduler_.edit(listener.expireNotifyJob, timeout - proxy::OP_MARGIN);

                    auto response = std::make_shared<ResponseByPartsBuilder>(
                        this->initHttpResponse(request->create_response<ResponseByParts>()));
                    response->flush();

                    if (!root.isMember("refresh") or !root["refresh"].asBool()){
                        dht_->get(infoHash, [this, response](const dht::Sp<dht::Value>& value){
                            auto output = Json::writeString(jsonBuilder_, value->toJson()) + "\n";
                            response->append_chunk(output);
                            response->flush();
                            return true;
                        },
                        [response] (bool /*ok*/){
                            response->done();
                        });
                    } else {
                        response->append_chunk("{}\n");
                        response->done();
                    }
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
                [this, infoHash, pushToken, isAndroid, clientId](const std::vector<std::shared_ptr<Value>>& values, bool expired){
                    threadPool_->run([this, infoHash, pushToken, isAndroid, clientId, values, expired](){
                        // Build message content
                        Json::Value json;
                        json["key"] = infoHash.toString();
                        json["to"] = clientId;
                        if (expired and values.size() < 3){
                            std::stringstream ss;
                            for(size_t i = 0; i < values.size(); ++i){
                                if(i != 0) ss << ",";
                                ss << values[i]->id;
                            }
                            json["exp"] = ss.str();
                        }
                        sendPushNotification(pushToken, std::move(json), isAndroid);
                    });
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
                    sendPushNotification(pushToken, std::move(json), isAndroid);
                }
            );
        }
        schedulerCv_.notify_one();
        auto response = this->initHttpResponse(request->create_response());
        response.set_body("{}\n");
        return response.done();
    } catch (...){
        auto response = this->initHttpResponse(
            request->create_response(restinio::status_internal_server_error()));
        response.set_body(this->RESP_MSG_INTERNAL_SERVER_ERRROR);
        return response.done();
    }
    return restinio::request_handling_status_t::accepted;
}

RequestStatus
DhtProxyServer::unsubscribe(restinio::request_handle_t request,
                            restinio::router::route_params_t params)
{
    requestNum_++;

    dht::InfoHash infoHash(params["hash"].to_string());
    if (!infoHash)
        infoHash = dht::InfoHash::get(params["hash"].to_string());

    if (!dht_){
        auto response = this->initHttpResponse(
            request->create_response(restinio::status_service_unavailable()));
        response.set_body(this->RESP_MSG_SERVICE_UNAVAILABLE);
        return response.done();
    }

    try {
        std::string err;
        Json::Value root;
        Json::CharReaderBuilder rbuilder;
        auto* char_data = reinterpret_cast<const char*>(b.data());
        auto reader = std::unique_ptr<Json::CharReader>(rbuilder.newCharReader());

        if (!reader->parse(char_data, char_data + b.size(), &root, &err)){
            auto response = this->initHttpResponse(
                request->create_response(restinio::status_bad_request()));
            response.set_body(this->RESP_MSG_JSON_INCORRECT);
            return response.done();
        }
        auto pushToken = root["key"].asString();
        if (pushToken.empty()) return;
        auto clientId = root["client_id"].asString();

        cancelPushListen(pushToken, infoHash, clientId);
        auto response = this->initHttpResponse(request->create_response());
        return response.done();
    } catch (...){
        auto response = this->initHttpResponse(
            request->create_response(restinio::status_internal_server_error()));
        response.set_body(this->RESP_MSG_INTERNAL_SERVER_ERRROR);
        return response.done();
    }
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
    for (auto listener = listeners->second.begin(); listener != listeners->second.end();){
        if (listener->clientId == clientId){
            if (dht_)
                dht_->cancelListen(key, std::move(listener->internalToken));
            listener = listeners->second.erase(listener);
        } else {
            ++listener;
        }
    }
    if (listeners->second.empty()){
        pushListener->second.listeners.erase(listeners);
    }
    if (pushListener->second.listeners.empty()){
        pushListeners_.erase(pushListener);
    }
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

RequestStatus
DhtProxyServer::put(restinio::request_handle_t request,
                    restinio::router::route_params_t params)
{
    requestNum_++;
    dht::InfoHash infoHash(params["hash"].to_string());
    if (!infoHash)
        infoHash = dht::InfoHash::get(params["hash"].to_string());

    if (!dht_){
        auto response = this->initHttpResponse(
            request->create_response(restinio::status_service_unavailable()));
        response.set_body(this->RESP_MSG_SERVICE_UNAVAILABLE);
        return response.done();
    }
    else if (request->body().empty()){
        auto response = this->initHttpResponse(
            request->create_response(restinio::status_bad_request()));
        response.set_body(this->RESP_MSG_MISSING_PARAMS);
        return response.done();
    }

    try {
        std::string err;
        Json::Value root;
        Json::CharReaderBuilder rbuilder;
        auto* char_data = reinterpret_cast<const char*>(request->body().data());
        auto reader = std::unique_ptr<Json::CharReader>(rbuilder.newCharReader());

        if (reader->parse(char_data, char_data + request->body().size(), &root, &err)){
            auto value = std::make_shared<dht::Value>(root);
            bool permanent = root.isMember("permanent");
            std::cout << "Got put " << infoHash << " " << *value <<
                         " " << (permanent ? "permanent" : "") << std::endl;
            if (permanent){
                std::string pushToken, clientId, platform;
                auto& pVal = root["permanent"];
                if (pVal.isObject()){
                    pushToken = pVal["key"].asString();
                    clientId = pVal["client_id"].asString();
                    platform = pVal["platform"].asString();
                }
                std::unique_lock<std::mutex> lock(schedulerLock_);
                scheduler_.syncTime();
                auto timeout = scheduler_.time() + proxy::OP_TIMEOUT;
                auto vid = value->id;
                auto sPuts = puts_.emplace(infoHash, SearchPuts{}).first;
                auto r = sPuts->second.puts.emplace(vid, PermanentPut{});
                auto& pput = r.first->second;
                if (r.second){
                    pput.expireJob = scheduler_.add(timeout, [this, infoHash, vid]{
                        std::cout << "Permanent put expired: " << infoHash << " " << vid << std::endl;
                        cancelPut(infoHash, vid);
                    });
#ifdef OPENDHT_PUSH_NOTIFICATIONS
                    if (not pushToken.empty()){
                        bool isAndroid = platform == "android";
                        pput.expireNotifyJob = scheduler_.add(timeout - proxy::OP_MARGIN,
                            [this, infoHash, vid, pushToken, clientId, isAndroid]
                        {
                            std::cout << "Permanent put refresh: " << infoHash << " " << vid << std::endl;
                            Json::Value json;
                            json["timeout"] = infoHash.toString();
                            json["to"] = clientId;
                            json["vid"] = std::to_string(vid);
                            sendPushNotification(pushToken, std::move(json), isAndroid);
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
            dht_->put(infoHash, value, [this, request, value](bool ok){
                if (ok){
                    auto output = Json::writeString(jsonBuilder_, value->toJson()) + "\n";
                    auto response = this->initHttpResponse(request->create_response());
                    response.append_body(output);
                    response.done();
                } else {
                    auto response = this->initHttpResponse(request->create_response(
                        restinio::status_bad_gateway()));
                    response.set_body(this->RESP_MSG_PUT_FAILED);
                    response.done();
                }
            }, dht::time_point::max(), permanent);
        } else {
            auto response = this->initHttpResponse(
                request->create_response(restinio::status_bad_request()));
            response.set_body(this->RESP_MSG_JSON_INCORRECT);
            return response.done();
        }
    } catch (const std::exception& e){
        std::cout << "Error performing put: " << e.what() << std::endl;
        auto response = this->initHttpResponse(
            request->create_response(restinio::status_internal_server_error()));
        response.set_body(this->RESP_MSG_INTERNAL_SERVER_ERRROR);
        return response.done();
    }
    return restinio::request_handling_status_t::accepted;
}

#ifdef OPENDHT_PROXY_SERVER_IDENTITY

RequestStatus DhtProxyServer::putSigned(restinio::request_handle_t request,
                                        restinio::router::route_params_t params) const
{
    requestNum_++;
    dht::InfoHash infoHash(params["hash"].to_string());
    if (!infoHash)
        infoHash = dht::InfoHash::get(params["hash"].to_string());

    if (!dht_){
        auto response = this->initHttpResponse(
            request->create_response(restinio::status_service_unavailable()));
        response.set_body(this->RESP_MSG_SERVICE_UNAVAILABLE);
        return response.done();
    }
    else if (request->body().empty()){
        auto response = this->initHttpResponse(
            request->create_response(restinio::status_bad_request()));
        response.set_body(this->RESP_MSG_MISSING_PARAMS);
        return response.done();
    }

    try {
        std::string err;
        Json::Value root;
        Json::CharReaderBuilder rbuilder;
        auto* char_data = reinterpret_cast<const char*>(request->body().data());
        auto reader = std::unique_ptr<Json::CharReader>(rbuilder.newCharReader());

        if (reader->parse(char_data, char_data + request->body().size(), &root, &err)){

            auto value = std::make_shared<Value>(root);

            dht_->putSigned(infoHash, value, [this, request, value](bool ok){
                if (ok){
                    auto output = Json::writeString(jsonBuilder_, value->toJson()) + "\n";
                    auto response = this->initHttpResponse(request->create_response());
                    response.append_body(output);
                    response.done();
                } else {
                    auto response = this->initHttpResponse(request->create_response(
                        restinio::status_bad_gateway()));
                    response.set_body(this->RESP_MSG_PUT_FAILED);
                    response.done();
                }
            });
        } else {
            auto response = this->initHttpResponse(
                request->create_response(restinio::status_bad_request()));
            response.set_body(this->RESP_MSG_JSON_INCORRECT);
            return response.done();
        }
    } catch (const std::exception& e){
        std::cout << "Error performing put: " << e.what() << std::endl;
        auto response = this->initHttpResponse(
            request->create_response(restinio::status_internal_server_error()));
        response.set_body(this->RESP_MSG_INTERNAL_SERVER_ERRROR);
        return response.done();
    }
    return restinio::request_handling_status_t::accepted;
}

RequestStatus
DhtProxyServer::putEncrypted(restinio::request_handle_t request,
                             restinio::router::route_params_t params)
{
    requestNum_++;
    dht::InfoHash infoHash(params["hash"].to_string());
    if (!infoHash)
        infoHash = dht::InfoHash::get(params["hash"].to_string());

    if (!dht_){
        auto response = this->initHttpResponse(
            request->create_response(restinio::status_service_unavailable()));
        response.set_body(this->RESP_MSG_SERVICE_UNAVAILABLE);
        return response.done();
    }
    else if (request->body().empty()){
        auto response = this->initHttpResponse(
            request->create_response(restinio::status_bad_request()));
        response.set_body(this->RESP_MSG_MISSING_PARAMS);
        return response.done();
    }

    try {
        std::string err;
        Json::Value root;
        Json::CharReaderBuilder rbuilder;
        auto* char_data = reinterpret_cast<const char*>(request->body().data());
        auto reader = std::unique_ptr<Json::CharReader>(rbuilder.newCharReader());

        if (reader->parse(char_data, char_data + request->body().size(), &root, &err)){
            InfoHash to(root["to"].asString());
            if (!to){
                auto response = this->initHttpResponse(
                    request->create_response(restinio::status_bad_request()));
                response.set_body(this->RESP_MSG_DESTINATION_NOT_FOUND);
                return response.done();
            }
            auto value = std::make_shared<Value>(root);
            dht_->putEncrypted(infoHash, to, value, [this, request, value](bool ok){
                if (ok){
                    auto output = Json::writeString(jsonBuilder_, value->toJson()) + "\n";
                    auto response = this->initHttpResponse(request->create_response());
                    response.append_body(output);
                    response.done();
                } else {
                    auto response = this->initHttpResponse(request->create_response(
                        restinio::status_bad_gateway()));
                    response.set_body(this->RESP_MSG_PUT_FAILED);
                    response.done();
                }
            });
        } else {
            auto response = this->initHttpResponse(
                request->create_response(restinio::status_bad_request()));
            response.set_body(this->RESP_MSG_JSON_INCORRECT);
            return response.done();
        }
    } catch (const std::exception& e){
        std::cout << "Error performing put: " << e.what() << std::endl;
        auto response = this->initHttpResponse(
            request->create_response(restinio::status_internal_server_error()));
        response.set_body(this->RESP_MSG_INTERNAL_SERVER_ERRROR);
        return response.done();
    }
    return restinio::request_handling_status_t::accepted;
}

#endif // OPENDHT_PROXY_SERVER_IDENTITY

RequestStatus
DhtProxyServer::options(restinio::request_handle_t request,
                        restinio::router::route_params_t params)
{
    this->requestNum_++;
#ifdef OPENDHT_PROXY_SERVER_IDENTITY
    const auto methods = "OPTIONS, GET, POST, LISTEN, SIGN, ENCRYPT";
#else
    const auto methods = "OPTIONS, GET, POST, LISTEN";
#endif
    auto response = initHttpResponse(request->create_response());
    response.append_header(restinio::http_field::access_control_allow_methods, methods);
    response.append_header(restinio::http_field::access_control_allow_headers, "content-type");
    response.append_header(restinio::http_field::access_control_max_age, "86400");
    return response.done();
}

RequestStatus
DhtProxyServer::getFiltered(restinio::request_handle_t request,
                            restinio::router::route_params_t params)
{
    requestNum_++;
    auto value = params["value"].to_string();
    dht::InfoHash infoHash(params["hash"].to_string());
    if (!infoHash)
        infoHash = dht::InfoHash::get(params["hash"].to_string());

    if (!dht_){
        auto response = this->initHttpResponse(
            request->create_response(restinio::status_service_unavailable()));
        response.set_body(this->RESP_MSG_SERVICE_UNAVAILABLE);
        return response.done();
    }

    auto response = std::make_shared<ResponseByPartsBuilder>(
        this->initHttpResponse(request->create_response<ResponseByParts>()));
    response->flush();
    try {
        dht_->get(infoHash, [this, response](const dht::Sp<dht::Value>& value){
            auto output = Json::writeString(jsonBuilder_, value->toJson()) + "\n";
            response->append_chunk(output);
            response->flush();
            return true;
        },
        [response] (bool /*ok*/){
            response->done();
        },
            {}, value
        );
    } catch (const std::exception& e){
        auto response = this->initHttpResponse(
            request->create_response(restinio::status_internal_server_error()));
        response.set_body(this->RESP_MSG_INTERNAL_SERVER_ERRROR);
        return response.done();
    }
    return restinio::request_handling_status_t::accepted;
}

void
DhtProxyServer::removeClosedListeners(bool testSession)
{
    // clean useless listeners
    std::lock_guard<std::mutex> lock(lockListener_);
    auto listener = currentListeners_.begin();
    while (listener != currentListeners_.end()){
        auto cancel = dht_ and (not testSession); //TODO or !open(listener->connId)
        if (cancel){
            dht_->cancelListen(listener->hash, std::move(listener->token));
            // Remove listener if unused
            listener = currentListeners_.erase(listener);
        } else {
             ++listener;
        }
    }
}

}
