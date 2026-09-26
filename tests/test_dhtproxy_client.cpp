// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT

#include "test_dhtproxy_client.h"

#include <any>
#include <mutex>
#include <thread>

#if defined(__clang__)
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wkeyword-macro"
#elif defined(__GNUC__)
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wpedantic"
#endif
#define private public
#include "opendht/http.h"
#include "opendht/dht_proxy_client.h"
#undef private
#if defined(__clang__)
#pragma clang diagnostic pop
#elif defined(__GNUC__)
#pragma GCC diagnostic pop
#endif

#include "../src/op_cache.cpp"
#include "../src/dht_proxy_client.cpp"

namespace test {
CPPUNIT_TEST_SUITE_REGISTRATION(DhtProxyClientTester);

using namespace dht;

void
DhtProxyClientTester::testResubscribeUsesKeyRoute()
{
#ifdef OPENDHT_PUSH_NOTIFICATIONS
    DhtProxyClient client({}, {}, [] {}, "http://127.0.0.1:8080", "OpenDHT-Test", "client-id", "push-token");

    DhtProxyClient::Listener listener {ValueCallback([](const std::vector<Sp<Value>>&, bool) { return true; })};
    listener.opstate = std::make_shared<DhtProxyClient::OperationState>();
    listener.cb = [](const std::vector<Sp<Value>>&, bool, system_clock::time_point) {
        return true;
    };

    auto key = InfoHash::get("proxy-client-resubscribe");
    client.resubscribe(key, 1, listener);

    CPPUNIT_ASSERT(listener.request);
    CPPUNIT_ASSERT_EQUAL(std::string("/key/") + key.toString(), std::string(listener.request->header_.request_target()));
    CPPUNIT_ASSERT(listener.request->body_.find("\"refresh\"") != std::string::npos);
    CPPUNIT_ASSERT(listener.request->body_.find("true") != std::string::npos);
#else
    CPPUNIT_ASSERT(true);
#endif
}

void
DhtProxyClientTester::testSetPushNotificationTokenResubscribesWithNewToken()
{
#ifdef OPENDHT_PUSH_NOTIFICATIONS
    DhtProxyClient client({}, {}, [] {}, "http://127.0.0.1:8080", "OpenDHT-Test", "client-id", "old-token");

    client.statusIpv4_ = NodeStatus::Connected;

    auto key = InfoHash::get("proxy-client-token-rotation");
    auto& search = client.searches_[key];
    auto [it, inserted] = search.listeners.emplace(std::piecewise_construct,
                                                   std::forward_as_tuple(1),
                                                   std::forward_as_tuple(ValueCallback(
                                                       [](const std::vector<Sp<Value>>&, bool) { return true; })));
    CPPUNIT_ASSERT(inserted);

    auto& listener = it->second;
    listener.opstate = std::make_shared<DhtProxyClient::OperationState>();
    listener.cb = [](const std::vector<Sp<Value>>&, bool, system_clock::time_point) {
        return true;
    };

    client.setPushNotificationToken("new-token");

    CPPUNIT_ASSERT(listener.request);
    CPPUNIT_ASSERT_EQUAL(std::string("/key/") + key.toString(), std::string(listener.request->header_.request_target()));
    CPPUNIT_ASSERT(listener.request->body_.find("new-token") != std::string::npos);
    CPPUNIT_ASSERT(listener.request->body_.find("old-token") == std::string::npos);
    CPPUNIT_ASSERT(listener.request->body_.find("\"refresh\"") != std::string::npos);
    CPPUNIT_ASSERT(listener.request->body_.find("true") != std::string::npos);
#else
    CPPUNIT_ASSERT(true);
#endif
}

void
DhtProxyClientTester::testRestartListenersFetchesValuesAfterFailedSubscribe()
{
#ifdef OPENDHT_PUSH_NOTIFICATIONS
    DhtProxyClient client({}, {}, [] {}, "http://127.0.0.1:8080", "OpenDHT-Test", "client-id", "push-token");

    auto addListener = [&](const InfoHash& key, bool ok) -> DhtProxyClient::Listener& {
        auto& search = client.searches_[key];
        auto [it, inserted] = search.listeners.emplace(std::piecewise_construct,
                                                       std::forward_as_tuple(1),
                                                       std::forward_as_tuple(ValueCallback(
                                                           [](const std::vector<Sp<Value>>&, bool) { return true; })));
        CPPUNIT_ASSERT(inserted);
        auto& listener = it->second;
        listener.opstate = std::make_shared<DhtProxyClient::OperationState>();
        listener.opstate->ok = ok;
        listener.cb = [](const std::vector<Sp<Value>>&, bool, system_clock::time_point) {
            return true;
        };
        return listener;
    };

    // The subscription of this listener failed (e.g. no network): values stored on the
    // key since then were never received.
    auto failedKey = InfoHash::get("proxy-client-failed-subscribe");
    auto& failed = addListener(failedKey, false);
    auto healthyKey = InfoHash::get("proxy-client-healthy-subscribe");
    auto& healthy = addListener(healthyKey, true);

    client.restartListeners({});

    CPPUNIT_ASSERT(failed.request);
    CPPUNIT_ASSERT_EQUAL(std::string("/key/") + failedKey.toString(),
                         std::string(failed.request->header_.request_target()));
    CPPUNIT_ASSERT(failed.request->body_.find("push-token") != std::string::npos);
    // Without "refresh", the server answers with the values it stores for the key.
    CPPUNIT_ASSERT(failed.request->body_.find("\"refresh\"") == std::string::npos);

    CPPUNIT_ASSERT(!healthy.request);
#else
    CPPUNIT_ASSERT(true);
#endif
}

void
DhtProxyClientTester::testStalePushResubscribesAndFetchesValues()
{
#ifdef OPENDHT_PUSH_NOTIFICATIONS
    // A proxy that accepts connections but never answers: the request built by the client
    // stays in place, and no failure triggers another resubscription.
    asio::io_context silentContext;
    asio::ip::tcp::acceptor silentProxy(silentContext, {asio::ip::make_address("127.0.0.1"), 0});
    auto proxyUrl = "http://127.0.0.1:" + std::to_string(silentProxy.local_endpoint().port());
    DhtProxyClient client({}, {}, [] {}, proxyUrl, "OpenDHT-Test", "client-id", "push-token");

    auto key = InfoHash::get("proxy-client-stale-push");
    DhtProxyClient::Listener* listener {nullptr};
    {
        std::lock_guard lock(client.searchLock_);
        auto& search = client.searches_[key];
        auto [it, inserted] = search.listeners.emplace(std::piecewise_construct,
                                                       std::forward_as_tuple(1),
                                                       std::forward_as_tuple(ValueCallback(
                                                           [](const std::vector<Sp<Value>>&, bool) { return true; })));
        CPPUNIT_ASSERT(inserted);
        listener = &it->second;
        listener->opstate = std::make_shared<DhtProxyClient::OperationState>();
        listener->cb = [](const std::vector<Sp<Value>>&, bool, system_clock::time_point) {
            return true;
        };
    }

    // The server still notifies with the session of a previous client (e.g. the account was
    // restarted): the value it announces, typically an incoming call, is dropped.
    auto result = client.pushNotificationReceived({
        {"s",   "previous-session"},
        {"to",  "client-id"       },
        {"key", key.toString()    }
    });
    CPPUNIT_ASSERT(result == PushNotificationResult::IgnoredWrongSession);

    // The client resubscribes asynchronously, and must ask for the values the server stores.
    std::string body;
    for (int i = 0; i < 500 && body.empty(); ++i) {
        {
            std::lock_guard lock(client.searchLock_);
            if (listener->request)
                body = listener->request->body_;
        }
        if (body.empty())
            std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
    CPPUNIT_ASSERT(!body.empty());
    CPPUNIT_ASSERT(body.find("push-token") != std::string::npos);
    CPPUNIT_ASSERT(body.find(client.pushSessionId_) != std::string::npos);
    CPPUNIT_ASSERT(body.find("\"refresh\"") == std::string::npos);
#else
    CPPUNIT_ASSERT(true);
#endif
}

} // namespace test