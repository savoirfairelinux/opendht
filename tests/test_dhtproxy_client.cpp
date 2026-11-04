// Copyright (c) 2014-2026 Savoir-faire Linux Inc.
// SPDX-License-Identifier: MIT

#include "test_dhtproxy_client.h"

#include <any>
#include <mutex>

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

} // namespace test