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

#ifdef OPENDHT_PUSH_NOTIFICATIONS
namespace {
void
finishSync(DhtProxyClient& client,
           const std::shared_ptr<dht::http::Request>& request,
           const std::vector<Sp<Value>>& values,
           uint64_t revision = 1,
           bool complete = true,
           bool snapshot = true,
           const std::string& epoch = "test-epoch")
{
    Json::Value marker;
    marker["sync"]["epoch"] = epoch;
    marker["sync"]["revision"] = Json::UInt64(revision);
    marker["sync"]["complete"] = complete;
    marker["sync"]["snapshot"] = snapshot;
    auto body = std::string {};
    for (const auto& value : values)
        body += Json::writeString(client.jsonBuilder_, value->toJson()) + "\n";
    body += Json::writeString(client.jsonBuilder_, marker) + "\n";
    request->cbs_.on_body(body.data(), body.size());
    dht::http::Response response;
    response.status_code = 200;
    request->cbs_.on_state_change(dht::http::Request::State::DONE, response);
    client.periodic(nullptr, 0, {}, clock::now());
}
} // namespace
#endif

void
DhtProxyClientTester::testReadinessShutdown()
{
    for (bool push : {false, true}) {
        DhtProxyClient client({}, {}, [] {}, "", "OpenDHT-Test", "client-id", push ? "push-token" : "");
        client.httpContext_.stop();
        client.httpClientThread_.join();
        client.proxyUrl_ = "http://127.0.0.1:1";
        auto key = InfoHash::get("readiness-shutdown");
        std::vector<bool> results;
        auto values = [](const std::vector<Sp<Value>>&, bool) {
            return true;
        };
        CPPUNIT_ASSERT(client.listen(key, values, {}, {}, [&](bool ok) {
            results.push_back(ok);
            CPPUNIT_ASSERT(client.getLocal(key, {}).empty());
        }) != 0);
        CPPUNIT_ASSERT(results.empty());
        client.shutdown({}, true);
        CPPUNIT_ASSERT(results == std::vector<bool>({false}));
        client.shutdown({}, true);
        CPPUNIT_ASSERT_EQUAL(size_t(1), results.size());
        CPPUNIT_ASSERT_EQUAL(size_t(0), client.listen(key, values, {}, {}, [&](bool ok) { results.push_back(ok); }));
        CPPUNIT_ASSERT(results == std::vector<bool>({false, false}));
    }
}

void
DhtProxyClientTester::testReadinessReentrancy()
{
    DhtProxyClient client({}, {}, [] {}, "", "OpenDHT-Test", "client-id", "");
    client.httpContext_.stop();
    client.httpClientThread_.join();
    client.proxyUrl_ = "http://127.0.0.1:1";
    auto key = InfoHash::get("ready-reentrancy");
    std::vector<bool> results;
    client.listen(
        key,
        [](const std::vector<Sp<Value>>&, bool) { return true; },
        {},
        {},
        [&](bool ok) {
            auto unlocked = client.searchLock_.try_lock();
            if (unlocked)
                client.searchLock_.unlock();
            CPPUNIT_ASSERT(unlocked);
            CPPUNIT_ASSERT(client.getLocal(key, {}).empty());
            results.push_back(ok);
        });
    auto request = client.searches_.at(key).listeners.begin()->second.request;
    std::string marker = "{\"sync\":{\"complete\":true}}\n";
    request->cbs_.on_body(marker.data(), marker.size());
    client.periodic(nullptr, 0, {}, clock::now());
    CPPUNIT_ASSERT(results == std::vector<bool>({true}));
}

void
DhtProxyClientTester::testReadinessCancelsAnotherListener()
{
    DhtProxyClient client({}, {}, [] {}, "", "OpenDHT-Test", "client-id", "");
    client.httpContext_.stop();
    client.httpClientThread_.join();
    client.proxyUrl_ = "http://127.0.0.1:1";
    auto key = InfoHash::get("ready-cancel-neighbor");
    size_t second = 0;
    unsigned firstCalls = 0;
    unsigned secondCalls = 0;
    auto values = [](const std::vector<Sp<Value>>&, bool) {
        return true;
    };
    client.listen(key, values, {}, {}, [&](bool ok) {
        auto unlocked = client.searchLock_.try_lock();
        if (unlocked)
            client.searchLock_.unlock();
        CPPUNIT_ASSERT(unlocked);
        CPPUNIT_ASSERT(ok);
        ++firstCalls;
        CPPUNIT_ASSERT(client.cancelListen(key, second));
    });
    second = client.listen(key, values, {}, {}, [&](bool) { ++secondCalls; });
    auto request = client.searches_.at(key).listeners.begin()->second.request;
    std::string marker = "{\"sync\":{\"complete\":true}}\n";
    request->cbs_.on_body(marker.data(), marker.size());
    client.periodic(nullptr, 0, {}, clock::now());
    CPPUNIT_ASSERT_EQUAL(1u, firstCalls);
    CPPUNIT_ASSERT_EQUAL(0u, secondCalls);
}

#ifdef OPENDHT_PUSH_NOTIFICATIONS
void
DhtProxyClientTester::testRejectsUnrevisionedPushes()
{
    DhtProxyClient client({}, {}, [] {}, "", "OpenDHT-Test", "client-id", "push-token");
    client.httpContext_.stop();
    client.httpClientThread_.join();
    client.proxyUrl_ = "http://127.0.0.1:1";
    auto key = InfoHash::get("unrevisioned-push-rejection");
    client.listen(key, [](const std::vector<Sp<Value>>&, bool) { return true; }, {}, {});
    auto& listener = client.searches_.at(key).listeners.begin()->second;
    auto value = std::make_shared<Value>("obsolete");
    value->id = 42;
    finishSync(client, listener.request, {value}, 5);
    auto synchronized = listener.request;
    auto requestCount = client.requests_.size();
    for (const auto& notification : std::vector<std::map<std::string, std::string>> {
             {{"key", key.toString()}, {"t", "10000"}},
             {{"key", key.toString()}, {"expired", "true"}, {"ids", "42"}},
             {{"key", key.toString()}, {"epoch", "test-epoch"}},
             {{"key", key.toString()}, {"revision", "6"}}}) {
        CPPUNIT_ASSERT(client.pushNotificationReceived(notification) == PushNotificationResult::Error);
        CPPUNIT_ASSERT(listener.request == synchronized);
        CPPUNIT_ASSERT_EQUAL(requestCount, client.requests_.size());
        CPPUNIT_ASSERT_EQUAL(uint64_t(5), listener.syncRevision);
        CPPUNIT_ASSERT(listener.opstate->ok.load());
        CPPUNIT_ASSERT(client.getLocalById(key, 42));
    }
    CPPUNIT_ASSERT(client.pushNotificationReceived({
        {"key",      key.toString()},
        {"epoch",    "test-epoch"  },
        {"revision", "6"           },
        {"expired",  "true"        },
        {"ids",      "42"          }
    }) == PushNotificationResult::ValuesExpired);
    client.periodic(nullptr, 0, {}, clock::now());
    CPPUNIT_ASSERT(!client.getLocalById(key, 42));
    client.restartListeners({});
    auto validation = listener.request;
    CPPUNIT_ASSERT(client.pushNotificationReceived({
        {"key", key.toString()}
    }) == PushNotificationResult::Error);
    finishSync(client, validation, {}, 6, true, false);
    CPPUNIT_ASSERT(listener.request == validation);
    CPPUNIT_ASSERT(listener.opstate->ok.load());
    CPPUNIT_ASSERT(!client.getLocalById(key, 42));
}

void
DhtProxyClientTester::testInitialReadinessFailures()
{
    for (unsigned failure = 0; failure < 4; ++failure) {
        bool push = failure == 1 || failure == 3;
        DhtProxyClient client({}, {}, [] {}, "", "OpenDHT-Test", "client-id", push ? "push-token" : "");
        client.httpContext_.stop();
        client.httpClientThread_.join();
        client.proxyUrl_ = "http://127.0.0.1:1";
        auto key = InfoHash::get("initial-readiness-failure");
        std::vector<bool> results;
        CPPUNIT_ASSERT(client.listen(
                           key,
                           [](const std::vector<Sp<Value>>&, bool) { return true; },
                           {},
                           {},
                           [&](bool ok) { results.push_back(ok); })
                       != 0);
        auto& listener = client.searches_.at(key).listeners.begin()->second;
        auto request = listener.request;
        if (failure == 0) {
            std::string marker = "{\"sync\":{\"complete\":false}}\n";
            request->cbs_.on_body(marker.data(), marker.size());
        } else if (failure == 3) {
            finishSync(client, request, {}, 1, false);
        } else {
            dht::http::Response response;
            response.status_code = 503;
            request->cbs_.on_state_change(dht::http::Request::State::DONE, response);
        }
        client.periodic(nullptr, 0, {}, clock::now());
        CPPUNIT_ASSERT(results == std::vector<bool>({false}));
        client.shutdown({}, true);
        CPPUNIT_ASSERT_EQUAL(size_t(1), results.size());
    }
}

void
DhtProxyClientTester::testReadinessRecoveryIsOneShot()
{
    DhtProxyClient client({}, {}, [] {}, "", "OpenDHT-Test", "client-id", "push-token");
    client.httpContext_.stop();
    client.httpClientThread_.join();
    client.proxyUrl_ = "http://127.0.0.1:1";
    auto key = InfoHash::get("readiness-recovery");
    auto values = [](const std::vector<Sp<Value>>&, bool) {
        return true;
    };
    std::vector<bool> first;
    CPPUNIT_ASSERT(client.listen(key, values, {}, {}, [&](bool ok) { first.push_back(ok); }) != 0);
    auto& listener = client.searches_.at(key).listeners.begin()->second;
    auto request = listener.request;
    dht::http::Response response;
    response.status_code = 503;
    request->cbs_.on_state_change(dht::http::Request::State::DONE, response);
    client.periodic(nullptr, 0, {}, clock::now());
    CPPUNIT_ASSERT(first == std::vector<bool>({false}));
    std::vector<bool> second;
    CPPUNIT_ASSERT(client.listen(key, values, {}, {}, [&](bool ok) { second.push_back(ok); }) != 0);
    CPPUNIT_ASSERT(second.empty());
    client.handleResubscribe({}, key, 1, listener.opstate);
    finishSync(client, listener.request, {}, 1);
    CPPUNIT_ASSERT(first == std::vector<bool>({false}));
    CPPUNIT_ASSERT(second == std::vector<bool>({true}));
    client.shutdown({}, true);
    CPPUNIT_ASSERT_EQUAL(size_t(1), first.size());
    CPPUNIT_ASSERT_EQUAL(size_t(1), second.size());
}
#endif

void
DhtProxyClientTester::testResubscribeUsesKeyRoute()
{
#ifdef OPENDHT_PUSH_NOTIFICATIONS
    DhtProxyClient client({}, {}, [] {}, "http://127.0.0.1:8080", "OpenDHT-Test", "client-id", "push-token");

    DhtProxyClient::Listener listener {ValueCallback([](const std::vector<Sp<Value>>&, bool) { return true; })};
    listener.opstate = std::make_shared<DhtProxyClient::OperationState>();
    listener.needsRecovery = false;
    listener.syncEpoch = "test-epoch";
    listener.cb = [](const std::vector<Sp<Value>>&, bool, system_clock::time_point) {
        return true;
    };

    auto key = InfoHash::get("proxy-client-resubscribe");
    client.resubscribe(key, 1, listener);

    CPPUNIT_ASSERT(listener.request);
    CPPUNIT_ASSERT_EQUAL(std::string("/key/") + key.toString(), std::string(listener.request->header_.request_target()));
    CPPUNIT_ASSERT(listener.request->body_.find("test-epoch") != std::string::npos);
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
    listener.needsRecovery = false;
    listener.syncEpoch = "test-epoch";
    listener.syncRevision = 4;
    listener.cb = [](const std::vector<Sp<Value>>&, bool, system_clock::time_point) {
        return true;
    };

    client.setPushNotificationToken("new-token");

    CPPUNIT_ASSERT(listener.request);
    CPPUNIT_ASSERT_EQUAL(std::string("/key/") + key.toString(), std::string(listener.request->header_.request_target()));
    CPPUNIT_ASSERT(listener.request->body_.find("new-token") != std::string::npos);
    CPPUNIT_ASSERT(listener.request->body_.find("old-token") == std::string::npos);
    CPPUNIT_ASSERT(listener.request->body_.find("test-epoch") != std::string::npos);
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

    CPPUNIT_ASSERT(healthy.request);
    CPPUNIT_ASSERT(healthy.request->body_.find("\"sync\"") != std::string::npos);
#else
    CPPUNIT_ASSERT(true);
#endif
}

#ifdef OPENDHT_PUSH_NOTIFICATIONS
void
DhtProxyClientTester::testWrongSessionPushDoesNotTouchSubscriptions()
{
    DhtProxyClient client({}, {}, [] {}, "", "OpenDHT-Test", "client-id", "push-token");
    client.httpContext_.stop();
    client.httpClientThread_.join();
    client.proxyUrl_ = "http://127.0.0.1:1";
    auto key = InfoHash::get("wrong-session-isolation");
    client.listen(key, [](const std::vector<Sp<Value>>&, bool) { return true; }, {}, {});
    auto& listener = client.searches_.at(key).listeners.begin()->second;
    auto value = std::make_shared<Value>("current-session-value");
    value->id = 42;
    finishSync(client, listener.request, {value}, 5);
    client.statusIpv4_ = NodeStatus::Disconnected;
    client.statusIpv6_ = NodeStatus::Disconnected;
    client.launchConnectedCbs_ = false;
    auto request = listener.request;
    auto generation = listener.opstate->generation.load();
    auto expiration = listener.refreshSubscriberTimer->expiry();
    std::vector<std::map<std::string, std::string>> notifications {
        {{"s", "old-session"}, {"key", key.toString()}, {"epoch", "old-epoch"}, {"revision", "99"}},
        {{"s", "old-session"}, {"key", key.toString()}, {"exp", "42"}},
        {{"s", "old-session"}, {"timeout", key.toString()}},
        {{"s", "old-session"}, {"timeout", key.toString()}, {"vid", "42"}}
    };
    for (const auto& notification : notifications) {
        CPPUNIT_ASSERT(client.pushNotificationReceived(notification) == PushNotificationResult::IgnoredWrongSession);
        CPPUNIT_ASSERT(listener.request == request);
        CPPUNIT_ASSERT_EQUAL(generation, listener.opstate->generation.load());
        CPPUNIT_ASSERT(!listener.needsRecovery);
        CPPUNIT_ASSERT(listener.opstate->ok.load());
        CPPUNIT_ASSERT(listener.refreshSubscriberTimer->expiry() == expiration);
        CPPUNIT_ASSERT_EQUAL(std::string("test-epoch"), listener.syncEpoch);
        CPPUNIT_ASSERT_EQUAL(uint64_t(5), listener.syncRevision);
        CPPUNIT_ASSERT(client.getLocalById(key, 42));
        CPPUNIT_ASSERT(client.statusIpv4_ == NodeStatus::Disconnected);
        CPPUNIT_ASSERT(client.statusIpv6_ == NodeStatus::Disconnected);
        CPPUNIT_ASSERT(!client.launchConnectedCbs_.load());
        CPPUNIT_ASSERT(client.callbacks_.empty());
    }
}

void
DhtProxyClientTester::testNewSessionSynchronizesIndependently()
{
    DhtProxyClient client({}, {}, [] {}, "", "OpenDHT-Test", "client-id", "push-token");
    client.httpContext_.stop();
    client.httpClientThread_.join();
    client.proxyUrl_ = "http://127.0.0.1:1";
    auto key = InfoHash::get("new-session-independent-sync");
    CPPUNIT_ASSERT(client.pushNotificationReceived({
                       {"s",   "old-session" },
                       {"key", key.toString()}
    })
                   == PushNotificationResult::IgnoredWrongSession);
    CPPUNIT_ASSERT(client.searches_.empty());
    client.listen(key, [](const std::vector<Sp<Value>>&, bool) { return true; }, {}, {});
    auto& listener = client.searches_.at(key).listeners.begin()->second;
    Json::Value body;
    std::string error;
    auto reader = std::unique_ptr<Json::CharReader>(Json::CharReaderBuilder {}.newCharReader());
    const auto& requestBody = listener.request->body_;
    CPPUNIT_ASSERT(reader->parse(requestBody.data(), requestBody.data() + requestBody.size(), &body, &error));
    CPPUNIT_ASSERT_EQUAL(client.pushSessionId_, body["session_id"].asString());
    CPPUNIT_ASSERT(body["sync"].isObject() && body["sync"].empty());
    auto value = std::make_shared<Value>("new-session-snapshot");
    value->id = 43;
    finishSync(client, listener.request, {value});
    CPPUNIT_ASSERT(listener.opstate->ok.load());
    CPPUNIT_ASSERT(!listener.needsRecovery);
    CPPUNIT_ASSERT(client.getLocalById(key, 43)->data == value->data);
}

void
DhtProxyClientTester::testFailedTimerRetryFetchesValues()
{
    DhtProxyClient client({}, {}, [] {}, "", "OpenDHT-Test", "client-id", "push-token");
    client.httpContext_.stop();
    client.httpClientThread_.join();
    client.proxyUrl_ = "http://127.0.0.1:1";
    auto key = InfoHash::get("failed-timer-retry");
    client.listen(key, [](const std::vector<Sp<Value>>&, bool) { return true; }, {}, {});
    auto& listener = client.searches_.at(key).listeners.begin()->second;
    listener.opstate->ok = false;
    client.handleResubscribe({}, key, 1, listener.opstate);
    CPPUNIT_ASSERT(listener.request->body_.find("\"refresh\"") == std::string::npos);
}

void
DhtProxyClientTester::testFullRetryRemovesAbsentValues()
{
    DhtProxyClient client({}, {}, [] {}, "", "OpenDHT-Test", "client-id", "push-token");
    client.httpContext_.stop();
    client.httpClientThread_.join();
    client.proxyUrl_ = "http://127.0.0.1:1";
    auto key = InfoHash::get("full-retry-absent-values");
    client.listen(key, [](const std::vector<Sp<Value>>&, bool) { return true; }, {}, {});
    auto& listener = client.searches_.at(key).listeners.begin()->second;
    auto value = std::make_shared<Value>("expired-while-offline");
    value->id = 42;
    listener.cb({value}, false, system_clock::time_point(std::chrono::seconds(10)));
    listener.opstate->ok = false;
    client.restartListeners({});
    auto request = listener.request;
    finishSync(client, request, {});
    CPPUNIT_ASSERT(!client.getLocalById(key, value->id));
}

void
DhtProxyClientTester::testStreamingFallbackExpiresSnapshot()
{
    DhtProxyClient client({}, {}, [] {}, "", "OpenDHT-Test", "client-id", "push-token");
    client.httpContext_.stop();
    client.httpClientThread_.join();
    client.proxyUrl_ = "http://127.0.0.1:1";
    auto key = InfoHash::get("full-retry-push-ordering");
    client.listen(key, [](const std::vector<Sp<Value>>&, bool) { return true; }, {}, {});
    auto& listener = client.searches_.at(key).listeners.begin()->second;
    auto value = std::make_shared<Value>("live-value");
    value->id = 42;
    listener.cb({value}, false, system_clock::time_point(std::chrono::seconds(10)));
    listener.opstate->ok = false;
    client.restartListeners({});
    finishSync(client, listener.request, {value}, 10);
    client.deviceKey_.clear();
    client.restartListeners({});
    auto expired = value->toJson();
    expired["expired"] = true;
    auto body = Json::writeString(client.jsonBuilder_, expired) + "\n";
    listener.request->cbs_.on_body(body.data(), body.size());
    client.periodic(nullptr, 0, {}, clock::now());
    CPPUNIT_ASSERT(!client.getLocalById(key, value->id));
}

void
DhtProxyClientTester::testLateRetryResponseDoesNotResurrectExpiredValue()
{
    DhtProxyClient client({}, {}, [] {}, "", "OpenDHT-Test", "client-id", "push-token");
    client.httpContext_.stop();
    client.httpClientThread_.join();
    client.proxyUrl_ = "http://127.0.0.1:1";
    auto key = InfoHash::get("full-retry-late-response");
    client.listen(key, [](const std::vector<Sp<Value>>&, bool) { return true; }, {}, {});
    auto& listener = client.searches_.at(key).listeners.begin()->second;
    auto value = std::make_shared<Value>("already-expired-value");
    value->id = 42;
    finishSync(client, listener.request, {value}, 10);
    listener.opstate->ok = false;
    client.restartListeners({});
    auto staleRequest = listener.request;
    client.pushNotificationReceived({
        {"key",      key.toString()},
        {"exp",      "42"          },
        {"epoch",    "test-epoch"  },
        {"revision", "11"          }
    });
    finishSync(client, staleRequest, {value}, 10);
    client.handleResubscribe({}, key, 1, listener.opstate);
    finishSync(client, listener.request, {}, 11);
    finishSync(client, staleRequest, {value}, 10);
    CPPUNIT_ASSERT(!client.getLocalById(key, value->id));
}

void
DhtProxyClientTester::testTruncatedRecoveryRemainsFailed()
{
    DhtProxyClient client({}, {}, [] {}, "", "OpenDHT-Test", "client-id", "push-token");
    client.httpContext_.stop();
    client.httpClientThread_.join();
    client.proxyUrl_ = "http://127.0.0.1:1";
    auto key = InfoHash::get("truncated-full-retry");
    client.listen(key, [](const std::vector<Sp<Value>>&, bool) { return true; }, {}, {});
    auto& listener = client.searches_.at(key).listeners.begin()->second;
    listener.opstate->ok = false;
    client.restartListeners({});
    auto request = listener.request;
    request->response_.status_code = 200;
    request->cbs_.on_body("{\"id\":", 6);
    request->terminate(asio::error::connection_reset);
    CPPUNIT_ASSERT(!listener.opstate->ok.load());
}

void
DhtProxyClientTester::testTruncatedRecoveryAtEofFails()
{
    DhtProxyClient client({}, {}, [] {}, "", "OpenDHT-Test", "client-id", "push-token");
    client.httpContext_.stop();
    client.httpClientThread_.join();
    client.proxyUrl_ = "http://127.0.0.1:1";
    auto key = InfoHash::get("truncated-recovery-eof");
    client.listen(key, [](const std::vector<Sp<Value>>&, bool) { return true; }, {}, {});
    auto& listener = client.searches_.at(key).listeners.begin()->second;
    auto request = listener.request;
    request->init_parser();
    std::string response = "HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n{";
    CPPUNIT_ASSERT(llhttp_execute(request->parser_.get(), response.data(), response.size()) == HPE_OK);
    request->handle_response(asio::error::eof, 0);
    CPPUNIT_ASSERT(!listener.opstate->ok.load());
}

void
DhtProxyClientTester::testMissingCompletionDoesNotReconcile()
{
    DhtProxyClient client({}, {}, [] {}, "", "OpenDHT-Test", "client-id", "push-token");
    client.httpContext_.stop();
    client.httpClientThread_.join();
    client.proxyUrl_ = "http://127.0.0.1:1";
    auto key = InfoHash::get("missing-completion");
    client.listen(key, [](const std::vector<Sp<Value>>&, bool) { return true; }, {}, {});
    auto& listener = client.searches_.at(key).listeners.begin()->second;
    auto value = std::make_shared<Value>("keep-value");
    value->id = 42;
    finishSync(client, listener.request, {value});
    client.restartListeners({});
    auto request = listener.request;
    request->cbs_.on_body("{}\n", 3);
    dht::http::Response response;
    response.status_code = 200;
    request->cbs_.on_state_change(dht::http::Request::State::DONE, response);
    client.periodic(nullptr, 0, {}, clock::now());
    CPPUNIT_ASSERT(!listener.opstate->ok.load());
    CPPUNIT_ASSERT(client.getLocalById(key, 42));
    CPPUNIT_ASSERT(listener.refreshSubscriberTimer->expiry() <= system_clock::now() + std::chrono::seconds(2));
}

void
DhtProxyClientTester::testSnapshotExpirationIgnoresClockRollback()
{
    DhtProxyClient client({}, {}, [] {}, "", "OpenDHT-Test", "client-id", "push-token");
    client.httpContext_.stop();
    client.httpClientThread_.join();
    client.proxyUrl_ = "http://127.0.0.1:1";
    auto key = InfoHash::get("snapshot-clock-rollback");
    client.listen(key, [](const std::vector<Sp<Value>>&, bool) { return true; }, {}, {});
    auto& listener = client.searches_.at(key).listeners.begin()->second;
    auto value = std::make_shared<Value>("expired-value");
    value->id = 42;
    listener.cb({value}, false, system_clock::now() + std::chrono::hours(1));
    finishSync(client, listener.request, {});
    CPPUNIT_ASSERT(!client.getLocalById(key, 42));
}

void
DhtProxyClientTester::testSupersededFailureDoesNotPoisonSuccessfulRetry()
{
    DhtProxyClient client({}, {}, [] {}, "", "OpenDHT-Test", "client-id", "push-token");
    client.httpContext_.stop();
    client.httpClientThread_.join();
    client.proxyUrl_ = "http://127.0.0.1:1";
    auto key = InfoHash::get("superseded-full-retry");
    client.listen(key, [](const std::vector<Sp<Value>>&, bool) { return true; }, {}, {});
    auto& listener = client.searches_.at(key).listeners.begin()->second;
    auto oldRequest = listener.request;
    oldRequest->response_.status_code = 503;
    oldRequest->terminate(asio::error::eof);
    client.periodic(nullptr, 0, {}, clock::now());
    client.restartListeners({});
    auto newRequest = listener.request;
    CPPUNIT_ASSERT(newRequest != oldRequest);
    finishSync(client, newRequest, {});
    dht::http::Response response;
    response.status_code = 503;
    oldRequest->cbs_.on_state_change(dht::http::Request::State::DONE, response);
    client.periodic(nullptr, 0, {}, clock::now());
    CPPUNIT_ASSERT(listener.opstate->ok.load());
}

void
DhtProxyClientTester::testSyncCoalescesConnectivityChanges()
{
    DhtProxyClient client({}, {}, [] {}, "", "OpenDHT-Test", "client-id", "push-token");
    client.httpContext_.stop();
    client.httpClientThread_.join();
    client.proxyUrl_ = "http://127.0.0.1:1";
    auto key = InfoHash::get("coalesced-sync");
    client.listen(key, [](const std::vector<Sp<Value>>&, bool) { return true; }, {}, {});
    auto& listener = client.searches_.at(key).listeners.begin()->second;
    auto request = listener.request;
    client.restartListeners({});
    client.restartListeners({});
    CPPUNIT_ASSERT(listener.request == request);
    finishSync(client, request, {}, 5);
    CPPUNIT_ASSERT(listener.request == request);
    client.restartListeners({});
    CPPUNIT_ASSERT(listener.request != request);
    auto body = listener.request->body_;
    CPPUNIT_ASSERT(body.find("test-epoch") != std::string::npos);
    CPPUNIT_ASSERT(body.find("\"revision\":5") != std::string::npos);
    auto validation = listener.request;
    client.restartListeners({});
    client.restartListeners({});
    CPPUNIT_ASSERT(listener.request == validation);
    finishSync(client, listener.request, {}, 5, true, false);
    CPPUNIT_ASSERT(listener.opstate->ok.load());
}

void
DhtProxyClientTester::testTokenRotationDuringRecovery()
{
    DhtProxyClient client({}, {}, [] {}, "", "OpenDHT-Test", "client-id", "old-token");
    client.httpContext_.stop();
    client.httpClientThread_.join();
    client.proxyUrl_ = "http://127.0.0.1:1";
    client.statusIpv4_ = NodeStatus::Connected;
    auto key = InfoHash::get("rotation-during-recovery");
    client.listen(key, [](const std::vector<Sp<Value>>&, bool) { return true; }, {}, {});
    auto& listener = client.searches_.at(key).listeners.begin()->second;
    auto recovery = listener.request;
    client.setPushNotificationToken("new-token");
    CPPUNIT_ASSERT(listener.request == recovery);
    finishSync(client, recovery, {}, 1);
    CPPUNIT_ASSERT(listener.request != recovery);
    CPPUNIT_ASSERT(listener.request->body_.find("new-token") != std::string::npos);
    finishSync(client, listener.request, {}, 1, true, false);
    CPPUNIT_ASSERT(listener.opstate->ok.load());
}

void
DhtProxyClientTester::testTokenRotationBackToPreviousEpoch()
{
    DhtProxyClient client({}, {}, [] {}, "", "OpenDHT-Test", "client-id", "first-token");
    client.httpContext_.stop();
    client.httpClientThread_.join();
    client.proxyUrl_ = "http://127.0.0.1:1";
    client.statusIpv4_ = NodeStatus::Connected;
    auto key = InfoHash::get("rotation-back-to-previous-epoch");
    client.listen(key, [](const std::vector<Sp<Value>>&, bool) { return true; }, {}, {});
    auto& listener = client.searches_.at(key).listeners.begin()->second;
    finishSync(client, listener.request, {}, 1);
    client.setPushNotificationToken("second-token");
    finishSync(client, listener.request, {}, 1, true, true, "second-epoch");
    CPPUNIT_ASSERT(listener.opstate->ok.load());
    client.setPushNotificationToken("first-token");
    finishSync(client, listener.request, {}, 2);
    CPPUNIT_ASSERT(listener.opstate->ok.load());
    CPPUNIT_ASSERT_EQUAL(std::string("test-epoch"), listener.syncEpoch);
}

void
DhtProxyClientTester::testAuthoritativeEpochAfterStalePush()
{
    DhtProxyClient client({}, {}, [] {}, "", "OpenDHT-Test", "client-id", "push-token");
    client.httpContext_.stop();
    client.httpClientThread_.join();
    client.proxyUrl_ = "http://127.0.0.1:1";
    auto key = InfoHash::get("authoritative-epoch-after-stale-push");
    client.listen(key, [](const std::vector<Sp<Value>>&, bool) { return true; }, {}, {});
    auto& listener = client.searches_.at(key).listeners.begin()->second;
    finishSync(client, listener.request, {}, 1);
    client.restartListeners({});
    auto stale = listener.request;
    client.pushNotificationReceived({
        {"key",      key.toString()     },
        {"epoch",    "intervening-epoch"},
        {"revision", "1"                }
    });
    finishSync(client, stale, {}, 1);
    finishSync(client, listener.request, {}, 1, true, true, "current-epoch");
    CPPUNIT_ASSERT(listener.opstate->ok.load());
    CPPUNIT_ASSERT_EQUAL(std::string("current-epoch"), listener.syncEpoch);
    auto current = listener.request;
    client.pushNotificationReceived({
        {"key",      key.toString()     },
        {"epoch",    "intervening-epoch"},
        {"revision", "2"                }
    });
    CPPUNIT_ASSERT(listener.request != current);
    CPPUNIT_ASSERT(listener.request->body_.find("current-epoch") != std::string::npos);
    finishSync(client, listener.request, {}, 1, true, false, "current-epoch");
    CPPUNIT_ASSERT(listener.opstate->ok.load());
}

void
DhtProxyClientTester::testSyncEditsAndDuplicateValues()
{
    DhtProxyClient client({}, {}, [] {}, "", "OpenDHT-Test", "client-id", "push-token");
    client.httpContext_.stop();
    client.httpClientThread_.join();
    client.proxyUrl_ = "http://127.0.0.1:1";
    auto key = InfoHash::get("snapshot-edits");
    unsigned additions = 0;
    unsigned expirations = 0;
    client.listen(key,
                  [&](const std::vector<Sp<Value>>& values, bool expired) {
                      (expired ? expirations : additions) += values.size();
                      return true;
                  },
                  {},
                  {});
    auto& listener = client.searches_.at(key).listeners.begin()->second;
    auto identity = dht::crypto::generateIdentity("SnapshotEditAuthor");
    auto original = std::make_shared<Value>("original");
    original->id = 42;
    original->seq = 1;
    original->sign(*identity.first);
    finishSync(client, listener.request, {original}, 1);
    client.restartListeners({});
    finishSync(client, listener.request, {}, 1, true, false);
    CPPUNIT_ASSERT_EQUAL(1u, additions);
    auto edited = std::make_shared<Value>("edited");
    edited->id = 42;
    edited->seq = 2;
    edited->sign(*identity.first);
    client.pushNotificationReceived({
        {"key",      key.toString()},
        {"epoch",    "test-epoch"  },
        {"revision", "2"           }
    });
    finishSync(client, listener.request, {edited}, 2);
    CPPUNIT_ASSERT_EQUAL(2u, additions);
    CPPUNIT_ASSERT_EQUAL(0u, expirations);
    CPPUNIT_ASSERT(client.getLocalById(key, 42)->data == edited->data);
    client.pushNotificationReceived({
        {"key",      key.toString()},
        {"epoch",    "test-epoch"  },
        {"revision", "1"           }
    });
    CPPUNIT_ASSERT(client.getLocalById(key, 42)->data == edited->data);
}

void
DhtProxyClientTester::testIncompleteSnapshotDoesNotReconcile()
{
    DhtProxyClient client({}, {}, [] {}, "", "OpenDHT-Test", "client-id", "push-token");
    client.httpContext_.stop();
    client.httpClientThread_.join();
    client.proxyUrl_ = "http://127.0.0.1:1";
    auto key = InfoHash::get("incomplete-snapshot");
    client.listen(key, [](const std::vector<Sp<Value>>&, bool) { return true; }, {}, {});
    auto& listener = client.searches_.at(key).listeners.begin()->second;
    auto value = std::make_shared<Value>("keep-until-complete");
    value->id = 42;
    finishSync(client, listener.request, {value}, 1);
    listener.opstate->ok = false;
    client.restartListeners({});
    finishSync(client, listener.request, {}, 2, false);
    CPPUNIT_ASSERT(client.getLocalById(key, 42));
    CPPUNIT_ASSERT(!listener.opstate->ok.load());
    client.handleResubscribe({}, key, 1, listener.opstate);
    auto recovery = listener.request;
    finishSync(client, recovery, {}, 2);
    CPPUNIT_ASSERT(!client.getLocalById(key, 42));
}
void
DhtProxyClientTester::testSubscriptionDeadline()
{
    DhtProxyClient client({}, {}, [] {}, "", "OpenDHT-Test", "client-id", "push-token");
    client.httpContext_.stop();
    client.httpClientThread_.join();
    client.proxyUrl_ = "http://127.0.0.1:1";
    client.subscriptionRequestTimeout_ = std::chrono::seconds(0);
    auto key = InfoHash::get("subscription-deadline");
    client.listen(key, [](const std::vector<Sp<Value>>&, bool) { return true; }, {}, {});
    auto& listener = client.searches_.at(key).listeners.begin()->second;
    auto request = listener.request;
    CPPUNIT_ASSERT(listener.opstate->inFlight.load());
    client.httpContext_.restart();
    client.httpContext_.poll();
    client.httpContext_.stop();
    client.periodic(nullptr, 0, {}, clock::now());
    CPPUNIT_ASSERT(!listener.opstate->inFlight.load());
    CPPUNIT_ASSERT(!listener.opstate->ok.load());
    CPPUNIT_ASSERT(request->finishing_.load());
    CPPUNIT_ASSERT(listener.needsRecovery);
    CPPUNIT_ASSERT(listener.refreshSubscriberTimer->expiry() <= system_clock::now() + std::chrono::seconds(2));
    client.handleResubscribe({}, key, 1, listener.opstate);
    CPPUNIT_ASSERT(listener.request != request);
}

void
DhtProxyClientTester::testInvalidPushRevision()
{
    DhtProxyClient client({}, {}, [] {}, "", "OpenDHT-Test", "client-id", "push-token");
    client.httpContext_.stop();
    client.httpClientThread_.join();
    client.proxyUrl_ = "http://127.0.0.1:1";
    auto key = InfoHash::get("invalid-push-revision");
    client.listen(key, [](const std::vector<Sp<Value>>&, bool) { return true; }, {}, {});
    auto& listener = client.searches_.at(key).listeners.begin()->second;
    finishSync(client, listener.request, {}, 5);
    auto request = listener.request;
    for (const auto& revision : {"-1", "+6", " 6", "6 ", "6x", "", "18446744073709551616"}) {
        CPPUNIT_ASSERT(client.pushNotificationReceived({
                           {"key",      key.toString()},
                           {"epoch",    "test-epoch"  },
                           {"revision", revision      }
        })
                       == PushNotificationResult::Error);
        CPPUNIT_ASSERT_EQUAL(uint64_t(5), listener.observedRevision);
        CPPUNIT_ASSERT_EQUAL(uint64_t(5), listener.syncRevision);
        CPPUNIT_ASSERT(listener.request == request);
        CPPUNIT_ASSERT(!listener.needsRecovery);
    }
    client.pushNotificationReceived({
        {"key",      key.toString()},
        {"epoch",    "test-epoch"  },
        {"revision", "6"           }
    });
    CPPUNIT_ASSERT(listener.request != request);
    finishSync(client, listener.request, {}, 6);
    CPPUNIT_ASSERT(listener.opstate->ok.load());
}

void
DhtProxyClientTester::testRecoveryBackoff()
{
    DhtProxyClient client({}, {}, [] {}, "", "OpenDHT-Test", "client-id", "push-token");
    client.httpContext_.stop();
    client.httpClientThread_.join();
    client.proxyUrl_ = "http://127.0.0.1:1";
    auto key = InfoHash::get("recovery-backoff");
    client.listen(key, [](const std::vector<Sp<Value>>&, bool) { return true; }, {}, {});
    auto& listener = client.searches_.at(key).listeners.begin()->second;
    for (unsigned attempt = 0; attempt < 8; ++attempt) {
        auto request = listener.request;
        auto generation = listener.opstate->generation.load();
        Json::Value marker;
        marker["sync"]["epoch"] = "test-epoch";
        marker["sync"]["revision"] = Json::UInt64(1);
        marker["sync"]["snapshot"] = true;
        marker["sync"]["complete"] = false;
        marker["sync"]["retry"] = Json::Value(Json::objectValue);
        auto body = Json::writeString(client.jsonBuilder_, marker) + "\n";
        request->cbs_.on_body(body.data(), body.size());
        dht::http::Response response;
        response.status_code = 200;
        request->cbs_.on_state_change(dht::http::Request::State::DONE, response);
        client.periodic(nullptr, 0, {}, clock::now());
        CPPUNIT_ASSERT(listener.request == request);
        CPPUNIT_ASSERT_EQUAL(generation, listener.opstate->generation.load());
        CPPUNIT_ASSERT(!listener.opstate->inFlight.load());
        CPPUNIT_ASSERT(!listener.opstate->ok.load());
        CPPUNIT_ASSERT(listener.retryDelay <= std::chrono::seconds(60));
        client.handleResubscribe({}, key, 1, listener.opstate);
        CPPUNIT_ASSERT(listener.request != request);
    }
    CPPUNIT_ASSERT(listener.retryDelay == std::chrono::seconds(60));
    finishSync(client, listener.request, {}, 1);
    CPPUNIT_ASSERT(listener.retryDelay == std::chrono::seconds(1));
    CPPUNIT_ASSERT(listener.refreshSubscriberTimer->expiry() > system_clock::now() + std::chrono::minutes(1));
}

void
DhtProxyClientTester::testContiguousExpiration()
{
    DhtProxyClient client({}, {}, [] {}, "", "OpenDHT-Test", "client-id", "push-token");
    client.httpContext_.stop();
    client.httpClientThread_.join();
    client.proxyUrl_ = "http://127.0.0.1:1";
    auto key = InfoHash::get("contiguous-expiration");
    client.listen(key, [](const std::vector<Sp<Value>>&, bool) { return true; }, {}, {});
    auto& listener = client.searches_.at(key).listeners.begin()->second;
    auto first = std::make_shared<Value>("first");
    first->id = 42;
    auto second = std::make_shared<Value>("second");
    second->id = 43;
    finishSync(client, listener.request, {first, second}, 5);
    CPPUNIT_ASSERT(listener.cache.onValuesAdded({first, second}, system_clock::now()));
    auto request = listener.request;
    client.pushNotificationReceived({
        {"key",      key.toString()},
        {"epoch",    "test-epoch"  },
        {"revision", "6"           },
        {"expired",  "true"        },
        {"ids",      "42,43"       }
    });
    client.periodic(nullptr, 0, {}, clock::now());
    CPPUNIT_ASSERT(listener.request == request);
    CPPUNIT_ASSERT(!client.getLocalById(key, 42));
    CPPUNIT_ASSERT(!client.getLocalById(key, 43));
    CPPUNIT_ASSERT_EQUAL(uint64_t(6), listener.syncRevision);
    client.resubscribe(key, 1, listener);
    finishSync(client, listener.request, {}, 6, true, false);
    CPPUNIT_ASSERT(!client.getLocalById(key, 42));
    CPPUNIT_ASSERT(!client.getLocalById(key, 43));
    CPPUNIT_ASSERT(listener.opstate->ok.load());
    request = listener.request;
    client.pushNotificationReceived({
        {"key",      key.toString()},
        {"epoch",    "test-epoch"  },
        {"revision", "8"           },
        {"exp",      "42"          }
    });
    CPPUNIT_ASSERT(listener.request != request);
    CPPUNIT_ASSERT(listener.needsRecovery);
}
#endif

} // namespace test